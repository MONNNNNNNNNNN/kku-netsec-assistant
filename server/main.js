#!/usr/bin/env node
'use strict';
/*
 * NetSec Board server.
 *   node server/main.js --config netsec.json
 * Starts the HTTP board, the syslog receiver (if enabled), the cron scheduler for pull
 * sources, the notifier and the LLM queue. Zero npm dependencies; Node >= 22.13.
 */
const http = require('node:http');
const db_ = require('./db.js');
const { loadConfig } = require('./config.js');
const { Pipeline, toItem } = require('./pipeline.js');
const { Scheduler } = require('./scheduler.js');
const { SyslogCollector } = require('./collectors/syslog.js');
const PULL = require('./collectors/pull.js');
const { Notifier } = require('./notify.js');
const { LlmQueue } = require('./llmqueue.js');
const { createHandler } = require('./http.js');

const VERSION = require('../package.json').version;
const PULLERS = { wazuh: PULL.pullWazuh, zabbix: PULL.pullZabbix, configdrop: PULL.pullConfigDrop, fortigate: PULL.pullFortigateBackup };

/** One pull run: fetch, ingest, flush, resolve stale config cards, then advance the cursor. */
function makeJob(name, { cfg, db, pipeline }) {
  return async (ctx) => {
    const r = await PULLERS[name](cfg.sources[name], ctx.cursor);
    for (const e of r.events) pipeline.ingest(e, name);
    pipeline.flush();
    for (const c of (r.extra && r.extra.configs) || []) {
      db_.setMeta(db, `config:${c.device}`, c.summary);
      pipeline.resolveStale(name, c.device, new Set(c.events.map((e) => e.fingerprint)));
    }
    ctx.setCursor(r.cursor); // after the write: at-least-once, and fingerprints dedupe repeats
    return { n: r.events.length };
  };
}

/** Wire everything together. opts: {listen, startSources, jitter, log} */
async function createApp(loaded, opts = {}) {
  const { cfg, raw } = loaded;
  const db = db_.openDb(cfg.dataDir);
  const log = opts.log || ((m) => console.error(`[board] ${m}`));
  const app = { cfg, rawConfig: raw, db, version: VERSION, log };
  // live stream: response -> session token hash, so a stream ends when its session does
  const sse = new Map();
  app.sse = sse;
  app.sseAdd = (res, tokenHash) => sse.set(res, tokenHash);
  app.sseDrop = (res) => sse.delete(res);
  app.sseEndSession = (tokenHash) => { for (const [res, h] of sse) if (h === tokenHash) { res.end(); sse.delete(res); } };
  app.broadcast = (event, data) => {
    const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of sse.keys()) res.write(msg);
  };
  // Pipeline changes are coalesced: at most one "items" event per interval, each card once.
  // A plain repeat (count +1) only sends {id, count, lastSeen}; a burst of 2,000 lines/s must
  // not become 2,000 full events/s per browser.
  const sseMs = opts.sseIntervalMs ?? 1000;
  let pendingFull = new Map(), pendingPatch = new Map(), pendingNotes = [], sseTimer = null, lastSse = 0;
  const flushSse = () => {
    sseTimer = null; lastSse = Date.now();
    if (pendingFull.size || pendingPatch.size) {
      app.broadcast('items', { full: [...pendingFull.values()], patch: [...pendingPatch.values()].filter((p) => !pendingFull.has(p.id)) });
    }
    if (pendingNotes.length) app.broadcast('notify', { items: pendingNotes.slice(0, 20), more: Math.max(0, pendingNotes.length - 20) });
    pendingFull = new Map(); pendingPatch = new Map(); pendingNotes = [];
  };
  const armSse = () => { if (!sseTimer) sseTimer = setTimeout(flushSse, Math.max(0, lastSse + sseMs - Date.now())); };
  app.queueItem = (c) => {
    if (!c.item) return;
    if (c.repeat && !c.escalated && !c.isNew) pendingPatch.set(c.id, { id: c.id, count: c.item.count, lastSeen: c.item.lastSeen });
    else pendingFull.set(c.id, c.item);
    armSse();
  };
  app.flushSse = flushSse;

  app.pipeline = new Pipeline({ db, cfg, batchMs: opts.batchMs ?? 200 });
  app.notifier = new Notifier({ db, cfg, senders: opts.senders });
  app.llmq = new LlmQueue({ db, cfg: cfg.llm, pipeline: app.pipeline, lang: cfg.lang, chat: opts.chat });
  app.scheduler = new Scheduler({ db, tzOffsetMinutes: cfg.tzOffsetMinutes, jitter: opts.jitter ?? true, backoffBaseMs: opts.backoffBaseMs });
  const recovered = app.llmq.recover();
  if (recovered) log(`llm: ${recovered} card(s) left queued by the last run were reset`);

  app.pipeline.on('change', (c) => {
    app.queueItem(c);
    if (!c.llm) { app.notifier.consider(c); app.llmq.consider(c); }
    else if (c.escalated) app.notifier.consider({ ...c, isNew: false });
  });
  app.notifier.on('board', (n) => { pendingNotes.push(n); armSse(); });
  app.notifier.on('error', (e) => log(`notify ${e.channel}: ${e.error}`));
  app.llmq.on('status', (s) => app.broadcast('llm', s));
  app.scheduler.on('source', (name) => app.broadcast('source', { name, ...db_.sourceState(db, name) }));

  for (const name of Object.keys(PULLERS)) {
    if (cfg.sources[name] && cfg.sources[name].enabled) app.scheduler.add(name, cfg.sources[name].schedule, makeJob(name, { cfg, db, pipeline: app.pipeline }));
  }

  // items written by another process (`cli/board.js pull` from system cron) -> tell browsers to refetch
  let dv = db.prepare('PRAGMA data_version').get().data_version;
  const dvTimer = setInterval(() => {
    const v = db.prepare('PRAGMA data_version').get().data_version;
    if (v !== dv) { dv = v; app.broadcast('refresh', {}); }
  }, 2000);
  // heartbeat; also ends streams whose session was logged out, expired or revoked (user passwd)
  const sessionAlive = db.prepare('SELECT 1 FROM sessions WHERE token_hash = ? AND expires > ?');
  const hb = setInterval(() => {
    for (const [res, h] of sse) {
      if (!sessionAlive.get(h, Date.now())) { res.end(); sse.delete(res); } else res.write(': ping\n\n');
    }
  }, opts.heartbeatMs ?? 25000);
  const ret = setInterval(() => db_.retention(db, cfg.retentionDays), 6 * 3600000);
  for (const t of [dvTimer, hb, ret]) t.unref();
  db_.retention(db, cfg.retentionDays);

  if (opts.startSources !== false) {
    if (cfg.sources.syslog.enabled) {
      app.syslog = new SyslogCollector({ cfg: cfg.sources.syslog, db, pipeline: app.pipeline });
      app.syslogAddress = await app.syslog.start();
      if (!cfg.sources.syslog.allow.length) log('syslog: allowlist is empty, every sender is dropped (set sources.syslog.allow)');
    }
    app.scheduler.start({ runOnStart: opts.runOnStart !== false });
    app.notifier.start();
  }

  // slow clients: headers within 20 s, whole request within 60 s; Node checks these timers every
  // connectionsCheckingInterval (default 30 s), so check every 5 s to actually enforce them
  app.server = http.createServer({ connectionsCheckingInterval: opts.connCheckMs ?? 5000 }, createHandler(app));
  app.server.headersTimeout = opts.headersTimeoutMs ?? 20000;
  app.server.requestTimeout = opts.requestTimeoutMs ?? 60000;
  if (opts.listen !== false) {
    await new Promise((res, rej) => { app.server.once('error', rej); app.server.listen(opts.port ?? cfg.listen.port, opts.host ?? cfg.listen.host, () => { app.server.removeListener('error', rej); res(); }); });
    const a = app.server.address();
    app.url = `http://${a.family === 'IPv6' ? `[${a.address}]` : a.address}:${a.port}`;
  }

  app.close = async () => {
    clearInterval(dvTimer); clearInterval(hb); clearInterval(ret); clearTimeout(sseTimer);
    app.scheduler.stop(); app.notifier.stop(); app.llmq.stop();
    if (app.syslog) app.syslog.stop();
    app.pipeline.flush();
    await app.notifier.idle();
    await Promise.allSettled([...app.scheduler.jobs.values()].map((j) => j.running).filter(Boolean));
    for (const res of sse.keys()) res.end();
    await new Promise((res) => app.server.close(() => res()));
    db.close();
  };
  app.toItem = toItem;
  return app;
}

async function main() {
  const argv = process.argv.slice(2);
  const i = argv.indexOf('--config');
  const file = i >= 0 ? argv[i + 1] : process.env.NETSEC_CONFIG || 'netsec.json';
  const loaded = loadConfig(file);
  const app = await createApp(loaded);
  console.error(`[board] NetSec Board ${VERSION} on ${app.url} (data ${loaded.cfg.dataDir})`);
  if (app.syslogAddress) console.error(`[board] syslog on ${JSON.stringify(app.syslogAddress)}`);
  console.error(`[board] pull sources: ${[...app.scheduler.jobs.keys()].join(', ') || 'none'}; LLM: ${app.llmq.enabled ? app.llmq.cfg.model : 'off'}`);
  // last resort: a bug in one request or job must not take the board down (log it, keep serving)
  process.on('unhandledRejection', (e) => console.error(`[board] unhandled rejection: ${e && e.stack ? e.stack : e}`));
  const stop = async () => { await app.close(); process.exit(0); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (require.main === module) {
  main().catch((e) => {
    if (e.code === 'EADDRINUSE' || e.code === 'EACCES') console.error(`[board] cannot listen on ${e.address}:${e.port} (${e.code === 'EADDRINUSE' ? 'already in use: is another board or the demo still running?' : 'permission denied'}). Stop the other process, or set listen.port in the config / NETSEC_LISTEN_PORT.`);
    else if (e.code === 'ENOENT' && /netsec\.json|\.json'?$/.test(e.path || '')) console.error(`[board] no config file ${e.path}: run "node cli/board.js init" first (or pass --config <file>).`);
    else console.error(e.stack || e.message);
    process.exit(1);
  });
}

module.exports = { createApp, makeJob, PULLERS, VERSION };
