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
const { loadConfig, sevRank } = require('./config.js');
const { Pipeline, toItem } = require('./pipeline.js');
const { Scheduler } = require('./scheduler.js');
const { SyslogCollector } = require('./collectors/syslog.js');
const PULL = require('./collectors/pull.js');
const { Notifier } = require('./notify.js');
const { LlmQueue } = require('./llmqueue.js');
const { createHandler } = require('./http.js');

const VERSION = require('../package.json').version;
const PULLERS = { wazuh: PULL.pullWazuh, zabbix: PULL.pullZabbix, configdrop: PULL.pullConfigDrop, fortigate: PULL.pullFortigateBackup };

/**
 * One pull run: fetch, ingest, flush, resolve stale config cards, then advance the cursor.
 * The first run of a source (no cursor yet) is a quiet baseline: every open problem and the
 * initial lookback appear as cards, but channels and automatic AI stay silent
 * (sources.<name>.quietFirstRun: false turns that off).
 */
function makeJob(name, { cfg, db, pipeline, log = () => {} }) {
  return async (ctx) => {
    const r = await PULLERS[name](cfg.sources[name], ctx.cursor);
    const quiet = !ctx.cursor && cfg.sources[name].quietFirstRun !== false;
    for (const e of r.events) pipeline.ingest(e, name, { quiet });
    pipeline.flush();
    if (quiet && r.events.length) log(`${name}: first run, ${r.events.length} event(s) loaded without notifications`);
    for (const c of (r.extra && r.extra.configs) || []) {
      db_.setMeta(db, `config:${c.device}`, c.summary);
      pipeline.resolveStale(name, c.device, new Set(c.events.map((e) => e.fingerprint)));
    }
    ctx.setCursor(r.cursor); // after the write: at-least-once, and fingerprints dedupe repeats
    return { n: r.events.length };
  };
}

/**
 * Wire everything together. opts: {listen, startSources, jitter, log, role}
 * role "cli" (`cli/board.js pull` from system cron) is a lean writer: no LLM queue, no
 * recovery of the server's LLM state, no retention. The running server picks its rows up.
 */
async function createApp(loaded, opts = {}) {
  const { cfg, raw } = loaded;
  const cli = opts.role === 'cli';
  const db = db_.openDb(cfg.dataDir);
  const boot = require('./auth.js').bootstrapAdmin(db);
  if (boot) (opts.log || ((m) => console.error(`[board] ${m}`)))(`created admin "${boot}" from secrets.env (NETSEC_ADMIN_HASH)`);
  const log = opts.log || ((m) => console.error(`[board] ${m}`));
  const app = { cfg, rawConfig: raw, db, version: VERSION, log };
  // live stream: response -> session token hash, so a stream ends when its session does
  const sse = new Map();
  app.sse = sse;
  app.sseAdd = (res, tokenHash) => sse.set(res, tokenHash);
  app.sseDrop = (res) => sse.delete(res);
  app.sseEndSession = (tokenHash) => { for (const [res, h] of sse) if (h === tokenHash) { res.end(); sse.delete(res); } };
  // a stalled client (phone in the background, TCP window 0) must not make Node buffer forever:
  // past the cap the stream ends, the browser reconnects (retry: 3000) and refetches
  const sseMaxBuffer = opts.sseMaxBuffer ?? 1024 * 1024;
  app.sseWrite = (res, msg) => {
    if (res.writableLength > sseMaxBuffer) { sse.delete(res); res.destroy(); return; }
    res.write(msg);
  };
  app.broadcast = (event, data) => {
    const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of [...sse.keys()]) app.sseWrite(res, msg);
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
  // the CLI never talks to the LLM: the server owns the queue (and its in-flight state)
  app.llmq = new LlmQueue({ db, cfg: cli ? null : cfg.llm, pipeline: app.pipeline, lang: cfg.lang, chat: opts.chat });
  app.scheduler = new Scheduler({ db, tzOffsetMinutes: cfg.tzOffsetMinutes, jitter: opts.jitter ?? true, backoffBaseMs: opts.backoffBaseMs, lockDir: cfg.dataDir });
  if (!cli) {
    const recovered = app.llmq.recover();
    if (recovered) log(`llm: ${recovered} card(s) left queued by the last run were reset`);
  }

  // rows another process (the CLI) inserted, re-opened or escalated are swept up when
  // data_version changes; what this process did itself is skipped (it already handled it)
  let swept = db.prepare('SELECT COALESCE(MAX(id), 0) AS m FROM items').get().m;
  let sweptAt = Date.now();
  const ownIds = new Set();
  const touched = new Map(); // id -> when this process re-opened or escalated it
  app.sweepForeign = () => {
    const started = Date.now();
    const rows = db.prepare('SELECT * FROM items WHERE id > ? OR reopened_at > ? OR escalated_at > ? ORDER BY id').all(swept, sweptAt, sweptAt);
    let n = 0;
    for (const r of rows) {
      let c;
      if (r.id > swept) {
        if (ownIds.delete(r.id)) continue;
        c = { id: r.id, item: toItem(r), isNew: true, escalated: false, foreign: true };
      } else {
        const at = Math.max(r.reopened_at || 0, r.escalated_at || 0);
        if ((touched.get(r.id) || 0) >= at) continue;
        const reopened = (r.reopened_at || 0) > sweptAt;
        c = { id: r.id, item: toItem(r), isNew: reopened, reopened, escalated: (r.escalated_at || 0) > sweptAt, foreign: true };
      }
      n++;
      app.queueItem(c);
      app.notifier.boardNote(c); // channels were already routed by the writer
      app.llmq.consider(c);
    }
    for (const r of rows) swept = Math.max(swept, r.id);
    sweptAt = started;
    for (const id of ownIds) if (id <= swept) ownIds.delete(id);
    for (const [id, t] of touched) if (t < started) touched.delete(id); // later sweeps only look past `started`
    return n;
  };

  app.pipeline.on('change', (c) => {
    if (c.isNew && !c.reopened && c.id > swept) ownIds.add(c.id);
    if (c.reopened || c.escalated) touched.set(c.id, Date.now());
    app.queueItem(c);
    if (c.quiet) { app.notifier.boardNote(c); return; } // first-run baseline: board only
    // K6/K7: defence in depth. The notifier routes on item.pageSeverity (K7c), which leaves out
    // correlation raises and AI raises on device-low cards, now and on any later re-open or re-arm.
    // K6 correlation raises never page by themselves (one side may come from log text)
    if (c.correlated) { if (c.escalated) app.notifier.boardNote({ ...c, isNew: false }); return; }
    if (!c.llm) { app.notifier.consider(c); app.llmq.consider(c); }
    // K7: an LLM escalation pages only when the device-derived severity is already medium or more;
    // otherwise an attacker who talks the model into "malicious" on a low event could page the NOC
    else if (c.escalated) {
      if (sevRank(c.item.devSeverity) >= sevRank('medium')) app.notifier.consider({ ...c, isNew: false });
      else app.notifier.boardNote({ ...c, isNew: false });
    }
  });
  app.notifier.on('board', (n) => { pendingNotes.push(n); armSse(); });
  app.notifier.on('error', (e) => log(`notify ${e.channel}: ${e.error}`));
  app.llmq.on('status', (s) => app.broadcast('llm', s));
  app.scheduler.on('source', (name) => app.broadcast('source', { name, ...db_.sourceState(db, name) }));

  for (const name of Object.keys(PULLERS)) {
    if (cfg.sources[name] && cfg.sources[name].enabled) app.scheduler.add(name, cfg.sources[name].schedule, makeJob(name, { cfg, db, pipeline: app.pipeline, log }));
  }

  // items written by another process (`cli/board.js pull` from system cron) -> tell browsers to refetch
  let dv = db.prepare('PRAGMA data_version').get().data_version;
  const dvTimer = setInterval(() => {
    const v = db.prepare('PRAGMA data_version').get().data_version;
    if (v !== dv) { dv = v; app.sweepForeign(); app.broadcast('refresh', {}); }
  }, 2000);
  // heartbeat; also ends streams whose session was logged out, expired or revoked (user passwd)
  const sessionAlive = db.prepare('SELECT 1 FROM sessions WHERE token_hash = ? AND expires > ?');
  const hb = setInterval(() => {
    for (const [res, h] of sse) {
      if (!sessionAlive.get(h, Date.now())) { res.end(); sse.delete(res); } else app.sseWrite(res, ': ping\n\n');
    }
  }, opts.heartbeatMs ?? 25000);
  const ret = setInterval(() => db_.retention(db, cfg.retentionDays), 6 * 3600000);
  // K4: close idle cards of never-resolving events (every 10 min; not in the cron CLI)
  const idle = setInterval(() => app.pipeline.resolveIdle(), opts.idleSweepMs ?? 600000);
  idle.unref();
  if (cli) clearInterval(idle);
  app.stopIdle = () => clearInterval(idle);
  for (const t of [dvTimer, hb, ret]) t.unref();
  if (cli) { clearInterval(dvTimer); clearInterval(hb); clearInterval(ret); } else db_.retention(db, cfg.retentionDays);

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
    clearInterval(dvTimer); clearInterval(hb); clearInterval(ret); app.stopIdle(); clearTimeout(sseTimer);
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
  if (loaded.secretsWarning) console.error(`[board] WARN ${loaded.secretsWarning}`);
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
    if (e.code === 'EACCES' && e.syscall !== 'listen' && e.path) console.error(`[board] cannot read ${e.path} (permission denied): the board runs as ${process.getuid ? `uid ${process.getuid()}` : 'this user'}; make the file readable for it (netsec.json holds no secrets: chmod 644 is fine).`);
    else if ((e.code === 'EADDRINUSE' || e.code === 'EACCES') && e.syscall === 'listen') console.error(`[board] cannot listen on ${e.address}:${e.port} (${e.code === 'EADDRINUSE' ? 'already in use: is another board or the demo still running?' : 'permission denied'}). Stop the other process, or set listen.port in the config / NETSEC_LISTEN_PORT.`);
    else if (e.code === 'ENOENT' && /netsec\.json|\.json'?$/.test(e.path || '')) console.error(`[board] no config file ${e.path}: run "node cli/board.js init" first (or pass --config <file>).`);
    else console.error(e.stack || e.message);
    process.exit(1);
  });
}

module.exports = { createApp, makeJob, PULLERS, VERSION };
