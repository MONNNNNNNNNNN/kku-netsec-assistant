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
  const sse = new Set();
  app.sse = sse;
  app.broadcast = (event, data) => {
    const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of sse) res.write(msg);
  };

  app.pipeline = new Pipeline({ db, cfg, batchMs: opts.batchMs ?? 200 });
  app.notifier = new Notifier({ db, cfg, senders: opts.senders });
  app.llmq = new LlmQueue({ db, cfg: cfg.llm, pipeline: app.pipeline, lang: cfg.lang, chat: opts.chat });
  app.scheduler = new Scheduler({ db, tzOffsetMinutes: cfg.tzOffsetMinutes, jitter: opts.jitter ?? true, backoffBaseMs: opts.backoffBaseMs });

  app.pipeline.on('change', (c) => {
    if (c.item) app.broadcast('item', c.item);
    if (!c.llm) { app.notifier.consider(c); app.llmq.consider(c); }
    else if (c.escalated) app.notifier.consider({ ...c, isNew: false });
  });
  app.notifier.on('board', (n) => app.broadcast('notify', n));
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
  const hb = setInterval(() => { for (const res of sse) res.write(': ping\n\n'); }, 25000);
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

  app.server = http.createServer(createHandler(app));
  app.server.headersTimeout = 20000;
  app.server.requestTimeout = 60000;
  if (opts.listen !== false) {
    await new Promise((res) => app.server.listen(opts.port ?? cfg.listen.port, opts.host ?? cfg.listen.host, res));
    const a = app.server.address();
    app.url = `http://${a.family === 'IPv6' ? `[${a.address}]` : a.address}:${a.port}`;
  }

  app.close = async () => {
    clearInterval(dvTimer); clearInterval(hb); clearInterval(ret);
    app.scheduler.stop(); app.notifier.stop(); app.llmq.stop();
    if (app.syslog) app.syslog.stop();
    app.pipeline.flush();
    await app.notifier.idle();
    await Promise.allSettled([...app.scheduler.jobs.values()].map((j) => j.running).filter(Boolean));
    for (const res of sse) res.end();
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
  const stop = async () => { await app.close(); process.exit(0); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (require.main === module) main().catch((e) => { console.error(e.stack || e.message); process.exit(1); });

module.exports = { createApp, makeJob, PULLERS, VERSION };
