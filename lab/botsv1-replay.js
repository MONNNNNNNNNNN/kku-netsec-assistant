#!/usr/bin/env node
'use strict';
/*
 * X1: real FortiGate logs (Splunk BOTSv1, CC0 1.0) through the board.
 *   node lab/botsv1-replay.js [--traffic-lines 200000] [--out results/real-data/x1-botsv1.json]
 * Input: lab/botsv1/botsv1.fgt_{event,utm}.json.gz and botsv1.fgt_traffic.first200k.json
 * (download: lab/README.md). Each record's _raw is the line as written by the receiving syslog
 * server ("Aug 13 22:06:24 192.168.250.1 date=... devid=..."); the replay strips that header and
 * sends "<PRI>date=..." like a FortiGate does.
 *
 * Three measurements:
 *  a) offline, every line: parse rate, device fields, trust split, injection flags (every flagged
 *     value is listed for manual false-positive review), repeated keys, severity per subtype
 *  b) timeline: the real pipeline + notifier with the clock set to each event's own time, so the
 *     cards, bursts and pushes per day are what a NOC would have seen (not a compressed replay)
 *  c) throughput: TCP syslog into a running board (octet-counted frames), lines/s end to end
 * Output: aggregates only (no raw lines) to --out.
 */
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const readline = require('node:readline');
const net = require('node:net');
const os = require('node:os');
const N = require('../src/core.js');
const T = require('../server/trust.js');
const { parseSyslog, payloadKind } = require('../server/collectors/syslog.js');
const { loadConfig } = require('../server/config.js');
const db_ = require('../server/db.js');
const { Pipeline } = require('../server/pipeline.js');
const { Notifier } = require('../server/notify.js');

const ROOT = path.join(__dirname, '..');
const DIR = path.join(__dirname, 'botsv1');
const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const OUT = path.resolve(ROOT, arg('out', 'results/real-data/x1-botsv1.json'));
const TRAFFIC = Number(arg('traffic-lines', 200000));
const FILES = [['fgt_event', 'botsv1.fgt_event.json.gz'], ['fgt_utm', 'botsv1.fgt_utm.json.gz'], ['fgt_traffic', 'botsv1.fgt_traffic.first200k.json']];
const LEVEL_PRI = { emergency: 0, alert: 1, critical: 2, error: 3, warning: 4, notice: 5, information: 6, debug: 7 };

/** "Aug 13 22:06:24 192.168.250.1 date=..." -> "<PRI>date=..." (local7) */
function toSyslog(raw) {
  const body = raw.replace(/^[A-Z][a-z]{2} [ \d]?\d \d\d:\d\d:\d\d \S+ /, '');
  const level = (body.match(/\blevel="?(\w+)/) || [])[1];
  return `<${23 * 8 + (LEVEL_PRI[level] ?? 5)}>${body}`;
}

async function* records(limitTraffic) {
  for (const [st, f] of FILES) {
    const p = path.join(DIR, f);
    if (!fs.existsSync(p)) throw new Error(`missing ${p}: see lab/README.md (download)`);
    const input = f.endsWith('.gz') ? fs.createReadStream(p).pipe(zlib.createGunzip()) : fs.createReadStream(p);
    let n = 0;
    for await (const line of readline.createInterface({ input, crlfDelay: Infinity })) {
      if (!line) continue;
      const j = JSON.parse(line);
      const raw = j.result && j.result._raw; // the export ends with a {"lastrow": true} record
      if (!raw) continue;
      yield { st, raw };
      if (st === 'fgt_traffic' && ++n >= limitTraffic) break;
    }
  }
}

const inc = (o, k, n = 1) => { o[k] = (o[k] || 0) + n; };

async function offline() {
  const r = { lines: {}, parsed: 0, withDeviceIds: 0, subtypes: {}, severity: {}, untrustedKeys: {}, trustedKeys: {}, flagged: 0, flaggedSamples: [], flagReasons: {}, duplicateKeyLines: 0, duplicateKeys: {}, syslogFormat: {} };
  for await (const { st, raw } of records(TRAFFIC)) {
    inc(r.lines, st);
    const p = parseSyslog(toSyslog(raw));
    inc(r.syslogFormat, p.format);
    if (payloadKind(p.msg) !== 'fortigate') continue;
    const f = N.parseFortiLog(p.msg);
    r.parsed++;
    if (f.devid && f.logid) r.withDeviceIds++;
    const e = T.fortigate(f, Date.now());
    const kind = e.kind;
    r.subtypes[kind] = r.subtypes[kind] || { n: 0, severity: {} };
    r.subtypes[kind].n++; inc(r.subtypes[kind].severity, e.detSeverity); inc(r.severity, e.detSeverity);
    for (const k of Object.keys(e.untrusted)) inc(r.untrustedKeys, k);
    for (const k of Object.keys(e.trusted)) inc(r.trustedKeys, k);
    if ((f.__dup || []).length) { r.duplicateKeyLines++; for (const k of f.__dup) inc(r.duplicateKeys, k); }
    const inj = e.flags.filter((x) => !/^duplicate field/.test(x));
    if (inj.length) {
      r.flagged++;
      for (const x of inj) inc(r.flagReasons, x.replace(/^[^:]+: /, ''));
      // every distinct flagged (field, value) for the manual review; BOTSv1 is CC0, values are fine to keep
      const fields = inj.map((x) => x.split(':')[0]);
      for (const k of fields) {
        const v = String(e.untrusted[k] || '').slice(0, 200);
        if (!r.flaggedSamples.some((s) => s.field === k && s.value === v) && r.flaggedSamples.length < 300) r.flaggedSamples.push({ kind, field: k, value: v, reasons: inj.filter((x) => x.startsWith(`${k}:`)).map((x) => x.replace(/^[^:]+: /, '')) });
      }
    }
  }
  return r;
}

async function timeline() {
  // the real pipeline + notifier, clock = event time; default config (minSeverity low, budget 120/min)
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x1-'));
  const { cfg } = loadConfig(null, { dataDir, notify: { channels: [{ name: 'ntfy', type: 'ntfy', url: 'http://sink.invalid', topic: 't', minSeverity: 'high' }, { name: 'line', type: 'line', channelToken: 'x', to: 'C', minSeverity: 'high' }] } }, {});
  const db = db_.openDb(dataDir);
  let clock = 0;
  const now = () => clock;
  const pipeline = new Pipeline({ db, cfg, now, batchMs: -1 });
  const sent = { ntfy: 0, line: 0 };
  const senders = { ntfy: async () => { sent.ntfy++; }, line: async () => { sent.line++; } };
  const notifier = new Notifier({ db, cfg, now, senders });
  // as main.js: correlation raises are board notes only; K4 idle resolves and S1 re-opens go through consider
  let autoResolved = 0, reopened = 0;
  pipeline.on('change', (c) => { if (c.idle) autoResolved++; if (c.reopened) reopened++; if (!c.correlated) notifier.consider(c); });
  const perDay = {};
  let lastFlush = 0, lastDigest = 0, lastIdle = 0, first = null, last = 0, n = 0;
  const lineCh = notifier.channels.find((c) => c.name === 'line');
  // order by event time across the three files (they are sorted newest-first in the export)
  const all = [];
  for await (const { raw } of records(TRAFFIC)) {
    const body = toSyslog(raw);
    const p = parseSyslog(body);
    if (payloadKind(p.msg) !== 'fortigate') continue;
    const f = N.parseFortiLog(p.msg);
    const t = Date.parse(`${f.date}T${f.time}+07:00`) || 0;
    all.push([t, f]);
  }
  all.sort((a, b) => a[0] - b[0]);
  for (const [t, f] of all) {
    clock = t; first = first ?? t; last = t; n++;
    const day = new Date(t).toISOString().slice(0, 10);
    perDay[day] = perDay[day] || { events: 0 };
    perDay[day].events++;
    const e = T.fortigate(f, t);
    e.ts = t;
    pipeline.ingest(e, 'syslog');
    if (t - lastFlush >= 200) { pipeline.flush(); lastFlush = t; }
    if (t - lastIdle >= 600000) { pipeline.flush(); pipeline.resolveIdle(); lastIdle = t; } // the 10-min K4 sweep
    if (t - lastDigest >= lineCh.digestEveryMinutes * 60000) { pipeline.flush(); await notifier.flushDigest(lineCh); lastDigest = t; }
  }
  pipeline.flush();
  await notifier.idle();
  await notifier.flushDigest(lineCh);
  const items = db.prepare('SELECT severity, count, trusted, first_seen, resolved_at FROM items').all();
  const filtered = db_.sourceState(db, 'syslog').filtered;
  for (const it of items) { const d = new Date(it.first_seen).toISOString().slice(0, 10); if (perDay[d]) perDay[d].newCards = (perDay[d].newCards || 0) + 1; }
  const out = {
    events: n, spanDays: +((last - first) / 86400000).toFixed(1), filteredBelowLow: filtered,
    cards: items.length, burstCards: items.filter((i) => JSON.parse(i.trusted).burst === 'true').length,
    cardsBySeverity: items.reduce((a, i) => (inc(a, i.severity), a), {}),
    eventsInCards: items.reduce((a, i) => a + i.count, 0),
    pushes: sent.ntfy, lineMessages: sent.line,
    openAtEnd: items.filter((i) => i.resolved_at == null).length, autoResolved, reopened,
    busiestDays: Object.entries(perDay).sort((a, b) => b[1].events - a[1].events).slice(0, 5).map(([d, v]) => ({ day: d, events: v.events, newCards: v.newCards || 0 })),
  };
  db.close();
  return out;
}

async function throughput() {
  const { createApp } = require('../server/main.js');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x1t-'));
  const loaded = loadConfig(null, { dataDir, listen: { host: '127.0.0.1', port: 0 }, sources: { syslog: { enabled: true, port: 0, udp: false, allow: ['127.0.0.1'], ratePerSec: 1e6, minSeverity: 'low' } } }, {});
  const app = await createApp(loaded, { log: () => {}, runOnStart: false });
  const frames = [];
  for await (const { raw } of records(Math.min(TRAFFIC, 100000))) { const b = Buffer.from(toSyslog(raw)); frames.push(Buffer.concat([Buffer.from(`${b.length} `), b])); }
  const t0 = process.hrtime.bigint();
  await new Promise((res, rej) => { const s = net.connect(app.syslogAddress.tcp.port, '127.0.0.1', () => s.end(Buffer.concat(frames))); s.on('close', res); s.on('error', rej); });
  const st = () => db_.sourceState(app.db, 'syslog');
  for (;;) { app.pipeline.flush(); if (st().received + st().filtered >= frames.length) break; await new Promise((r) => setTimeout(r, 50)); }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const r = { lines: frames.length, ms: Math.round(ms), linesPerSec: Math.round(frames.length / (ms / 1000)), received: st().received, filtered: st().filtered, dropped: st().dropped, unsupported: st().unsupported, cpu: `${os.cpus().length}x ${os.cpus()[0].model || os.arch()}`, node: process.version };
  await app.close();
  return r;
}

(async () => {
  const sums = fs.existsSync(path.join(DIR, 'SHA256SUMS')) ? fs.readFileSync(path.join(DIR, 'SHA256SUMS'), 'utf8').trim().split('\n') : [];
  const result = {
    dataset: { name: 'Splunk Boss of the SOC v1 (BOTSv1), FortiGate sourcetypes', license: 'CC0 1.0 Universal (github.com/splunk/botsv1/blob/master/LICENSE)', source: 'https://s3.amazonaws.com/botsdataset/botsv1/json-by-sourcetype/', sha256: sums, fortiosEra: '2016 (FortiOS 5.x, FGT60D)' },
    ranAt: new Date().toISOString(),
    offline: await offline(),
  };
  result.timeline = await timeline();
  result.throughput = await throughput();
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(result, null, 2)}\n`);
  const o = result.offline;
  console.log(`X1 lines ${JSON.stringify(o.lines)} parsed ${o.parsed} deviceIds ${o.withDeviceIds} flagged ${o.flagged} dupLines ${o.duplicateKeyLines}`);
  console.log(`timeline ${JSON.stringify(result.timeline)}`);
  console.log(`throughput ${JSON.stringify(result.throughput)}`);
  console.log(`wrote ${OUT}`);
})().catch((e) => { console.error(e); process.exit(1); });
