#!/usr/bin/env node
'use strict';
/*
 * X2: the board against this VM's REAL Wazuh (after `sudo sh lab/wazuh-prepare.sh`).
 *   node lab/x2-wazuh.js [--lookback 24h] [--attack]
 * Reads the read-only indexer user's password from /etc/netsec-board/wazuh-ro-password (0640,
 * never printed). With --attack it runs lab/attack.sh against the lab victim first.
 * Measures, publishing aggregates only (no IP, user name or log line from real traffic):
 *   - setup's live test against the real indexer
 *   - completeness: alerts the indexer holds (level >= 4, the board's "low") vs alerts the board
 *     fetched, for the same window
 *   - lab attacks: cards per rule, the random-username brute force grouping, prompt-injection
 *     flags, alert -> card latency
 *   - restart: same counts, no duplicates (cursor continuity)
 *   - real internet traffic on this host: alerts/day, cards, distinct sources, pushes/day
 * Writes results/real-data/x2-wazuh.json.
 */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const M = require('../mocks/servers.js');
const { loadConfig } = require('../server/config.js');
const { createApp } = require('../server/main.js');
const { requestOk } = require('../server/net.js');

const ROOT = path.join(__dirname, '..');
const PW_FILE = '/etc/netsec-board/wazuh-ro-password';
const CA = '/etc/netsec-board/wazuh-root-ca.pem';
const URL_ = process.env.WAZUH_URL || 'https://127.0.0.1:9200';
const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const LOOKBACK = arg('lookback', '24h');
// --from 2026-10-15T00:00:00+07:00: start the board's cursor there (real history) instead of the
// initial lookback; the board then pulls forward with its normal code (paging, lag window)
const FROM = arg('from', null);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function indexer(body, what = '_search') {
  const password = fs.readFileSync(PW_FILE, 'utf8').trim();
  const r = await requestOk(`${URL_}/wazuh-alerts-*/${what}`, { body, basic: { username: 'netsec_board_ro', password }, caFile: CA, timeoutMs: 30000 });
  return r.json;
}

(async () => {
  const out = { ranAt: new Date().toISOString(), lookback: LOOKBACK };
  const password = fs.readFileSync(PW_FILE, 'utf8').trim();

  // 1. setup's live test (the wizard) against the real indexer
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x2s-'));
  const s = spawnSync(process.execPath, [path.join(ROOT, 'cli/board.js'), 'setup', '--config', path.join(dir, 'netsec.json'), '--non-interactive'], { env: { PATH: process.env.PATH, NETSEC_SETUP_WAZUH_URL: URL_, NETSEC_SETUP_WAZUH_USER: 'netsec_board_ro', NETSEC_SETUP_WAZUH_PASSWORD: password, NETSEC_SETUP_NOTIFY: 'none' }, encoding: 'utf8' });
  out.setup = s.stdout.split('\n').filter((l) => /Wazuh indexer/.test(l)).map((l) => l.trim().replace(/\d+ alert/, 'N alert'));
  // the wizard has no caFile question: a self-signed indexer CA must be accepted somehow
  out.setupNote = /self.signed|certificate/i.test(s.stdout) ? 'TLS: the wizard could not verify the indexer certificate (no caFile question)' : null;

  // 2. attacks (lab victim) if asked
  if (process.argv.includes('--attack')) {
    out.attackStartedAt = Date.now();
    const a = spawnSync('sh', [path.join(__dirname, 'attack.sh'), '300', '50'], { encoding: 'utf8' });
    out.attack = { exit: a.status, tail: a.stdout.trim().split('\n').slice(-1)[0] };
  }

  // 3. the board pulls (quiet first run), until it has caught up
  const sinks = await M.mockSinks();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x2-'));
  const cfgOver = { dataDir, lang: 'en', listen: { host: '127.0.0.1', port: 0 }, sources: { wazuh: { enabled: true, schedule: '@every 1h', url: URL_, username: 'netsec_board_ro', password, caFile: CA, minSeverity: 'low', initialLookback: LOOKBACK } }, notify: { channels: [{ name: 'ntfy', type: 'ntfy', url: `${sinks.url}/ntfy`, topic: 't', minSeverity: 'high' }] } };
  let app = await createApp(loadConfig(null, cfgOver, {}), { log: () => {}, runOnStart: false });
  if (FROM) app.db.prepare("INSERT INTO source_state(source, cursor) VALUES('wazuh', ?) ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor").run(JSON.stringify({ maxTs: Date.parse(FROM), seen: [] }));
  const t0 = Date.now();
  let runs = 0;
  for (;;) { const r = await app.scheduler.run('wazuh'); runs++; if (!r.ok) throw new Error(`pull failed: ${r.error}`); if (r.n < 5000 || runs > 50) break; }
  const st = () => app.db.prepare("SELECT received, filtered FROM source_state WHERE source = 'wazuh'").get();
  // the board's first query starts lagWindow (120 s) before the cursor
  const windowStart = FROM ? Date.parse(FROM) - 120000 : t0 - (/(\d+)h/.test(LOOKBACK) ? Number(LOOKBACK.match(/(\d+)h/)[1]) * 3600000 : 3600000);
  const idx = await indexer({ query: { bool: { filter: [{ range: { timestamp: { gte: windowStart, lte: t0, format: 'epoch_millis' } } }, { range: { 'rule.level': { gte: 4 } } }] } } }, '_count');
  const idxAll = await indexer({ query: { range: { timestamp: { gte: windowStart, lte: t0, format: 'epoch_millis' } } } }, '_count');
  out.completeness = { from: FROM, indexerLevel4plus: idx.count, indexerAll: idxAll.count, boardFetched: st().received + st().filtered, boardReceived: st().received, boardFiltered: st().filtered, runs, pullMs: Date.now() - t0, alertsPerSec: Math.round((st().received + st().filtered) / ((Date.now() - t0) / 1000)) };

  // 4. cards per rule / agent, without identities
  const items = app.db.prepare("SELECT title, count, severity, flags, samples, trusted, untrusted FROM items WHERE source = 'wazuh'").all();
  const byRule = {};
  for (const it of items) {
    const tr = JSON.parse(it.trusted);
    const k = `${tr['rule.id']} ${String(tr['rule.description'] || it.title.replace(/ \(.*\)$/, '')).slice(0, 70)}`;
    const agent = tr['agent.name'] === 'lab-victim' ? 'lab' : 'host';
    byRule[k] = byRule[k] || { lab: { cards: 0, events: 0 }, host: { cards: 0, events: 0 }, severity: it.severity };
    byRule[k][agent].cards++; byRule[k][agent].events += it.count;
  }
  out.cardsByRule = byRule;
  out.cards = items.length;
  out.pushesAfterQuietFirstRun = sinks.requests.length;
  const lab = items.filter((it) => JSON.parse(it.trusted)['agent.name'] === 'lab-victim');
  out.lab = {
    cards: lab.length, events: lab.reduce((n, i) => n + i.count, 0),
    sshCards: lab.filter((i) => /ssh/i.test(i.title)).map((i) => ({ title: i.title.replace(/ \(.*\)$/, ''), count: i.count, samples: JSON.parse(i.samples).length })),
    flaggedCards: lab.filter((i) => JSON.parse(i.flags).length).map((i) => ({ title: i.title.replace(/ \(.*\)$/, ''), flags: JSON.parse(i.flags) })),
  };
  const host = items.filter((it) => JSON.parse(it.trusted)['agent.name'] !== 'lab-victim');
  const srcs = new Set(host.map((i) => JSON.parse(i.untrusted || '{}')['data.srcip'] || JSON.parse(i.trusted)['data.srcip']).filter(Boolean));
  out.hostTraffic = { cards: host.length, events: host.reduce((n, i) => n + i.count, 0), distinctSources: srcs.size };

  // 5. restart: same database, pull again -> nothing counted twice
  const before = app.db.prepare("SELECT SUM(count) AS n FROM items WHERE source = 'wazuh'").get().n;
  await app.close();
  app = await createApp(loadConfig(null, cfgOver, {}), { log: () => {}, runOnStart: false });
  await app.scheduler.run('wazuh');
  const after = app.db.prepare("SELECT SUM(count) AS n FROM items WHERE source = 'wazuh'").get().n;
  out.restart = { eventsBefore: before, eventsAfter: after, newSinceRestart: after - before };
  await app.close(); sinks.server.close();

  // 6. --live N: pull latency with the board's real scheduler (every 15 s) while a short lab attack
  // runs; alert timestamp -> card visible, includes Filebeat's shipping delay
  const LIVE = Number(arg('live', 0));
  if (LIVE) {
    const liveDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x2l-'));
    const startCursor = Date.now() - 5000;
    const live = await createApp(loadConfig(null, { ...cfgOver, dataDir: liveDir, sources: { wazuh: { ...cfgOver.sources.wazuh, schedule: '@every 15s' } } }, {}), { log: () => {}, runOnStart: false, jitter: false });
    live.db.prepare("INSERT INTO source_state(source, cursor) VALUES('wazuh', ?) ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor").run(JSON.stringify({ maxTs: startCursor, seen: [] }));
    live.scheduler.start({ runOnStart: true });
    const seenAt = new Map();
    const poll = setInterval(() => { for (const r of live.db.prepare("SELECT id, first_seen, trusted FROM items WHERE source = 'wazuh'").all()) if (!seenAt.has(r.id) && JSON.parse(r.trusted)['agent.name'] === 'lab-victim') seenAt.set(r.id, Date.now() - r.first_seen); }, 250);
    const { spawn } = require('node:child_process');
    await new Promise((resolve) => { const p = spawn('sh', [path.join(__dirname, 'attack.sh'), '20', '10'], { stdio: 'ignore' }); p.on('close', resolve); });
    await sleep(LIVE * 1000);
    clearInterval(poll);
    const lat = [...seenAt.values()].sort((a, b) => a - b);
    out.liveLatency = { schedule: '15s', labCards: lat.length, alertToCardMs: lat.length ? { min: lat[0], median: lat[Math.floor(lat.length / 2)], max: lat[lat.length - 1] } : null };
    await live.close();
  }

  fs.mkdirSync(path.join(ROOT, 'results/real-data'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'results/real-data/x2-wazuh.json'), `${JSON.stringify(out, null, 2)}\n`);
  console.log(JSON.stringify(out, null, 1));
})().catch((e) => { console.error('x2:', e.stack || e.message); process.exit(1); });
