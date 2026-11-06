#!/usr/bin/env node
'use strict';
/*
 * X4: the board against a REAL Zabbix 7.0 (lab/compose.yaml + lab/zabbix-setup.js).
 *   A: pull (event.get/problem.get with the read-only API token), board in this process
 *   B: push (the real deploy/zabbix-media-webhook.js, run by the Zabbix alerter) into the
 *      board-hook container; read from its database
 * Problems are real: the agent reports vfs.file.exists[/tmp/netsec-fail], a High trigger fires.
 * Measures: setup/check against the real API (and through a proxy that strips Authorization),
 * the quiet first run, problem -> card latency (pull and push), recovery -> resolved, recurrence
 * -> re-opened unacked + notified. Writes results/real-data/x4-zabbix.json.
 */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync, spawnSync } = require('node:child_process');
const M = require('../mocks/servers.js');
const { loadConfig } = require('../server/config.js');
const { createApp } = require('../server/main.js');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const DATA = path.join(__dirname, 'data');
const token = fs.readFileSync(path.join(DATA, 'zabbix-token'), 'utf8').trim();
const adminPw = fs.readFileSync(path.join(DATA, 'zabbix-admin-password'), 'utf8').trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t = () => Date.now();
const agent = (cmd) => execFileSync('docker', ['compose', '-f', path.join(__dirname, 'compose.yaml'), 'exec', '-T', 'zbx-agent', 'sh', '-c', cmd], { stdio: 'pipe' });
async function until(fn, ms = 120000, step = 500) { const end = t() + ms; for (;;) { const v = await fn(); if (v) return v; if (t() > end) throw new Error('timeout'); await sleep(step); } }

let adminAuth;
async function zbx(method, params) {
  const r = await fetch('http://127.0.0.1:18080/api_jsonrpc.php', { method: 'POST', headers: { 'content-type': 'application/json-rpc', ...(adminAuth ? { authorization: `Bearer ${adminAuth}` } : {}) }, body: JSON.stringify({ jsonrpc: '2.0', method, params, id: 1 }) });
  const j = await r.json(); if (j.error) throw new Error(j.error.data || j.error.message); return j.result;
}
let TRIGGER = null; // our lab trigger; Zabbix's own "Zabbix server" host has unrelated open problems
const openProblems = async () => (await zbx('problem.get', { output: ['eventid'], source: 0, object: 0, objectids: [TRIGGER] })).length;

function setupCheck(url) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x4s-'));
  const r = spawnSync(process.execPath, [path.join(ROOT, 'cli/board.js'), 'setup', '--config', path.join(dir, 'netsec.json'), '--non-interactive'], { env: { PATH: process.env.PATH, NETSEC_SETUP_ZABBIX_URL: url, NETSEC_SETUP_ZABBIX_TOKEN: token, NETSEC_SETUP_NOTIFY: 'none' }, encoding: 'utf8' });
  const lines = r.stdout.split('\n').filter((l) => /Zabbix API|hint:/.test(l)).map((l) => l.trim());
  return { url, lines };
}

(async () => {
  const version = await zbx('apiinfo.version', {}); // must be called without an Authorization header (real 7.0)
  adminAuth = await zbx('user.login', { username: 'Admin', password: adminPw });
  TRIGGER = (await zbx('trigger.get', { filter: { description: 'NetSec lab: fail flag set on {HOST.NAME}' }, output: ['triggerid'] }))[0].triggerid;
  const out = { zabbix: version, ranAt: new Date().toISOString(), setup: [setupCheck('http://127.0.0.1:18080'), setupCheck('http://127.0.0.1:18081')] };
  console.log('setup', JSON.stringify(out.setup));

  // clean start: no problem open, board-hook DB fresh
  agent('rm -f /tmp/netsec-fail');
  await until(async () => (await openProblems()) === 0);
  const sinks = await M.mockSinks();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x4-'));
  const loaded = loadConfig(null, { dataDir, lang: 'en', listen: { host: '127.0.0.1', port: 0 }, sources: { zabbix: { enabled: true, schedule: '@every 3s', url: 'http://127.0.0.1:18080', token, minSeverity: 'low' } }, notify: { channels: [{ name: 'ntfy', type: 'ntfy', url: `${sinks.url}/ntfy`, topic: 't', minSeverity: 'high' }] } }, {});

  // 1. a problem already open before the board's first pull -> quiet baseline
  agent('touch /tmp/netsec-fail');
  const t0 = t();
  await until(async () => (await openProblems()) === 1);
  out.zabbixDetectMs = t() - t0;
  const app = await createApp(loaded, { log: () => {}, runOnStart: true, jitter: false });
  const hookDb = () => new DatabaseSync(path.join(DATA, 'hookdata', 'board.db'), { readOnly: true });
  const card = () => app.db.prepare("SELECT id, count, resolved_at, acked_by, reopened_at FROM items WHERE source = 'zabbix' AND trusted LIKE ?").get(`%"triggerid":"${TRIGGER}"%`);
  const hookCard = () => { try { const d = hookDb(); const r = d.prepare("SELECT count, resolved_at, reopened_at FROM items WHERE source = 'zabbix' AND trusted LIKE ?").get(`%"triggerid":"${TRIGGER}"%`); d.close(); return r; } catch { return null; } };
  await until(() => card());
  await app.notifier.idle();
  out.baseline = { cardOnFirstPull: !!card(), cardsOnFirstPull: app.db.prepare("SELECT COUNT(*) AS n FROM items WHERE source = 'zabbix'").get().n, pushes: sinks.requests.length };
  const pushedAtStart = await until(() => hookCard(), 60000).then(() => true, () => false);
  out.webhook = { problemCard: pushedAtStart };

  // 2. recovery -> resolved (pull and push)
  agent('rm -f /tmp/netsec-fail');
  let s = t();
  await until(() => card() && card().resolved_at);
  out.recovery = { pullMs: t() - s };
  await until(() => { const h = hookCard(); return h && h.resolved_at; }, 60000).then(() => { out.recovery.webhookResolved = true; }, () => { out.recovery.webhookResolved = false; });

  // 3. ack the card, then the problem comes back: re-opened, unacked, pushed (pull)
  app.db.prepare('UPDATE items SET acked_by = ?, acked_at = ? WHERE id = ?').run('op', t(), card().id);
  agent('touch /tmp/netsec-fail');
  s = t();
  await until(() => card() && !card().resolved_at && card().reopened_at);
  out.recurrence = { pullMs: t() - s, acked: card().acked_by, count: card().count };
  await app.notifier.idle();
  out.recurrence.pushes = sinks.requests.filter((r) => r.url === '/ntfy').length;
  await until(() => { const h = hookCard(); return h && !h.resolved_at && h.reopened_at; }, 60000).then(() => { out.recurrence.webhookReopened = true; }, () => { out.recurrence.webhookReopened = false; });
  out.recurrence.webhookMs = t() - s;

  // tidy
  agent('rm -f /tmp/netsec-fail');
  out.sourceState = app.db.prepare("SELECT status, received, fails, last_error FROM source_state WHERE source = 'zabbix'").get();
  out.hookState = (() => { try { const d = hookDb(); const r = d.prepare("SELECT received FROM source_state WHERE source = 'hook:zabbix'").get(); d.close(); return r; } catch { return null; } })();
  await app.close(); sinks.server.close();
  fs.mkdirSync(path.join(ROOT, 'results/real-data'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'results/real-data/x4-zabbix.json'), `${JSON.stringify(out, null, 2)}\n`);
  console.log(JSON.stringify(out, null, 2));
})().catch((e) => { console.error('x4:', e.stack || e.message); process.exit(1); });
