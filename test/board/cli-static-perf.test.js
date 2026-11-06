'use strict';
// Admin CLI (init, user, pull from cron, check, audit-export), static safety checks on the board UI, performance.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const M = require('../../mocks/servers.js');
const db_ = require('../../server/db.js');
const { startBoard, login, api, tmp, waitFor } = require('./helpers.js');

const ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(ROOT, 'cli/board.js');
const run = (args, env = {}, cwd = ROOT) => new Promise((resolve) => execFile(process.execPath, [CLI, ...args], { cwd, env: { ...process.env, ...env } }, (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr })));

test('cli: init writes a 0600 config and an admin with a one-time password; user add/list; refuses a second admin', async () => {
  const dir = tmp();
  const cfg = path.join(dir, 'netsec.json');
  const r = await run(['init', '--config', cfg]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /created admin user "admin" with password: \S{12,}/);
  assert.equal((fs.statSync(cfg).mode & 0o777).toString(8), '600');
  const again = await run(['init', '--config', cfg]);
  assert.match(again.stdout, /exists, kept[\s\S]*1 user\(s\) exist, no user created/);
  const pwFile = path.join(dir, 'pw');
  fs.writeFileSync(pwFile, 'operator-pass-123\n');
  assert.equal((await run(['user', 'add', 'nong', '--role', 'operator', '--password-file', pwFile, '--config', cfg])).code, 0);
  const list = await run(['user', 'list', '--config', cfg]);
  assert.match(list.stdout, /admin\tadmin/);
  assert.match(list.stdout, /nong\toperator/);
  assert.notEqual((await run(['user', 'add', 'x', '--role', 'root', '--config', cfg])).code, 0);
});

test('cli: pull from system cron writes items and runs; check reports endpoint classes, empty allowlist, Zabbix header hint; audit-export', async () => {
  const dir = tmp();
  const wz = await M.mockWazuh({ username: 'ro', password: 'cli-wz-pass' });
  const zbx = await M.mockZabbix({ token: 'cli-zbx-tok', stripAuth: true });
  try {
    const cfg = path.join(dir, 'netsec.json');
    fs.writeFileSync(cfg, JSON.stringify({
      dataDir: './data',
      sources: {
        syslog: { enabled: true, allow: [] },
        wazuh: { enabled: true, url: wz.url, username: 'ro', password: 'env:CLI_WZ' },
        zabbix: { enabled: true, url: zbx.url, token: 'env:CLI_ZBX' },
      },
      notify: { channels: [{ name: 'tg', type: 'telegram', botToken: 'literal-token-in-file', chatId: '1' }] },
      llm: { url: 'http://8.8.8.8/v1', model: 'm' },
    }));
    const env = { CLI_WZ: 'cli-wz-pass', CLI_ZBX: 'cli-zbx-tok' };
    assert.equal((await run(['init', '--config', cfg], env)).code, 0);
    // the exact line a crontab would run
    const p = await run(['pull', 'wazuh', '--config', cfg], env);
    assert.equal(p.code, 0, p.stderr);
    assert.match(p.stdout, /pull wazuh: 4 event\(s\)/);
    const db = db_.openDb(path.join(dir, 'data'));
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM items WHERE source = 'wazuh'").get().n, 3);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM runs WHERE source = 'wazuh' AND ok = 1").get().n, 1);
    db.close();
    assert.equal((await run(['pull', 'fortigate', '--config', cfg], env)).code, 2, 'disabled source');
    const z = await run(['pull', 'zabbix', '--config', cfg], env);
    assert.equal(z.code, 1);
    assert.match(z.stderr, /Not authorized/);
    const c = await run(['check', '--config', cfg], env);
    assert.equal(c.code, 1);
    assert.match(c.stdout, /ERROR syslog: allowlist is empty/);
    assert.match(c.stdout, /ok {4}wazuh indexer 127\.0\.0\.1:\d+ \(loopback\)/);
    assert.match(c.stdout, /ERROR zabbix 7\.0\.5: .*Not authorized[\s\S]*strip the Authorization header/);
    assert.match(c.stdout, /WARN {2}notify\.channels\[0\]\.botToken is a literal secret/);
    assert.match(c.stdout, /tg \(telegram\) -> api\.telegram\.org \[(remote|unresolved[^\]]*)\].*masked text only/);
    assert.match(c.stdout, /ERROR refused: LLM endpoint 8\.8\.8\.8 .*not on-prem.*llm\.allowRemote/);
    const a = await run(['audit-export', '--config', cfg], env);
    assert.equal(a.code, 0);
    assert.equal(a.stdout, '', 'no LLM calls yet');
  } finally { wz.server.close(); zbx.server.close(); }
});

test('board UI never writes HTML from strings (stored XSS through log fields is impossible by construction)', () => {
  const js = fs.readFileSync(path.join(ROOT, 'board/board.js'), 'utf8');
  const code = js.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'setAttribute(\'style\'', 'srcdoc']) assert.ok(!code.includes(sink), sink);
  assert.match(code, /if \(k\.startsWith\('on'\)\) el\.addEventListener/, 'event handlers are bound with addEventListener, never as attributes');
  assert.match(code, /\/\^https\?:\\\/\\\/\/i\.test\(it\.link\)/, 'source links are http(s) only');
  const html = fs.readFileSync(path.join(ROOT, 'board/index.html'), 'utf8');
  assert.ok(!/<script>[^<]/.test(html) && !/style="/.test(html) && !/ on\w+="/.test(html), 'no inline script/style/handlers (CSP)');
  assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(js + html + fs.readFileSync(path.join(ROOT, 'board/board.css'), 'utf8')), 'no external resources');
});

test('performance: 10,000 syslog lines in under 60 s with no drops; API p95 under 200 ms', async () => {
  const LOGS = fs.readFileSync(path.join(ROOT, 'samples/fgt-logs.log'), 'utf8').split('\n').filter(Boolean).filter((l) => !/type="traffic"/.test(l));
  const { app } = await startBoard({ sources: { syslog: { enabled: true, port: 0, udp: false, allow: ['127.0.0.1'], ratePerSec: 50000, minSeverity: 'info' } } }, { batchMs: 200 });
  try {
    // vary the source IP so cards do not all collapse into a few fingerprints
    const lines = Array.from({ length: 10000 }, (_, i) => LOGS[i % LOGS.length].replace(/srcip=[\d.]+/, `srcip=10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`));
    const t0 = Date.now();
    for (let i = 0; i < lines.length; i += 1000) await M.sendSyslog(lines.slice(i, i + 1000), { port: app.syslogAddress.tcp.port, proto: 'tcp' });
    await waitFor(() => db_.sourceState(app.db, 'syslog').received >= 10000, 60000, 100);
    const ms = Date.now() - t0;
    const st = db_.sourceState(app.db, 'syslog');
    assert.equal(st.received + st.filtered, 10000, 'every line accounted for');
    assert.equal(st.dropped, 0, 'no drops');
    assert.ok(ms < 60000, `${ms} ms`);
    const s = await login(app, 'view');
    const times = [];
    for (let i = 0; i < 60; i++) {
      const t = performance.now();
      const r = await api(app, s, 'GET', i % 2 ? '/api/summary' : '/api/items');
      assert.equal(r.status, 200);
      times.push(performance.now() - t);
    }
    times.sort((a, b) => a - b);
    const p95 = times[Math.floor(times.length * 0.95)];
    console.log(`# perf: ingest 10k lines in ${ms} ms; API p95 ${p95.toFixed(1)} ms (${app.db.prepare('SELECT COUNT(*) AS n FROM items').get().n} items)`);
    assert.ok(p95 < 200, `p95 ${p95} ms`);
  } finally { await app.close(); }
});
