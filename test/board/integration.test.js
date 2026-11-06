'use strict';
// Integration: a real board process (in-process) against the mock vendor APIs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const M = require('../../mocks/servers.js');
const db_ = require('../../server/db.js');
const { startBoard, login, api, sse, waitFor, tmp, sleep, sseItemIds } = require('./helpers.js');

const ROOT = path.join(__dirname, '..', '..');
const LOGS = fs.readFileSync(path.join(ROOT, 'samples/fgt-logs.log'), 'utf8').split('\n').filter(Boolean);

test('pull sources on a schedule tick: Wazuh + Zabbix items via API and SSE, cursors stop duplicates, notifications reach the sink', async () => {
  const wz = await M.mockWazuh({ username: 'ro', password: 'wz-pass-xyz' });
  const zbx = await M.mockZabbix({ token: 'zbx-token-xyz' });
  const sinks = await M.mockSinks();
  const { app } = await startBoard({
    sources: {
      wazuh: { enabled: true, schedule: '@every 1h', url: wz.url, username: 'ro', password: 'wz-pass-xyz', quietFirstRun: false },
      zabbix: { enabled: true, schedule: '@every 1h', url: zbx.url, token: 'zbx-token-xyz', quietFirstRun: false },
    },
    notify: { channels: [{ name: 'ntfy', type: 'ntfy', url: `${sinks.url}/ntfy`, topic: 'noc', minSeverity: 'high' }] },
    publicUrl: 'https://board.example',
  });
  try {
    const s = await login(app, 'view');
    const stream = await sse(app, s);
    assert.equal(stream.status, 200);
    assert.deepEqual(await Promise.all([app.scheduler.run('wazuh'), app.scheduler.run('zabbix')]), [{ ok: true, n: 4 }, { ok: true, n: 4 }]);
    let items = (await api(app, s, 'GET', '/api/items')).json.items;
    assert.equal(items.filter((i) => i.source === 'wazuh').length, 3, 'the level-3 alert is below minSeverity low');
    assert.equal(db_.sourceState(app.db, 'wazuh').filtered, 1);
    assert.equal(items.filter((i) => i.source === 'zabbix').length, 4);
    assert.ok(zbx.state.calls.filter((c) => c.method === 'event.get').every((c) => c.auth === 'Bearer zbx-token-xyz'), 'Bearer header, no auth field');
    await waitFor(() => sseItemIds(stream.events).size >= 7);
    await waitFor(() => stream.events.some((e) => e.event === 'notify'));
    // second tick: nothing new -> no duplicates; then one new alert each
    await app.scheduler.run('wazuh'); await app.scheduler.run('zabbix');
    assert.equal((await api(app, s, 'GET', '/api/items')).json.items.length, 7);
    wz.add(1); zbx.add(1);
    assert.deepEqual(await app.scheduler.run('wazuh'), { ok: true, n: 1 });
    assert.deepEqual(await app.scheduler.run('zabbix'), { ok: true, n: 1 });
    items = (await api(app, s, 'GET', '/api/items')).json.items;
    const wzTotal = items.filter((i) => i.source === 'wazuh').reduce((n, i) => n + i.count, 0);
    assert.equal(wzTotal, 4, 'the new alert was ingested exactly once (it repeats rule 5710, so the card count goes to 2)');
    const runs = app.db.prepare('SELECT COUNT(*) AS n FROM runs WHERE ok = 1').get().n;
    assert.equal(runs, 6);
    await app.notifier.idle();
    const pushes = sinks.requests.filter((r) => r.url === '/ntfy');
    assert.ok(pushes.length >= 3, 'high/critical alerts pushed');
    assert.ok(pushes.every((p) => p.body.click.startsWith('https://board.example/#item-')));
    const sum = (await api(app, s, 'GET', '/api/summary')).json;
    assert.equal(sum.sources.find((x) => x.name === 'wazuh').status, 'ok');
    stream.stop();
  } finally { await app.close(); for (const m of [wz, zbx, sinks]) m.server.close(); }
});

test('auth and CSRF: 401 without session, 403 without CSRF or role, 415 without JSON, admin-only redacted config', async () => {
  process.env.NSB_IT_SECRET = 'very-secret-zabbix-token';
  const { app } = await startBoard({ sources: { zabbix: { token: 'env:NSB_IT_SECRET' } } });
  try {
    for (const p of ['/api/items', '/api/summary', '/api/events', '/api/me']) assert.equal((await fetch(app.url + p)).status, 401, p);
    const op = await login(app, 'op');
    const view = await login(app, 'view');
    const admin = await login(app, 'admin');
    app.pipeline.ingest(require('../../server/trust.js').generic({ title: 't', severity: 'high', key: 'k' }), 'generic');
    app.pipeline.flush();
    const id = app.db.prepare('SELECT id FROM items').get().id;
    assert.equal((await api(app, { ...op, csrf: '' }, 'POST', `/api/items/${id}/pin`, {})).status, 403, 'no CSRF token');
    assert.equal((await api(app, { ...op, csrf: 'forged' }, 'POST', `/api/items/${id}/pin`, {})).status, 403, 'wrong CSRF token');
    assert.equal((await api(app, op, 'POST', `/api/items/${id}/pin`, {}, { 'content-type': 'text/plain' })).status, 415);
    assert.equal((await api(app, view, 'POST', `/api/items/${id}/pin`, {})).status, 403, 'viewer cannot pin');
    assert.equal((await api(app, view, 'POST', `/api/items/${id}/view`, {})).status, 200, 'viewer can record a view');
    assert.equal((await api(app, op, 'POST', `/api/items/${id}/pin`, {})).status, 200);
    assert.equal((await api(app, op, 'GET', '/api/config')).status, 403);
    const c = await api(app, admin, 'GET', '/api/config');
    assert.equal(c.status, 200);
    assert.ok(!c.text.includes('very-secret-zabbix-token'));
    assert.match(c.json.sources.zabbix.token, /set via env/);
    const actions = app.db.prepare('SELECT username, action FROM user_actions').all().map((a) => `${a.username}:${a.action}`);
    for (const a of ['op:login', 'view:view-item', 'op:pin']) assert.ok(actions.includes(a), a);
    const bad = await fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'op', password: 'nope' }) });
    assert.equal(bad.status, 401);
    const big = await fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'x'.repeat(10000) }) });
    assert.equal(big.status, 413, 'login body limit');
    // headers
    const page = await fetch(`${app.url}/`);
    assert.match(page.headers.get('content-security-policy'), /default-src 'none'; script-src 'self'/);
    assert.equal(page.headers.get('x-frame-options'), 'DENY');
    const again = await fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'op', password: 'op-password-123' }) });
    assert.match(again.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  } finally { await app.close(); }
});

test('pin, ack and snooze persist across a restart and record who did it', async () => {
  const dataDir = tmp();
  let { app } = await startBoard({ dataDir });
  const T = require('../../server/trust.js');
  for (const k of ['a', 'b', 'c']) app.pipeline.ingest(T.generic({ title: `item ${k}`, severity: 'medium', key: k }), 'generic');
  app.pipeline.flush();
  const ids = app.db.prepare('SELECT id FROM items ORDER BY id').all().map((x) => x.id);
  let s = await login(app, 'op');
  assert.equal((await api(app, s, 'POST', `/api/items/${ids[0]}/pin`, { pinned: true })).json.item.pinnedBy, 'op');
  assert.equal((await api(app, s, 'POST', `/api/items/${ids[1]}/ack`, { acked: true })).json.item.ackedBy, 'op');
  const sn = (await api(app, s, 'POST', `/api/items/${ids[2]}/snooze`, { hours: 8 })).json.item;
  assert.ok(sn.snoozedUntil > Date.now() + 7.9 * 3600000);
  assert.equal((await api(app, s, 'POST', `/api/items/${ids[2]}/snooze`, { hours: 3 })).status, 400);
  await app.close();
  ({ app } = await startBoard({ dataDir }));
  try {
    s = await login(app, 'view');
    const items = new Map((await api(app, s, 'GET', '/api/items')).json.items.map((i) => [i.id, i]));
    assert.equal(items.get(ids[0]).pinnedBy, 'op');
    assert.equal(items.get(ids[1]).ackedBy, 'op');
    assert.equal(items.get(ids[2]).snoozedBy, 'op');
    const sum = (await api(app, s, 'GET', '/api/summary')).json;
    assert.equal(sum.counts.medium, 1, 'acked and snoozed items are not counted as open');
  } finally { await app.close(); }
});

test('hooks: token required (constant-time), disabled hook 404, Zabbix PROBLEM then RESOLVED, Wazuh integration payload, body limit', async () => {
  const { app } = await startBoard({ hooks: { zabbix: { token: 'hook-zbx-123' }, wazuh: { token: 'hook-wz-123' } } });
  try {
    const post = (p, body, tok, ct = 'application/json') => fetch(app.url + p, { method: 'POST', headers: { 'content-type': ct, ...(tok ? { authorization: `Bearer ${tok}` } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) });
    const zev = { eventid: '777', triggerid: '555', severity: 'High', name: 'Core uplink down', host: 'core-sw-01', status: 'PROBLEM' };
    assert.equal((await post('/hooks/zabbix', zev)).status, 401);
    assert.equal((await post('/hooks/zabbix', zev, 'wrong')).status, 401);
    assert.equal((await post('/hooks/generic', { title: 'x' }, 'anything')).status, 404);
    const ok = await post('/hooks/zabbix', zev, 'hook-zbx-123');
    assert.equal(ok.status, 202);
    assert.deepEqual(await ok.json(), { accepted: 1 });
    let row = app.db.prepare("SELECT * FROM items WHERE source = 'zabbix'").get();
    assert.equal(row.severity, 'high');
    assert.equal(JSON.parse(row.trusted).via, 'hook:zabbix');
    assert.equal((await post('/hooks/zabbix', { ...zev, status: 'RESOLVED' }, 'hook-zbx-123')).status, 202);
    row = app.db.prepare("SELECT * FROM items WHERE source = 'zabbix'").get();
    assert.ok(row.resolved_at, 'resolved by the hook');
    const alert = M.wazuhAlert(2)._source;
    assert.equal((await post('/hooks/wazuh', alert, 'hook-wz-123')).status, 202);
    assert.equal(app.db.prepare("SELECT COUNT(*) AS n FROM items WHERE source = 'wazuh'").get().n, 1);
    assert.equal((await post('/hooks/wazuh', 'x'.repeat(1100000), 'hook-wz-123')).status, 413);
    assert.equal((await post('/hooks/wazuh', '{bad json', 'hook-wz-123')).status, 400);
    assert.equal(db_.sourceState(app.db, 'hook:zabbix').received, 2);
  } finally { await app.close(); }
});

test('syslog end to end: spoofed sender dropped and shown on the source tile; XSS payload stored and served as plain text', async () => {
  const { app } = await startBoard({ sources: { syslog: { enabled: true, port: 0, allow: ['127.0.0.1'], minSeverity: 'low' } } }, { runOnStart: false });
  try {
    const port = app.syslogAddress.udp.port;
    const xss = LOGS[1].replace(/agent="[^"]*"/, 'agent="<img src=x onerror=alert(document.cookie)><script>alert(1)</script>"');
    await M.sendSyslog([xss], { port });
    await M.sendSyslog([LOGS[4], LOGS[5]], { port, localAddress: '127.0.0.2' });
    await sleep(300);
    app.syslog.flushCounters();
    const s = await login(app, 'view');
    const items = (await api(app, s, 'GET', '/api/items')).json.items;
    assert.equal(items.length, 1);
    assert.equal(items[0].untrusted.agent, '<img src=x onerror=alert(document.cookie)><script>alert(1)</script>', 'kept verbatim as data');
    const src = (await api(app, s, 'GET', '/api/summary')).json.sources.find((x) => x.name === 'syslog');
    assert.equal(src.dropped, 2);
    assert.deepEqual(src.droppedSenders, { '127.0.0.2': 2 });
  } finally { await app.close(); }
});

test('Explain: adversarial LLM is overridden by the guard; an off-prem LLM is refused and the board keeps running', async () => {
  const llm = await M.mockLlm({ mode: 'adversarial' });
  let { app } = await startBoard({ sources: { syslog: { enabled: true, port: 0, allow: ['127.0.0.1'] } }, llm: { url: llm.url, model: 'mock', budgetPerHour: 10, autoMinSeverity: 'critical' } });
  try {
    await M.sendSyslog([LOGS[1], LOGS[2]], { port: app.syslogAddress.udp.port });
    await sleep(300);
    const s = await login(app, 'op');
    const items = (await api(app, s, 'GET', '/api/items')).json.items;
    const target = items.find((i) => i.flags.length);
    const r = await api(app, s, 'POST', `/api/items/${target.id}/explain`, {});
    assert.equal(r.status, 202);
    assert.equal(r.json.position, 1);
    await waitFor(() => app.db.prepare('SELECT llm_state FROM items WHERE id = ?').get(target.id).llm_state === 'done', 5000);
    const it = (await api(app, s, 'GET', '/api/items')).json.items.find((i) => i.id === target.id);
    assert.notEqual(it.llm.classification, 'benign');
    assert.ok(it.llm.overridden.some((o) => /injection flags|risk floor/.test(o)));
    assert.equal(it.severity, target.severity, 'severity unchanged by a benign answer');
    assert.equal(llm.seen.length, 1);
    assert.ok(!JSON.stringify(llm.seen).includes('198.51.100.77'), 'masked before sending');
  } finally { await app.close(); llm.server.close(); }
  ({ app } = await startBoard({ llm: { url: 'http://8.8.8.8:9/v1', model: 'm' } }));
  try {
    app.pipeline.ingest(require('../../server/trust.js').generic({ title: 'x', severity: 'high', key: 'k' }), 'generic');
    app.pipeline.flush();
    const s = await login(app, 'op');
    const id = app.db.prepare('SELECT id FROM items').get().id;
    assert.equal((await api(app, s, 'POST', `/api/items/${id}/explain`, {})).status, 202);
    await waitFor(() => app.db.prepare('SELECT llm_state FROM items WHERE id = ?').get(id).llm_state === 'error');
    assert.equal((await fetch(`${app.url}/healthz`)).status, 200, 'still serving');
    assert.match((await api(app, s, 'GET', '/api/summary')).json.llm.lastError, /not on-prem/);
  } finally { await app.close(); }
});

test('source down: degraded then down with backoff, recovery resets; Pull now via API', async () => {
  const wz = await M.mockWazuh({ username: 'ro', password: 'pw-123456' });
  const { app } = await startBoard({ sources: { wazuh: { enabled: true, schedule: '@every 1h', url: wz.url, username: 'ro', password: 'pw-123456' } } }, { backoffBaseMs: 60000 });
  try {
    app.scheduler.start({ runOnStart: false });
    const s = await login(app, 'op');
    wz.state.fail = true;
    for (let i = 1; i <= 3; i++) {
      const r = (await api(app, s, 'POST', '/api/sources/wazuh/pull', {})).json;
      assert.equal(r.ok, false);
      const st = db_.sourceState(app.db, 'wazuh');
      assert.equal(st.status, i >= 3 ? 'down' : 'degraded');
      assert.ok(Math.abs(st.next_run - (Date.now() + 60000 * 2 ** (i - 1))) < 5000, `backoff ${i}`);
    }
    assert.match(db_.sourceState(app.db, 'wazuh').last_error, /HTTP 503/);
    wz.state.fail = false;
    assert.equal((await api(app, s, 'POST', '/api/sources/wazuh/pull', {})).json.ok, true);
    const st = db_.sourceState(app.db, 'wazuh');
    assert.equal(st.status, 'ok'); assert.equal(st.fails, 0);
    assert.ok(st.next_run > Date.now() + 3500000, 'back on the normal schedule');
    assert.equal((await api(app, s, 'POST', '/api/sources/nope/pull', {})).status, 404);
    const v = await login(app, 'view');
    assert.equal((await api(app, v, 'POST', '/api/sources/wazuh/pull', {})).status, 403);
  } finally { await app.close(); wz.server.close(); }
});

test('config backups: file-drop gives finding cards + INCOMPLETE card and resolves fixed findings; FortiGate REST uses GET on 7.4 and POST on 7.6', async () => {
  const dir = tmp();
  const conf = fs.readFileSync(path.join(ROOT, 'samples/fgt-demo.conf'), 'utf8');
  fs.writeFileSync(path.join(dir, 'FGT-DEMO-CORE_20261106.conf'), conf);
  fs.copyFileSync(path.join(ROOT, 'test/fixtures/incomplete.conf'), path.join(dir, 'lab_20261106.conf'));
  const f74 = await M.mockFortigate({ version: '7.4.5', token: 'fgt-tok-74' });
  const f76 = await M.mockFortigate({ version: '7.6.1', token: 'fgt-tok-76' });
  const { app } = await startBoard({ sources: {
    configdrop: { enabled: true, schedule: '@every 1h', dir },
    fortigate: { enabled: true, schedule: '@every 1h', url: f74.url, token: 'fgt-tok-74' },
  } });
  try {
    assert.equal((await app.scheduler.run('configdrop')).ok, true);
    let rows = app.db.prepare("SELECT * FROM items WHERE source = 'configdrop' AND resolved_at IS NULL").all();
    const inc = rows.find((x) => JSON.parse(x.trusted).check === 'COVERAGE');
    assert.ok(inc, 'INCOMPLETE card');
    const demo = rows.filter((x) => JSON.parse(x.trusted).device !== JSON.parse(inc.trusted).device);
    assert.ok(demo.some((x) => JSON.parse(x.trusted).check === 'FW-ANY-ANY' && x.severity === 'critical'));
    assert.equal((await app.scheduler.run('configdrop')).n, 0, 'unchanged files are not re-read');
    // admin removes the any-any rule -> its card resolves on the next backup
    fs.writeFileSync(path.join(dir, 'FGT-DEMO-CORE_20261106.conf'), conf.replace(/ {4}edit 9\n[\s\S]*?\n {4}next\n/, ''));
    await app.scheduler.run('configdrop');
    const anyAny = app.db.prepare("SELECT resolved_at FROM items WHERE source = 'configdrop' AND trusted LIKE '%FW-ANY-ANY%'").get();
    assert.ok(anyAny.resolved_at, 'fixed finding resolved');
    const s = await login(app, 'view');
    const sum = (await api(app, s, 'GET', '/api/summary')).json;
    assert.equal(sum.configs.length, 2);
    assert.ok(sum.configs.some((c) => c.complete === false));
    // REST backup
    assert.equal((await app.scheduler.run('fortigate')).ok, true);
    assert.deepEqual(f74.calls.filter((c) => c.url.includes('backup')).map((c) => c.method), ['GET']);
    assert.equal((await app.scheduler.run('fortigate')).n, 0, 'unchanged config (same sha) is skipped');
    app.cfg.sources.fortigate.url = f76.url; app.cfg.sources.fortigate.token = 'fgt-tok-76';
    db_.updateSource(app.db, 'fortigate', { cursor: null });
    assert.equal((await app.scheduler.run('fortigate')).ok, true);
    assert.deepEqual(f76.calls.filter((c) => c.url.includes('backup')).map((c) => c.method), ['GET', 'POST'], '405 on GET -> POST');
    assert.equal(JSON.parse(db_.sourceState(app.db, 'fortigate').cursor).method, 'POST', 'method remembered');
    app.cfg.sources.fortigate.token = 'wrong';
    const bad = await app.scheduler.run('fortigate');
    assert.match(bad.error, /HTTP 401.*file-drop/);
  } finally { await app.close(); f74.server.close(); f76.server.close(); }
});

test('no secret appears in API responses, the database file or the server log', async () => {
  const secrets = { NSB_S1: 'SECRET-wazuh-pw-9f3a', NSB_S2: 'SECRET-zabbix-tok-77c1', NSB_S3: 'SECRET-line-tok-a1b2', NSB_S4: 'SECRET-hook-tok-5e6f', NSB_S5: 'SECRET-webhook-hmac-0d9e' };
  Object.assign(process.env, secrets);
  const wz = await M.mockWazuh({ username: 'ro', password: secrets.NSB_S1 });
  const zbx = await M.mockZabbix({ token: secrets.NSB_S2 });
  const sinks = await M.mockSinks();
  const logs = [];
  const { app, dataDir } = await startBoard({
    sources: {
      wazuh: { enabled: true, schedule: '@every 1h', url: wz.url, username: 'ro', password: 'env:NSB_S1', quietFirstRun: false },
      zabbix: { enabled: true, schedule: '@every 1h', url: zbx.url, token: 'env:NSB_S2', quietFirstRun: false },
    },
    hooks: { generic: { token: 'env:NSB_S4' } },
    notify: { channels: [
      { name: 'line', type: 'line', apiBase: `${sinks.url}/line`, channelToken: 'env:NSB_S3', to: 'C1', minSeverity: 'info', mode: 'immediate' },
      { name: 'wh', type: 'webhook', url: `${sinks.url}/fail`, secret: 'env:NSB_S5', minSeverity: 'info' },
    ] },
  }, { log: (m) => logs.push(m) });
  try {
    await app.scheduler.run('wazuh'); await app.scheduler.run('zabbix');
    zbx.state.stripAuth = true;
    await app.scheduler.run('zabbix');
    await app.notifier.idle();
    const admin = await login(app, 'admin');
    const bodies = [];
    for (const p of ['/api/items', '/api/summary', '/api/config', '/api/me']) bodies.push((await api(app, admin, 'GET', p)).text);
    app.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    const files = fs.readdirSync(dataDir).map((f) => fs.readFileSync(path.join(dataDir, f)).toString('latin1'));
    const hay = [...bodies, ...files, ...logs].join('\n');
    for (const v of Object.values(secrets)) assert.ok(!hay.includes(v), `leaked ${v}`);
    assert.ok(sinks.requests.some((r) => r.headers.authorization === `Bearer ${secrets.NSB_S3}`), 'the secret was used, just never stored');
    for (const f of [app.db.file, `${app.db.file}-wal`, `${app.db.file}-shm`]) if (fs.existsSync(f)) assert.equal((fs.statSync(f).mode & 0o777).toString(8), '600', f);
  } finally { await app.close(); for (const m of [wz, zbx, sinks]) m.server.close(); }
});
