'use strict';
/*
 * Anonymous attacker suite: everything a client with no session (and no hook token, and an
 * unlisted syslog address) can reach. Raw sockets where fetch would sanitise the request.
 * Findings A1-A6 of the anonymous review each have a test here; each fails on 627d7e1.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const M = require('../../mocks/servers.js');
const db_ = require('../../server/db.js');
const A = require('../../server/auth.js');
const T = require('../../server/trust.js');
const { clientAddress, trustedProxies } = require('../../server/http.js');
const { startBoard, login, api, sleep, waitFor } = require('./helpers.js');

const ROOT = path.join(__dirname, '..', '..');
const LOGS = fs.readFileSync(path.join(ROOT, 'samples/fgt-logs.log'), 'utf8').split('\n').filter(Boolean);
const SECRET_TITLE = 'ANON-CANARY-7f3a';

/** Send raw bytes, return {status, head, body, closed} once the server answers or closes. */
function raw(app, bytes, { waitMs = 1500 } = {}) {
  const { port } = new URL(app.url);
  return new Promise((resolve) => {
    const s = net.connect(Number(port), '127.0.0.1');
    let buf = '';
    const done = (closed) => {
      clearTimeout(t); s.destroy();
      const [head, ...rest] = buf.split('\r\n\r\n');
      resolve({ status: Number((head.match(/^HTTP\/1\.1 (\d{3})/) || [])[1]) || null, head, body: rest.join('\r\n\r\n'), closed });
    };
    const t = setTimeout(() => done(false), waitMs);
    s.on('data', (d) => { buf += d; if (/\r\n\r\n/.test(buf) && /content-length: (\d+)/i.test(buf)) { const n = Number(buf.match(/content-length: (\d+)/i)[1]); if (Buffer.byteLength(buf.split('\r\n\r\n').slice(1).join('\r\n\r\n')) >= n) done(true); } });
    s.on('close', () => done(true));
    s.on('error', () => done(true));
    s.write(bytes);
  });
}
const alive = async (app) => (await fetch(`${app.url}/healthz`)).status === 200;

async function anonBoard(over = {}, opts = {}) {
  const logs = [];
  const b = await startBoard({ hooks: { zabbix: { token: 'hook-zbx-token-123' }, ratePerMin: 5 }, ...over }, { log: (m) => logs.push(m), ...opts });
  b.app.pipeline.ingest(T.generic({ title: SECRET_TITLE, severity: 'high', key: 'canary' }), 'generic');
  b.app.pipeline.flush();
  return { ...b, logs };
}

test('A1: malformed request targets get 400 and the board stays up (was: process exit)', async () => {
  const { app, logs } = await anonBoard();
  try {
    for (const target of ['//a:99999', 'http://a:99999/', 'http://[/', '//[::1', '/%00', '/..%2f..%2fnetsec.json']) {
      const r = await raw(app, `GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
      assert.ok([400, 404].includes(r.status), `${target} -> ${r.status}`);
      assert.ok(await alive(app), `alive after ${target}`);
    }
    // absolute-form with a bad port: exactly the request that used to kill the process
    assert.equal((await raw(app, 'GET //a:99999 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')).status, 400);
    assert.equal(logs.filter((l) => /^500 /.test(l)).length, 0, 'no 500s logged');
  } finally { await app.close(); }
});

test('A1: the handler never leaks a rejection, even if a route throws after headers', async () => {
  const { app } = await anonBoard();
  try {
    const before = process.listenerCount('unhandledRejection');
    let leaked = null;
    const h = (e) => { leaked = e; };
    process.on('unhandledRejection', h);
    app.server.emit('request', Object.assign(new (require('node:stream').PassThrough)(), { url: '//a:99999', method: 'GET', headers: {}, socket: { remoteAddress: '127.0.0.1' } }), { headersSent: false, writeHead() {}, end() {} });
    await sleep(50);
    process.removeListener('unhandledRejection', h);
    assert.equal(process.listenerCount('unhandledRejection'), before);
    assert.equal(leaked, null);
  } finally { await app.close(); }
});

test('every route x method without a session: never data, never 500, always the security headers', async () => {
  const { app, logs } = await anonBoard();
  try {
    const paths = ['/api/me', '/api/items', '/api/summary', '/api/config', '/api/events', '/api/logout', '/api/login',
      '/api/items/1/pin', '/api/items/1/ack', '/api/items/1/snooze', '/api/items/1/explain', '/api/items/1/view',
      '/api/sources/wazuh/pull', '/api/sources/syslog/pull', '/hooks/zabbix', '/hooks/wazuh', '/hooks/generic',
      '/netsec.json', '/data/board.db', '/package.json', '/board/board.js', '/.git/config', '/api/items?x=1', '/API/ITEMS'];
    for (const p of paths) {
      for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
        const r = await fetch(`${app.url}${p}`, { method, headers: method === 'POST' || method === 'PUT' || method === 'PATCH' ? { 'content-type': 'application/json' } : {}, body: ['POST', 'PUT', 'PATCH'].includes(method) ? '{}' : undefined });
        const body = await r.text();
        const where = `${method} ${p}`;
        assert.notEqual(r.status, 500, where);
        if (p === '/api/login' && method === 'POST') { assert.equal(r.status, 401, where); continue; }
        assert.ok([401, 403, 404].includes(r.status), `${where} -> ${r.status}`);
        assert.ok(!body.includes(SECRET_TITLE), `${where} leaks item data`);
        assert.match(r.headers.get('content-security-policy') || '', /default-src 'none'/, `${where} CSP`);
        assert.equal(r.headers.get('x-content-type-options'), 'nosniff', where);
        assert.equal(r.headers.get('x-frame-options'), 'DENY', where);
      }
    }
    // public files carry no data; healthz says only ok + version
    for (const p of ['/', '/board.js', '/board.css', '/icon.svg']) {
      const r = await fetch(`${app.url}${p}`);
      assert.equal(r.status, 200, p);
      assert.ok(!(await r.text()).includes(SECRET_TITLE), p);
    }
    assert.deepEqual(Object.keys(await (await fetch(`${app.url}/healthz`)).json()).sort(), ['ok', 'version']);
    assert.equal(logs.filter((l) => /^500 /.test(l)).length, 0);
  } finally { await app.close(); }
});

test('A4: malformed cookies are ignored: 401, not 500, nothing logged', async () => {
  const { app, logs } = await anonBoard();
  try {
    for (const cookie of ['nsb_sid=%E0', 'nsb_sid=%', 'nsb_sid=%E0%A4%A; other=1', 'nsb_sid=', '=x; nsb_sid', `nsb_sid=${'A'.repeat(4000)}`, Array.from({ length: 300 }, (_, i) => `c${i}=%zz`).join('; ')]) {
      const r = await fetch(`${app.url}/api/me`, { headers: { cookie } });
      assert.equal(r.status, 401, cookie.slice(0, 30));
    }
    assert.deepEqual(logs, []);
    assert.deepEqual(A.parseCookies('a=%E0; nsb_sid=ok'), { nsb_sid: 'ok' });
  } finally { await app.close(); }
});

test('CSRF and cross-site: form posts and token-less requests are refused', async () => {
  const { app } = await anonBoard();
  try {
    const id = app.db.prepare('SELECT id FROM items').get().id;
    // a cross-site <form> can only send text/plain, urlencoded or multipart
    for (const ct of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x']) {
      assert.equal((await fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': ct }, body: '{"username":"admin","password":"admin-password-123"}' })).status, 415, ct);
    }
    const s = await login(app, 'op');
    assert.equal((await api(app, { ...s, csrf: '' }, 'POST', `/api/items/${id}/ack`, {})).status, 403, 'session cookie without the CSRF header');
    assert.equal((await api(app, { ...s, csrf: 'wrong' }, 'POST', `/api/items/${id}/ack`, {})).status, 403);
    assert.equal((await fetch(`${app.url}/api/items/${id}/ack`, { method: 'POST', headers: { cookie: s.cookie, 'x-csrf-token': s.csrf, 'content-type': 'text/plain' }, body: '{}' })).status, 415);
    assert.equal(app.db.prepare('SELECT acked_by FROM items WHERE id = ?').get(id).acked_by, null);
    // the cookie itself is not readable or sent cross-site
    const set = (await fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'view', password: 'view-password-123' }) })).headers.get('set-cookie');
    assert.match(set, /HttpOnly/); assert.match(set, /SameSite=Strict/);
  } finally { await app.close(); }
});

test('SSE without a session is refused before any stream starts', async () => {
  const { app } = await anonBoard();
  try {
    const r = await raw(app, 'GET /api/events HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n');
    assert.equal(r.status, 401);
    assert.doesNotMatch(r.head, /text\/event-stream/);
    assert.equal(app.sse.size, 0);
  } finally { await app.close(); }
});

test('A5: hooks: bad tokens are refused and cannot use up the real caller\'s rate limit', async () => {
  const { app } = await anonBoard();
  try {
    const post = (auth, body = '{"name":"x","severity":"4","eventid":"1"}', ct = 'application/json') => fetch(`${app.url}/hooks/zabbix`, { method: 'POST', headers: { 'content-type': ct, ...(auth ? { authorization: auth } : {}) }, body });
    assert.equal((await post()).status, 401);
    assert.equal((await post('Bearer wrong')).status, 401);
    assert.equal((await post('bearer hook-zbx-token-123')).status, 401, 'scheme is case-sensitive here; no partial matches');
    assert.equal((await post('Bearer hook-zbx-token-1234')).status, 401);
    assert.equal((await fetch(`${app.url}/hooks/zabbix`)).status, 404, 'GET');
    assert.equal((await fetch(`${app.url}/hooks/wazuh`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer x' }, body: '{}' })).status, 404, 'not enabled');
    // anonymous junk from the same address (a proxy without trustProxy): only the junk is limited
    const junk = [];
    for (let i = 0; i < 12; i++) junk.push((await post(`Bearer guess-${i}`)).status);
    assert.ok(junk.includes(429), `junk is rate limited: ${junk}`);
    assert.equal((await post('Bearer hook-zbx-token-123')).status, 202, 'the real Zabbix still gets through');
    // 2 MB body with a valid token
    assert.equal((await post('Bearer hook-zbx-token-123', JSON.stringify({ name: 'x'.repeat(2 * 1024 * 1024) }))).status, 413);
    assert.equal((await post('Bearer hook-zbx-token-123', 'name=x', 'text/plain')).status, 415);
    assert.equal((await post('Bearer hook-zbx-token-123', '{nope')).status, 400);
  } finally { await app.close(); }
});

test('A2: X-Forwarded-For counts only from a trusted proxy, and only its rightmost untrusted hop', () => {
  const P = trustedProxies(true);
  assert.equal(clientAddress('127.0.0.1', '6.6.6.6, 203.0.113.9', P), '203.0.113.9', 'the proxy appended the real peer last');
  assert.equal(clientAddress('::ffff:127.0.0.1', '203.0.113.9', P), '203.0.113.9');
  assert.equal(clientAddress('198.51.100.7', '1.2.3.4', P), '198.51.100.7', 'a direct client cannot claim an address');
  assert.equal(clientAddress('127.0.0.1', '203.0.113.9, 127.0.0.1', P), '203.0.113.9', 'proxy chain hops are skipped');
  assert.equal(clientAddress('127.0.0.1', undefined, P), '127.0.0.1');
  assert.equal(clientAddress('10.0.0.2', '203.0.113.9', trustedProxies(['10.0.0.0/24'])), '203.0.113.9');
  assert.equal(clientAddress('10.0.1.2', '203.0.113.9', trustedProxies(['10.0.0.0/24'])), '10.0.1.2');
  assert.equal(clientAddress('127.0.0.1', '203.0.113.9', trustedProxies(false)), '127.0.0.1');
  // Docker: the peer is the bridge gateway; compose sets NETSEC_TRUST_PROXY to the bridge range
  const { envOverrides } = require('../../server/config.js');
  const dock = envOverrides({ NETSEC_TRUST_PROXY: '172.16.0.0/12' }).trustProxy;
  assert.deepEqual(dock, ['172.16.0.0/12']);
  assert.equal(clientAddress('::ffff:172.20.0.1', '6.6.6.6, 198.51.100.4', trustedProxies(dock)), '198.51.100.4');
  assert.equal(envOverrides({ NETSEC_TRUST_PROXY: 'true' }).trustProxy, true);
  assert.equal(envOverrides({ NETSEC_TRUST_PROXY: 'false' }).trustProxy, false);
  assert.equal(envOverrides({}).trustProxy, undefined);
});

test('A2: a client rotating X-Forwarded-For through the proxy is still throttled as itself', async () => {
  const { app } = await anonBoard({ trustProxy: true });
  try {
    const statuses = [];
    for (let i = 0; i < 7; i++) {
      // nginx-style: client-supplied XFF first, the real peer (198.51.100.50) appended last
      const r = await fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': `10.9.${i}.1, 198.51.100.50` }, body: JSON.stringify({ username: 'admin', password: `wrong-${i}` }) });
      statuses.push(r.status);
    }
    assert.ok(statuses.slice(5).every((s) => s === 429), `throttled after 5: ${statuses}`);
    const ips = new Set(app.db.prepare("SELECT ip FROM user_actions WHERE action = 'login-failed'").all().map((r) => r.ip));
    assert.deepEqual([...ips], ['198.51.100.50'], 'the audit log records the real address');
  } finally { await app.close(); }
});

test('A3: IPv6 counts per /64; one address holds at most 2 checks; 4 slots are kept for known logins', () => {
  assert.equal(A.ipKey('2001:db8:1:2:aaaa::1'), '2001:db8:1:2::/64');
  assert.equal(A.ipKey('2001:db8:1:2:ffff:ffff:ffff:ffff'), '2001:db8:1:2::/64');
  assert.equal(A.ipKey('2001:0db8:0001:0002::9'), '2001:db8:1:2::/64');
  assert.equal(A.ipKey('::1'), '0:0:0:0::/64');
  assert.equal(A.ipKey('::ffff:192.0.2.1'), '192.0.2.1');
  assert.equal(A.ipKey('192.0.2.1'), '192.0.2.1');
  let now = 0;
  const th = new A.Throttle(() => now);
  for (let i = 1; i <= 6; i++) th.fail(`2001:db8:1:2::${i.toString(16)}`);
  assert.ok(th.wait('2001:db8:1:2:dead:beef:0:1') > 0, 'a new address in the same /64 is already slowed');
  assert.equal(th.wait('2001:db8:1:3::1'), 0, 'the next /64 is not');
  // slots
  const t2 = new A.Throttle(() => now);
  assert.ok(t2.acquire('192.0.2.1')); assert.ok(t2.acquire('192.0.2.1'));
  assert.equal(t2.acquire('192.0.2.1'), false, 'per address: 2');
  let got = 2;
  for (let i = 2; i < 40; i++) if (t2.acquire(`192.0.2.${i}`)) got++;
  assert.equal(got, 20 - A.RESERVED_CHECKS, 'unknown callers stop at 16');
  assert.equal(t2.acquire('198.51.100.1', true), true, 'a known (user, address) still gets a slot');
  t2.release('192.0.2.1'); t2.release('192.0.2.1');
  assert.ok(t2.acquire('192.0.2.1'), 'released slots come back');
});

test('A3: a login spray from many addresses does not lock the admin out of a known address', async () => {
  const { app } = await anonBoard({ trustProxy: true });
  try {
    const go = (xff, password) => fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': xff }, body: JSON.stringify({ username: 'admin', password }) }).then((r) => r.status);
    assert.equal(await go('10.20.0.5', 'admin-password-123'), 200, 'the admin logged in from here before');
    // 40 workers keep a spray going for 1.2 s, each request from a fresh /64
    const stopAt = Date.now() + 1200;
    const spray = [];
    const worker = async (w) => { for (let k = 0; Date.now() < stopAt; k++) spray.push(await go(`2001:db8:${(w * 1000 + k).toString(16)}:7::1`, `guess-${k}`)); };
    const workers = Promise.all(Array.from({ length: 40 }, (_, w) => worker(w)));
    await sleep(300);
    const admin = [];
    for (let i = 0; i < 5; i++) { admin.push(await go('10.20.0.5', 'admin-password-123')); await sleep(50); }
    await workers;
    assert.ok(spray.includes(503), 'the spray did saturate the unknown slots');
    assert.ok(!spray.includes(200));
    assert.deepEqual(admin, [200, 200, 200, 200, 200], `admin during the spray: ${admin}`);
  } finally { await app.close(); }
});

test('slow clients: a connection that never finishes its headers is closed', async () => {
  const { app } = await anonBoard({}, { headersTimeoutMs: 600, requestTimeoutMs: 1200, connCheckMs: 100 });
  try {
    const t0 = Date.now();
    const r = await raw(app, 'GET /healthz HTTP/1.1\r\nHost: x\r\nX-a: ', { waitMs: 5000 });
    assert.ok(r.closed, 'closed by the server');
    assert.ok(Date.now() - t0 < 3000, `closed after ${Date.now() - t0} ms`);
    assert.ok(await alive(app));
  } finally { await app.close(); }
  const { app: def } = await anonBoard();
  try {
    assert.equal(def.server.headersTimeout, 20000);
    assert.equal(def.server.requestTimeout, 60000);
  } finally { await def.close(); }
});

test('syslog: unlisted senders (UDP and TCP), oversize lines, CEF/CSV and an endless TCP line are all dropped and counted', async () => {
  const { app } = await anonBoard({ sources: { syslog: { enabled: true, port: 0, allow: ['127.0.0.2'], minSeverity: 'info' } } });
  try {
    const port = app.syslogAddress.udp.port;
    const tport = app.syslogAddress.tcp.port;
    const n0 = app.db.prepare('SELECT COUNT(*) AS n FROM items').get().n;
    await M.sendSyslog([LOGS[1], LOGS[2]], { port, localAddress: '127.0.0.1' });
    await M.sendSyslog([LOGS[1]], { port: tport, proto: 'tcp', localAddress: '127.0.0.1' });
    await M.sendSyslog([`<14>1 - h app - - - devid="FGT" logid="1" ${'x'.repeat(20000)}`], { port, localAddress: '127.0.0.2', raw: true });
    await M.sendSyslog(['<14>CEF:0|Fortinet|Fortigate|v7|1|x|5|src=1.2.3.4', '<14>date=2026-11-06,time=10:00:00,devname=x'], { port, localAddress: '127.0.0.2', raw: true });
    // an allowed sender that never sends a newline: the 1 MB buffer cap closes it
    await new Promise((resolve) => {
      const s = net.connect({ port: tport, host: '127.0.0.1', localAddress: '127.0.0.2' }, () => {
        const chunk = Buffer.alloc(64 * 1024, 0x41);
        const pump = () => { while (!s.destroyed && s.write(chunk)) { /* fill */ } };
        s.on('drain', pump); pump();
      });
      s.on('close', resolve); s.on('error', resolve);
    });
    await sleep(300);
    app.syslog.flushCounters();
    const st = db_.sourceState(app.db, 'syslog');
    const senders = JSON.parse(st.dropped_senders);
    assert.equal(senders['127.0.0.1'], 3, 'two UDP + one TCP connection from an unlisted address');
    assert.equal(senders['127.0.0.2 (size)'], 2, 'the oversize datagram and the endless TCP line');
    assert.equal(st.unsupported, 2);
    assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM items').get().n, n0, 'nothing reached the board');
    assert.ok(await alive(app));
  } finally { await app.close(); }
});

test('the board serves the TH/EN manual itself: public, offline (no external resources), its own narrow CSP', async () => {
  const { app } = await anonBoard();
  try {
    const r = await fetch(`${app.url}/manual.html?lang=en`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.match(html, /NetSec Board manual/);
    assert.match(html, /คู่มือการใช้งาน NetSec Board/, 'Thai text is there too');
    assert.ok(!/fonts\.(googleapis|gstatic)/.test(html), 'no external fonts');
    const csp = r.headers.get('content-security-policy');
    assert.match(csp, /default-src 'none'/);
    assert.ok(!/https?:/.test(csp), 'the manual may load nothing from the network');
    assert.ok(!html.includes(SECRET_TITLE), 'no board data in the manual');
  } finally { await app.close(); }
});
