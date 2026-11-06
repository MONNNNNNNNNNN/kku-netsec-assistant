'use strict';
// Regression tests for the v0.4 scrutiny findings (F1-F14). Each test fails on the code before the fix.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const M = require('../../mocks/servers.js');
const db_ = require('../../server/db.js');
const A = require('../../server/auth.js');
const T = require('../../server/trust.js');
const { startBoard, login, api, sse, waitFor, tmp, sleep, sseItemIds } = require('./helpers.js');

const ROOT = path.join(__dirname, '..', '..');
const LOGS = fs.readFileSync(path.join(ROOT, 'samples/fgt-logs.log'), 'utf8').split('\n').filter(Boolean);
const VPN = LOGS[7]; // event/vpn "SSL VPN login fail", carries user="..."
const randomUser = (l, i) => l.replace(/user="[^"]*"/, `user="u${i}-${Math.random().toString(36).slice(2, 8)}"`);

test('F1: a brute force with 200 random user names stays one card and one notification', async () => {
  assert.match(VPN, /user="/);
  const sinks = await M.mockSinks();
  const { app } = await startBoard({
    sources: { syslog: { enabled: true, port: 0, udp: false, allow: ['127.0.0.1'], minSeverity: 'low' } },
    notify: { channels: [{ name: 'ntfy', type: 'ntfy', url: `${sinks.url}/ntfy`, topic: 't', minSeverity: 'high' }] },
  });
  try {
    await M.sendSyslog(Array.from({ length: 200 }, (_, i) => randomUser(VPN, i)), { port: app.syslogAddress.tcp.port, proto: 'tcp' });
    await waitFor(() => db_.sourceState(app.db, 'syslog').received >= 200, 10000);
    await app.notifier.idle();
    const rows = app.db.prepare("SELECT count, samples FROM items WHERE kind = 'event/vpn'").all();
    assert.equal(rows.length, 1, 'one card');
    assert.equal(rows[0].count, 200);
    const samples = JSON.parse(rows[0].samples);
    assert.equal(samples.length, 5, 'user names kept as a capped sample');
    assert.ok(samples.every((x) => /^u\d+-/.test(x.untrusted.user)));
    assert.equal(sinks.requests.filter((r) => r.url === '/ntfy').length, 1, 'one push, not 200');
  } finally { await app.close(); sinks.server.close(); }
});

test('F2: a clean repeat on the same flow keeps the injection flag, the first sample, and the LLM sees the flagged sample', async () => {
  const llm = await M.mockLlm({ mode: 'adversarial' });
  const { app } = await startBoard({ sources: { syslog: { enabled: true, port: 0, allow: ['127.0.0.1'] } }, llm: { url: llm.url, model: 'm' } });
  try {
    const port = app.syslogAddress.udp.port;
    await M.sendSyslog([LOGS[1]], { port });
    await sleep(150);
    await M.sendSyslog([LOGS[1].replace(/agent="[^"]*"/, 'agent="curl/8.5"'), LOGS[1].replace(/agent="[^"]*"/, 'agent="Mozilla/5.0"')], { port });
    await waitFor(() => (app.db.prepare('SELECT count FROM items').get() || {}).count === 3);
    const row = app.db.prepare('SELECT * FROM items').get();
    assert.ok(JSON.parse(row.flags).some((f) => f.startsWith('agent:')), 'flag survives the clean repeats');
    const samples = JSON.parse(row.samples);
    assert.equal(samples.length, 3);
    assert.match(samples[0].untrusted.agent, /SYSTEM NOTICE/, 'first sample kept');
    assert.equal(JSON.parse(row.untrusted).agent, 'Mozilla/5.0', 'latest shown too');
    const s = await login(app, 'op');
    assert.equal((await api(app, s, 'POST', `/api/items/${row.id}/explain`, {})).status, 202);
    await waitFor(() => llm.seen.length === 1);
    assert.match(JSON.stringify(llm.seen[0]), /agent: instruction override/, 'the prompt carries the flagged sample');
  } finally { await app.close(); llm.server.close(); }
});

test('F3: 2,000 repeats in a burst become a handful of coalesced SSE events with count patches', async () => {
  const { app } = await startBoard({ sources: { syslog: { enabled: true, port: 0, udp: false, allow: ['127.0.0.1'], ratePerSec: 100000 } } }, { sseIntervalMs: 1000 });
  try {
    const s = await login(app, 'view');
    const stream = await sse(app, s);
    const t0 = Date.now();
    await M.sendSyslog(Array(2000).fill(LOGS[1]), { port: app.syslogAddress.tcp.port, proto: 'tcp' });
    await waitFor(() => db_.sourceState(app.db, 'syslog').received >= 2000, 10000);
    await sleep(1100 - Math.min(1000, Date.now() - t0) + 100);
    const live = stream.events.filter((e) => e.event === 'items' || e.event === 'item');
    const secs = Math.max(1, Math.ceil((Date.now() - t0) / 1000));
    assert.ok(live.length <= secs + 1, `${live.length} events in ${secs} s (was 2,000)`);
    const last = live.at(-1).data;
    const p = [...last.full, ...last.patch].find((x) => x.count);
    assert.equal(p.count, 2000, 'the last event carries the final count');
    assert.ok(live.slice(1).every((e) => e.data.full.length === 0), 'repeats travel as small patches, not full items');
    assert.equal(sseItemIds(stream.events).size, 1);
    stream.stop();
  } finally { await app.close(); }
});

test('F4: a Zabbix recovery event resolves the card in pull mode', async () => {
  const zbx = await M.mockZabbix({ token: 'zt-123456' });
  const { app } = await startBoard({ sources: { zabbix: { enabled: true, schedule: '@every 1h', url: zbx.url, token: 'zt-123456' } } });
  try {
    await app.scheduler.run('zabbix');
    const problem = zbx.state.events[0];
    const card = () => app.db.prepare("SELECT resolved_at, count FROM items WHERE source = 'zabbix' AND trusted LIKE ?").get(`%"triggerid":"${problem.objectid}"%`);
    assert.equal(card().resolved_at, null);
    zbx.recover(problem.eventid);
    await app.scheduler.run('zabbix');
    assert.ok(card().resolved_at, 'resolved by the value-0 event');
    assert.equal(card().count, 1, 'the recovery does not count as a repeat');
    assert.deepEqual(zbx.state.calls.filter((c) => c.method === 'event.get').at(-1).params.value, [0, 1]);
  } finally { await app.close(); zbx.server.close(); }
});

test('F5: 20 parallel logins leave the event loop free; every UDP line is either received or counted as a kernel drop', async () => {
  const { app } = await startBoard({ sources: { syslog: { enabled: true, port: 0, allow: ['127.0.0.1'], minSeverity: 'info', ratePerSec: 100000 } } });
  try {
    // with scryptSync the loop is blocked for the whole spray (availability about 0); async scrypt keeps it about 0.95
    let ticks = 0;
    const ticker = setInterval(() => ticks++, 2);
    const t0 = Date.now();
    const statuses = await Promise.all(Array.from({ length: 20 }, () => fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin-password-123' }) }).then((r) => r.status)));
    const elapsed = Date.now() - t0;
    clearInterval(ticker);
    assert.ok((ticks * 2) / elapsed > 0.4, `event loop available ${((ticks * 2) / elapsed).toFixed(2)} of ${elapsed} ms`);
    assert.ok(statuses.every((x) => x === 200 || x === 503), statuses.join(','));
    const lines = Array.from({ length: 500 }, (_, i) => LOGS[i % LOGS.length].replace(/srcport=\d+/, `srcport=${10000 + i}`));
    await M.sendSyslog(lines, { port: app.syslogAddress.udp.port });
    await sleep(500);
    app.syslog.flushCounters();
    const st = db_.sourceState(app.db, 'syslog');
    assert.equal(st.received + st.filtered + st.kernel_drops, 500, 'nothing disappears silently');
  } finally { await app.close(); }
  // a deliberately tiny receive buffer: losses happen, and the kernel drop counter shows every one
  const { app: small } = await startBoard({ sources: { syslog: { enabled: true, port: 0, tcp: false, allow: ['127.0.0.1'], minSeverity: 'info', ratePerSec: 100000, recvBufferBytes: 4096 } } });
  try {
    await M.sendSyslog(Array.from({ length: 500 }, (_, i) => LOGS[i % LOGS.length].replace(/srcport=\d+/, `srcport=${20000 + i}`)), { port: small.syslogAddress.udp.port });
    await sleep(500);
    small.syslog.flushCounters();
    const st = db_.sourceState(small.db, 'syslog');
    if (st.kernel_drops === 0 && st.received + st.filtered === 500) return; // the kernel kept up; nothing to account for
    assert.ok(st.kernel_drops > 0, 'losses are visible');
    assert.equal(st.received + st.filtered + st.kernel_drops, 500);
    const s = await login(small, 'view');
    assert.equal((await api(small, s, 'GET', '/api/summary')).json.sources.find((x) => x.name === 'syslog').kernelDrops, st.kernel_drops);
  } finally { await small.close(); }
});

test('F7: logout and a password change end open SSE streams', async () => {
  const { app } = await startBoard({}, { heartbeatMs: 150 });
  try {
    const a = await login(app, 'view');
    const stream1 = await sse(app, a);
    await api(app, a, 'POST', '/api/logout', {});
    await waitFor(() => stream1.ended, 2000);
    const b = await login(app, 'op');
    const stream2 = await sse(app, b);
    A.setPassword(app.db, 'op', 'a-new-password-1'); // what `cli/board.js user passwd` does
    await waitFor(() => stream2.ended, 2000);
    assert.equal(app.sse.size, 0);
  } finally { await app.close(); }
});

test('F9: after a restart, cards left queued for the LLM recover; on-demand ones run, Explain works again', async () => {
  const llm = await M.mockLlm({ mode: 'honest' });
  const dataDir = tmp();
  let { app } = await startBoard({ dataDir });
  for (const k of ['a', 'b']) app.pipeline.ingest(T.generic({ title: k, severity: 'high', key: k }), 'generic');
  app.pipeline.flush();
  const [a, b] = app.db.prepare('SELECT id FROM items ORDER BY id').all().map((r) => r.id);
  app.db.prepare("UPDATE items SET llm_state = 'queued', llm = ? WHERE id = ?").run(JSON.stringify({ demand: true }), a);
  app.db.prepare("UPDATE items SET llm_state = 'running' WHERE id = ?").run(b);
  await app.close(); // as if the process died mid-queue
  ({ app } = await startBoard({ dataDir, llm: { url: llm.url, model: 'm' } }));
  try {
    await waitFor(() => app.db.prepare('SELECT llm_state FROM items WHERE id = ?').get(a).llm_state === 'done', 5000);
    assert.equal(app.db.prepare('SELECT llm_state FROM items WHERE id = ?').get(b).llm_state, 'none', 'automatic one is "not triaged" again');
    const s = await login(app, 'op');
    assert.equal((await api(app, s, 'POST', `/api/items/${b}/explain`, {})).status, 202);
    await waitFor(() => app.db.prepare('SELECT llm_state FROM items WHERE id = ?').get(b).llm_state === 'done', 5000);
  } finally { await app.close(); llm.server.close(); }
});

test('F10: digests survive a restart, and items pulled by system cron reach LINE through the running server', async () => {
  const sinks = await M.mockSinks();
  const zbx = await M.mockZabbix({ token: 'cron-zbx-tok' });
  const dir = tmp();
  const cfgFile = path.join(dir, 'netsec.json');
  fs.writeFileSync(cfgFile, JSON.stringify({
    dataDir: './data',
    sources: { zabbix: { enabled: true, schedule: 'external', url: zbx.url, token: 'env:F10_ZBX' } },
    notify: { channels: [{ name: 'line', type: 'line', apiBase: `${sinks.url}/line`, channelToken: 'line-tok', to: 'C1', minSeverity: 'high' }] },
  }));
  const { loadConfig } = require('../../server/config.js');
  const { createApp } = require('../../server/main.js');
  process.env.F10_ZBX = 'cron-zbx-tok';
  let app = await createApp(loadConfig(cfgFile), { listen: false, jitter: false, runOnStart: false, log: () => {} });
  try {
    assert.equal(db_.sourceState(app.db, 'zabbix').next_run, null, 'schedule "external": the server never pulls it');
    // the crontab line, in another process
    const r = await new Promise((resolve) => execFile(process.execPath, [path.join(ROOT, 'cli/board.js'), 'pull', 'zabbix', '--config', cfgFile], { env: { ...process.env } }, (err, stdout, stderr) => resolve({ err, stdout, stderr })));
    assert.equal(r.err, null, r.stderr);
    const ch = app.notifier.channels[0];
    assert.equal(app.notifier.pending(ch), 2, 'the CLI queued the high + disaster problems');
    assert.equal(sinks.requests.length, 0);
    await app.close();
    app = await createApp(loadConfig(cfgFile), { listen: false, jitter: false, runOnStart: false, log: () => {} }); // restart
    assert.equal(app.notifier.pending(app.notifier.channels[0]), 2, 'still queued after a restart');
    assert.equal(await app.notifier.flushDigest(app.notifier.channels[0]), true);
    const push = sinks.requests.find((x) => x.url === '/line/v2/bot/message/push');
    assert.match(push.body.messages[0].text, /digest: 2 item/);
    assert.equal(app.notifier.pending(app.notifier.channels[0]), 0);
  } finally { await app.close(); sinks.server.close(); zbx.server.close(); }
});

test('F12: a pinned card is returned even with 650 newer items', async () => {
  const { app } = await startBoard();
  try {
    app.pipeline.ingest(T.generic({ title: 'old pinned', severity: 'low', key: 'pinned', time: '2026-01-01T00:00:00Z' }), 'generic');
    app.pipeline.flush();
    const id = app.db.prepare('SELECT id FROM items').get().id;
    app.db.prepare('UPDATE items SET pinned_by = ?, pinned_at = ?, last_seen = 1 WHERE id = ?').run('op', Date.now(), id);
    for (let i = 0; i < 650; i++) app.pipeline.ingest(T.generic({ title: `n${i}`, severity: 'low', key: `n${i}` }), 'generic');
    app.pipeline.flush();
    const s = await login(app, 'view');
    const items = (await api(app, s, 'GET', '/api/items')).json.items;
    assert.ok(items.some((i) => i.id === id && i.pinnedBy === 'op'));
    assert.equal(items.length, 601);
  } finally { await app.close(); }
});

test('F13: an escalation clears a snooze and notifies', async () => {
  const sinks = await M.mockSinks();
  const { app } = await startBoard({ notify: { channels: [{ name: 'n', type: 'ntfy', url: `${sinks.url}/ntfy`, topic: 't', minSeverity: 'medium' }] } });
  try {
    app.pipeline.ingest(T.generic({ title: 'disk filling', severity: 'medium', key: 'disk' }), 'generic');
    app.pipeline.flush();
    await app.notifier.idle();
    const id = app.db.prepare('SELECT id FROM items').get().id;
    const s = await login(app, 'op');
    await api(app, s, 'POST', `/api/items/${id}/snooze`, { hours: 24 });
    app.pipeline.ingest(T.generic({ title: 'disk filling', severity: 'medium', key: 'disk' }), 'generic');
    app.pipeline.flush();
    await app.notifier.idle();
    assert.ok(app.db.prepare('SELECT snoozed_until FROM items WHERE id = ?').get(id).snoozed_until, 'a plain repeat keeps the snooze');
    app.pipeline.ingest(T.generic({ title: 'disk full', severity: 'critical', key: 'disk' }), 'generic');
    app.pipeline.flush();
    await app.notifier.idle();
    assert.equal(app.db.prepare('SELECT snoozed_until FROM items WHERE id = ?').get(id).snoozed_until, null);
    assert.deepEqual(sinks.requests.map((r) => r.body.title), ['NetSec MEDIUM', 'NetSec CRITICAL']);
  } finally { await app.close(); sinks.server.close(); }
});

test('F11 + F14: env overrides make the unedited example config container-ready; check warns about pull + hook double counting', async () => {
  const { loadConfig } = require('../../server/config.js');
  const l = loadConfig(path.join(ROOT, 'netsec.example.json'), {}, { NETSEC_LISTEN_HOST: '0.0.0.0', NETSEC_DATA_DIR: '/data', NETSEC_BACKUP_DIR: '/backups', NETSEC_SYSLOG_BIND: '0.0.0.0' });
  assert.equal(l.cfg.listen.host, '0.0.0.0');
  assert.equal(l.cfg.dataDir, '/data');
  assert.equal(l.cfg.sources.configdrop.dir, '/backups');
  assert.equal(l.cfg.sources.syslog.bind, '0.0.0.0');
  const compose = fs.readFileSync(path.join(ROOT, 'compose.yaml'), 'utf8');
  for (const k of ['NETSEC_LISTEN_HOST: 0.0.0.0', 'NETSEC_DATA_DIR: /data', 'NETSEC_BACKUP_DIR: /backups']) assert.ok(compose.includes(k), k);
  const dir = tmp();
  const cfg = path.join(dir, 'netsec.json');
  const wz = await M.mockWazuh({ username: 'ro', password: 'pw-1234567' });
  try {
    fs.writeFileSync(cfg, JSON.stringify({ dataDir: './data', sources: { wazuh: { enabled: true, url: wz.url, username: 'ro', password: 'env:F14_PW' } }, hooks: { wazuh: { token: 'env:F14_HOOK' } } }));
    const run = (args) => new Promise((resolve) => execFile(process.execPath, [path.join(ROOT, 'cli/board.js'), ...args, '--config', cfg], { env: { ...process.env, F14_PW: 'pw-1234567', F14_HOOK: 'hook-tok-123' } }, (err, stdout) => resolve(stdout)));
    await run(['init']);
    assert.match(await run(['check']), /WARN {2}wazuh: both the pull .* and the push hook .* counted twice/);
  } finally { wz.server.close(); }
});

// ---------------------------------------------------------------- anonymous review: privacy (P1-P3)

const PRIVATE = ['db-prod-01', 'core-sw-02', 'ldap-03', 'web-01', 'mail-02', '10.1.1.5', '10.1.1.6', '203.0.113.77', 'oracle', 'svc_backup'];
function privacyEvents() {
  const z = (id, host) => T.zabbix({ eventid: String(id), clock: Math.floor(Date.now() / 1000), severity: '4', name: `Disk full on ${host}`, objectid: String(900 + id), value: '1', hosts: [{ host, name: host }] });
  const w = (id, agent, ip, user) => T.wazuh({ timestamp: new Date().toISOString(), rule: { level: 12, id: `57${id}`, description: 'sshd: brute force trying to get access' }, agent: { id: `00${id}`, name: agent, ip }, data: { srcip: '203.0.113.77', srcuser: user }, full_log: `sshd: Invalid user ${user} from 203.0.113.77 on ${agent}` }, `w${id}`);
  return [z(1, 'db-prod-01'), z(2, 'core-sw-02'), z(3, 'ldap-03'), w(1, 'web-01', '10.1.1.5', 'oracle'), w(2, 'mail-02', '10.1.1.6', 'svc_backup')];
}

test('P1: LINE digests and Telegram pushes carry no host, agent, user name or IP of any item', async () => {
  const sinks = await M.mockSinks();
  const { app } = await startBoard({
    notify: { channels: [
      { name: 'line', type: 'line', apiBase: `${sinks.url}/line`, channelToken: 'line-tok', to: 'C1', minSeverity: 'high' },
      { name: 'tg', type: 'telegram', apiBase: `${sinks.url}/tg`, botToken: 'tg-tok', chatId: '1', minSeverity: 'high' },
    ] },
  });
  try {
    for (const e of privacyEvents()) app.pipeline.ingest(e, e.source);
    app.pipeline.flush();
    await app.notifier.idle();
    const line = app.notifier.channels.find((c) => c.name === 'line');
    assert.equal(app.notifier.pending(line), 5);
    assert.equal(await app.notifier.flushDigest(line), true);
    const digest = sinks.requests.find((r) => r.url === '/line/v2/bot/message/push').body.messages[0].text;
    assert.match(digest, /digest: 5 item/);
    const pushes = sinks.requests.filter((r) => r.url.startsWith('/tg/')).map((r) => r.body.text);
    assert.equal(pushes.length, 5);
    for (const text of [digest, ...pushes]) for (const p of PRIVATE) assert.ok(!text.includes(p), `"${p}" leaked in: ${text}`);
    assert.match(digest, /HOSTNAME_\d/);
  } finally { await app.close(); sinks.server.close(); }
});

test('P2: the LLM request carries no raw IP or user name (masked, then unmasked locally)', async () => {
  const llm = await M.mockLlm({ mode: 'honest' });
  const { app } = await startBoard({ llm: { url: llm.url, model: 'm' } });
  try {
    for (const e of privacyEvents()) app.pipeline.ingest(e, e.source);
    app.pipeline.flush();
    const s = await login(app, 'op');
    const id = app.db.prepare("SELECT id FROM items WHERE source = 'wazuh' ORDER BY id LIMIT 1").get().id;
    assert.equal((await api(app, s, 'POST', `/api/items/${id}/explain`, {})).status, 202);
    await waitFor(() => llm.seen.length >= 1, 10000);
    const sent = JSON.stringify(llm.seen);
    for (const p of ['10.1.1.5', '203.0.113.77', 'oracle']) assert.ok(!sent.includes(p), `"${p}" reached the LLM`);
  } finally { await app.close(); llm.server.close(); }
});

test('P3: the repository holds no real e-mail, KKU host, public IP or non-noreply commit author', async (t) => {
  const { execFileSync } = require('node:child_process');
  try { execFileSync('git', ['rev-parse', '--git-dir'], { cwd: ROOT, stdio: 'ignore' }); } catch { return t.skip('needs git and a git checkout'); }
  const files = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter((f) => f && !/\.(png|jpg|ico)$|package-lock\.json$/.test(f));
  const OK_MAIL = /^(noc@uni\.example|noc@example\.org|[\w+.-]+@users\.noreply\.github\.com)$/;
  // a single-digit first octet is a version number (or 8.8.8.8, the tests' "public endpoint")
  const OK_IP = /^(10|127|0|255)\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\.|^192\.0\.2\.|^198\.51\.100\.|^203\.0\.113\.|^169\.254\.|^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./; // private, documentation, CGNAT
  const bad = [];
  for (const f of files) {
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8');
    for (const m of text.match(/[\w.%+-]+@[\w-]+(\.[\w-]+)+/g) || []) if (!OK_MAIL.test(m) && !/^[\w-]+@\d/.test(m) && !/@(types|playwright|v\d)/.test(m)) bad.push(`${f}: e-mail ${m}`);
    for (const m of text.match(/\b[a-z0-9-]+(\.[a-z0-9-]+)*\.kku\.ac\.th\b/gi) || []) if (!/(^|\.)example\.kku\.ac\.th$/i.test(m)) bad.push(`${f}: host ${m}`);
    for (const m of text.match(/\b(\d{1,3}\.){3}\d{1,3}\b/g) || []) if (!OK_IP.test(m) && m.split('.').every((o) => Number(o) <= 255) && !/^\d\./.test(m)) bad.push(`${f}: IP ${m}`);
  }
  for (const a of execFileSync('git', ['log', '--format=%ae%n%ce'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean)) if (!/@users\.noreply\.github\.com$/.test(a)) bad.push(`commit author ${a}`);
  assert.deepEqual([...new Set(bad)], []);
});
