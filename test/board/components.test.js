'use strict';
// Component tests: syslog receiver, notification rules and channels, LLM queue.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const C = require('../../server/config.js');
const db_ = require('../../server/db.js');
const trust = require('../../server/trust.js');
const N = require('../../src/core.js');
const { Pipeline } = require('../../server/pipeline.js');
const { SyslogCollector, parseSyslog, allowed } = require('../../server/collectors/syslog.js');
const { Notifier, maskForCloud, inQuiet, SENDERS } = require('../../server/notify.js');
const { LlmQueue } = require('../../server/llmqueue.js');
const M = require('../../mocks/servers.js');
const { tmp, sleep, waitFor } = require('./helpers.js');

const ROOT = path.join(__dirname, '..', '..');
const LOGS = fs.readFileSync(path.join(ROOT, 'samples/fgt-logs.log'), 'utf8').split('\n').filter(Boolean);
function setup(over = {}) {
  const db = db_.openDb(tmp());
  const cfg = C.loadConfig(null, over).cfg;
  const pipeline = new Pipeline({ db, cfg, batchMs: -1 });
  return { db, cfg, pipeline };
}

test('syslog parsing: RFC 5424 (with structured data and BOM), RFC 3164, FortiGate default, raw', () => {
  const a = parseSyslog('<189>1 2026-11-06T10:00:00+07:00 FGT-CORE - - - [meta x="1"] ﻿date=2026-11-06 devid="FG1" logid="0419016384"');
  assert.equal(a.format, 'rfc5424'); assert.equal(a.host, 'FGT-CORE'); assert.equal(a.sev, 5); assert.equal(a.facility, 23);
  assert.match(a.msg, /^date=2026-11-06 devid/);
  const b = parseSyslog('<38>Nov  6 10:00:00 web-01 sshd[123]: Accepted publickey for x');
  assert.equal(b.format, 'rfc3164'); assert.equal(b.app, 'sshd'); assert.equal(b.msg, 'Accepted publickey for x');
  const c = parseSyslog(`<189>${LOGS[1]}`);
  assert.equal(c.format, 'raw'); assert.match(c.msg, /^date=/);
  assert.equal(parseSyslog('no pri at all').format, 'none');
});

test('syslog allowlist: exact IPs, IPv4 CIDR, IPv4-mapped IPv6; empty list accepts nobody', () => {
  assert.ok(allowed(['10.0.0.1'], '10.0.0.1'));
  assert.ok(allowed(['10.0.0.0/24'], '::ffff:10.0.0.77'));
  assert.ok(!allowed(['10.0.0.0/24'], '10.0.1.1'));
  assert.ok(allowed(['0.0.0.0/0'], '8.8.8.8'));
  assert.ok(!allowed([], '127.0.0.1'));
  assert.ok(allowed(['fd00::5'], 'fd00::5'));
});

test('syslog receiver over UDP and TCP: allowlisted sender ingested, spoofed sender dropped and counted, CSV/CEF unsupported, rate limit', async () => {
  const { db, cfg, pipeline } = setup({ sources: { syslog: { allow: ['127.0.0.1'], ratePerSec: 50, minSeverity: 'info' } } });
  const sc = new SyslogCollector({ cfg: { ...cfg.sources.syslog, port: 0 }, db, pipeline });
  const addr = await sc.start();
  try {
    await M.sendSyslog([LOGS[1]], { port: addr.udp.port, proto: 'udp' });
    await M.sendSyslog([LOGS[2], LOGS[3]], { port: addr.tcp.port, proto: 'tcp' }); // octet counting
    await M.sendSyslog([`<189>${LOGS[4]}`, `<189>${LOGS[5]}`], { port: addr.tcp.port, proto: 'tcp', framing: 'newline', raw: true }); // newline framing, one write
    await M.sendSyslog([LOGS[1]], { port: addr.udp.port, proto: 'udp', localAddress: '127.0.0.2' }); // spoofed / not allowed
    await M.sendSyslog(['<189>date=2026-11-06,time=10:00:00,devid=FG1', '<189>CEF:0|Fortinet|Fortigate|7.4|0419016384|x|5|'], { port: addr.udp.port, proto: 'udp', raw: true });
    await waitFor(() => pipeline.queue.length >= 5 && sc.pending.dropped >= 1 && sc.pending.unsupported >= 2, 3000);
    pipeline.flush();
    sc.flushCounters();
    const items = db.prepare('SELECT source, kind, trusted FROM items').all();
    assert.equal(items.length, 5);
    assert.ok(items.every((i) => JSON.parse(i.trusted).sender === '127.0.0.1'));
    const st = db_.sourceState(db, 'syslog');
    assert.equal(st.dropped, 1);
    assert.deepEqual(JSON.parse(st.dropped_senders), { '127.0.0.2': 1 });
    assert.equal(st.unsupported, 2);
    // rate limit: 50/s bucket, 120 lines at once -> some dropped as "(rate)"
    await M.sendSyslog(Array(120).fill(LOGS[0]), { port: addr.tcp.port, proto: 'tcp' });
    await sleep(200);
    sc.flushCounters();
    const st2 = db_.sourceState(db, 'syslog');
    assert.ok(st2.dropped > 1);
    assert.ok(JSON.parse(st2.dropped_senders)['127.0.0.1 (rate)'] > 0);
  } finally { sc.stop(); db.close(); }
});

function fakeSenders() {
  const sent = [];
  const mk = (type) => async (ch, msg) => { sent.push({ type, ch: ch.name, ...msg }); };
  return { sent, senders: { ntfy: mk('ntfy'), telegram: mk('telegram'), line: mk('line'), webhook: mk('webhook') } };
}
function item(db, over = {}) {
  const e = trust.fortigate(N.parseFortiLog(LOGS[1]));
  const id = db.prepare("INSERT INTO items(fingerprint, source, kind, severity, det_severity, title, trusted, untrusted, flags, count, first_seen, last_seen) VALUES(?, 'fortigate', 'utm/ips', ?, ?, ?, ?, ?, '[]', 1, 1, 1)")
    .run(crypto.randomUUID(), over.severity || 'high', over.severity || 'high', e.title, JSON.stringify({ ...e.trusted, user: 'somchai.k' }), JSON.stringify(e.untrusted)).lastInsertRowid;
  return { id: Number(id), source: 'fortigate', kind: 'utm/ips', severity: over.severity || 'high', title: over.title || `${e.title} from 198.51.100.77 user somchai.k at portal.uni.example`, count: 1, trusted: { ...e.trusted, user: 'somchai.k' }, untrusted: e.untrusted, ...over };
}

test('notify rules: minSeverity, source filter, re-notify on escalation only, snoozed/acked skipped, board event', async () => {
  const { db } = setup();
  const { sent, senders } = fakeSenders();
  const cfg = C.loadConfig(null, { notify: { channels: [{ name: 'n', type: 'ntfy', url: 'http://127.0.0.1:1/x', topic: 't', minSeverity: 'high' }, { name: 'w', type: 'webhook', url: 'http://127.0.0.1:1/w', minSeverity: 'medium', sources: ['zabbix'] }] } }).cfg;
  const n = new Notifier({ db, cfg, senders });
  const board = [];
  n.on('board', (x) => board.push(x));
  const it = item(db, { severity: 'high' });
  n.consider({ item: it, isNew: true }); await n.idle();
  assert.equal(sent.length, 1, 'ntfy yes; webhook filtered by source');
  assert.equal(board.length, 1);
  n.consider({ item: it, repeat: true }); await n.idle();
  assert.equal(sent.length, 1, 'plain repeat: no re-notify');
  n.consider({ item: { ...it, severity: 'high' }, escalated: true }); await n.idle();
  assert.equal(sent.length, 1, 'not higher than last sent: no re-notify');
  n.consider({ item: { ...it, severity: 'critical' }, escalated: true }); await n.idle();
  assert.equal(sent.length, 2, 'escalation re-notifies');
  n.consider({ item: { ...item(db, { severity: 'medium' }) }, isNew: true }); await n.idle();
  assert.equal(sent.length, 2, 'below minSeverity');
  n.consider({ item: { ...item(db), snoozedUntil: Date.now() + 3600000 }, isNew: true }); await n.idle();
  n.consider({ item: { ...item(db), ackedBy: 'op' }, isNew: true }); await n.idle();
  assert.equal(sent.length, 2, 'snoozed and acked items are quiet');
  db.close();
});

test('notify: cloud channels get masked text (no raw IP, hostname or account name); on-prem webhook keeps it', async () => {
  const { db } = setup();
  const { sent, senders } = fakeSenders();
  const cfg = C.loadConfig(null, { notify: { channels: [
    { name: 'tg', type: 'telegram', botToken: 'x', chatId: '1', minSeverity: 'high' },
    { name: 'ln', type: 'line', channelToken: 'x', to: 'C1', minSeverity: 'high', mode: 'immediate' },
    { name: 'pub', type: 'ntfy', url: 'https://ntfy.sh', topic: 't', minSeverity: 'high' },
    { name: 'wh', type: 'webhook', url: 'http://10.0.0.5/hook', minSeverity: 'high' },
  ] } }).cfg;
  const n = new Notifier({ db, cfg, senders });
  n.consider({ item: item(db), isNew: true }); await n.idle();
  assert.equal(sent.length, 4);
  for (const s of sent.filter((x) => x.type !== 'webhook')) {
    const all = `${s.title} ${s.text}`;
    for (const raw of ['198.51.100.77', 'somchai.k', 'portal.uni.example']) assert.ok(!all.includes(raw), `${s.ch} leaked ${raw}: ${all}`);
    assert.match(all, /PUB_IP_1/);
    assert.match(all, /USER_1/);
  }
  assert.match(sent.find((x) => x.type === 'webhook').text, /198\.51\.100\.77/);
  assert.match(maskForCloud('admin bob logged in from 10.1.2.3', { trusted: { user: 'bob' } }), /^admin USER_1 logged in from PRIV_IP_1$/);
  db.close();
});

test('notify: quiet hours (Bangkok), rate limit overflow and LINE digest with a hard daily cap', async () => {
  assert.ok(inQuiet({ start: '22:00', end: '07:00' }, Date.parse('2026-11-06T23:30:00+07:00'), 420));
  assert.ok(inQuiet({ start: '22:00', end: '07:00' }, Date.parse('2026-11-07T06:59:00+07:00'), 420));
  assert.ok(!inQuiet({ start: '22:00', end: '07:00' }, Date.parse('2026-11-06T12:00:00+07:00'), 420));
  const { db } = setup();
  const { sent, senders } = fakeSenders();
  let now = Date.parse('2026-11-06T23:00:00+07:00');
  const cfg = C.loadConfig(null, { notify: { channels: [
    { name: 'night', type: 'ntfy', url: 'http://127.0.0.1:1', topic: 't', minSeverity: 'high', quietHours: { start: '22:00', end: '07:00', except: 'critical' } },
  ] } }).cfg;
  const n = new Notifier({ db, cfg, senders, now: () => now });
  n.consider({ item: item(db, { severity: 'high' }), isNew: true });
  n.consider({ item: item(db, { severity: 'critical' }), isNew: true });
  await n.idle();
  assert.deepEqual(sent.map((s) => s.severity), ['critical'], 'quiet hours hold high, let critical through');
  now = Date.parse('2026-11-07T08:00:00+07:00');
  await n.flushDigest(n.channels[0]);
  assert.equal(sent.length, 2);
  assert.match(sent[1].title, /digest: 1 item/);

  // LINE flood: 100 critical alerts in one day -> digests only, never more than maxPerDay messages
  const { db: db2 } = setup();
  const f = fakeSenders();
  now = Date.parse('2026-11-06T09:00:00+07:00');
  const cfg2 = C.loadConfig(null, { notify: { channels: [{ name: 'line', type: 'line', channelToken: 'x', to: 'C1', minSeverity: 'high', maxPerDay: 8 }] } }).cfg;
  const n2 = new Notifier({ db: db2, cfg: cfg2, senders: f.senders, now: () => now });
  for (let i = 0; i < 100; i++) {
    n2.consider({ item: item(db2, { severity: 'critical', title: `alert ${i}` }), isNew: true });
    if (i % 5 === 4) { await n2.idle(); await n2.flushDigest(n2.channels[0]); now += 60000; }
  }
  await n2.idle();
  assert.equal(f.sent.length, 8, 'daily cap holds');
  assert.ok(f.sent.every((s) => /digest/.test(s.title)));
  assert.ok(db2.prepare("SELECT COUNT(*) AS n FROM notifications WHERE error = 'daily cap'").get().n > 0);
  now = Date.parse('2026-11-07T09:00:00+07:00');
  n2.consider({ item: item(db2, { severity: 'critical' }), isNew: true });
  await n2.flushDigest(n2.channels[0]);
  assert.equal(f.sent.length, 9, 'new Bangkok day, new allowance');
  assert.match(f.sent[8].text, /held back by the daily cap/);

  // rate limit: max 3 per 10 min, the rest go to the digest
  const { db: db3 } = setup();
  const g = fakeSenders();
  const n3 = new Notifier({ db: db3, cfg: C.loadConfig(null, { notify: { channels: [{ name: 'r', type: 'webhook', url: 'http://x', minSeverity: 'high', rateLimit: { max: 3, perMinutes: 10 } }] } }).cfg, senders: g.senders });
  for (let i = 0; i < 6; i++) { n3.consider({ item: item(db3), isNew: true }); await n3.idle(); }
  assert.equal(g.sent.length, 3);
  await n3.flushDigest(n3.channels[0]);
  assert.equal(g.sent.length, 4);
  assert.match(g.sent[3].title, /digest: 3 item/);
  for (const d of [db, db2, db3]) d.close();
});

test('notify channels against mock sinks: ntfy JSON, Telegram, LINE push + quota, webhook HMAC signature', async () => {
  const sinks = await M.mockSinks();
  try {
    const msg = { title: 'NetSec HIGH', text: '[HIGH] x: ภาษาไทย ok', severity: 'high', link: 'https://b/#item-1', items: [1] };
    await SENDERS.ntfy({ url: `${sinks.url}/ntfy`, topic: 'noc', token: 'ntfy-tok', email: 'noc@example.org' }, msg);
    await SENDERS.telegram({ apiBase: `${sinks.url}/tg`, botToken: 'BOT', chatId: '-100' }, msg);
    await SENDERS.line({ apiBase: `${sinks.url}/line`, channelToken: 'LINE-TOK', to: 'C1' }, msg);
    await SENDERS.webhook({ url: `${sinks.url}/hook`, secret: 'shh' }, msg);
    const [nt, tg, ln, wh] = sinks.requests;
    assert.deepEqual({ topic: nt.body.topic, title: nt.body.title, priority: nt.body.priority, click: nt.body.click, email: nt.body.email }, { topic: 'noc', title: 'NetSec HIGH', priority: 4, click: 'https://b/#item-1', email: 'noc@example.org' });
    assert.equal(nt.headers.authorization, 'Bearer ntfy-tok');
    assert.match(nt.body.message, /ภาษาไทย/, 'UTF-8 survives (JSON publish, not headers)');
    assert.equal(tg.url, '/tg/botBOT/sendMessage');
    assert.equal(tg.body.chat_id, '-100');
    assert.equal(ln.url, '/line/v2/bot/message/push');
    assert.equal(ln.headers.authorization, 'Bearer LINE-TOK');
    assert.equal(ln.body.messages[0].type, 'text');
    const sig = crypto.createHmac('sha256', 'shh').update(`${wh.headers['x-netsec-timestamp']}.${wh.raw}`).digest('hex');
    assert.equal(wh.headers['x-netsec-signature'], `sha256=${sig}`);
    await assert.rejects(SENDERS.webhook({ url: `${sinks.url}/fail` }, msg), /webhook HTTP 500/);
    await assert.rejects(SENDERS.telegram({ apiBase: `${sinks.url}/fail?`, botToken: 'SECRET-BOT', chatId: '1' }, msg), (e) => !e.message.includes('SECRET-BOT'));
  } finally { sinks.server.close(); }
});

test('LLM queue: on-demand first, budget per hour, oldest automatic entry dropped when full, severity never lowered, guard applied', async () => {
  const { db, pipeline } = setup();
  const llm = await M.mockLlm({ mode: 'adversarial' });
  try {
    const q = new LlmQueue({ db, cfg: { url: llm.url, model: 'm', budgetPerHour: 2, queueMax: 3, batch: 2, autoMinSeverity: 'high' }, pipeline, lang: 'en' });
    const ids = [];
    for (const l of [LOGS[1], LOGS[4], LOGS[5], LOGS[7], LOGS[8]]) {
      pipeline.ingest(trust.fortigate(N.parseFortiLog(l)), 'syslog');
    }
    const ch = pipeline.flush();
    for (const c of ch) ids.push(c.id);
    q.running = true; // hold the worker while we fill the queue
    for (const id of ids.slice(0, 4)) q.enqueue(id, false);
    assert.equal(q.queue.length, 3, 'queueMax');
    assert.equal(db.prepare('SELECT llm_state FROM items WHERE id = ?').get(ids[0]).llm_state, 'skipped', 'oldest automatic entry dropped');
    q.enqueue(ids[4], true);
    assert.equal(q.queue[0].id, ids[4], 'Explain jumps the queue');
    q.running = false;
    q.kick();
    await waitFor(() => !q.running && db.prepare("SELECT COUNT(*) AS n FROM llm_audit").get().n === 2, 5000);
    assert.equal(q.used(), 2);
    assert.ok(q.nextSlot() > Date.now() + 3500000, 'budget exhausted -> next slot in about an hour');
    assert.equal(db.prepare('SELECT llm_state FROM items WHERE id = ?').get(ids[1]).llm_state, 'skipped', 'Explain over a full queue drops the next oldest automatic entry');
    const done = db.prepare("SELECT * FROM items WHERE llm_state = 'done'").all();
    assert.equal(done.length, 3, 'the 3 queued items: 2 calls, batch 2');
    for (const r of done) {
      const v = JSON.parse(r.llm);
      assert.equal(r.severity, r.det_severity, 'benign verdict did not lower severity');
      assert.notEqual(v.classification, 'benign', 'guard overrode the manipulated "benign"');
      assert.ok(v.overridden.length >= 1);
    }
    // audit holds masked prompts only
    for (const a of db.prepare('SELECT messages FROM llm_audit').all()) assert.ok(!/198\.51\.100\.77|10\.50\.0\.10/.test(a.messages));
    q.stop();
  } finally { llm.server.close(); db.close(); }
});

test('LLM queue: an off-prem endpoint is refused per item without throwing', async () => {
  const { db, pipeline } = setup();
  pipeline.ingest(trust.fortigate(N.parseFortiLog(LOGS[1])), 'syslog');
  const [c] = pipeline.flush();
  const q = new LlmQueue({ db, cfg: { url: 'http://8.8.8.8:1/v1', model: 'm' }, pipeline });
  q.enqueue(c.id, true);
  await waitFor(() => db.prepare('SELECT llm_state FROM items WHERE id = ?').get(c.id).llm_state === 'error', 5000);
  assert.match(JSON.parse(db.prepare('SELECT llm FROM items WHERE id = ?').get(c.id).llm).error, /not on-prem.*llm\.allowRemote/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM llm_audit').get().n, 0, 'nothing was sent');
  q.stop(); db.close();
});
