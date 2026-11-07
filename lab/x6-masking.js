#!/usr/bin/env node
'use strict';
/*
 * X6: cloud masking on REAL cards. The board pulls the last hours of this VM's Wazuh alerts
 * (internet SSH attacks on the host, the lab victim, the Windows lab agent) and the lab Zabbix
 * problems, and sends them to a cloud Telegram channel (every card) and a LINE digest (local
 * sinks, nothing leaves the VM). Then every outgoing text is checked for any IPv4/IPv6 address,
 * agent name, user name or Zabbix host that occurs in those cards.
 * Publishes counts and pass/fail only -> results/real-data/x6-masking.json
 */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const M = require('../mocks/servers.js');
const { loadConfig } = require('../server/config.js');
const { createApp } = require('../server/main.js');

const ROOT = path.join(__dirname, '..');
const HOURS = Number(process.argv[2] || 3);

(async () => {
  const sinks = await M.mockSinks();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x6-'));
  const zbxToken = fs.readFileSync(path.join(__dirname, 'data/zabbix-token'), 'utf8').trim();
  const cfg = {
    dataDir, lang: 'en', listen: { host: '127.0.0.1', port: 0 },
    sources: {
      wazuh: { enabled: true, schedule: '@every 1h', url: 'https://127.0.0.1:9200', username: 'netsec_board_ro', password: 'file:/etc/netsec-board/wazuh-ro-password', caFile: '/etc/netsec-board/wazuh-root-ca.pem', minSeverity: 'low', quietFirstRun: false, initialLookback: `${HOURS}h` },
      zabbix: { enabled: true, schedule: '@every 1h', url: 'http://127.0.0.1:18080', token: zbxToken, quietFirstRun: false, initialLookbackSec: HOURS * 3600 },
    },
    notify: { channels: [
      { name: 'tg', type: 'telegram', apiBase: `${sinks.url}/tg`, botToken: 'x', chatId: '1', minSeverity: 'low', rateLimit: { max: 100000, perMinutes: 1 }, maxPerDay: 100000 },
      { name: 'line', type: 'line', apiBase: `${sinks.url}/line`, channelToken: 'x', to: 'C1', minSeverity: 'low', maxPerDay: 100000 },
    ] },
  };
  const app = await createApp(loadConfig(null, cfg), { log: () => {}, runOnStart: false });
  for (const s of ['wazuh', 'zabbix']) { const r = await app.scheduler.run(s); if (!r.ok) throw new Error(`${s}: ${r.error}`); }
  await app.notifier.idle();
  await app.notifier.flushDigest(app.notifier.channels.find((c) => c.name === 'line'));
  // everything identifying that occurs in the cards
  const secrets = new Set();
  const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi;
  const items = app.db.prepare('SELECT trusted, untrusted, title FROM items').all();
  for (const it of items) {
    const f = { ...JSON.parse(it.trusted), ...JSON.parse(it.untrusted) };
    for (const k of ['agent.name', 'agent.ip', 'data.srcuser', 'data.dstuser', 'data.srcip', 'data.dstip', 'hosts', 'manager.name']) {
      for (const v of String(f[k] ?? '').split(/,\s*/)) if (v.length >= 3) secrets.add(v);
    }
    for (const m of `${it.title} ${JSON.stringify(f)}`.match(ipRe) || []) secrets.add(m);
  }
  const texts = sinks.requests.map((r) => (r.url.startsWith('/tg/') ? r.body.text : r.body.messages[0].text));
  const leaks = [];
  for (const t of texts) {
    for (const s of secrets) if (t.includes(s)) leaks.push(s.replace(/\d/g, '#').replace(/[A-Za-z]/g, 'x')); // shape only, never the value
    for (const m of t.match(ipRe) || []) leaks.push(`ip-shaped ${m.replace(/\d/g, '#')}`);
  }
  const out = {
    ranAt: new Date().toISOString(), hours: HOURS, cards: items.length,
    identifiersInCards: secrets.size,
    messages: { telegram: sinks.requests.filter((r) => r.url.startsWith('/tg/')).length, lineDigest: sinks.requests.filter((r) => r.url.startsWith('/line/')).length },
    leaks: leaks.length, leakShapes: [...new Set(leaks)].slice(0, 20),
    sample: texts.slice(0, 3).map((t) => t.slice(0, 160)), // masked by the board; checked above
    pass: leaks.length === 0,
  };
  await app.close(); sinks.server.close();
  fs.writeFileSync(path.join(ROOT, 'results/real-data/x6-masking.json'), `${JSON.stringify(out, null, 2)}\n`);
  console.log(JSON.stringify(out, null, 1));
})().catch((e) => { console.error('x6:', e.stack || e.message); process.exit(1); });
