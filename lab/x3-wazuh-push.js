#!/usr/bin/env node
'use strict';
/*
 * X3: the REAL Wazuh integration (deploy/custom-netsec-board.py, installed by
 * lab/wazuh-prepare.sh --push-hook: level >= 7 alerts -> POST http://127.0.0.1:8480/hooks/wazuh)
 * into a board on 127.0.0.1:8480, while lab/attack.sh attacks the lab victim (an agent of this
 * VM's manager). Measures alert -> card latency, cards per rule, the brute-force grouping and
 * prompt-injection flags. Aggregates only -> results/real-data/x3-wazuh-push.json
 */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { loadConfig } = require('../server/config.js');
const { createApp } = require('../server/main.js');

const ROOT = path.join(__dirname, '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-x3-'));
  const loaded = loadConfig(null, { dataDir, lang: 'en', listen: { host: '127.0.0.1', port: 8480 }, hooks: { wazuh: { token: 'file:/etc/netsec-board/wazuh-hook-token' } }, sources: { wazuh: { minSeverity: 'low' } } });
  const app = await createApp(loaded, { log: () => {}, runOnStart: false });
  const seenAt = new Map();
  const poll = setInterval(() => { for (const r of app.db.prepare('SELECT id, first_seen FROM items').all()) if (!seenAt.has(r.id)) seenAt.set(r.id, { at: Date.now(), firstSeen: r.first_seen }); }, 250);
  const t0 = Date.now();
  // async: the board in this process must keep serving the integration while the attack runs
  // (spawnSync blocked its event loop for minutes and the integration's posts timed out)
  const attack = await new Promise((resolve) => { const p = spawn('sh', [path.join(__dirname, 'attack.sh'), process.env.SSH_N || '100', '50'], { stdio: 'ignore' }); p.on('close', (status) => resolve({ status })); });
  // Wazuh's frequency rules (e.g. 5712 brute force) and integratord need a little time
  for (let i = 0; i < 90; i++) { await sleep(1000); if (Date.now() - t0 > 60000 && i > 30) break; }
  clearInterval(poll);
  const items = app.db.prepare("SELECT id, title, count, severity, flags, samples, trusted, untrusted FROM items WHERE source = 'wazuh'").all();
  const lab = items.filter((i) => JSON.parse(i.trusted)['agent.name'] === 'lab-victim');
  const lat = lab.map((i) => seenAt.get(i.id)).filter(Boolean).map((s) => s.at - s.firstSeen).sort((a, b) => a - b);
  const out = {
    ranAt: new Date().toISOString(), attackExit: attack.status,
    hookReceived: app.db.prepare("SELECT received, dropped FROM source_state WHERE source = 'hook:wazuh'").get() || null,
    window: { from: new Date(t0).toISOString(), to: new Date().toISOString() },
    cards: items.length, labCards: lab.length, hostCards: items.length - lab.length,
    alertToCardMs: lat.length ? { min: lat[0], median: lat[Math.floor(lat.length / 2)], max: lat[lat.length - 1] } : null,
    allCards: items.map((i) => { const t = JSON.parse(i.trusted); return { agent: t['agent.name'] === 'lab-victim' ? 'lab-victim' : t['agent.id'] === '000' ? 'manager-host' : 'other', rule: t['rule.id'], level: t['rule.level'], count: i.count }; }),
    labByRule: lab.map((i) => { const t = JSON.parse(i.trusted); return { rule: t['rule.id'], level: t['rule.level'], title: i.title.replace(/ \(.*\)$/, ''), count: i.count, severity: i.severity, samples: JSON.parse(i.samples).length, flags: JSON.parse(i.flags) }; }),
  };
  // push completeness: what the manager raised at level >= 7 in the window (indexer, via Filebeat)
  // vs what the hook accepted; give Filebeat time to ship the last alerts
  await sleep(45000);
  const { requestOk } = require('../server/net.js');
  const pw = fs.readFileSync('/etc/netsec-board/wazuh-ro-password', 'utf8').trim();
  const cnt = async (extra) => (await requestOk('https://127.0.0.1:9200/wazuh-alerts-*/_count', { body: { query: { bool: { filter: [{ range: { timestamp: { gte: t0, lte: Date.parse(out.window.to), format: 'epoch_millis' } } }, { range: { 'rule.level': { gte: 7 } } }, ...extra] } } }, basic: { username: 'netsec_board_ro', password: pw }, caFile: '/etc/netsec-board/wazuh-root-ca.pem' })).json.count;
  out.pushCompleteness = { indexerLevel7plus: await cnt([]), indexerLabLevel7plus: await cnt([{ term: { 'agent.name': 'lab-victim' } }]), hookAccepted: out.hookReceived && out.hookReceived.received, hookRateLimited: out.hookReceived && out.hookReceived.dropped };
  await app.close();
  fs.writeFileSync(path.join(ROOT, 'results/real-data/x3-wazuh-push.json'), `${JSON.stringify(out, null, 2)}\n`);
  console.log(JSON.stringify(out, null, 1));
})().catch((e) => { console.error('x3:', e.stack || e.message); process.exit(1); });
