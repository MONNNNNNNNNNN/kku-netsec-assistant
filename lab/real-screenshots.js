#!/usr/bin/env node
'use strict';
/*
 * Screenshots of the board on REAL data, safe to publish (docs/screenshots/real-*.png):
 *  - this VM's real Wazuh alerts (internet SSH attacks, the lab victim, the Windows lab agent):
 *    every IP, FQDN and e-mail is replaced by core.mask tokens, and user/agent/host names by
 *    USER_n / HOSTNAME_n, BEFORE they reach the board (nothing real is rendered)
 *  - real FortiGate lines from BOTSv1 (CC0 1.0) as they are
 *  - a real Zabbix 7.0 problem from the lab (our own host names)
 *   node lab/real-screenshots.js        (Wazuh read-only user + lab Zabbix as in lab/README.md)
 */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const zlib = require('node:zlib');
const readline = require('node:readline');
const { chromium } = require('playwright');
const N = require('../src/core.js');
const T = require('../server/trust.js');
const A = require('../server/auth.js');
const { requestOk } = require('../server/net.js');
const { loadConfig } = require('../server/config.js');
const { createApp } = require('../server/main.js');
const { pullZabbix } = require('../server/collectors/pull.js');

const ROOT = path.join(__dirname, '..');
const SHOTS = path.join(ROOT, 'docs/screenshots');
const NAME_KEYS = ['agent.name', 'manager.name', 'predecoder.hostname', 'data.srcuser', 'data.dstuser', 'data.win.eventdata.targetUserName', 'data.win.eventdata.subjectUserName', 'data.win.system.computer'];

/** Mask a whole alert: collect names first, replace them everywhere, then core.mask IPs/FQDNs/e-mails. */
function maskAlerts(alerts) {
  const st = N.newMaskState();
  const names = new Map();
  const flat = (o, p = '', out = {}) => { for (const [k, v] of Object.entries(o || {})) { const key = p ? `${p}.${k}` : k; if (v && typeof v === 'object' && !Array.isArray(v)) flat(v, key, out); else out[key] = v; } return out; };
  for (const a of alerts) {
    const f = flat(a);
    for (const k of NAME_KEYS) {
      const v = String(f[k] ?? '').trim();
      if (v.length >= 2 && !names.has(v)) names.set(v, `${/user/i.test(k) ? 'USER' : 'HOSTNAME'}_${names.size + 1}`);
    }
  }
  const order = [...names.keys()].sort((a, b) => b.length - a.length);
  const esc = (v) => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const scrub = (s) => { let t = s; for (const v of order) t = t.replace(new RegExp(`(?<![A-Za-z0-9])${esc(v)}(?![A-Za-z0-9])`, 'g'), names.get(v)); return N.mask(t, st).text; };
  const walk = (o) => (Array.isArray(o) ? o.map(walk) : o && typeof o === 'object' ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, walk(v)])) : typeof o === 'string' ? scrub(o) : o);
  return alerts.map(walk);
}

(async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-shots-'));
  const loaded = loadConfig(null, { dataDir, lang: 'en', listen: { host: '127.0.0.1', port: 0 }, llm: { url: 'http://127.0.0.1:11434/v1', model: 'qwen2.5:3b-instruct' } }, {});
  const db0 = require('../server/db.js').openDb(dataDir);
  A.addUser(db0, 'noc', 'screenshot-pass-1', 'operator'); db0.close();
  const app = await createApp(loaded, { log: () => {}, runOnStart: false });

  // 1. real Wazuh alerts, masked before ingest
  const pw = fs.readFileSync('/etc/netsec-board/wazuh-ro-password', 'utf8').trim();
  const r = await requestOk('https://127.0.0.1:9200/wazuh-alerts-*/_search', { body: { size: 400, sort: [{ timestamp: { order: 'desc' } }], query: { range: { 'rule.level': { gte: 4 } } } }, basic: { username: 'netsec_board_ro', password: pw }, caFile: '/etc/netsec-board/wazuh-root-ca.pem', timeoutMs: 60000 });
  const hits = r.json.hits.hits;
  // GeoIP enrichment: keep country/city, drop the coordinates
  const masked = maskAlerts(hits.map((h) => { const a = h._source; if (a.GeoLocation) delete a.GeoLocation.location; return a; }));
  masked.forEach((a, i) => app.pipeline.ingest(T.wazuh(a, `m${i}`), 'wazuh'));
  // 2. BOTSv1 FortiGate (CC0) as is: Cerber C2, IPS, a config change
  const want = { cerber: 1, ips: 2, config: 1 };
  for (const f of ['botsv1.fgt_utm.json.gz', 'botsv1.fgt_event.json.gz']) {
    for await (const l of readline.createInterface({ input: fs.createReadStream(path.join(__dirname, 'botsv1', f)).pipe(zlib.createGunzip()) })) {
      const x = l && JSON.parse(l).result; if (!x || !x._raw) continue;
      const line = x._raw.replace(/^[A-Z][a-z]{2} [ \d]?\d \d\d:\d\d:\d\d \S+ /, '');
      const p = N.parseFortiLog(line);
      const k = /Cerber/.test(p.app || '') ? 'cerber' : p.subtype === 'ips' && /critical|high/.test(p.severity || '') ? 'ips' : p.logdesc === 'Configuration changed' ? 'config' : null;
      if (!k || !want[k]) continue;
      want[k]--; app.pipeline.ingest(T.fortigate(p, Date.now()), 'syslog');
    }
  }
  // 3. a real Zabbix problem (lab host names are ours)
  try { const z = await pullZabbix({ url: 'http://127.0.0.1:18080', token: fs.readFileSync(path.join(__dirname, 'data/zabbix-token'), 'utf8').trim(), initialLookbackSec: 86400 }, null); z.events.forEach((e) => app.pipeline.ingest(e, 'zabbix')); } catch { /* lab Zabbix down: skip */ }
  app.pipeline.flush();

  const browser = await chromium.launch();
  const page = await (await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light' })).newPage();
  await page.goto(app.url);
  await page.fill('#u', 'noc'); await page.fill('#p', 'screenshot-pass-1'); await page.click('button[type=submit]');
  await page.waitForSelector('.tile.hero'); await page.waitForTimeout(800);
  fs.mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: path.join(SHOTS, 'real-board.png') });
  let card = page.locator('#app .card', { hasText: 'sshd' }).first();
  if (!(await card.count())) card = page.locator('#app .card', { hasText: 'wazuh' }).first();
  if (await card.count()) { await card.locator('button[aria-expanded]').click(); await page.waitForTimeout(400); await card.scrollIntoViewIfNeeded(); await page.screenshot({ path: path.join(SHOTS, 'real-card.png') }); }
  // privacy check of what the page shows: no IPv4 outside documentation/private lab ranges and BOTSv1
  const text = await page.evaluate(() => document.body.innerText);
  const ips = [...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])];
  await browser.close(); await app.close();
  console.log(JSON.stringify({ wazuhAlerts: hits.length, ipsVisible: ips }, null, 1));
})().catch((e) => { console.error('shots:', e.stack || e.message); process.exit(1); });
