#!/usr/bin/env node
'use strict';
/*
 * Smoke test for a running demo board (Docker or `npm run demo`):
 *   node scripts/smoke.js http://127.0.0.1:8480
 * Logs in as the demo admin and waits until cards from syslog, Wazuh, Zabbix and the
 * config file-drop are on the board and a spoofed syslog sender has been dropped.
 * SMOKE_LOGIN_ONLY=1: only check /healthz, login and the API (production with sources off).
 */
const base = (process.argv[2] || 'http://127.0.0.1:8480').replace(/\/+$/, '');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  for (let i = 0; ; i++) {
    try { if ((await fetch(`${base}/healthz`)).ok) break; } catch { /* not up yet */ }
    if (i > 60) throw new Error('/healthz not ready after 120 s');
    await sleep(2000);
  }
  const r = await fetch(`${base}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: process.env.DEMO_ADMIN_PASSWORD || 'demo-admin-pass' }) });
  if (r.status !== 200) throw new Error(`login HTTP ${r.status}`);
  const cookie = r.headers.get('set-cookie').split(';')[0];
  const get = async (p) => (await fetch(base + p, { headers: { cookie } })).json();
  if (process.env.SMOKE_LOGIN_ONLY) { // production config with every source off: reachable + login + API
    const sum = await get('/api/summary');
    console.log(`ok: login works, ${sum.sources.filter((x) => x.enabled).length} source(s) enabled, open ${JSON.stringify(sum.counts)}`);
    return;
  }
  const want = ['fortigate', 'wazuh', 'zabbix', 'configdrop'];
  let missing = want, sum = null;
  for (let i = 0; i < 45; i++) {
    const { items } = await get('/api/items');
    sum = await get('/api/summary');
    const have = new Set(items.map((x) => x.source));
    missing = want.filter((s) => !have.has(s));
    const syslog = sum.sources.find((s) => s.name === 'syslog');
    if (!missing.length && (syslog.dropped > 0 || process.env.SMOKE_NO_SPOOF)) {
      console.log(`ok: ${items.length} items from ${[...have].join(', ')}; open ${JSON.stringify(sum.counts)}; syslog dropped ${syslog.dropped}; LLM ${sum.llm.enabled ? `${sum.llm.used}/${sum.llm.budgetPerHour}` : 'off'}`);
      return;
    }
    await sleep(2000);
  }
  throw new Error(`not live after 90 s: missing ${missing.join(', ') || '-'}; sources ${JSON.stringify(sum && sum.sources.map((s) => [s.name, s.status, s.lastError]))}`);
})().catch((e) => { console.error(`smoke: ${e.message}`); process.exit(1); });
