#!/usr/bin/env node
'use strict';
/*
 * Demo lab: starts every mock and keeps them producing events, so a fresh board is live
 * without any real device. Used by `npm run demo` and the compose "demo" profile.
 *   node mocks/lab.js [--host 127.0.0.1] [--board-syslog 127.0.0.1:5514] [--backups ./demo-backups]
 * Ports: FortiGate 18443, Wazuh indexer 19200, Zabbix 18081, notification sinks 18090, LLM 11435.
 * Every mock is UNVERIFIED against real devices (see mocks/servers.js).
 */
const fs = require('node:fs');
const path = require('node:path');
const M = require('./servers.js');

const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : process.env[`LAB_${k.toUpperCase().replace(/-/g, '_')}`] || d; };
const host = opt('host', '127.0.0.1');
const [sysHost, sysPort] = opt('board-syslog', '127.0.0.1:5514').split(':');
const backups = path.resolve(opt('backups', './demo-backups'));

(async () => {
  const fgt = await M.mockFortigate({ port: 18443, host, token: 'demo-fgt-token' });
  const wz = await M.mockWazuh({ port: 19200, host, username: 'board_ro', password: 'demo-wazuh-pass' });
  const zbx = await M.mockZabbix({ port: 18081, host, token: 'demo-zabbix-token' });
  const sinks = await M.mockSinks({ port: 18090, host });
  const llm = await M.mockLlm({ port: 11435, host, mode: 'adversarial', delayMs: 1500 });
  fs.mkdirSync(backups, { recursive: true });
  fs.copyFileSync(path.join(__dirname, '..', 'samples/fgt-demo.conf'), path.join(backups, 'FGT-DEMO-CORE_20261106.conf'));
  console.log(`[lab] fortigate ${fgt.url} · wazuh ${wz.url} · zabbix ${zbx.url} · sinks ${sinks.url} (GET /_requests) · llm ${llm.url}`);
  console.log(`[lab] syslog -> ${sysHost}:${sysPort} · config backups in ${backups}`);

  const lines = fs.readFileSync(path.join(__dirname, '..', 'samples/fgt-logs.log'), 'utf8').split('\n').filter(Boolean);
  let i = 0;
  const tick = async () => {
    const batch = [lines[i++ % lines.length], lines[i++ % lines.length]];
    try { await M.sendSyslog(batch, { host: sysHost, port: Number(sysPort), proto: 'udp' }); } catch (e) { console.error(`[lab] syslog: ${e.message}`); }
  };
  setInterval(tick, 4000);
  setInterval(() => wz.add(1), 15000);
  setInterval(() => zbx.add(1), 25000);
  // a host that is not on the allowlist keeps trying (the board should count and drop it)
  setInterval(() => M.sendSyslog([lines[1]], { host: sysHost, port: Number(sysPort), proto: 'udp', localAddress: host === '127.0.0.1' ? '127.0.0.2' : undefined }).catch(() => {}), 10000);
  tick();
})();
