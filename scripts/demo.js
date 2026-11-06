#!/usr/bin/env node
'use strict';
/*
 * One-command demo: mocks + board, all on 127.0.0.1.
 *   npm run demo   ->  open http://127.0.0.1:8480  (admin / demo-admin-pass, viewer / demo-viewer-pass)
 * Mock-only secrets; never reuse them.
 */
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
Object.assign(process.env, {
  DEMO_WAZUH_PASSWORD: 'demo-wazuh-pass', DEMO_ZABBIX_TOKEN: 'demo-zabbix-token', DEMO_FGT_TOKEN: 'demo-fgt-token',
  DEMO_LINE_TOKEN: 'demo-line-token', DEMO_HOOK_TOKEN: 'demo-hook-token',
});
process.chdir(ROOT);
const lab = spawn(process.execPath, ['mocks/lab.js', '--backups', './demo-backups'], { stdio: 'inherit' });
const { loadConfig } = require('../server/config.js');
const { createApp } = require('../server/main.js');
const db_ = require('../server/db.js');
const A = require('../server/auth.js');

(async () => {
  await new Promise((r) => setTimeout(r, 600));
  const loaded = loadConfig(process.env.DEMO_CONFIG || 'netsec.demo.json');
  const db = db_.openDb(loaded.cfg.dataDir);
  if (!db.prepare('SELECT 1 FROM users WHERE username = ?').get('admin')) A.addUser(db, 'admin', 'demo-admin-pass', 'admin');
  if (!db.prepare('SELECT 1 FROM users WHERE username = ?').get('viewer')) A.addUser(db, 'viewer', 'demo-viewer-pass', 'viewer');
  db.close();
  const app = await createApp(loaded);
  console.log(`[demo] board on ${app.url}  (admin / demo-admin-pass, viewer / demo-viewer-pass)`);
  const stop = async () => { lab.kill(); await app.close(); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
})().catch((e) => { console.error(e); lab.kill(); process.exit(1); });
