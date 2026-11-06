#!/usr/bin/env node
'use strict';
/*
 * NetSec Board admin CLI.
 *   node cli/board.js init [--config netsec.json]          first run: config file + admin user (password printed once)
 *   node cli/board.js user add <name> [--role viewer|operator|admin] [--password-file f]
 *   node cli/board.js user passwd <name> [--password-file f]
 *   node cli/board.js user list
 *   node cli/board.js pull <wazuh|zabbix|configdrop|fortigate>  one pull, for system cron / systemd timers
 *   node cli/board.js check                                 config, connectivity, on-prem class of every endpoint
 *   node cli/board.js test-notify <channel-name>
 *   node cli/board.js audit-export [--since 2026-11-01]     LLM audit trail as JSON lines (masked prompts only)
 * --config defaults to $NETSEC_CONFIG or ./netsec.json. Exit codes: 0 ok, 1 check found errors, 2 usage.
 */
const fs = require('node:fs');
const path = require('node:path');
const { loadConfig, literalSecrets } = require('../server/config.js');
const db_ = require('../server/db.js');
const A = require('../server/auth.js');
const { validEntry } = require('../server/collectors/syslog.js');

function args(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) { const k = a.slice(2); o[k] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true; } else o._.push(a);
  }
  return o;
}
const o = args(process.argv.slice(2));
const cfgFile = o.config || process.env.NETSEC_CONFIG || 'netsec.json';
const die = (m, code = 2) => { console.error(m); process.exit(code); };
const readPw = () => (o['password-file'] ? fs.readFileSync(o['password-file'], 'utf8').trim() : null);

async function main() {
  const [cmd, sub, name] = o._;
  if (cmd === 'init') {
    if (!fs.existsSync(cfgFile)) {
      fs.copyFileSync(path.join(__dirname, '..', 'netsec.example.json'), cfgFile);
      fs.chmodSync(cfgFile, 0o600);
      console.log(`wrote ${cfgFile} (every source is off; edit it, then run "check")`);
    } else console.log(`${cfgFile} exists, kept`);
    const { cfg } = loadConfig(cfgFile);
    const db = db_.openDb(cfg.dataDir);
    const n = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
    if (!n) {
      const pw = readPw() || A.randomPassword();
      A.addUser(db, o.admin || 'admin', pw, 'admin');
      console.log(`created admin user "${o.admin || 'admin'}"${o['password-file'] ? '' : ` with password: ${pw}\n(shown once; change it with: node cli/board.js user passwd ${o.admin || 'admin'})`}`);
    } else console.log(`${n} user(s) exist, no user created`);
    console.log(`database: ${db.file}`);
    db.close();
    return;
  }

  if (!fs.existsSync(cfgFile)) die(`no config ${cfgFile}: run "node cli/board.js init" first`);
  const loaded = loadConfig(cfgFile);
  const { cfg } = loaded;

  if (cmd === 'user') {
    const db = db_.openDb(cfg.dataDir);
    if (sub === 'list') { for (const u of db.prepare('SELECT username, role, created FROM users ORDER BY id').all()) console.log(`${u.username}\t${u.role}\t${u.created}`); return; }
    if (!name) die('usage: user add|passwd <name>');
    const pw = readPw() || A.randomPassword();
    if (sub === 'add') A.addUser(db, name, pw, o.role || 'viewer');
    else if (sub === 'passwd') A.setPassword(db, name, pw);
    else die('usage: user add|passwd|list');
    db_.logAction(db, 'cli', `user ${sub}`, null, name);
    console.log(o['password-file'] ? `ok: ${name}` : `ok: ${name}, password: ${pw} (shown once)`);
    return;
  }

  if (cmd === 'pull') {
    const { createApp, PULLERS } = require('../server/main.js');
    if (!PULLERS[sub]) die(`usage: pull <${Object.keys(PULLERS).join('|')}>`);
    // the scheduler takes <dataDir>/pull-<source>.lock (shared with the server's runs and "Pull now"),
    // and releases it before we exit: a failed pull must not leave it behind
    const app = await createApp(loaded, { listen: false, startSources: false, jitter: false, batchMs: -1, role: 'cli' });
    if (!app.scheduler.jobs.has(sub)) { await app.close(); die(`source ${sub} is not enabled in ${cfgFile}`); }
    let r;
    try { r = await app.scheduler.run(sub); await app.notifier.idle(); } finally { await app.close(); }
    if (r.skipped) { console.log(`pull ${sub}: already running, skipped`); return; }
    if (!r.ok) die(`pull ${sub} failed: ${r.error}`, 1);
    console.log(`pull ${sub}: ${r.n} event(s)`);
    return;
  }

  if (cmd === 'test-notify') {
    const { Notifier } = require('../server/notify.js');
    const db = db_.openDb(cfg.dataDir);
    await new Notifier({ db, cfg }).test(sub);
    console.log(`sent a test message to ${sub}`);
    return;
  }

  if (cmd === 'audit-export') {
    const db = db_.openDb(cfg.dataDir);
    const since = o.since ? Date.parse(o.since) : 0;
    for (const r of db.prepare('SELECT * FROM llm_audit WHERE ts >= ? ORDER BY id').all(since)) {
      process.stdout.write(`${JSON.stringify({ ...r, ts: new Date(r.ts).toISOString(), item_ids: JSON.parse(r.item_ids || '[]'), overrides: JSON.parse(r.overrides || '[]'), messages: JSON.parse(r.messages || '[]') })}\n`);
    }
    return;
  }

  if (cmd === 'check') return check(loaded);
  die('usage: board.js init|user|pull|check|test-notify|audit-export (see the header of cli/board.js)');
}

async function check({ cfg, raw }) {
  const LLM = require('../server/llm.js');
  const PULL = require('../server/collectors/pull.js');
  const { request } = require('../server/net.js');
  const { channelConfig, lineQuota } = require('../server/notify.js');
  let errors = 0;
  const ok = (m) => console.log(`  ok    ${m}`);
  const warn = (m) => console.log(`  WARN  ${m}`);
  const err = (m) => { errors++; console.log(`  ERROR ${m}`); };
  const cls = async (u) => { try { const c = await LLM.classifyUrl(u); return c.cls; } catch (e) { return `unresolved (${e.message})`; } };

  console.log(`config ${cfgFile}`);
  for (const p of literalSecrets(raw)) warn(`${p} is a literal secret in the file; use "env:NAME" or "file:/run/secrets/x"`);
  const lc = await cls(`http://${cfg.listen.host}`);
  if (lc !== 'loopback' && !cfg.cookieSecure) warn(`board listens on ${cfg.listen.host} (${lc}) without cookieSecure: put it behind TLS (deploy/Caddyfile.example) and set "cookieSecure": true`);
  else ok(`board listens on ${cfg.listen.host}:${cfg.listen.port} (${lc})`);
  if (/^https:/i.test(cfg.publicUrl || '') && !/\.example\./.test(cfg.publicUrl) && !cfg.trustProxy) warn('publicUrl is https but trustProxy is off: behind a proxy every client shares its address, so 5 failed logins by anyone slow down everyone. Set "trustProxy": true (proxy on this host) or a list of proxy addresses');
  if (Array.isArray(cfg.trustProxy)) {
    const bad = cfg.trustProxy.filter((a) => !validEntry(a));
    if (bad.length) err(`trustProxy: cannot parse ${bad.join(', ')} (use IPs or CIDRs such as 10.0.0.5, 172.16.0.0/12, fd00::/8)`);
  }
  if (cfg.trustProxy === true) ok('trustProxy: X-Forwarded-For is honoured only from 127.0.0.1/::1 (list the proxy addresses if the proxy runs elsewhere)');
  const db = db_.openDb(cfg.dataDir);
  ok(`database ${db.file} (mode ${(fs.statSync(db.file).mode & 0o777).toString(8)}, retention ${cfg.retentionDays} days)`);
  if (!db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get().n) err('no admin user: run "init"');

  console.log('sources');
  const s = cfg.sources;
  if (s.syslog.enabled) {
    if (!s.syslog.allow.length) err('syslog: allowlist is empty, every sender is dropped (sources.syslog.allow)');
    const badAllow = s.syslog.allow.filter((a) => !validEntry(a));
    if (badAllow.length) err(`syslog: allowlist entries that never match: ${badAllow.join(', ')} (use IPs or CIDRs)`);
    else ok(`syslog on ${s.syslog.bind}:${s.syslog.port} ${s.syslog.tcp !== false ? 'tcp' : ''}${s.syslog.udp !== false ? '+udp' : ''}, allow ${s.syslog.allow.join(', ')}`);
    const st = db_.sourceState(db, 'syslog');
    if (st.unsupported) err(`syslog: ${st.unsupported} message(s) in CSV/CEF format. On the FortiGate: config log syslogd setting / set format rfc5424 (or default)`);
    if (s.syslog.udp !== false) warn('syslog: UDP has no delivery guarantee and its source address can be forged, so the allowlist cannot stop a spoofer on the path. Use FortiGate "set mode reliable" (TCP) and set "udp": false');
  }
  if (s.wazuh.enabled) {
    try {
      const r = await request(`${s.wazuh.url.replace(/\/+$/, '')}/${s.wazuh.index}/_search`, { body: { size: 0 }, basic: { username: s.wazuh.username, password: s.wazuh.password }, caFile: s.wazuh.caFile || undefined });
      if (r.status === 200) ok(`wazuh indexer ${new URL(s.wazuh.url).host} (${await cls(s.wazuh.url)}): ${r.json && r.json.hits ? JSON.stringify(r.json.hits.total) : '?'} alerts`);
      else err(`wazuh indexer HTTP ${r.status}: the user needs read on ${s.wazuh.index} (role: cluster_composite_ops_ro + index read)`);
    } catch (e) { err(`wazuh: ${e.message}`); }
  }
  if (s.zabbix.enabled) {
    try {
      const r = await PULL.checkZabbix(s.zabbix);
      if (r.ok) ok(`zabbix ${r.version} at ${new URL(s.zabbix.url).host} (${await cls(s.zabbix.url)}): token accepted`);
      else err(`zabbix ${r.version}: ${r.error}${r.hint ? `\n        ${r.hint}` : ''}`);
    } catch (e) { err(`zabbix: ${e.message}`); }
  }
  if (s.configdrop.enabled) {
    if (!fs.existsSync(s.configdrop.dir)) err(`configdrop: folder ${s.configdrop.dir} not found`);
    else ok(`configdrop ${s.configdrop.dir}: ${fs.readdirSync(s.configdrop.dir).filter((f) => /\.(conf|cfg|txt)$/i.test(f)).length} backup file(s)`);
  }
  if (s.fortigate.enabled) {
    warn('fortigate REST backup needs an API admin with config read/write (or super_admin). The file-drop collector needs no device privilege.');
    try {
      const r = await request(`${s.fortigate.url.replace(/\/+$/, '')}/api/v2/monitor/system/status`, { headers: { authorization: `Bearer ${s.fortigate.token}` }, caFile: s.fortigate.caFile || undefined });
      if (r.status === 200) ok(`fortigate ${(r.json && r.json.version) || ''} at ${new URL(s.fortigate.url).host} (${await cls(s.fortigate.url)})${/v?7\.(6|[7-9])/.test((r.json && r.json.version) || '') ? ': 7.6+, backup uses POST' : ''}`);
      else err(`fortigate HTTP ${r.status}`);
    } catch (e) { err(`fortigate: ${e.message}`); }
  }
  for (const h of ['zabbix', 'wazuh', 'generic']) if (cfg.hooks[h] && cfg.hooks[h].token) ok(`hook /hooks/${h} enabled (Bearer token)`);
  for (const h of ['zabbix', 'wazuh']) {
    if (cfg.hooks[h] && cfg.hooks[h].token && s[h].enabled && s[h].schedule !== 'external') warn(`${h}: both the pull (sources.${h}) and the push hook (hooks.${h}) are on, so every event is counted twice. Use one per source.`);
  }

  console.log('notifications');
  for (const c of (cfg.notify.channels || []).map(channelConfig)) {
    if (!c.enabled) continue;
    const target = c.url || (c.type === 'telegram' ? c.apiBase || 'https://api.telegram.org' : c.type === 'line' ? c.apiBase || 'https://api.line.me' : '');
    const where = target ? await cls(target) : '?';
    const line = `${c.name} (${c.type}) -> ${target ? new URL(target).host : '?'} [${where}], min ${c.minSeverity}, ${c.mode}${c.cloud ? ', masked text only' : ''}`;
    if (where === 'remote' && !c.cloud) warn(`${line}: remote host but cloud=false sends unmasked titles`);
    else ok(line);
    if (c.type === 'line') {
      try { const q = await lineQuota(c); ok(`  LINE quota ${JSON.stringify(q.quota)}, used this month ${q.used}`); } catch (e) { warn(`  LINE quota check failed: ${e.message}`); }
    }
  }

  console.log('llm');
  if (!cfg.llm || !cfg.llm.url) ok('off (the board works fully without it)');
  else {
    try {
      const r = await LLM.checkEndpoint(cfg.llm.url, { allowRemote: !!cfg.llm.allowRemote, allowHttpLan: !!cfg.llm.allowHttpLan, remoteHint: 'llm.allowRemote', httpHint: 'llm.allowHttpLan' });
      ok(`${cfg.llm.model} at ${new URL(cfg.llm.url).host}: ${r.endpoint_class}${r.endpoint_overrides.length ? ` (overrides: ${r.endpoint_overrides.join(', ')})` : ''}, budget ${cfg.llm.budgetPerHour ?? 4}/h`);
    } catch (e) { err(e.message); }
  }
  db.close();
  console.log(errors ? `\n${errors} error(s)` : '\nno errors');
  process.exitCode = errors ? 1 : 0;
}

main().catch((e) => die(e.message, 1));
