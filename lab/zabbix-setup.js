#!/usr/bin/env node
'use strict';
/*
 * Configure the lab Zabbix 7.0 through its real JSON-RPC API (run after `docker compose -f
 * lab/compose.yaml up -d zbx-db zbx-server zbx-web zbx-agent zbx-strip`):
 *   - Admin password replaced (the default "zabbix" never stays), saved to lab/data (0600)
 *   - a read-only user "netsec_board" (User role, read on one host group) and its API token
 *   - host "lab-agent" with item vfs.file.exists[/tmp/netsec-fail] and a High trigger on it
 *   - the REAL deploy/zabbix-media-webhook.js as a webhook media type, Admin media, an action
 *     (problem + recovery) posting to the board-hook container
 *   - lab/data/board-hook.json for that board (webhook only)
 * Idempotent: objects that exist are reused.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const API = process.env.ZBX_API || 'http://127.0.0.1:18080/api_jsonrpc.php';
const DATA = path.join(__dirname, 'data');
const ROOT = path.join(__dirname, '..');
fs.mkdirSync(DATA, { recursive: true });
const save = (f, v) => { fs.writeFileSync(path.join(DATA, f), v, { mode: 0o600 }); fs.chmodSync(path.join(DATA, f), 0o600); };
const load = (f) => { try { return fs.readFileSync(path.join(DATA, f), 'utf8').trim(); } catch { return null; } };
const pw = () => `${crypto.randomBytes(15).toString('base64url')}-Aa1`;

let auth = null;
async function rpc(method, params, useAuth = true) {
  const r = await fetch(API, { method: 'POST', headers: { 'content-type': 'application/json-rpc', ...(useAuth && auth ? { authorization: `Bearer ${auth}` } : {}) }, body: JSON.stringify({ jsonrpc: '2.0', method, params, id: 1 }) });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${j.error.message} ${j.error.data || ''}`);
  return j.result;
}

(async () => {
  // wait for the frontend + database schema
  let version;
  for (let i = 0; i < 90; i++) { try { version = await rpc('apiinfo.version', {}, false); break; } catch { await new Promise((r) => setTimeout(r, 2000)); } }
  if (!version) throw new Error('Zabbix API did not come up');
  console.log(`Zabbix API ${version}`);

  // 1. Admin: default password once, then a random one
  let adminPw = load('zabbix-admin-password');
  try { auth = await rpc('user.login', { username: 'Admin', password: adminPw || 'zabbix' }, false); } catch (e) {
    if (adminPw) throw e;
    throw new Error(`login failed: ${e.message}`);
  }
  const admin = (await rpc('user.get', { filter: { username: 'Admin' }, output: ['userid'] }))[0];
  if (!adminPw) {
    adminPw = pw();
    await rpc('user.update', { userid: admin.userid, current_passwd: 'zabbix', passwd: adminPw });
    save('zabbix-admin-password', adminPw);
    auth = await rpc('user.login', { username: 'Admin', password: adminPw }, false);
    console.log('Admin password replaced (lab/data/zabbix-admin-password)');
  }

  // 2. host group, host, item, trigger
  const group = (await rpc('hostgroup.get', { filter: { name: 'NetSec lab' }, output: ['groupid'] }))[0] || { groupid: (await rpc('hostgroup.create', { name: 'NetSec lab' })).groupids[0] };
  let host = (await rpc('host.get', { filter: { host: 'lab-agent' }, output: ['hostid'], selectInterfaces: ['interfaceid'] }))[0];
  if (!host) {
    const hostid = (await rpc('host.create', { host: 'lab-agent', name: 'Lab agent', groups: [{ groupid: group.groupid }], interfaces: [{ type: 1, main: 1, useip: 0, ip: '', dns: 'zbx-agent', port: '10050' }] })).hostids[0];
    host = (await rpc('host.get', { hostids: hostid, output: ['hostid'], selectInterfaces: ['interfaceid'] }))[0];
  }
  const key = 'vfs.file.exists[/tmp/netsec-fail]';
  if (!(await rpc('item.get', { hostids: host.hostid, filter: { key_: key }, output: ['itemid'] })).length) {
    await rpc('item.create', { hostid: host.hostid, interfaceid: host.interfaces[0].interfaceid, name: 'NetSec lab fail flag', key_: key, type: 0, value_type: 3, delay: '5s' });
  }
  if (!(await rpc('trigger.get', { hostids: host.hostid, output: ['triggerid'] })).length) {
    await rpc('trigger.create', { description: 'NetSec lab: fail flag set on {HOST.NAME}', expression: `last(/lab-agent/${key})=1`, priority: 4 });
  }
  console.log('host lab-agent, item and trigger ready');

  // 3. read-only API user + token for the board
  const role = (await rpc('role.get', { filter: { name: 'User role' }, output: ['roleid'] }))[0];
  const ug = (await rpc('usergroup.get', { filter: { name: 'netsec-ro' }, output: ['usrgrpid'] }))[0] || { usrgrpid: (await rpc('usergroup.create', { name: 'netsec-ro', hostgroup_rights: [{ id: group.groupid, permission: 2 }] })).usrgrpids[0] };
  let ro = (await rpc('user.get', { filter: { username: 'netsec_board' }, output: ['userid'] }))[0];
  if (!ro) ro = { userid: (await rpc('user.create', { username: 'netsec_board', passwd: pw(), roleid: role.roleid, usrgrps: [{ usrgrpid: ug.usrgrpid }] })).userids[0] };
  if (!load('zabbix-token')) {
    for (const t of await rpc('token.get', { userids: [ro.userid], output: ['tokenid'] })) await rpc('token.delete', [t.tokenid]);
    const tokenid = (await rpc('token.create', { name: 'netsec-board', userid: ro.userid })).tokenids[0];
    save('zabbix-token', (await rpc('token.generate', [tokenid]))[0].token);
    console.log('read-only API token for netsec_board (lab/data/zabbix-token)');
  }

  // 4. the real webhook media type -> board-hook
  let hookToken = load('board-hook-token');
  if (!hookToken) { hookToken = crypto.randomBytes(24).toString('base64url'); save('board-hook-token', hookToken); }
  const script = fs.readFileSync(path.join(ROOT, 'deploy/zabbix-media-webhook.js'), 'utf8');
  const parameters = [
    ['board_url', 'http://172.30.77.80:8480'], ['token', hookToken], ['eventid', '{EVENT.ID}'], ['triggerid', '{TRIGGER.ID}'],
    ['severity', '{EVENT.NSEVERITY}'], ['status', '{EVENT.STATUS}'], ['name', '{EVENT.NAME}'], ['host', '{HOST.NAME}'], ['opdata', '{EVENT.OPDATA}'],
  ].map(([name, value]) => ({ name, value }));
  const templates = [{ eventsource: 0, recovery: 0, subject: 'Problem: {EVENT.NAME}', message: '{EVENT.NAME}' }, { eventsource: 0, recovery: 1, subject: 'Resolved: {EVENT.NAME}', message: '{EVENT.NAME}' }];
  let mt = (await rpc('mediatype.get', { filter: { name: 'NetSec Board' }, output: ['mediatypeid'] }))[0];
  // status 0 = enabled: a media type created through the API is disabled by default (7.0)
  if (mt) await rpc('mediatype.update', { mediatypeid: mt.mediatypeid, script, parameters, status: 0 });
  else mt = { mediatypeid: (await rpc('mediatype.create', { name: 'NetSec Board', type: 4, status: 0, script, parameters, timeout: '10s', message_templates: templates })).mediatypeids[0] };
  await rpc('user.update', { userid: admin.userid, medias: [{ mediatypeid: mt.mediatypeid, sendto: 'netsec-board', active: 0, severity: 63, period: '1-7,00:00-24:00' }] });
  if (!(await rpc('action.get', { filter: { name: 'NetSec Board' }, output: ['actionid'] })).length) {
    await rpc('action.create', {
      name: 'NetSec Board', eventsource: 0, status: 0, esc_period: '1h',
      operations: [{ operationtype: 0, opmessage_usr: [{ userid: admin.userid }], opmessage: { default_msg: 1, mediatypeid: mt.mediatypeid } }],
      recovery_operations: [{ operationtype: 11, opmessage: { default_msg: 1 } }],
    });
  }
  console.log('webhook media type "NetSec Board" (deploy/zabbix-media-webhook.js) and action ready');

  // 5. config of the webhook board (inside the lab network)
  fs.writeFileSync(path.join(DATA, 'board-hook.json'), `${JSON.stringify({ listen: { host: '0.0.0.0', port: 8480 }, dataDir: '/lab/hookdata', lang: 'en', hooks: { zabbix: { token: hookToken } }, board: { notifyMinSeverity: 'high' } }, null, 2)}\n`, { mode: 0o644 });
  fs.writeFileSync(path.join(DATA, 'zabbix-version'), `${version}\n`);
  console.log(`done: Zabbix ${version}`);
})().catch((e) => { console.error(`zabbix-setup: ${e.message}`); process.exit(1); });
