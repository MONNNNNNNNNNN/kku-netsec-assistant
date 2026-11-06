'use strict';
/*
 * Pull collectors (run by the scheduler or once from system cron). Read-only by design:
 *  - wazuh:      Wazuh indexer `POST <index>/_search` (port 9200, not the 55000 manager API),
 *                with a read-only indexer user (cluster_composite_ops_ro + read on wazuh-alerts*).
 *  - zabbix:     JSON-RPC `event.get` (problem events, with host names) using
 *                `Authorization: Bearer <API token>` (Zabbix 6.4+; the `auth` field was removed in 7.2).
 *  - configdrop: a folder that an existing backup job writes into (no device privilege needed).
 *  - fortigate:  REST config backup, opt-in. FortiOS 7.6+ needs POST (GET returns 405);
 *                the account needs more than read-only access, so file-drop is the default.
 * Each returns { events, cursor, extra }. API shapes follow the vendor docs cited in mocks/.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { request, requestOk } = require('../net.js');
const trust = require('../trust.js');

// ---------------------------------------------------------------- Wazuh indexer
async function pullWazuh(cfg, cursor) {
  const url = `${cfg.url.replace(/\/+$/, '')}/${encodeURIComponent(cfg.index || 'wazuh-alerts-*').replace(/%2A/g, '*')}/_search`;
  const size = cfg.pageSize || 500;
  let cur = cursor && cursor.ts ? { ts: cursor.ts, ids: cursor.ids || [] } : null;
  const events = [];
  for (let page = 0; page < 10; page++) {
    const range = cur ? { gte: cur.ts } : { gte: `now-${cfg.initialLookback || '1h'}` };
    const body = {
      size,
      sort: [{ timestamp: { order: 'asc' } }],
      query: { bool: { filter: [{ range: { timestamp: range } }], ...(cur && cur.ids.length ? { must_not: [{ ids: { values: cur.ids } }] } : {}) } },
    };
    const r = await requestOk(url, { body, basic: cfg.username ? { username: cfg.username, password: cfg.password } : null, caFile: cfg.caFile || undefined, timeoutMs: 30000 });
    const hits = (r.json && r.json.hits && r.json.hits.hits) || [];
    for (const h of hits) events.push(trust.wazuh(h._source || {}, h._id, cfg));
    if (!hits.length) break;
    const lastTs = hits[hits.length - 1]._source.timestamp;
    const sameTs = hits.filter((h) => h._source.timestamp === lastTs).map((h) => h._id);
    cur = { ts: lastTs, ids: (cur && cur.ts === lastTs ? [...cur.ids, ...sameTs] : sameTs).slice(-1000) };
    if (hits.length < size) break;
  }
  return { events, cursor: cur || cursor || null };
}

// ---------------------------------------------------------------- Zabbix
function zabbixUrl(u) { return /\.php$/.test(u) ? u : `${u.replace(/\/+$/, '')}/api_jsonrpc.php`; }
async function zabbixRpc(cfg, method, params, auth = true) {
  const r = await requestOk(zabbixUrl(cfg.url), {
    body: { jsonrpc: '2.0', method, params, id: 1 },
    headers: { 'content-type': 'application/json-rpc', ...(auth ? { authorization: `Bearer ${cfg.token}` } : {}) },
    caFile: cfg.caFile || undefined,
  });
  if (!r.json) throw new Error(`Zabbix: not JSON (${r.text.slice(0, 80)})`);
  if (r.json.error) {
    const msg = `${r.json.error.message} ${r.json.error.data || ''}`.trim();
    const e = new Error(`Zabbix API error: ${msg}`);
    if (/not author|session terminated|re-login/i.test(msg)) e.hint = 'The API token was not accepted. If the token is valid, the web server may strip the Authorization header: Apache "CGIPassAuth On" (or SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1) for api_jsonrpc.php; nginx "fastcgi_param HTTP_AUTHORIZATION $http_authorization;".';
    throw e;
  }
  return r.json.result;
}
async function pullZabbix(cfg, cursor) {
  const limit = cfg.pageSize || 500;
  let from = cursor && cursor.eventid ? Number(cursor.eventid) + 1 : null;
  const events = [];
  let last = cursor && cursor.eventid ? Number(cursor.eventid) : null;
  for (let page = 0; page < 10; page++) {
    const params = {
      output: ['eventid', 'clock', 'severity', 'name', 'objectid', 'acknowledged', 'opdata', 'r_eventid'],
      source: 0, object: 0, value: 1,
      selectHosts: ['host', 'name'], selectTags: ['tag', 'value'],
      sortfield: ['eventid'], sortorder: 'ASC', limit,
      ...(from ? { eventid_from: String(from) } : { time_from: String(Math.floor(Date.now() / 1000) - (cfg.initialLookbackSec || 3600)) }),
    };
    const rows = await zabbixRpc(cfg, 'event.get', params);
    for (const ev of rows) {
      events.push(trust.zabbix(ev, cfg));
      last = Math.max(last || 0, Number(ev.eventid));
    }
    if (rows.length < limit) break;
    from = last + 1;
  }
  return { events, cursor: last ? { eventid: String(last) } : cursor || null };
}

/** Checks the token and detects a stripped Authorization header. */
async function checkZabbix(cfg) {
  const version = await zabbixRpc(cfg, 'apiinfo.version', {}, false);
  try {
    await zabbixRpc(cfg, 'host.get', { output: ['hostid'], limit: 1 });
    return { ok: true, version };
  } catch (e) {
    return { ok: false, version, error: e.message, hint: e.hint };
  }
}

// ---------------------------------------------------------------- config backups
function ingestConfig(text, source, file, extra) {
  const r = trust.configEvents(text, { source, file });
  return { events: r.events, extra: { ...extra, config: r } };
}

async function pullConfigDrop(cfg, cursor) {
  const dir = cfg.dir;
  if (!dir || !fs.existsSync(dir)) throw new Error(`config drop folder not found: ${dir}`);
  const seen = (cursor && cursor.files) || {};
  const next = {};
  const events = [];
  const configs = [];
  const files = fs.readdirSync(dir).filter((f) => /\.(conf|cfg|txt)$/i.test(f)).sort();
  for (const f of files) {
    const p = path.join(dir, f);
    const st = fs.statSync(p);
    if (!st.isFile() || st.size > 50 * 1024 * 1024) continue;
    const sig = `${st.mtimeMs}:${st.size}`;
    next[f] = sig;
    if (seen[f] === sig) continue;
    const r = ingestConfig(fs.readFileSync(p, 'utf8'), 'configdrop', f);
    events.push(...r.events);
    configs.push(r.extra.config);
  }
  return { events, cursor: { files: next }, extra: { configs } };
}

async function pullFortigateBackup(cfg, cursor) {
  const base = `${cfg.url.replace(/\/+$/, '')}/api/v2/monitor/system/config/backup?scope=${encodeURIComponent(cfg.scope || 'global')}${cfg.vdom ? `&vdom=${encodeURIComponent(cfg.vdom)}` : ''}`;
  const headers = { authorization: `Bearer ${cfg.token}` };
  let method = (cursor && cursor.method) || (cfg.method && cfg.method !== 'auto' ? cfg.method.toUpperCase() : 'GET');
  let r = await request(base, { method, headers, caFile: cfg.caFile || undefined, timeoutMs: 60000 });
  if (r.status === 405 && (!cfg.method || cfg.method === 'auto')) {
    method = method === 'GET' ? 'POST' : 'GET'; // FortiOS 7.6.0 moved the backup call to POST
    r = await request(base, { method, headers, caFile: cfg.caFile || undefined, timeoutMs: 60000 });
  }
  if (r.status === 401 || r.status === 403) throw new Error(`FortiGate backup HTTP ${r.status}: the REST API admin needs config read/write (or super_admin) for backups. Prefer the file-drop collector.`);
  if (r.status < 200 || r.status >= 300) throw new Error(`FortiGate backup HTTP ${r.status}: ${r.text.slice(0, 120)}`);
  if (!/^#config-version=|^config /m.test(r.text)) throw new Error('FortiGate backup: response is not a configuration file');
  const sha = crypto.createHash('sha256').update(r.text).digest('hex');
  if (cursor && cursor.sha === sha) return { events: [], cursor: { method, sha }, extra: { unchanged: true } };
  const out = ingestConfig(r.text, 'fortigate', `rest-backup-${new Date().toISOString().slice(0, 10)}.conf`);
  return { events: out.events, cursor: { method, sha }, extra: { configs: [out.extra.config] } };
}

module.exports = { pullWazuh, pullZabbix, checkZabbix, zabbixRpc, pullConfigDrop, pullFortigateBackup, ingestConfig };
