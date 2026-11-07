'use strict';
/*
 * Pull collectors (run by the scheduler or once from system cron). Read-only by design:
 *  - wazuh:      Wazuh indexer `POST <index>/_search` (port 9200, not the 55000 manager API),
 *                with a read-only indexer user (cluster_composite_ops_ro + read on wazuh-alerts*).
 *  - zabbix:     JSON-RPC `event.get` (problem and recovery events, with host names) using
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

/*
 * Late arrivals. Filebeat ships alerts to the indexer seconds to minutes after their
 * `timestamp`, and Zabbix history syncers can commit a lower eventid after a higher one is
 * visible. A strict "after the last one" cursor would skip those for good, so each pull looks
 * back over a lag window and skips what it already saw there (the cursor keeps those ids).
 */
const LAG_MS = 120000, SEEN_MAX = 5000;
const keepSeen = (seen, floor) => seen.filter(([, t]) => t >= floor).slice(-SEEN_MAX);

// ---------------------------------------------------------------- Wazuh indexer
/** Explain the indexer errors seen in practice (the raw text alone does not say what to do). */
function wazuhHint(e) {
  const m = String(e.message);
  if (/circuit_breaking_exception/.test(m)) e.message = 'Wazuh indexer is out of heap memory (HTTP 429 circuit_breaking_exception), so it refuses every query. Raise -Xms/-Xmx in /etc/wazuh-indexer/jvm.options (half the RAM, at most 32g) and restart wazuh-indexer.';
  else if (/HTTP 401/.test(m)) e.message = `Wazuh indexer refused the user/password (HTTP 401). ${m.slice(0, 120)}`;
  else if (/security_exception|HTTP 403/.test(m)) e.message = 'The indexer user lacks read access to the index pattern (HTTP 403): it needs read + indices:data/read/search on wazuh-alerts-* (lab/wazuh-prepare.sh creates such a role).';
  else if (/self.signed|unable to verify|UNABLE_TO_VERIFY|certificate/i.test(m)) e.message = `TLS: the indexer certificate is not trusted; set sources.wazuh.caFile (Wazuh's root CA, e.g. /etc/wazuh-indexer/certs/root-ca.pem). ${m.slice(0, 100)}`;
  return e;
}

async function pullWazuh(cfg, cursor) {
  const url = `${cfg.url.replace(/\/+$/, '')}/${encodeURIComponent(cfg.index || 'wazuh-alerts-*').replace(/%2A/g, '*')}/_search`;
  const size = cfg.pageSize || 500;
  const lag = cfg.lagWindowMs ?? LAG_MS;
  // cursor: { maxTs (epoch ms), seen: [[_id, ts], ...] }; v0.4 cursors were { ts: ISO, ids }
  let maxTs = cursor ? (cursor.maxTs ?? (cursor.ts ? Date.parse(cursor.ts) : null)) : null;
  let seen = cursor ? (cursor.seen || (cursor.ids || []).map((id) => [id, maxTs])) : [];
  const events = [];
  for (let page = 0; page < 10; page++) {
    const range = maxTs != null ? { gte: maxTs - lag, format: 'epoch_millis' } : { gte: `now-${cfg.initialLookback || '1h'}` };
    const ids = seen.map(([id]) => id);
    const body = {
      size,
      sort: [{ timestamp: { order: 'asc' } }],
      query: { bool: { filter: [{ range: { timestamp: range } }], ...(ids.length ? { must_not: [{ ids: { values: ids } }] } : {}) } },
    };
    const r = await requestOk(url, { body, basic: cfg.username ? { username: cfg.username, password: cfg.password } : null, caFile: cfg.caFile || undefined, timeoutMs: 30000 }).catch((e) => { throw wazuhHint(e); });
    const hits = (r.json && r.json.hits && r.json.hits.hits) || [];
    for (const h of hits) {
      events.push(trust.wazuh(h._source || {}, h._id, cfg));
      const t = Date.parse(h._source && h._source.timestamp) || Date.now();
      seen.push([h._id, t]);
      maxTs = Math.max(maxTs ?? t, t);
    }
    if (maxTs != null) seen = keepSeen(seen, maxTs - lag);
    if (hits.length < size) break;
  }
  return { events, cursor: maxTs != null ? { maxTs, seen } : cursor || null };
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
// "value" (1 problem, 0 recovery) must be requested: real Zabbix returns only the listed fields,
// and without it no recovery ever resolved a card (found against Zabbix 7.0.32, lab/x4-zabbix.js)
const ZBX_OUTPUT = ['eventid', 'clock', 'severity', 'name', 'objectid', 'acknowledged', 'opdata', 'r_eventid', 'value'];
async function pullZabbix(cfg, cursor) {
  const limit = cfg.pageSize || 500;
  const lagSec = Math.ceil((cfg.lagWindowMs ?? LAG_MS) / 1000);
  // cursor: { eventid (max seen), clock (max seen), seen: [[eventid, clock], ...] }
  let maxClock = cursor && cursor.clock ? Number(cursor.clock) : null;
  let seen = (cursor && cursor.seen) || [];
  let last = cursor && cursor.eventid ? Number(cursor.eventid) : null;
  const seenIds = new Set(seen.map(([id]) => String(id)));
  const events = [];
  const take = (ev) => {
    if (seenIds.has(String(ev.eventid))) return;
    seenIds.add(String(ev.eventid));
    events.push(trust.zabbix(ev, cfg));
    seen.push([String(ev.eventid), Number(ev.clock) || 0]);
    last = Math.max(last || 0, Number(ev.eventid));
    maxClock = Math.max(maxClock || 0, Number(ev.clock) || 0);
  };
  // Everything fetched in this run is applied in eventid order at the end: the open-problem seed
  // must not be applied before older history of the same trigger (a problem that flapped in the
  // lookback was otherwise left resolved while open; found against Zabbix 7.0.32)
  const fetched = [];
  // first run: the problems that are open right now, however old (event.get alone would only
  // see the initial lookback). problem.get has no host names, so fetch those events by id.
  if (!cursor) {
    const open = await zabbixRpc(cfg, 'problem.get', { output: ['eventid'], source: 0, object: 0, recent: false, sortfield: ['eventid'], sortorder: 'ASC', limit: 5000 });
    const ids = (open || []).map((p) => p.eventid);
    for (let i = 0; i < ids.length; i += limit) {
      fetched.push(...await zabbixRpc(cfg, 'event.get', { output: ZBX_OUTPUT, eventids: ids.slice(i, i + limit), selectHosts: ['host', 'name'], selectTags: ['tag', 'value'] }));
    }
  }
  // then events by time: from the lag window before the newest clock seen (or the initial
  // lookback), paging by eventid inside this run
  const timeFrom = maxClock != null && cursor && cursor.clock ? maxClock - lagSec : Math.floor(Date.now() / 1000) - (cfg.initialLookbackSec || 3600);
  const legacyFrom = cursor && cursor.eventid && !cursor.clock ? Number(cursor.eventid) + 1 : null; // v0.4 cursor
  let from = legacyFrom;
  for (let page = 0; page < 10; page++) {
    const params = {
      output: ZBX_OUTPUT,
      source: 0, object: 0, value: [0, 1], // 1 = problem, 0 = recovery (resolves the card)
      selectHosts: ['host', 'name'], selectTags: ['tag', 'value'],
      sortfield: ['eventid'], sortorder: 'ASC', limit,
      ...(legacyFrom ? {} : { time_from: String(timeFrom) }),
      ...(from ? { eventid_from: String(from) } : {}),
    };
    const rows = await zabbixRpc(cfg, 'event.get', params);
    fetched.push(...rows);
    if (rows.length < limit) break;
    from = Math.max(...rows.map((r) => Number(r.eventid))) + 1;
  }
  fetched.sort((a, b) => Number(a.eventid) - Number(b.eventid));
  for (const ev of fetched) take(ev);
  if (maxClock != null) seen = keepSeen(seen, maxClock - lagSec);
  return { events, cursor: last ? { eventid: String(last), clock: maxClock, seen } : cursor || null };
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

module.exports = { wazuhHint, pullWazuh, pullZabbix, checkZabbix, zabbixRpc, pullConfigDrop, pullFortigateBackup, ingestConfig };
