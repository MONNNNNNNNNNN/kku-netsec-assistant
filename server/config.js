'use strict';
/*
 * Configuration: one JSON file. Secrets are references, never literals in the DB or logs:
 *   "env:NAME"   -> process.env.NAME
 *   "file:/path" -> trimmed file contents (Docker/systemd secrets)
 * A literal string also works for local testing; `check` warns about it.
 */
const fs = require('node:fs');
const path = require('node:path');

const SECRET_KEYS = /^(token|password|secret|apiKey|botToken|channelToken|hookToken)$/;
const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const sevRank = (s) => Math.max(0, SEV.indexOf(s));

const DEFAULTS = {
  listen: { host: '127.0.0.1', port: 8480 },
  dataDir: './data',
  retentionDays: 30,
  lang: 'th',
  tzOffsetMinutes: 420, // Asia/Bangkok, no DST
  cookieSecure: false,
  sessionHours: 12,
  board: { notifyMinSeverity: 'high', newCardsPerMinute: 120 },
  sources: {
    syslog: { enabled: false, bind: '127.0.0.1', port: 5514, udp: true, tcp: true, allow: [], ratePerSec: 2000, minSeverity: 'low' },
    wazuh: { enabled: false, schedule: '*/2 * * * *', url: '', index: 'wazuh-alerts-*', username: '', password: '', caFile: '', minSeverity: 'low', pageSize: 500 },
    zabbix: { enabled: false, schedule: '*/2 * * * *', url: '', token: '', caFile: '', minSeverity: 'low', pageSize: 500 },
    configdrop: { enabled: false, schedule: '*/5 * * * *', dir: './backups' },
    fortigate: { enabled: false, schedule: '0 2 * * *', url: '', token: '', caFile: '', method: 'auto', scope: 'global' },
  },
  hooks: { zabbix: { token: '' }, wazuh: { token: '' }, generic: { token: '' }, ratePerMin: 120 },
  notify: { channels: [] },
  llm: null,
};

function merge(a, b) {
  if (Array.isArray(b) || typeof b !== 'object' || b === null) return b === undefined ? a : b;
  const out = { ...(a && typeof a === 'object' && !Array.isArray(a) ? a : {}) };
  for (const [k, v] of Object.entries(b)) out[k] = merge(out[k], v);
  return out;
}

function resolveSecret(v) {
  if (typeof v !== 'string' || !v) return v || '';
  if (v.startsWith('env:')) return process.env[v.slice(4)] || '';
  if (v.startsWith('file:')) {
    try { return fs.readFileSync(v.slice(5), 'utf8').trim(); } catch { return ''; }
  }
  return v;
}

/** Deep copy with every secret resolved (kept in memory only). */
function resolveAll(o) {
  if (Array.isArray(o)) return o.map(resolveAll);
  if (!o || typeof o !== 'object') return o;
  const out = {};
  for (const [k, v] of Object.entries(o)) out[k] = SECRET_KEYS.test(k) ? resolveSecret(v) : resolveAll(v);
  return out;
}

/** Deep copy safe to show: secrets replaced by "set"/"" and their reference kind; URL passwords removed. */
function redact(o) {
  if (Array.isArray(o)) return o.map(redact);
  if (typeof o === 'string') return o.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@\s]*@/i, '$1[redacted]@');
  if (!o || typeof o !== 'object') return o;
  const out = {};
  for (const [k, v] of Object.entries(o)) out[k] = SECRET_KEYS.test(k) ? (v ? `[set${typeof v === 'string' && /^(env|file):/.test(v) ? ` via ${v.split(':')[0]}` : ''}]` : '') : redact(v);
  return out;
}

/** Literal secrets in the raw file (not env:/file:) — `check` warns about these. */
function literalSecrets(o, p = '') {
  const out = [];
  if (Array.isArray(o)) o.forEach((v, i) => out.push(...literalSecrets(v, `${p}[${i}]`)));
  else if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) {
    if (SECRET_KEYS.test(k) && typeof v === 'string' && v && !/^(env|file):/.test(v)) out.push(`${p}${p ? '.' : ''}${k}`);
    else out.push(...literalSecrets(v, `${p}${p ? '.' : ''}${k}`));
  }
  return out;
}

/**
 * Deployment overrides from the environment (Docker/systemd), applied over the file:
 * NETSEC_LISTEN_HOST, NETSEC_LISTEN_PORT, NETSEC_DATA_DIR, NETSEC_BACKUP_DIR, NETSEC_SYSLOG_BIND,
 * NETSEC_TRUST_PROXY ("true", "false" or a comma list of proxy addresses/CIDRs).
 * They let the unedited example config run in a container (listen 0.0.0.0, data in /data; in
 * Docker every client arrives from the bridge gateway, so the proxy's X-Forwarded-For is needed).
 */
function envOverrides(env = process.env) {
  const o = {};
  if (env.NETSEC_LISTEN_HOST || env.NETSEC_LISTEN_PORT) o.listen = { ...(env.NETSEC_LISTEN_HOST ? { host: env.NETSEC_LISTEN_HOST } : {}), ...(env.NETSEC_LISTEN_PORT ? { port: Number(env.NETSEC_LISTEN_PORT) } : {}) };
  if (env.NETSEC_DATA_DIR) o.dataDir = env.NETSEC_DATA_DIR;
  if (env.NETSEC_TRUST_PROXY !== undefined) {
    const v = env.NETSEC_TRUST_PROXY.trim();
    o.trustProxy = v === 'true' ? true : v === 'false' || v === '' ? false : v.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (env.NETSEC_BACKUP_DIR || env.NETSEC_SYSLOG_BIND) {
    o.sources = {};
    if (env.NETSEC_BACKUP_DIR) o.sources.configdrop = { dir: env.NETSEC_BACKUP_DIR };
    if (env.NETSEC_SYSLOG_BIND) o.sources.syslog = { bind: env.NETSEC_SYSLOG_BIND };
  }
  return o;
}

/**
 * secrets.env next to the config file (NAME=value, the systemd EnvironmentFile format, written
 * by `cli/board.js setup`) is loaded into process.env, so a plain `node server/main.js`
 * resolves its env: secrets. Variables already set win (Docker env_file, systemd).
 * Returns a warning string, or null.
 */
function loadSecretsFile(configFile) {
  const p = path.join(path.dirname(path.resolve(configFile)), 'secrets.env');
  let st;
  try { st = fs.statSync(p); } catch { return null; }
  if (!st.isFile()) return null;
  // under systemd the file is root-only and already loaded by EnvironmentFile: unreadable is fine
  try { process.loadEnvFile(p); } catch (e) { return e.code === 'EACCES' ? null : `${p}: ${e.message}`; }
  return (st.mode & 0o077) ? `${p} is readable by group/others (mode ${(st.mode & 0o777).toString(8)}): chmod 600 ${p}` : null;
}

function loadConfig(file, overrides = {}, env = process.env) {
  const secretsWarning = file && env === process.env ? loadSecretsFile(file) : null;
  const raw = file ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  const merged = merge(merge(merge(DEFAULTS, raw), envOverrides(env)), overrides);
  const base = file ? path.dirname(path.resolve(file)) : process.cwd();
  merged.dataDir = path.resolve(base, merged.dataDir);
  if (merged.sources.configdrop.dir) merged.sources.configdrop.dir = path.resolve(base, merged.sources.configdrop.dir);
  // a relative CA file (e.g. certs/wazuh-root-ca.pem, mounted next to netsec.json in Docker) is relative to the config
  for (const k of ['wazuh', 'zabbix', 'fortigate']) { const s = merged.sources[k]; if (s && s.caFile) s.caFile = path.resolve(base, s.caFile); }
  return { raw: merged, cfg: resolveAll(merged), file: file ? path.resolve(file) : null, secretsWarning };
}

module.exports = { DEFAULTS, SEV, sevRank, merge, resolveSecret, resolveAll, redact, literalSecrets, loadConfig, loadSecretsFile, envOverrides };
