'use strict';
/*
 * Per-source normalisers with a field-trust map. Every event has the same shape:
 *   { source, kind, ts, title, trusted, untrusted, flags, floor, detSeverity, fingerprint, link, resolve? }
 * trusted   = fields the device/monitoring system generates itself
 * untrusted = fields an outside party can influence (User-Agent, URLs, log text, names)
 * detSeverity comes only from trusted fields (plus the injection detector, which can only raise it).
 * The LLM sees the same split (core.buildFieldPrompt) and can never lower detSeverity.
 */
const crypto = require('node:crypto');
const N = require('../src/core.js');
const { SEV, sevRank } = require('./config.js');

const maxSev = (...s) => s.filter(Boolean).reduce((a, b) => (sevRank(b) > sevRank(a) ? b : a), 'info');
const FIELD_CAP = 2000, MAX_FIELDS = 80;

function capFields(o) {
  const out = {};
  for (const [k, v] of Object.entries(o || {}).slice(0, MAX_FIELDS)) {
    if (v == null || v === '') continue;
    const s = typeof v === 'string' ? v : Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v);
    out[k] = s.length > FIELD_CAP ? `${s.slice(0, FIELD_CAP)}…[+${s.length - FIELD_CAP}]` : s;
  }
  return out;
}

function fingerprint(source, kind, parts) {
  return crypto.createHash('sha256').update([source, kind, ...parts.map((p) => String(p ?? ''))].join('\u0001')).digest('hex').slice(0, 32);
}

/** Detector flags for every untrusted value; a flagged event is at least "medium". */
function flagsOf(untrusted) {
  const flags = [];
  for (const [k, v] of Object.entries(untrusted)) {
    const d = N.detectInjection(String(v));
    if (d.flagged) flags.push(`${k}: ${d.reasons.join(', ')}`);
  }
  return flags;
}

const MAX_FUTURE_MS = 5 * 60000;
function finish(e) {
  // a device clock in the future would keep the card on top and out of retention: clamp it
  const now = Date.now();
  e.ts = Number.isFinite(e.ts) ? Math.min(e.ts, now + MAX_FUTURE_MS) : now;
  e.trusted = capFields(e.trusted);
  e.untrusted = capFields(e.untrusted);
  e.flags = [...flagsOf(e.untrusted), ...(e.extraFlags || [])];
  delete e.extraFlags;
  if (e.flags.length) e.detSeverity = maxSev(e.detSeverity, 'medium');
  e.floor = sevRank(e.detSeverity) >= sevRank('medium') ? [`${e.source} severity ${e.detSeverity}`] : [];
  if (e.link && !/^https?:\/\//i.test(e.link)) e.link = null;
  // a flood of distinct fingerprints (a distributed scan) folds into one burst card per burstKey
  e.burstFingerprint = e.burstKey ? fingerprint(e.source, e.kind, ['burst', ...e.burstKey]) : null;
  delete e.burstKey;
  return e;
}

// ---------------------------------------------------------------- FortiGate (syslog)
const FGT_LEVEL = { emergency: 'critical', alert: 'critical', critical: 'critical', error: 'high', warning: 'medium', notice: 'info', information: 'info', debug: 'info' };
const FGT_IPS = { critical: 'critical', high: 'high', elevated: 'medium', medium: 'medium', low: 'low', info: 'info', informational: 'info' };

function fortigate(f, now = Date.now()) {
  const trusted = {}, untrusted = {};
  for (const [k, v] of Object.entries(f)) (N.UNTRUSTED.includes(k) ? untrusted : trusted)[k] = v;
  const kind = [f.type, f.subtype].filter(Boolean).join('/') || 'log';
  // UTM logs carry their own threat severity (IPS signatures are logged at level "alert" by
  // default, which would make every detection critical); other logs use the syslog level
  // threat severity (IPS/AV), else the client-reputation level when one was scored. NOT apprisk:
  // that is the application signature's static rating (on BOTSv1, 116,863 benign app-ctrl lines
  // such as OCSP carry apprisk=elevated, while the 9,231 Cerber C2 lines carry crlevel=critical)
  const utmSev = f.type === 'utm' ? FGT_IPS[String(f.severity || f.crlevel || '').toLowerCase()] : null;
  const det = utmSev || FGT_LEVEL[f.level] || 'info';
  const what = f.attack || f.virus || f.logdesc || f.catdesc || f.action || '';
  // a repeated key means some value smuggled extra fields (parseFortiLog kept the first)
  const dup = (f.__dup || []).length ? `duplicate field: ${f.__dup.join(', ')}` : null;
  const ts = Number(f.eventtime) ? Math.round(Number(f.eventtime) / (Number(f.eventtime) > 1e17 ? 1e6 : Number(f.eventtime) > 1e14 ? 1e3 : 1)) : now;
  return finish({
    source: 'fortigate', kind, ts: ts > 1e12 && ts < now + 86400000 ? ts : now,
    title: `${kind}${what ? `: ${what}` : ''}`,
    trusted, untrusted, detSeverity: det,
    // grouping keys are device-generated only: attacker-chosen fields (user names, URLs, agents)
    // must not split one attack into thousands of cards (they are kept as samples instead)
    fingerprint: fingerprint('fortigate', kind, [f.devid, f.logid, f.srcip || f.remip, f.dstip, f.attack || f.virus || f.policyid]),
    burstKey: [f.devid, f.logid, f.attack || f.virus || f.policyid],
    extraFlags: dup ? [dup] : [],
    link: null,
  });
}

// ---------------------------------------------------------------- generic syslog
const SYSLOG_SEV = ['critical', 'critical', 'critical', 'high', 'medium', 'info', 'info', 'info'];
function syslog(p, sender, now = Date.now()) {
  const trusted = { sender, host: p.host || sender, app: p.app || '', facility: p.facility, severity: p.sev, format: p.format };
  return finish({
    source: 'syslog', kind: p.app || 'syslog', ts: now,
    title: `${p.app || 'syslog'} on ${p.host || sender}`,
    trusted, untrusted: { msg: p.msg }, detSeverity: SYSLOG_SEV[p.sev] || 'info',
    // group by sender + app + a message shape (digits/hex stripped) so repeats collapse
    fingerprint: fingerprint('syslog', p.app, [sender, p.host, String(p.msg).replace(/[0-9a-f]{4,}|\d+/gi, '#').slice(0, 120)]),
    burstKey: [sender, p.app],
    link: null,
  });
}

// ---------------------------------------------------------------- Wazuh
function flatten(o, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(o || {})) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = Array.isArray(v) ? v.map((x) => (typeof x === 'object' ? JSON.stringify(x) : x)).join(', ') : v;
  }
  return out;
}
// rule.description can embed decoded fields ($(win.eventdata.x)), so it is untrusted too
const WAZUH_UNTRUSTED = (k) => k === 'full_log' || k === 'previous_output' || k === 'rule.description' || k.startsWith('data.') || k.startsWith('syscheck.');
function wazuhSev(level) {
  const l = Number(level) || 0;
  return l >= 13 ? 'critical' : l >= 10 ? 'high' : l >= 7 ? 'medium' : l >= 4 ? 'low' : 'info';
}
function wazuh(alert, id, opts = {}, now = Date.now()) {
  const flat = flatten(alert);
  const trusted = {}, untrusted = {};
  for (const [k, v] of Object.entries(flat)) (WAZUH_UNTRUSTED(k) ? untrusted : trusted)[k] = v;
  if (id) trusted._id = id;
  const r = alert.rule || {};
  const ts = Date.parse(alert.timestamp) || now;
  return finish({
    source: 'wazuh', kind: 'alert', ts,
    title: `${r.description || `rule ${r.id}`}${alert.agent && alert.agent.name ? ` (${alert.agent.name})` : ''}`,
    trusted, untrusted, detSeverity: wazuhSev(r.level),
    // no user names in the key: a brute force with random names stays one card. Below
    // perSourceCardsFrom (default medium) the source IP is not in the key either: internet SSH
    // scanning (rule 5710, low) made one card per attacker IP on a real host; the IPs stay as samples
    fingerprint: fingerprint('wazuh', 'alert', [r.id, alert.agent && alert.agent.id,
      sevRank(wazuhSev(r.level)) >= sevRank(SEV.includes(opts.perSourceCardsFrom) ? opts.perSourceCardsFrom : 'medium') ? flat['data.srcip'] : '']),
    burstKey: [r.id, alert.agent && alert.agent.id],
    link: opts.dashboardUrl ? `${opts.dashboardUrl.replace(/\/+$/, '')}/app/threat-hunting` : null,
  });
}

// ---------------------------------------------------------------- Zabbix
const ZBX_SEV = ['info', 'info', 'low', 'medium', 'high', 'critical'];
const ZBX_NAMES = { 'not classified': 0, information: 1, warning: 2, average: 3, high: 4, disaster: 5 };
function zabbixSevIndex(s) {
  if (s == null || s === '') return 0;
  const n = Number(s);
  if (Number.isInteger(n) && n >= 0 && n <= 5) return n;
  return ZBX_NAMES[String(s).toLowerCase()] ?? 0;
}
/**
 * ev: event.get row ({eventid, clock, severity, name, objectid, value, hosts, tags, opdata}) or webhook payload.
 * value "0" (recovery event, pull mode) or status RESOLVED/OK (webhook) resolves the problem card.
 */
function zabbix(ev, opts = {}, now = Date.now()) {
  const sev = zabbixSevIndex(ev.severity);
  const hosts = Array.isArray(ev.hosts) ? ev.hosts.map((h) => h.name || h.host).join(', ') : ev.host || '';
  const tags = Array.isArray(ev.tags) ? ev.tags.map((t) => `${t.tag}${t.value ? `:${t.value}` : ''}`).join(', ') : ev.tags || '';
  const triggerid = ev.objectid || ev.triggerid || '';
  const trusted = { eventid: ev.eventid, triggerid, severity: sev, severity_name: Object.keys(ZBX_NAMES)[sev], clock: ev.clock, acknowledged: ev.acknowledged, status: ev.status, value: ev.value, r_eventid: ev.r_eventid };
  const untrusted = { name: ev.name, hosts, opdata: ev.opdata, tags };
  const base = (opts.url || '').replace(/\/api_jsonrpc\.php$/, '').replace(/\/+$/, '');
  return finish({
    source: 'zabbix', kind: 'problem', ts: Number(ev.clock) ? Number(ev.clock) * 1000 : now,
    title: `${ev.name || `trigger ${triggerid}`}${hosts ? ` (${hosts})` : ''}`,
    trusted, untrusted, detSeverity: ZBX_SEV[sev],
    fingerprint: fingerprint('zabbix', 'problem', [triggerid || ev.name, hosts]),
    link: base && triggerid ? `${base}/tr_events.php?triggerid=${encodeURIComponent(triggerid)}&eventid=${encodeURIComponent(ev.eventid || '')}` : null,
    resolve: String(ev.value) === '0' || (ev.status !== undefined && /^(resolved|ok|0)$/i.test(String(ev.status).trim())),
  });
}

// ---------------------------------------------------------------- generic hook
function generic(p, now = Date.now()) {
  const sev = SEV.includes(p.severity) ? p.severity : 'info';
  return finish({
    source: 'generic', kind: String(p.kind || 'event').slice(0, 40), ts: Date.parse(p.time) || now,
    title: String(p.title || 'event').slice(0, 300),
    trusted: { ...(p.fields || {}), origin: p.origin || '' }, untrusted: p.untrusted || {}, detSeverity: sev,
    fingerprint: fingerprint('generic', p.kind || 'event', [p.key || p.title]),
    burstKey: [p.kind || 'event'],
    link: typeof p.link === 'string' ? p.link : null,
    resolve: !!p.resolved,
  });
}

// ---------------------------------------------------------------- FortiGate config backup
function hostnameOf(text) {
  const m = String(text).match(/^\s*set hostname "?([^"\r\n]+)"?/m);
  return m ? m[1].trim() : '';
}
/**
 * analyze() a backup: one event per critical/high finding, plus one INCOMPLETE event when
 * coverage is not complete. Returns {events, device, summary} — the caller resolves cards
 * whose finding disappeared from the newer backup.
 */
function configEvents(text, { source, file }, now = Date.now()) {
  const r = N.analyze(text);
  const device = hostnameOf(text) || String(file || 'device').replace(/[_-]?\d{8}.*$/, '').replace(/\.(conf|txt)$/i, '');
  const events = [];
  for (const f of r.findings) {
    if (!['critical', 'high'].includes(f.severity)) continue;
    events.push(finish({
      source, kind: 'config', ts: now,
      title: `${device}: ${f.titles ? f.titles.en : f.title}`,
      trusted: { device, model: r.meta.model, firmware: `${r.meta.version} build ${r.meta.build}`, check: f.check, iso: f.iso, instances: f.instances.length, refs: f.instances.slice(0, 5).map((i) => `${i.ref} (line ${i.line})`), why: f.whys ? f.whys.en : f.why, title_th: f.titles ? f.titles.th : '', file },
      untrusted: {}, detSeverity: f.severity,
      fingerprint: fingerprint(source, 'config', [device, f.check]), link: null,
    }));
  }
  if (!r.coverage.complete) {
    events.push(finish({
      source, kind: 'config', ts: now,
      title: `${device}: INCOMPLETE ANALYSIS (${r.coverage.gaps} item(s) not checked)`,
      trusted: { device, check: 'COVERAGE', parse_errors: r.coverage.parseErrors.length, skipped_rules: r.coverage.shadowSkipped.length, ipv6_policies: r.coverage.ipv6Policies, undefined_names: r.coverage.unresolved.slice(0, 10), file },
      untrusted: {}, detSeverity: 'medium',
      fingerprint: fingerprint(source, 'config', [device, 'COVERAGE']), link: null,
    }));
  }
  const summary = { device, file, model: r.meta.model, version: r.meta.version, policies: r.meta.policies, counts: r.counts, complete: r.coverage.complete, gaps: r.coverage.gaps, analyzedAt: new Date(now).toISOString() };
  return { events, device, summary };
}

module.exports = { fortigate, syslog, wazuh, zabbix, generic, configEvents, fingerprint, capFields, flatten, maxSev, wazuhSev, zabbixSevIndex };
