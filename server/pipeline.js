'use strict';
/*
 * ingest -> (filter by minSeverity) -> batch -> dedupe/upsert by fingerprint -> 'change' events.
 * Writes are batched in one transaction every 200 ms so a syslog burst costs one commit.
 * Severity rule: severity = max(deterministic severity, guarded LLM severity). Never lower.
 */
const { EventEmitter } = require('node:events');
const { tx, bumpSource, updateSource } = require('./db.js');
const { SEV, sevRank } = require('./config.js');
const { maxSev } = require('./trust.js');

const CLASS_SEV = { malicious: 'high', suspicious: 'medium', unknown: 'info', benign: 'info' };
/** Severity after the LLM: the guarded verdict can only add to the deterministic level. */
function finalSeverity(det, guarded) {
  if (!guarded) return det;
  let llm = CLASS_SEV[guarded.classification] || 'info';
  if (guarded.classification === 'malicious' && guarded.recommended_action === 'block_ip') llm = 'high';
  return maxSev(det, llm);
}

const MAX_FLAGS = 20, MAX_SAMPLES = 5;
const union = (a, b, max) => [...new Set([...(a || []), ...(b || [])])].slice(0, max);
/**
 * Up to MAX_SAMPLES distinct untrusted-field sets per card. The first is always kept; when
 * full, the newest unflagged sample is replaced, so flagged evidence survives later repeats.
 */
function addSample(samples, e, now) {
  if (!e.untrusted || !Object.keys(e.untrusted).length) return samples;
  const key = JSON.stringify(e.untrusted);
  if (samples.some((x) => JSON.stringify(x.untrusted) === key)) return samples;
  const s = { untrusted: e.untrusted, flags: e.flags || [], at: now };
  if (samples.length < MAX_SAMPLES) return [...samples, s];
  let i = samples.length - 1;
  while (i > 0 && samples[i].flags.length && !s.flags.length) i--;
  if (i === 0) return samples; // every slot after the first holds flagged evidence; keep it
  return [...samples.slice(0, i), ...samples.slice(i + 1), s];
}

function toItem(r) {
  if (!r) return null;
  const now = Date.now();
  return {
    id: r.id, fingerprint: r.fingerprint, source: r.source, kind: r.kind, severity: r.severity, detSeverity: r.det_severity,
    title: r.title, trusted: JSON.parse(r.trusted), untrusted: JSON.parse(r.untrusted), flags: JSON.parse(r.flags), samples: JSON.parse(r.samples || '[]'),
    count: r.count, firstSeen: r.first_seen, lastSeen: r.last_seen,
    pinnedBy: r.pinned_by, pinnedAt: r.pinned_at, ackedBy: r.acked_by, ackedAt: r.acked_at,
    snoozedUntil: r.snoozed_until && r.snoozed_until > now ? r.snoozed_until : null, snoozedBy: r.snoozed_until > now ? r.snoozed_by : null,
    resolvedAt: r.resolved_at, reopenedAt: r.reopened_at || null, link: r.link, llm: r.llm ? JSON.parse(r.llm) : null, llmState: r.llm_state,
  };
}

class Pipeline extends EventEmitter {
  constructor({ db, cfg, now = () => Date.now(), batchMs = 200 }) {
    super();
    this.db = db; this.cfg = cfg; this.now = now; this.queue = []; this.batchMs = batchMs; this.timer = null;
    this.sel = db.prepare('SELECT * FROM items WHERE fingerprint = ?');
    this.ins = db.prepare(`INSERT INTO items(fingerprint, source, kind, severity, det_severity, title, trusted, untrusted, flags, floor, samples, count, first_seen, last_seen, link, resolved_at)
      VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`);
    this.upd = db.prepare(`UPDATE items SET count = count + 1, last_seen = ?, det_severity = ?, severity = ?, title = ?, trusted = ?, untrusted = ?, flags = ?, floor = ?, samples = ?, link = ?,
      resolved_at = ?, acked_by = ?, acked_at = ?, snoozed_until = ?, snoozed_by = ?, reopened_at = ? WHERE id = ?`);
    this.byId = db.prepare('SELECT * FROM items WHERE id = ?');
  }

  minSeverity(source) {
    const name = String(source).replace(/^hook:/, '');
    const s = this.cfg.sources[name] || {};
    return SEV.includes(s.minSeverity) ? s.minSeverity : 'info';
  }

  /** Queue one normalised event. Returns false if filtered out. */
  ingest(evt, counterSource = evt.source) {
    if (!evt.resolve && sevRank(evt.detSeverity) < sevRank(this.minSeverity(counterSource))) {
      bumpSource(this.db, counterSource, 'filtered');
      return false;
    }
    this.queue.push({ evt, counterSource });
    if (!this.timer && this.batchMs >= 0) this.timer = setTimeout(() => { this.timer = null; this.flush(); }, this.batchMs);
    return true;
  }

  /** Write queued events in one transaction; emits 'change' per affected item. */
  flush() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    if (!this.queue.length) return [];
    const batch = this.queue.splice(0);
    const changes = [];
    const counts = {};
    tx(this.db, () => {
      for (const { evt, counterSource } of batch) {
        counts[counterSource] = (counts[counterSource] || 0) + 1;
        const c = this.upsert(evt);
        if (c) changes.push(c);
      }
      for (const [s, n] of Object.entries(counts)) { bumpSource(this.db, s, 'received', n); updateSource(this.db, s, { last_ok: this.now() }); }
    });
    for (const c of changes) { c.item = toItem(this.byId.get(c.id)); this.emit('change', c); }
    return changes;
  }

  upsert(e) {
    const now = this.now();
    const row = this.sel.get(e.fingerprint);
    const j = JSON.stringify;
    if (!row) {
      if (e.resolve) return null; // a "resolved" for something we never saw
      const r = this.ins.run(e.fingerprint, e.source, e.kind, e.detSeverity, e.detSeverity, e.title, j(e.trusted), j(e.untrusted), j(e.flags), j(e.floor), j(addSample([], e, now)), e.ts || now, Math.max(e.ts || now, now), e.link || null, null);
      return { id: Number(r.lastInsertRowid), isNew: true, escalated: false, resolved: false };
    }
    if (e.resolve) {
      if (row.resolved_at) return null;
      this.db.prepare('UPDATE items SET resolved_at = ?, last_seen = ? WHERE id = ?').run(now, now, row.id);
      return { id: row.id, isNew: false, escalated: false, resolved: true };
    }
    const det = maxSev(row.det_severity, e.detSeverity);
    const sev = maxSev(row.severity, det);
    const escalated = sevRank(sev) > sevRank(row.severity);
    const reopened = !!row.resolved_at;
    // an escalation or a recurrence (the problem was resolved and came back) re-opens an
    // acknowledged or snoozed card; a plain repeat keeps both
    const keepAck = row.acked_by && !escalated && !reopened;
    const keepSnooze = row.snoozed_until && !escalated && !reopened;
    // evidence is merged, never replaced: a clean repeat must not wash out an earlier injection
    const flags = union(JSON.parse(row.flags), e.flags, MAX_FLAGS);
    const floor = union(JSON.parse(row.floor || '[]'), e.floor, MAX_FLAGS);
    const samples = addSample(JSON.parse(row.samples || '[]'), e, now);
    this.upd.run(now, det, sev, e.title, j(e.trusted), j(e.untrusted), j(flags), j(floor), j(samples), e.link || null, null,
      keepAck ? row.acked_by : null, keepAck ? row.acked_at : null, keepSnooze ? row.snoozed_until : null, keepSnooze ? row.snoozed_by : null, reopened ? now : row.reopened_at, row.id);
    return { id: row.id, isNew: reopened, reopened, escalated, resolved: false, repeat: true };
  }

  /** Mark config cards resolved when their finding is gone from a newer backup. */
  resolveStale(source, device, keep) {
    const rows = this.db.prepare("SELECT id, fingerprint, trusted FROM items WHERE source = ? AND kind = 'config' AND resolved_at IS NULL").all(source);
    const now = this.now();
    for (const r of rows) {
      if (JSON.parse(r.trusted).device !== device || keep.has(r.fingerprint)) continue;
      this.db.prepare('UPDATE items SET resolved_at = ? WHERE id = ?').run(now, r.id);
      this.emit('change', { id: r.id, item: toItem(this.byId.get(r.id)), resolved: true });
    }
  }

  /** Apply a guarded LLM verdict: severity can only go up. */
  applyVerdict(id, verdict, meta) {
    const row = this.byId.get(id);
    if (!row) return null;
    const sev = maxSev(row.severity, finalSeverity(row.det_severity, verdict));
    const escalated = sevRank(sev) > sevRank(row.severity);
    this.db.prepare("UPDATE items SET llm = ?, llm_state = 'done', severity = ? WHERE id = ?").run(JSON.stringify({ ...verdict, ...meta }), sev, id);
    // same rule as upsert: an escalation re-opens an acknowledged or snoozed card
    if (escalated) this.db.prepare('UPDATE items SET acked_by = NULL, acked_at = NULL, snoozed_until = NULL, snoozed_by = NULL WHERE id = ?').run(id);
    const c = { id, item: toItem(this.byId.get(id)), escalated, llm: true };
    this.emit('change', c);
    return c;
  }

  setLlmState(id, state, error, meta) {
    const llm = error ? JSON.stringify({ error }) : meta ? JSON.stringify(meta) : null;
    this.db.prepare('UPDATE items SET llm_state = ?, llm = COALESCE(?, llm) WHERE id = ?').run(state, llm, id);
    this.emit('change', { id, item: toItem(this.byId.get(id)), llm: true });
  }
}

module.exports = { Pipeline, toItem, finalSeverity, CLASS_SEV, addSample };
