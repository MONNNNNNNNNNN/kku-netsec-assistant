'use strict';
/*
 * LLM triage queue. The board works fully without it. On CPU a 3B model needs minutes per
 * call (results/inject-eval-qwen2.5-3b-instruct.md), so:
 *  - "Explain" on a card queues it first (on demand);
 *  - new items at or above autoMinSeverity are queued automatically;
 *  - at most budgetPerHour calls per rolling hour (counted from llm_audit, so restarts do
 *    not reset it); when the queue is longer than queueMax, the oldest automatic entry is
 *    dropped and its card says so.
 * Every prompt is built by core.buildFieldPrompt from the per-source trust split, every
 * reply goes through validateVerdicts, and the item severity can only go up.
 */
const { EventEmitter } = require('node:events');
const N = require('../src/core.js');
const LLM = require('./llm.js');
const { sevRank } = require('./config.js');
const { toItem } = require('./pipeline.js');

const SUBJECT = { fortigate: 'FortiGate logs', wazuh: 'Wazuh alerts', zabbix: 'Zabbix problems', syslog: 'syslog messages', configdrop: 'firewall configuration findings', generic: 'monitoring events' };

class LlmQueue extends EventEmitter {
  constructor({ db, cfg, pipeline, lang = 'th', now = () => Date.now(), chat = LLM.chat }) {
    super();
    this.db = db; this.pipeline = pipeline; this.now = now; this.chat = chat; this.lang = lang;
    this.cfg = { budgetPerHour: 4, queueMax: 20, autoMinSeverity: 'high', batch: 5, timeoutMs: 1800000, maxTokens: 1200, ...(cfg || {}) };
    this.enabled = !!(cfg && cfg.url && cfg.model && cfg.enabled !== false);
    this.queue = []; this.running = false; this.timer = null; this.lastError = null;
  }

  used() {
    return this.db.prepare('SELECT COUNT(*) AS n FROM llm_audit WHERE ts > ?').get(this.now() - 3600000).n;
  }
  nextSlot() {
    if (this.used() < this.cfg.budgetPerHour) return this.now();
    const r = this.db.prepare('SELECT ts FROM llm_audit WHERE ts > ? ORDER BY ts ASC LIMIT 1 OFFSET ?').get(this.now() - 3600000, Math.max(0, this.used() - this.cfg.budgetPerHour));
    return r ? r.ts + 3600000 : this.now();
  }
  status() {
    return { enabled: this.enabled, model: this.enabled ? this.cfg.model : null, queued: this.queue.length, budgetPerHour: this.cfg.budgetPerHour, used: this.enabled ? this.used() : 0, nextSlotAt: this.enabled ? this.nextSlot() : null, running: this.running, lastError: this.lastError };
  }

  consider(change) {
    if (!this.enabled || !change.isNew || !change.item) return;
    const it = change.item;
    if (it.llmState === 'none' && sevRank(it.detSeverity) >= sevRank(this.cfg.autoMinSeverity)) this.enqueue(it.id, false);
  }

  /** Returns {position} (1 = next). */
  enqueue(id, demand) {
    if (!this.enabled) throw Object.assign(new Error('LLM is not configured'), { status: 409 });
    const at = this.queue.findIndex((q) => q.id === id);
    if (at >= 0) {
      if (demand && !this.queue[at].demand) { const [q] = this.queue.splice(at, 1); q.demand = true; this.queue.splice(this.queue.filter((x) => x.demand).length, 0, q); }
    } else {
      const q = { id, demand };
      if (demand) this.queue.splice(this.queue.filter((x) => x.demand).length, 0, q);
      else this.queue.push(q);
      this.pipeline.setLlmState(id, 'queued');
      while (this.queue.length > this.cfg.queueMax) {
        const i = this.queue.findIndex((x) => !x.demand);
        if (i < 0) break;
        const [old] = this.queue.splice(i, 1);
        this.pipeline.setLlmState(old.id, 'skipped', 'queue full: not triaged (budget)');
      }
    }
    const position = this.queue.findIndex((q) => q.id === id) + 1;
    this.emit('status', this.status());
    this.kick();
    return { position };
  }

  kick() {
    if (!this.enabled || this.running || !this.queue.length) return;
    const wait = this.nextSlot() - this.now();
    if (wait > 0) {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => this.kick(), wait + 50);
      this.timer.unref && this.timer.unref();
      return;
    }
    this.running = true;
    this.runBatch().catch((e) => { this.lastError = e.message; }).finally(() => { this.running = false; this.emit('status', this.status()); this.kick(); });
  }

  /** Take up to `batch` items from the same source (prompts are per source). */
  take() {
    const first = this.queue[0];
    const firstRow = this.db.prepare('SELECT source FROM items WHERE id = ?').get(first.id);
    const src = firstRow ? firstRow.source : null;
    const out = [];
    for (let i = 0; i < this.queue.length && out.length < this.cfg.batch;) {
      const row = this.db.prepare('SELECT * FROM items WHERE id = ?').get(this.queue[i].id);
      if (!row) { this.queue.splice(i, 1); continue; }
      if (row.source === src) { out.push(toItem(row)); this.queue.splice(i, 1); } else i++;
    }
    return out;
  }

  async runBatch() {
    const items = this.take();
    if (!items.length) return;
    for (const it of items) this.pipeline.setLlmState(it.id, 'running');
    const st = N.newMaskState();
    const records = items.map((it) => ({ trusted: it.trusted, untrusted: it.untrusted, floor: JSON.parse(this.db.prepare('SELECT floor FROM items WHERE id = ?').get(it.id).floor) }));
    const p = N.buildFieldPrompt(records, { maskState: st, subject: SUBJECT[items[0].source] || 'monitoring events', lang: this.lang });
    const audit = (rec) => this.db.prepare('INSERT INTO llm_audit(ts, item_ids, endpoint, endpoint_class, overrides, model, prompt_sha256, messages, reply, ms, error) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(this.now(), JSON.stringify(items.map((i) => i.id)), rec.endpoint, rec.endpoint_class, JSON.stringify(rec.endpoint_overrides || []), rec.model, rec.prompt_sha256, JSON.stringify(rec.messages), rec.reply ?? null, rec.ms ?? null, rec.error ?? null);
    let reply;
    try {
      const res = await this.chat(this.cfg.url, this.cfg.model, p.messages, {
        allowRemote: !!this.cfg.allowRemote, allowHttpLan: !!this.cfg.allowHttpLan, remoteHint: 'llm.allowRemote in the config', httpHint: 'llm.allowHttpLan in the config',
        apiKey: this.cfg.apiKey || undefined, timeoutMs: this.cfg.timeoutMs, maxTokens: Math.min(this.cfg.maxTokens, 300 + 150 * items.length), temperature: 0.2,
        audit, cmd: 'board', tool: 'netsec-board',
      });
      reply = res.text;
    } catch (e) {
      this.lastError = e.message;
      for (const it of items) this.pipeline.setLlmState(it.id, 'error', e.message);
      return;
    }
    this.lastError = null;
    const g = N.validateVerdicts(reply, p.entries);
    g.verdicts.forEach((v, i) => {
      this.pipeline.applyVerdict(items[i].id, {
        classification: v.classification, recommended_action: v.recommended_action, confidence: v.confidence,
        reason: N.unmask(v.reason, st.map), overridden: v.overridden,
      }, { model: this.cfg.model, at: this.now(), guard: 'validateVerdicts' });
    });
  }

  stop() { clearTimeout(this.timer); this.enabled = false; }
}

module.exports = { LlmQueue };
