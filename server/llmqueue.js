'use strict';
/*
 * LLM triage queue. The board works fully without it. On CPU a 3B model needs about 20-25 s per
 * card (qwen2.5:3b-instruct, 4 ARM cores, measured in lab/x5-llm.js), so:
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
    // automatic triage only for critical by default: on CPU the hourly budget is better spent on "Explain"
    // batch 1 by default: measured with qwen2.5:3b-instruct on 4 ARM cores (lab/x5-llm.js), batches of
    // 5 got a real verdict for only 4 of 11 cards (85 s per call) while single cards got 11 of 11
    // (23 s per call). 12 calls/hour is about 5 CPU-minutes per hour.
    this.cfg = { budgetPerHour: 12, queueMax: 20, autoMinSeverity: 'critical', batch: 1, timeoutMs: 1800000, maxTokens: 1200, ...(cfg || {}) };
    this.enabled = !!(cfg && cfg.url && cfg.model && cfg.enabled !== false);
    this.queue = []; this.running = false; this.timer = null; this.lastError = null;
  }

  /**
   * The queue lives in memory. After a restart, cards left "queued"/"running" would never
   * finish (and the UI would keep Explain disabled), so put them back: the on-demand ones
   * ("demand" in llm) go back in the queue, the rest return to "not triaged".
   */
  recover() {
    const rows = this.db.prepare("SELECT id, llm FROM items WHERE llm_state IN ('queued', 'running')").all();
    for (const r of rows) {
      const demand = (() => { try { return !!JSON.parse(r.llm || '{}').demand; } catch { return false; } })();
      this.db.prepare("UPDATE items SET llm_state = 'none' WHERE id = ?").run(r.id);
      if (demand && this.enabled) this.enqueue(r.id, true);
    }
    return rows.length;
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
      if (demand && !this.queue[at].demand) {
        const [q] = this.queue.splice(at, 1); q.demand = true; this.queue.splice(this.queue.filter((x) => x.demand).length, 0, q);
        this.pipeline.setLlmState(id, 'queued', null, { demand: true });
      }
    } else {
      const q = { id, demand };
      if (demand) this.queue.splice(this.queue.filter((x) => x.demand).length, 0, q);
      else this.queue.push(q);
      this.pipeline.setLlmState(id, 'queued', null, demand ? { demand: true } : null);
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
    // the prompt uses the flagged sample when there is one, so a clean repeat cannot hide the injection attempt
    const records = items.map((it) => {
      const flagged = (it.samples || []).find((x) => x.flags && x.flags.length);
      return { trusted: it.trusted, untrusted: flagged ? flagged.untrusted : it.untrusted, floor: JSON.parse(this.db.prepare('SELECT floor FROM items WHERE id = ?').get(it.id).floor) };
    });
    const p = N.buildFieldPrompt(records, { maskState: st, subject: SUBJECT[items[0].source] || 'monitoring events', lang: this.lang });
    const audit = (rec) => this.db.prepare('INSERT INTO llm_audit(ts, item_ids, endpoint, endpoint_class, overrides, model, prompt_sha256, messages, reply, ms, error) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(this.now(), JSON.stringify(items.map((i) => i.id)), rec.endpoint, rec.endpoint_class, JSON.stringify(rec.endpoint_overrides || []), rec.model, rec.prompt_sha256, JSON.stringify(rec.messages), rec.reply ?? null, rec.ms ?? null, rec.error ?? null);
    let reply;
    try {
      const res = await this.chat(this.cfg.url, this.cfg.model, p.messages, {
        allowRemote: !!this.cfg.allowRemote, allowHttpLan: !!this.cfg.allowHttpLan, remoteHint: 'llm.allowRemote in the config', httpHint: 'llm.allowHttpLan in the config',
        apiKey: this.cfg.apiKey || undefined, timeoutMs: this.cfg.timeoutMs, maxTokens: Math.min(this.cfg.maxTokens, 300 + 150 * items.length), temperature: 0.2,
        audit, cmd: 'board', tool: 'netsec-board', cacheMs: 5 * 60000,
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
