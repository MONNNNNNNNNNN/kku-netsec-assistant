'use strict';
/*
 * Built-in cron for pull sources: no overlapping runs, jitter (up to 10% of the period,
 * max 30 s) so many boards do not hit one API at the same second, and exponential
 * backoff after failures (1 min, 2 min, ... max 1 h). Status: ok -> degraded (1-2 failed
 * runs in a row) -> down (3+). Every run is recorded in `runs`.
 * The same job can be run once from system cron instead: `node cli/board.js pull <source>`.
 */
const { EventEmitter } = require('node:events');
const cron = require('./cron.js');
const { sourceState, updateSource } = require('./db.js');
const { pullLock } = require('./lock.js');

const MAX_DELAY = 2 ** 31 - 1;

class Scheduler extends EventEmitter {
  constructor({ db, tzOffsetMinutes = 420, jitter = true, now = () => Date.now(), backoffBaseMs = 60000, lockDir = null }) {
    super();
    this.db = db; this.tz = tzOffsetMinutes; this.jitter = jitter; this.now = now; this.backoffBaseMs = backoffBaseMs; this.lockDir = lockDir;
    this.jobs = new Map(); this.stopped = true;
  }

  /** fn(ctx) -> {n} ; ctx = { cursor, setCursor(obj) } */
  add(name, schedule, fn) {
    this.jobs.set(name, { name, spec: cron.parse(schedule), fn, timer: null, running: null });
    sourceState(this.db, name);
  }

  /** runOnStart: pull each source once shortly after boot (staggered), then follow its schedule. */
  start({ runOnStart = true } = {}) {
    this.stopped = false;
    let k = 0;
    for (const j of this.jobs.values()) {
      if (!runOnStart || j.spec.external) { this.plan(j); continue; }
      const at = this.now() + 1500 * ++k;
      updateSource(this.db, j.name, { next_run: at });
      j.timer = setTimeout(() => this.run(j.name).catch(() => {}), at - this.now());
      if (j.timer.unref) j.timer.unref();
    }
  }

  stop() {
    this.stopped = true;
    for (const j of this.jobs.values()) { clearTimeout(j.timer); j.timer = null; }
  }

  plan(j) {
    clearTimeout(j.timer);
    if (this.stopped) return;
    if (j.spec.external) { updateSource(this.db, j.name, { next_run: null }); this.emit('source', j.name); return; }
    const now = this.now();
    const st = sourceState(this.db, j.name);
    let at;
    if (st.fails > 0) at = now + Math.min(this.backoffBaseMs * 2 ** (st.fails - 1), 3600000);
    else {
      at = cron.next(j.spec, now, this.tz);
      if (this.jitter) at += Math.floor(Math.random() * Math.min(30000, cron.period(j.spec, now, this.tz) * 0.1));
    }
    updateSource(this.db, j.name, { next_run: at });
    const arm = () => {
      const d = at - this.now();
      if (d > MAX_DELAY) j.timer = setTimeout(arm, MAX_DELAY);
      else j.timer = setTimeout(() => this.run(j.name).catch(() => {}), Math.max(0, d));
      if (j.timer.unref) j.timer.unref();
    };
    arm();
    this.emit('source', j.name);
  }

  /** Run one job now (also used by "Pull now" and the CLI). Concurrent calls share the run. */
  run(name) {
    const j = this.jobs.get(name);
    if (!j) return Promise.reject(new Error(`unknown source ${name}`));
    if (j.running) return j.running;
    j.running = this._run(j).finally(() => { j.running = null; this.plan(j); });
    return j.running;
  }

  async _run(j) {
    // one run per source across processes (server, "Pull now", cron CLI): same cursor otherwise
    const lock = this.lockDir ? pullLock(this.lockDir, j.name) : { release() {} };
    if (!lock) return { ok: true, skipped: true, n: 0 };
    try { return await this._runLocked(j); } finally { lock.release(); }
  }

  async _runLocked(j) {
    const started = this.now();
    updateSource(this.db, j.name, { last_run: started, status: 'running' });
    this.emit('source', j.name);
    const st = sourceState(this.db, j.name);
    let cursor = null;
    try { cursor = st.cursor ? JSON.parse(st.cursor) : null; } catch { cursor = null; }
    const ctx = { cursor, setCursor: (c) => updateSource(this.db, j.name, { cursor: JSON.stringify(c) }) };
    try {
      const r = (await j.fn(ctx)) || {};
      updateSource(this.db, j.name, { last_ok: this.now(), last_error: null, fails: 0, status: 'ok' });
      this.db.prepare('INSERT INTO runs(source, started, ms, ok, n) VALUES(?, ?, ?, 1, ?)').run(j.name, started, this.now() - started, r.n || 0);
      return { ok: true, n: r.n || 0 };
    } catch (e) {
      const fails = sourceState(this.db, j.name).fails + 1;
      updateSource(this.db, j.name, { last_error: String(e.message).slice(0, 500), fails, status: fails >= 3 ? 'down' : 'degraded' });
      this.db.prepare('INSERT INTO runs(source, started, ms, ok, n, error) VALUES(?, ?, ?, 0, 0, ?)').run(j.name, started, this.now() - started, String(e.message).slice(0, 500));
      return { ok: false, error: e.message };
    } finally {
      this.emit('source', j.name);
    }
  }
}

module.exports = { Scheduler };
