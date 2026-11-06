'use strict';
/*
 * Cron schedules: standard 5 fields (minute hour day-of-month month day-of-week) with
 * "*", step "*\/n", ranges "a-b", "a-b/n" and lists; day-of-week 0-7 (0 and 7 = Sunday). When both day fields
 * are restricted, either may match (Vixie cron). Times are evaluated at a fixed UTC
 * offset (Asia/Bangkok = +420 min, no DST). Also "@every 30s|5m|1h" for intervals, and
 * "external" when system cron runs the pull instead (the built-in scheduler then skips it).
 */
const FIELDS = [
  ['minute', 0, 59], ['hour', 0, 23], ['dom', 1, 31], ['month', 1, 12], ['dow', 0, 7],
];
const ALIAS = { '@hourly': '0 * * * *', '@daily': '0 0 * * *', '@weekly': '0 0 * * 0', '@monthly': '0 0 1 * *' };

function parseField(src, min, max, name) {
  const set = new Set();
  for (const part of src.split(',')) {
    const m = part.match(/^(\*|(\d+)(?:-(\d+))?)(?:\/(\d+))?$/);
    if (!m) throw new Error(`cron ${name}: bad "${part}"`);
    let lo = min, hi = max;
    if (m[1] !== '*') { lo = Number(m[2]); hi = m[3] !== undefined ? Number(m[3]) : m[4] ? max : lo; }
    const step = m[4] ? Number(m[4]) : 1;
    if (lo < min || hi > max || lo > hi || step < 1) throw new Error(`cron ${name}: "${part}" out of range ${min}-${max}`);
    for (let v = lo; v <= hi; v += step) set.add(v);
  }
  return set;
}

function parse(expr) {
  const e = String(expr || '').trim();
  if (e === 'external') return { external: true, expr: e }; // run by system cron: `cli/board.js pull <source>`
  const every = e.match(/^@every\s+(\d+)(s|m|h)$/);
  if (every) {
    const ms = Number(every[1]) * { s: 1000, m: 60000, h: 3600000 }[every[2]];
    if (ms < 1000) throw new Error('cron @every: at least 1s');
    return { every: ms, expr: e };
  }
  const parts = (ALIAS[e] || e).split(/\s+/);
  if (parts.length !== 5) throw new Error(`cron: need 5 fields, got "${e}"`);
  const out = { expr: e };
  FIELDS.forEach(([name, min, max], i) => { out[name] = parseField(parts[i], min, max, name); });
  if (out.dow.has(7)) out.dow.add(0);
  out.domStar = parts[2] === '*';
  out.dowStar = parts[4] === '*';
  return out;
}

/** Next fire time strictly after `from` (ms epoch), evaluated at the given UTC offset. */
function next(spec, from = Date.now(), tzOffsetMinutes = 420) {
  const s = typeof spec === 'string' ? parse(spec) : spec;
  if (s.external) return null;
  if (s.every) return from + s.every;
  const off = tzOffsetMinutes * 60000;
  // work in "local" time by shifting into a UTC Date
  let t = Math.floor((from + off) / 60000) * 60000 + 60000;
  const limit = t + 366 * 86400000 * 5;
  while (t < limit) {
    const d = new Date(t);
    if (!s.month.has(d.getUTCMonth() + 1)) { d.setUTCMonth(d.getUTCMonth() + 1, 1); d.setUTCHours(0, 0, 0, 0); t = d.getTime(); continue; }
    const domOk = s.dom.has(d.getUTCDate()), dowOk = s.dow.has(d.getUTCDay());
    const dayOk = s.domStar && s.dowStar ? true : s.domStar ? dowOk : s.dowStar ? domOk : domOk || dowOk;
    if (!dayOk) { d.setUTCDate(d.getUTCDate() + 1); d.setUTCHours(0, 0, 0, 0); t = d.getTime(); continue; }
    if (!s.hour.has(d.getUTCHours())) { d.setUTCHours(d.getUTCHours() + 1, 0, 0, 0); t = d.getTime(); continue; }
    if (!s.minute.has(d.getUTCMinutes())) { t += 60000; continue; }
    return t - off;
  }
  throw new Error(`cron: no fire time within 5 years for "${s.expr}"`);
}

/** Typical gap between runs, used to bound jitter. */
function period(spec, from = Date.now(), tz = 420) {
  const s = typeof spec === 'string' ? parse(spec) : spec;
  if (s.external) return null;
  if (s.every) return s.every;
  const a = next(s, from, tz);
  return next(s, a, tz) - a;
}

module.exports = { parse, next, period };
