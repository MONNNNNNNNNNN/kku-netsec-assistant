'use strict';
/*
 * HTTP layer: static board files, JSON API, SSE stream and push hooks.
 *  - every /api route except login needs a session; POST/PUT/DELETE also need the
 *    session's x-csrf-token header and a JSON content type
 *  - roles: viewer reads; operator pins, acks, snoozes, explains, pulls; admin also reads config
 *  - hooks: POST /hooks/{zabbix,wazuh,generic} with "Authorization: Bearer <hook token>"
 *  - strict CSP, nosniff, no referrer, no framing; bodies are size-limited
 */
const fs = require('node:fs');
const path = require('node:path');
const A = require('./auth.js');
const { logAction, sourceState, getMeta } = require('./db.js');
const { toItem } = require('./pipeline.js');
const trust = require('./trust.js');
const { redact } = require('./config.js');

const BOARD = path.join(__dirname, '..', 'board');
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/board.css': ['board.css', 'text/css; charset=utf-8'],
  '/board.js': ['board.js', 'text/javascript; charset=utf-8'],
  '/icon.svg': ['icon.svg', 'image/svg+xml'],
};
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const SEC_HEADERS = { 'content-security-policy': CSP, 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY', 'cross-origin-opener-policy': 'same-origin', 'permissions-policy': 'camera=(), microphone=(), geolocation=()' };

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

function send(res, status, body, headers = {}) {
  const isBuf = Buffer.isBuffer(body);
  const data = isBuf ? body : typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { ...SEC_HEADERS, 'cache-control': 'no-store', ...(isBuf || typeof body === 'string' ? {} : { 'content-type': 'application/json; charset=utf-8' }), ...headers });
  res.end(data);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const len = Number(req.headers['content-length'] || 0);
    if (len > limit) { reject(new HttpError(413, `body larger than ${limit} bytes`)); req.resume(); return; }
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) { reject(new HttpError(413, `body larger than ${limit} bytes`)); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req, limit) {
  const ct = String(req.headers['content-type'] || '');
  if (!/^application\/json\b/i.test(ct)) throw new HttpError(415, 'content-type must be application/json');
  const b = await readBody(req, limit);
  try { return b.length ? JSON.parse(b.toString('utf8')) : {}; } catch { throw new HttpError(400, 'invalid JSON'); }
}

class Bucket {
  constructor(perMin) { this.perMin = perMin; this.m = new Map(); }
  take(key, now = Date.now()) {
    let b = this.m.get(key);
    if (!b) { b = { t: this.perMin, at: now }; this.m.set(key, b); if (this.m.size > 10000) this.m.delete(this.m.keys().next().value); }
    b.t = Math.min(this.perMin, b.t + ((now - b.at) / 60000) * this.perMin); b.at = now;
    if (b.t < 1) return false;
    b.t -= 1; return true;
  }
}

function createHandler(app) {
  const { db, cfg } = app;
  const throttle = new A.Throttle();
  const hookBucket = new Bucket((cfg.hooks && cfg.hooks.ratePerMin) || 120);
  const lastView = new Map();
  const clientIp = (req) => (cfg.trustProxy && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress);

  function session(req) {
    const tok = A.parseCookies(req.headers.cookie)[A.COOKIE];
    return { tok, s: A.getSession(db, tok) };
  }
  function need(req, role) {
    const { s } = session(req);
    if (!s) throw new HttpError(401, 'login required');
    if (A.roleRank(s.user.role) < A.roleRank(role)) throw new HttpError(403, `needs role ${role}`);
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const t = String(req.headers['x-csrf-token'] || '');
      if (!t || !A.safeEqual(t, s.csrf)) throw new HttpError(403, 'missing or wrong CSRF token');
    }
    return s;
  }

  const itemRow = db.prepare('SELECT * FROM items WHERE id = ?');
  function itemOr404(id) {
    const r = itemRow.get(Number(id));
    if (!r) throw new HttpError(404, 'no such item');
    return r;
  }
  function changed(id) {
    const item = toItem(itemRow.get(id));
    app.broadcast('item', item);
    return item;
  }

  function summary(role) {
    const now = Date.now();
    const open = db.prepare("SELECT severity, COUNT(*) AS n FROM items WHERE resolved_at IS NULL AND acked_by IS NULL AND (snoozed_until IS NULL OR snoozed_until < ?) GROUP BY severity").all(now);
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const r of open) counts[r.severity] = r.n;
    const hour = 3600000, start = Math.floor(now / hour) * hour - 23 * hour;
    const spark = Array(24).fill(0);
    for (const r of db.prepare('SELECT first_seen FROM items WHERE first_seen >= ?').all(start)) {
      const i = Math.floor((r.first_seen - start) / hour);
      if (i >= 0 && i < 24) spark[i]++;
    }
    const sources = Object.entries(cfg.sources).map(([name, s]) => {
      const st = sourceState(db, name);
      return { name, enabled: !!s.enabled, mode: name === 'syslog' ? 'push' : 'pull', schedule: s.schedule || null, status: s.enabled ? st.status : 'off', lastRun: st.last_run, lastOk: st.last_ok, nextRun: name === 'syslog' ? null : st.next_run, lastError: st.last_error, fails: st.fails, received: st.received, filtered: st.filtered, dropped: st.dropped, droppedSenders: JSON.parse(st.dropped_senders || '{}'), unsupported: st.unsupported, kernelDrops: st.kernel_drops || 0 };
    });
    for (const h of ['zabbix', 'wazuh', 'generic']) {
      if (!cfg.hooks[h] || !cfg.hooks[h].token) continue;
      const st = sourceState(db, `hook:${h}`);
      sources.push({ name: `hook:${h}`, enabled: true, mode: 'push', status: st.received ? 'ok' : 'listening', lastOk: st.last_ok, received: st.received, filtered: st.filtered, dropped: st.dropped, droppedSenders: {} });
    }
    const configs = db.prepare("SELECT value FROM meta WHERE key LIKE 'config:%'").all().map((r) => JSON.parse(r.value)).sort((a, b) => String(b.analyzedAt).localeCompare(String(a.analyzedAt)));
    const out = { counts, spark, sparkStart: start, sources, llm: app.llmq.status(), configs, notifyMinSeverity: (cfg.board && cfg.board.notifyMinSeverity) || 'high' };
    if (role === 'admin') {
      const day = now - 86400000;
      const n = (a) => db.prepare('SELECT COUNT(*) AS n FROM user_actions WHERE action = ? AND ts > ?').get(a, day).n;
      out.security = { loginFailed24h: n('login-failed'), loginLocked24h: n('login-locked'), pendingDigest: Object.fromEntries(app.notifier.channels.map((c) => [c.name, app.notifier.pending(c)])) };
    }
    return out;
  }

  async function hook(req, res, name) {
    const h = cfg.hooks[name];
    if (!h || !h.token) throw new HttpError(404, 'hook not enabled');
    const ip = clientIp(req);
    if (!hookBucket.take(ip)) throw new HttpError(429, 'rate limit');
    const auth = String(req.headers.authorization || '');
    if (!auth.startsWith('Bearer ') || !A.safeEqual(auth.slice(7), h.token)) throw new HttpError(401, 'bad hook token');
    const body = await readJson(req, 1024 * 1024);
    const list = Array.isArray(body) ? body.slice(0, 500) : [body];
    let n = 0;
    for (const p of list) {
      if (!p || typeof p !== 'object') continue;
      const evt = name === 'zabbix' ? trust.zabbix(p, cfg.sources.zabbix) : name === 'wazuh' ? trust.wazuh(p.parameters && p.parameters.alert ? p.parameters.alert : p, p.id || p._id, cfg.sources.wazuh) : trust.generic(p);
      evt.trusted.via = `hook:${name}`;
      if (app.pipeline.ingest(evt, `hook:${name}`)) n++;
    }
    app.pipeline.flush();
    require('./db.js').updateSource(db, `hook:${name}`, { last_ok: Date.now(), status: 'ok' });
    send(res, 202, { accepted: n });
  }

  const routes = [
    ['GET', /^\/healthz$/, (req, res) => send(res, 200, { ok: true, version: app.version })],
    ['POST', /^\/api\/login$/, async (req, res) => {
      const b = await readJson(req, 4096);
      const ip = clientIp(req);
      const r = await A.login(db, throttle, b.username, b.password, ip);
      logAction(db, String(b.username || '').slice(0, 40), r.ok ? 'login' : 'login-failed', null, r.ok ? null : r.error, ip);
      if (r.lockedNow) logAction(db, String(b.username || '').slice(0, 40), 'login-locked', null, `account+address locked for 15 min after ${A.LOCK_AFTER} failures`, ip);
      if (!r.ok) return send(res, r.status, { error: r.error }, r.retryAfter ? { 'retry-after': String(r.retryAfter) } : {});
      const s = A.createSession(db, r.user.id, cfg.sessionHours || 12);
      send(res, 200, { user: r.user, csrf: s.csrf }, { 'set-cookie': A.sessionCookie(s.token, { secure: cfg.cookieSecure, hours: cfg.sessionHours || 12 }) });
    }],
    ['POST', /^\/api\/logout$/, (req, res) => {
      const s = need(req, 'viewer');
      const tok = session(req).tok;
      A.destroySession(db, tok);
      app.sseEndSession(A.sha(tok));
      logAction(db, s.user.username, 'logout', null, null, clientIp(req));
      send(res, 200, { ok: true }, { 'set-cookie': A.clearCookie(cfg.cookieSecure) });
    }],
    ['GET', /^\/api\/me$/, (req, res) => { const s = need(req, 'viewer'); send(res, 200, { user: s.user, csrf: s.csrf, lang: cfg.lang }); }],
    ['GET', /^\/api\/items$/, (req, res) => {
      const s = need(req, 'viewer');
      const day = Date.now() - 86400000;
      // pinned cards always come back, however many newer items exist
      const rows = db.prepare(`SELECT * FROM items WHERE pinned_at IS NOT NULL
        UNION SELECT * FROM (SELECT * FROM items WHERE resolved_at IS NULL OR resolved_at > ? ORDER BY last_seen DESC LIMIT 600)
        ORDER BY last_seen DESC`).all(day);
      const k = s.user.username;
      if (!lastView.has(k) || Date.now() - lastView.get(k) > 600000) { lastView.set(k, Date.now()); logAction(db, k, 'view-items', null, `${rows.length} items`, clientIp(req)); }
      send(res, 200, { items: rows.map(toItem) });
    }],
    ['GET', /^\/api\/summary$/, (req, res) => { const s = need(req, 'viewer'); send(res, 200, summary(s.user.role)); }],
    ['POST', /^\/api\/items\/(\d+)\/(pin|ack|snooze|explain|view)$/, async (req, res, m) => {
      const action = m[2];
      const s = need(req, action === 'view' ? 'viewer' : 'operator');
      const b = await readJson(req, 4096);
      const r = itemOr404(m[1]);
      const now = Date.now(), who = s.user.username, ip = clientIp(req);
      if (action === 'view') { logAction(db, who, 'view-item', r.id, null, ip); return send(res, 200, { ok: true }); }
      if (action === 'pin') {
        const on = b.pinned !== false;
        db.prepare('UPDATE items SET pinned_by = ?, pinned_at = ? WHERE id = ?').run(on ? who : null, on ? now : null, r.id);
        logAction(db, who, on ? 'pin' : 'unpin', r.id, null, ip);
      } else if (action === 'ack') {
        const on = b.acked !== false;
        db.prepare('UPDATE items SET acked_by = ?, acked_at = ? WHERE id = ?').run(on ? who : null, on ? now : null, r.id);
        logAction(db, who, on ? 'ack' : 'unack', r.id, null, ip);
      } else if (action === 'snooze') {
        const hours = Number(b.hours);
        if (![0, 1, 8, 24].includes(hours)) throw new HttpError(400, 'hours must be 0, 1, 8 or 24');
        db.prepare('UPDATE items SET snoozed_until = ?, snoozed_by = ? WHERE id = ?').run(hours ? now + hours * 3600000 : null, hours ? who : null, r.id);
        logAction(db, who, hours ? `snooze ${hours}h` : 'unsnooze', r.id, null, ip);
      } else if (action === 'explain') {
        const q = app.llmq.enqueue(r.id, true);
        logAction(db, who, 'explain', r.id, null, ip);
        return send(res, 202, { queued: true, ...q, llm: app.llmq.status() });
      }
      send(res, 200, { item: changed(r.id) });
    }],
    ['POST', /^\/api\/sources\/([\w:-]+)\/pull$/, async (req, res, m) => {
      const s = need(req, 'operator');
      await readJson(req, 1024);
      if (!app.scheduler.jobs.has(m[1])) throw new HttpError(404, 'not a pull source (or disabled)');
      logAction(db, s.user.username, 'pull-now', null, m[1], clientIp(req));
      const r = await app.scheduler.run(m[1]);
      send(res, 200, r);
    }],
    ['GET', /^\/api\/config$/, (req, res) => { need(req, 'admin'); send(res, 200, redact(app.rawConfig)); }],
    ['GET', /^\/api\/events$/, (req, res) => {
      const s = need(req, 'viewer');
      res.writeHead(200, { ...SEC_HEADERS, 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store', connection: 'keep-alive', 'x-accel-buffering': 'no' });
      res.write(`retry: 3000\nevent: hello\ndata: ${JSON.stringify({ user: s.user.username })}\n\n`);
      app.sseAdd(res, A.sha(session(req).tok));
      req.on('close', () => app.sseDrop(res));
    }],
    ['POST', /^\/hooks\/(zabbix|wazuh|generic)$/, (req, res, m) => hook(req, res, m[1])],
  ];

  return async function handler(req, res) {
    const url = new URL(req.url, 'http://x');
    try {
      if (req.method === 'GET' && STATIC[url.pathname]) {
        const [f, type] = STATIC[url.pathname];
        return send(res, 200, fs.readFileSync(path.join(BOARD, f)), { 'content-type': type, 'cache-control': 'no-cache' });
      }
      for (const [method, re, fn] of routes) {
        const m = url.pathname.match(re);
        if (m && req.method === method) return await fn(req, res, m);
      }
      throw new HttpError(404, 'not found');
    } catch (e) {
      if (res.headersSent) { res.end(); return; }
      const status = e.status || 500;
      send(res, status, { error: status === 500 ? 'internal error' : e.message });
      if (status === 500) app.log && app.log(`500 ${req.method} ${url.pathname}: ${e.stack || e.message}`);
    }
  };
}

module.exports = { createHandler, HttpError, CSP, readBody };
