'use strict';
/*
 * Users, sessions, CSRF and login throttling.
 *  - passwords: scrypt (N=16384, r=8, p=1), constant-time compare
 *  - session: random 32-byte token in an HttpOnly SameSite=Strict cookie; only its sha256 is stored
 *  - CSRF: every state-changing /api request needs the per-session x-csrf-token header
 *  - throttling: per IP and per account; after 5 failures each attempt waits 2^(n-5) s,
 *    after 10 failures the account is locked for 15 minutes
 */
const crypto = require('node:crypto');

const ROLES = ['viewer', 'operator', 'admin'];
const roleRank = (r) => ROLES.indexOf(r);
const COOKIE = 'nsb_sid';
const LOCK_AFTER = 10, SLOW_AFTER = 5, LOCK_MS = 15 * 60000;
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(pw), salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString('base64')}$${h.toString('base64')}`;
}
function verifyPassword(pw, stored) {
  const [alg, N, r, p, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const want = Buffer.from(hash, 'base64');
  const got = crypto.scryptSync(String(pw), Buffer.from(salt, 'base64'), want.length, { N: Number(N), r: Number(r), p: Number(p) });
  return crypto.timingSafeEqual(want, got);
}
const DUMMY = hashPassword(crypto.randomBytes(8).toString('hex')); // equalises timing for unknown users

/** Constant-time string compare (via digests, so lengths do not leak). */
function safeEqual(a, b) {
  return crypto.timingSafeEqual(Buffer.from(sha(a), 'hex'), Buffer.from(sha(b), 'hex'));
}

function randomPassword() {
  return crypto.randomBytes(12).toString('base64url');
}

function addUser(db, username, password, role = 'viewer') {
  if (!/^[a-z0-9._-]{2,40}$/i.test(username)) throw new Error('username: 2-40 chars of a-z 0-9 . _ -');
  if (!ROLES.includes(role)) throw new Error(`role must be one of ${ROLES.join(', ')}`);
  if (String(password).length < 10) throw new Error('password must be at least 10 characters');
  db.prepare('INSERT INTO users(username, pass_hash, role, created) VALUES(?, ?, ?, ?)').run(username, hashPassword(password), role, new Date().toISOString());
}
function setPassword(db, username, password) {
  if (String(password).length < 10) throw new Error('password must be at least 10 characters');
  const n = db.prepare('UPDATE users SET pass_hash = ?, failed = 0, locked_until = 0 WHERE username = ?').run(hashPassword(password), username).changes;
  if (!n) throw new Error(`no user ${username}`);
  db.prepare('DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)').run(username);
}

class Throttle {
  constructor(now = () => Date.now()) { this.ip = new Map(); this.now = now; }
  /** ms the caller must still wait, 0 if allowed */
  wait(ip) {
    const r = this.ip.get(ip);
    return r ? Math.max(0, r.until - this.now()) : 0;
  }
  fail(ip) {
    const r = this.ip.get(ip) || { n: 0, until: 0 };
    r.n++;
    r.until = this.now() + (r.n >= SLOW_AFTER ? Math.min(LOCK_MS, 1000 * 2 ** (r.n - SLOW_AFTER)) : 0);
    this.ip.set(ip, r);
    if (this.ip.size > 10000) this.ip.delete(this.ip.keys().next().value);
  }
  ok(ip) { this.ip.delete(ip); }
}

/**
 * Returns {ok:true, user} or {ok:false, status, error, retryAfter}.
 * The same error text for unknown user and wrong password.
 */
function login(db, throttle, username, password, ip, now = Date.now()) {
  const ipWait = throttle.wait(ip);
  if (ipWait > 0) return { ok: false, status: 429, error: 'too many attempts, wait', retryAfter: Math.ceil(ipWait / 1000) };
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username || ''));
  if (u && u.locked_until > now) return { ok: false, status: 429, error: 'account locked, try later', retryAfter: Math.ceil((u.locked_until - now) / 1000) };
  const good = verifyPassword(String(password || ''), u ? u.pass_hash : DUMMY) && !!u;
  if (!good) {
    throttle.fail(ip);
    if (u) {
      const failed = u.failed + 1;
      const until = failed >= LOCK_AFTER ? now + LOCK_MS : failed >= SLOW_AFTER ? now + 1000 * 2 ** (failed - SLOW_AFTER) : 0;
      db.prepare('UPDATE users SET failed = ?, locked_until = ? WHERE id = ?').run(failed >= LOCK_AFTER ? 0 : failed, until, u.id);
    }
    return { ok: false, status: 401, error: 'wrong username or password' };
  }
  throttle.ok(ip);
  db.prepare('UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?').run(u.id);
  return { ok: true, user: { id: u.id, username: u.username, role: u.role } };
}

function createSession(db, userId, hours, now = Date.now()) {
  const token = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  db.prepare('INSERT INTO sessions(token_hash, user_id, csrf, created, expires) VALUES(?, ?, ?, ?, ?)').run(sha(token), userId, csrf, now, now + hours * 3600000);
  return { token, csrf };
}
function getSession(db, token, now = Date.now()) {
  if (!token) return null;
  const r = db.prepare('SELECT s.csrf, s.expires, u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?').get(sha(token));
  if (!r || r.expires < now) return null;
  return { user: { id: r.id, username: r.username, role: r.role }, csrf: r.csrf };
}
function destroySession(db, token) { if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(token)); }

function parseCookies(h) {
  const out = {};
  for (const part of String(h || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function sessionCookie(token, { secure, hours }) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.round(hours * 3600)}${secure ? '; Secure' : ''}`;
}
const clearCookie = (secure) => `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`;

module.exports = { ROLES, roleRank, COOKIE, hashPassword, verifyPassword, safeEqual, randomPassword, addUser, setPassword, Throttle, login, createSession, getSession, destroySession, parseCookies, sessionCookie, clearCookie, sha, LOCK_AFTER, SLOW_AFTER };
