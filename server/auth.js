'use strict';
/*
 * Users, sessions, CSRF and login throttling.
 *  - passwords: scrypt (N=16384, r=8, p=1), constant-time compare. Login checks use the async
 *    scrypt (thread pool), at most 20 at a time, so a login spray cannot stall syslog intake.
 *  - session: random 32-byte token in an HttpOnly SameSite=Strict cookie; only its sha256 is stored
 *  - CSRF: every state-changing /api request needs the per-session x-csrf-token header
 *  - throttling, without handing an attacker a way to lock out the admin:
 *      per IP:              after 5 failures each attempt waits 2^(n-5) s (max 15 min)
 *      per account + IP:    10 failures lock that pair for 15 minutes
 *      per account:         backoff only, max 30 s, and not for an address that logged in
 *                           successfully as this user in the last 30 days
 *    IPv6 addresses count per /64 (one host can rotate through a whole /64). At most 2 checks
 *    run at once per address, and 4 of the 20 slots are kept for (user, address) pairs that
 *    logged in before, so a spray from many addresses cannot lock everyone out with 503s.
 */
const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scryptAsync = promisify(crypto.scrypt);
const ROLES = ['viewer', 'operator', 'admin'];
const roleRank = (r) => ROLES.indexOf(r);
const COOKIE = 'nsb_sid';
const LOCK_AFTER = 10, SLOW_AFTER = 5, LOCK_MS = 15 * 60000, ACCOUNT_MAX_WAIT = 30000, KNOWN_MS = 30 * 86400000, MAX_CHECKS = 20, RESERVED_CHECKS = 4, PER_ADDRESS_CHECKS = 2;
const net = require('node:net');

/** Throttle key for an address: IPv4 as is, IPv6 by its /64. */
function ipKey(ip) {
  const s = String(ip || '').replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, '$1');
  if (!net.isIPv6(s)) return s;
  const [head, tail = ''] = s.split('::');
  const a = head ? head.split(':') : [], b = s.includes('::') && tail ? tail.split(':') : [];
  const full = s.includes('::') ? [...a, ...Array(8 - a.length - b.length).fill('0'), ...b] : a;
  return `${full.slice(0, 4).map((h) => parseInt(h, 16).toString(16)).join(':')}::/64`;
}
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const SCRYPT = { N: 16384, r: 8, p: 1 };

/** Sync hash: CLI and setup only (never on the request path). */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(pw), salt, 64, SCRYPT);
  return `scrypt$16384$8$1$${salt.toString('base64')}$${h.toString('base64')}`;
}
function parseHash(stored) {
  const [alg, N, r, p, salt, hash] = String(stored).split('$');
  return alg === 'scrypt' ? { opts: { N: Number(N), r: Number(r), p: Number(p) }, salt: Buffer.from(salt, 'base64'), want: Buffer.from(hash, 'base64') } : null;
}
function verifyPassword(pw, stored) {
  const h = parseHash(stored);
  return !!h && crypto.timingSafeEqual(h.want, crypto.scryptSync(String(pw), h.salt, h.want.length, h.opts));
}
async function verifyPasswordAsync(pw, stored) {
  const h = parseHash(stored);
  return !!h && crypto.timingSafeEqual(h.want, await scryptAsync(String(pw), h.salt, h.want.length, h.opts));
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
/**
 * First start after `cli/board.js setup`: no user yet, and secrets.env carries the admin's
 * scrypt hash (NETSEC_ADMIN_HASH, NETSEC_ADMIN_USER). Creates that admin. Returns the name or null.
 */
function bootstrapAdmin(db, env = process.env) {
  const hash = env.NETSEC_ADMIN_HASH;
  if (!hash || !parseHash(hash)) return null;
  if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n) return null;
  const name = /^[a-z0-9._-]{2,40}$/i.test(env.NETSEC_ADMIN_USER || '') ? env.NETSEC_ADMIN_USER : 'admin';
  db.prepare('INSERT INTO users(username, pass_hash, role, created) VALUES(?, ?, ?, ?)').run(name, hash, 'admin', new Date().toISOString());
  return name;
}

function setPassword(db, username, password) {
  if (String(password).length < 10) throw new Error('password must be at least 10 characters');
  const n = db.prepare('UPDATE users SET pass_hash = ?, failed = 0, locked_until = 0 WHERE username = ?').run(hashPassword(password), username).changes;
  if (!n) throw new Error(`no user ${username}`);
  db.prepare('DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)').run(username);
}

class Throttle {
  constructor(now = () => Date.now(), maxChecks = MAX_CHECKS) {
    this.ip = new Map(); this.pair = new Map(); this.now = now; this.active = 0; this.maxChecks = maxChecks;
    this.inflight = new Map();
    // the account backoff for user names that do not exist, so its answer does not reveal which do
    this.ghost = new Map();
  }
  ghostGet(name) { return this.ghost.get(name) || { failed: 0, locked_until: 0 }; }
  ghostFail(name, now) {
    const g = this.ghostGet(name);
    g.failed++;
    g.locked_until = g.failed >= SLOW_AFTER ? now + Math.min(ACCOUNT_MAX_WAIT, 1000 * 2 ** (g.failed - SLOW_AFTER)) : 0;
    this.ghost.delete(name); this.ghost.set(name, g);
    if (this.ghost.size > 10000) this.ghost.delete(this.ghost.keys().next().value);
  }
  /** ms the caller must still wait, 0 if allowed */
  wait(ipRaw) {
    const r = this.ip.get(ipKey(ipRaw));
    return r ? Math.max(0, r.until - this.now()) : 0;
  }
  fail(ipRaw) {
    const ip = ipKey(ipRaw);
    const r = this.ip.get(ip) || { n: 0, until: 0 };
    r.n++;
    r.until = this.now() + (r.n >= SLOW_AFTER ? Math.min(LOCK_MS, 1000 * 2 ** (r.n - SLOW_AFTER)) : 0);
    this.ip.set(ip, r);
    if (this.ip.size > 10000) this.ip.delete(this.ip.keys().next().value);
  }
  ok(ip) { this.ip.delete(ipKey(ip)); }
  pairKey(user, ip) { return JSON.stringify([user, ipKey(ip)]); }
  pairWait(user, ip) {
    const r = this.pair.get(this.pairKey(user, ip));
    return r ? Math.max(0, r.until - this.now()) : 0;
  }
  /** returns true when this failure locks the pair */
  pairFail(user, ip) {
    const k = this.pairKey(user, ip);
    const r = this.pair.get(k) || { n: 0, until: 0 };
    r.n++;
    const locked = r.n >= LOCK_AFTER;
    if (locked) { r.until = this.now() + LOCK_MS; r.n = 0; }
    this.pair.set(k, r);
    if (this.pair.size > 10000) this.pair.delete(this.pair.keys().next().value);
    return locked;
  }
  pairOk(user, ip) { this.pair.delete(this.pairKey(user, ip)); }
  /** A password-check slot. `known`: this (user, address) logged in before, may use the reserve. */
  acquire(ipRaw, known = false) {
    const k = ipKey(ipRaw);
    const mine = this.inflight.get(k) || 0;
    const cap = known ? this.maxChecks : this.maxChecks - Math.min(RESERVED_CHECKS, this.maxChecks - 1);
    if (this.active >= cap || mine >= PER_ADDRESS_CHECKS) return false;
    this.active++; this.inflight.set(k, mine + 1);
    return true;
  }
  release(ipRaw) {
    this.active = Math.max(0, this.active - 1);
    const k = ipKey(ipRaw), mine = (this.inflight.get(k) || 1) - 1;
    if (mine > 0) this.inflight.set(k, mine); else this.inflight.delete(k);
  }
}

/**
 * Returns {ok:true, user} or {ok:false, status, error, retryAfter, lockedNow}.
 * The same error text for unknown user and wrong password.
 */
async function login(db, throttle, username, password, ip, now = Date.now()) {
  const name = String(username || '');
  const ipWait = throttle.wait(ip);
  if (ipWait > 0) return { ok: false, status: 429, error: 'too many attempts, wait', retryAfter: Math.ceil(ipWait / 1000) };
  const pairWait = throttle.pairWait(name, ip);
  if (pairWait > 0) return { ok: false, status: 429, error: 'locked for this address, try later', retryAfter: Math.ceil(pairWait / 1000) };
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(name);
  const known = u && db.prepare('SELECT 1 FROM login_known WHERE user_id = ? AND ip = ? AND last_ok > ?').get(u.id, String(ip), now - KNOWN_MS);
  const acct = u || throttle.ghostGet(name); // same backoff and same answer whether or not the user exists
  if (!known && acct.locked_until > now) return { ok: false, status: 429, error: 'too many failures for this account, wait', retryAfter: Math.ceil((acct.locked_until - now) / 1000) };
  if (!throttle.acquire(ip, !!known)) return { ok: false, status: 503, error: 'busy, retry', retryAfter: 1 };
  let good;
  try { good = (await verifyPasswordAsync(String(password || ''), u ? u.pass_hash : DUMMY)) && !!u; } finally { throttle.release(ip); }
  if (!good) {
    throttle.fail(ip);
    const lockedNow = throttle.pairFail(name, ip);
    if (u) {
      const failed = u.failed + 1;
      const until = failed >= SLOW_AFTER ? now + Math.min(ACCOUNT_MAX_WAIT, 1000 * 2 ** (failed - SLOW_AFTER)) : 0;
      db.prepare('UPDATE users SET failed = ?, locked_until = ? WHERE id = ?').run(failed, until, u.id);
    } else throttle.ghostFail(name, now);
    return { ok: false, status: 401, error: 'wrong username or password', lockedNow };
  }
  throttle.ok(ip); throttle.pairOk(name, ip);
  db.prepare('UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?').run(u.id);
  db.prepare('INSERT INTO login_known(user_id, ip, last_ok) VALUES(?, ?, ?) ON CONFLICT(user_id, ip) DO UPDATE SET last_ok = excluded.last_ok').run(u.id, String(ip), now);
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
    if (i <= 0) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* malformed: ignore this cookie */ }
  }
  return out;
}
function sessionCookie(token, { secure, hours }) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.round(hours * 3600)}${secure ? '; Secure' : ''}`;
}
const clearCookie = (secure) => `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`;

module.exports = { bootstrapAdmin, ROLES, roleRank, COOKIE, hashPassword, verifyPassword, verifyPasswordAsync, safeEqual, randomPassword, addUser, setPassword, Throttle, login, createSession, getSession, destroySession, parseCookies, sessionCookie, clearCookie, sha, ipKey, LOCK_AFTER, SLOW_AFTER, ACCOUNT_MAX_WAIT, RESERVED_CHECKS };
