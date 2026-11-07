'use strict';
/*
 * Notifications. The board (SSE toasts, bell, browser Notification) is always on; these
 * channels are optional: ntfy, Telegram, LINE (Messaging API), webhook (HMAC-signed).
 * Email: use ntfy's e-mail forwarding (`email` on the ntfy channel) or a webhook to the
 * campus relay; there is deliberately no SMTP client here.
 *
 * Rules per channel: minSeverity, sources, quiet hours (Asia/Bangkok, `except` severity
 * still goes through), rate limit (overflow goes into the digest), daily cap, and
 * re-notify only when an item's severity rises. Cloud channels (Telegram, LINE, public
 * ntfy.sh) only ever get masked text: IPs, hostnames, e-mails and account names become tokens.
 */
const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');
const N = require('../src/core.js');
const { request } = require('./net.js');
const { sevRank } = require('./config.js');
const { getMeta, setMeta } = require('./db.js');
const { toItem } = require('./pipeline.js');

const TYPE_DEFAULTS = {
  ntfy: { cloud: false, mode: 'immediate' },
  telegram: { cloud: true, mode: 'immediate' },
  line: { cloud: true, mode: 'digest', maxPerDay: 8, digestEveryMinutes: 180 },
  webhook: { cloud: false, mode: 'immediate' },
};
const PRIORITY = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function channelConfig(c) {
  const d = TYPE_DEFAULTS[c.type] || {};
  const out = { enabled: true, minSeverity: 'high', sources: [], rateLimit: { max: 20, perMinutes: 10 }, digestEveryMinutes: 60, maxPerDay: 500, ...d, ...c };
  if (c.type === 'ntfy' && c.cloud === undefined && /(^|\.)ntfy\.sh$/i.test(safeHost(c.url))) out.cloud = true;
  return out;
}
function safeHost(u) { try { return new URL(u).hostname; } catch { return ''; } }

// internal host names that are not FQDNs (so core.mask would not catch them)
const HOST_FIELDS = ['devname', 'hostname', 'srcname', 'dstname', 'agent.name', 'agent.ip', 'manager.name', 'hosts', 'host', 'device'];

/**
 * Mask text for a cloud channel: IPs, FQDNs, e-mails, plus the account and host names of
 * every item in it (a digest passes all its items: masking only one would leak the others).
 */
function maskForCloud(text, items) {
  let t = String(text);
  const list = (Array.isArray(items) ? items : [items]).filter(Boolean);
  const values = (k) => list.flatMap((it) => [it.trusted && it.trusted[k], it.untrusted && it.untrusted[k]]);
  const pick = (keys) => [...new Set(keys.flatMap((k) => values(k).flatMap((v) => String(v ?? '').split(/,\s*/))).filter((v) => v.length >= 2 && v !== 'N/A'))];
  // whole tokens only: a short user name ("old") must not mangle words ("folder" -> "fUSER_1er")
  const esc = (v) => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const swap = (vals, kind) => {
    vals.sort((a, b) => b.length - a.length).forEach((v, i) => { t = t.replace(new RegExp(`(?<![A-Za-z0-9])${esc(v)}(?![A-Za-z0-9])`, 'g'), `${kind}_${i + 1}`); });
  };
  swap(pick(N.USER_FIELDS), 'USER');
  swap(pick(HOST_FIELDS), 'HOSTNAME');
  return N.mask(t, N.newMaskState()).text;
}

function localParts(ts, tz) {
  const d = new Date(ts + tz * 60000);
  return { minutes: d.getUTCHours() * 60 + d.getUTCMinutes(), dayStart: Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - tz * 60000 };
}
function inQuiet(q, ts, tz) {
  if (!q || !q.start || !q.end) return false;
  const toMin = (s) => { const [h, m] = String(s).split(':').map(Number); return h * 60 + (m || 0); };
  const { minutes } = localParts(ts, tz);
  const a = toMin(q.start), b = toMin(q.end);
  return a <= b ? minutes >= a && minutes < b : minutes >= a || minutes < b;
}

const itemId = (item) => (item && !Array.isArray(item) && item.id != null ? item.id : null);

function itemLine(item) {
  return `[${String(item.severity).toUpperCase()}] ${item.source}: ${item.title}${item.count > 1 ? ` (x${item.count})` : ''}`;
}

const SENDERS = {
  async ntfy(ch, msg) {
    const r = await request(ch.url, {
      body: { topic: ch.topic, title: msg.title, message: msg.text, priority: PRIORITY[msg.severity] || 3, tags: [msg.severity], ...(msg.link ? { click: msg.link } : {}), ...(ch.email ? { email: ch.email } : {}) },
      headers: ch.token ? { authorization: `Bearer ${ch.token}` } : {},
    });
    if (r.status >= 300) throw new Error(`ntfy HTTP ${r.status}`);
  },
  async telegram(ch, msg) {
    const base = (ch.apiBase || 'https://api.telegram.org').replace(/\/+$/, '');
    const r = await request(`${base}/bot${ch.botToken}/sendMessage`, { body: { chat_id: ch.chatId, text: `${msg.title}\n${msg.text}`.slice(0, 4000), disable_web_page_preview: true } });
    if (r.status >= 300) throw new Error(`telegram HTTP ${r.status}`); // the URL holds the token: never put it in the error
  },
  async line(ch, msg) {
    const base = (ch.apiBase || 'https://api.line.me').replace(/\/+$/, '');
    const r = await request(`${base}/v2/bot/message/push`, { body: { to: ch.to, messages: [{ type: 'text', text: `${msg.title}\n${msg.text}`.slice(0, 4900) }] }, headers: { authorization: `Bearer ${ch.channelToken}` } });
    if (r.status >= 300) throw new Error(`LINE HTTP ${r.status}: ${(r.json && r.json.message) || ''}`.trim());
  },
  async webhook(ch, msg) {
    const body = JSON.stringify({ event: msg.digest ? 'netsec.digest' : 'netsec.item', title: msg.title, text: msg.text, severity: msg.severity, link: msg.link || null, items: msg.items });
    const ts = String(Math.floor(Date.now() / 1000));
    const headers = { 'content-type': 'application/json', 'x-netsec-timestamp': ts };
    if (ch.secret) headers['x-netsec-signature'] = `sha256=${crypto.createHmac('sha256', ch.secret).update(`${ts}.${body}`).digest('hex')}`;
    const r = await request(ch.url, { body, headers });
    if (r.status >= 300) throw new Error(`webhook HTTP ${r.status}`);
  },
};

/** LINE monthly quota (for `check`). */
async function lineQuota(ch) {
  const base = (ch.apiBase || 'https://api.line.me').replace(/\/+$/, '');
  const h = { authorization: `Bearer ${ch.channelToken}` };
  const q = await request(`${base}/v2/bot/message/quota`, { headers: h });
  const c = await request(`${base}/v2/bot/message/quota/consumption`, { headers: h });
  return { quota: q.json, used: c.json && c.json.totalUsage };
}

class Notifier extends EventEmitter {
  constructor({ db, cfg, now = () => Date.now(), senders = SENDERS }) {
    super();
    this.db = db; this.cfg = cfg; this.now = now; this.senders = senders;
    this.tz = cfg.tzOffsetMinutes ?? 420;
    this.channels = (cfg.notify && cfg.notify.channels || []).map(channelConfig).filter((c) => c.enabled && SENDERS[c.type]);
    // digest / quiet-hour / overflow queue lives in the DB (notify_pending): it survives restarts,
    // and items pulled by `cli/board.js pull` (system cron) are sent by the running server
    this.qIns = db.prepare('INSERT OR IGNORE INTO notify_pending(channel, item_id, queued_at) VALUES(?, ?, ?)');
    this.timers = [];
    this.pendingSends = new Set();
    // sends started but not yet recorded: a burst starts many sends in one tick, and the rate
    // limit and daily cap must count them, or every one of them would pass the check
    this.inflight = new Map();
  }

  start() {
    for (const ch of this.channels) {
      const t = setInterval(() => this.flushDigest(ch).catch(() => {}), ch.digestEveryMinutes * 60000);
      t.unref();
      this.timers.push(t);
    }
  }
  stop() { for (const t of this.timers) clearInterval(t); }

  boardLink(item) {
    const base = (this.cfg.publicUrl || '').replace(/\/+$/, '');
    return base ? `${base}/#item-${item.id}` : null;
  }

  /** Whether a change is news at all (new, re-opened or escalated, and not muted). */
  newsworthy(change) {
    const item = change.item;
    if (!item || change.resolved) return false;
    if (!(change.isNew || change.escalated)) return false;
    return !(item.snoozedUntil || (item.ackedBy && !change.escalated));
  }
  /** Board toast + bell only (no channels): used for rows another process already routed. */
  boardNote(change) {
    if (!this.newsworthy(change)) return;
    const item = change.item;
    if (sevRank(item.severity) >= sevRank((this.cfg.board && this.cfg.board.notifyMinSeverity) || 'high')) {
      this.emit('board', { item, reason: change.escalated ? 'escalated' : change.reopened ? 'reopened' : 'new' });
    }
  }

  /** Called for every pipeline change. */
  consider(change) {
    if (!this.newsworthy(change)) return;
    const item = change.item;
    this.boardNote(change);
    for (const ch of this.channels) {
      const p = this.route(ch, item);
      if (p) this.pendingSends.add(p);
      if (p) p.finally(() => this.pendingSends.delete(p));
    }
  }

  /** Wait for sends started by consider() (tests, graceful shutdown). */
  async idle() { while (this.pendingSends.size) await Promise.allSettled([...this.pendingSends]); }

  /** Severity last sent for this item on this channel; null if never, or not since the card re-opened. */
  lastSent(ch, itemId, reopenedAt = null) {
    const r = this.db.prepare('SELECT severity, ts FROM notifications WHERE channel = ? AND item_id = ? AND ok = 1 ORDER BY id DESC LIMIT 1').get(ch.name, itemId);
    if (!r || (reopenedAt && r.ts < reopenedAt)) return null; // a recurrence is news again
    return r.severity;
  }
  /** Messages (not items: one digest = one message) sent since `since`. */
  sentSince(ch, since, digestToo = true) {
    return this.db.prepare(`SELECT COUNT(DISTINCT msg) AS n FROM notifications WHERE channel = ? AND ts >= ? AND ok = 1${digestToo ? '' : ' AND digest = 0'}`).get(ch.name, since).n;
  }

  route(ch, item) {
    if (sevRank(item.severity) < sevRank(ch.minSeverity)) return null;
    if (ch.sources.length && !ch.sources.includes(item.source)) return null;
    const prev = this.lastSent(ch, item.id, item.reopenedAt);
    if (prev && sevRank(item.severity) <= sevRank(prev)) return null; // re-notify on escalation only
    const now = this.now();
    const exceptOk = ch.quietHours && ch.quietHours.except && sevRank(item.severity) >= sevRank(ch.quietHours.except);
    const queue = () => { this.qIns.run(ch.name, item.id, now); return null; };
    if (inQuiet(ch.quietHours, now, this.tz) && !exceptOk) return queue();
    if (ch.mode === 'digest') return queue();
    if (this.sentSince(ch, now - ch.rateLimit.perMinutes * 60000, false) + (this.inflight.get(ch.name) || 0) >= ch.rateLimit.max) return queue();
    return this.send(ch, { title: `NetSec ${item.severity.toUpperCase()}`, text: itemLine(item), severity: item.severity, link: this.boardLink(item), items: [item.id] }, item, false);
  }

  async send(ch, msg, item, digest) {
    const now = this.now();
    const { dayStart } = localParts(now, this.tz);
    if (this.sentSince(ch, dayStart) + (this.inflight.get(ch.name) || 0) >= ch.maxPerDay) {
      setMeta(this.db, `notify_capped:${ch.name}`, (getMeta(this.db, `notify_capped:${ch.name}`) || 0) + 1);
      this.db.prepare('INSERT INTO notifications(ts, channel, item_id, severity, ok, digest, error) VALUES(?, ?, ?, ?, 0, ?, ?)').run(now, ch.name, itemId(item), msg.severity, digest ? 1 : 0, 'daily cap');
      return false;
    }
    const m = ch.cloud ? { ...msg, title: maskForCloud(msg.title, item), text: maskForCloud(msg.text, item), items: msg.items } : msg;
    this.inflight.set(ch.name, (this.inflight.get(ch.name) || 0) + 1); // synchronous: before the first await
    try {
      await this.senders[ch.type](ch, m);
      const msgId = crypto.randomUUID();
      const ids = digest ? msg.items : [item.id];
      const ins = this.db.prepare('INSERT INTO notifications(ts, channel, msg, item_id, severity, ok, digest) VALUES(?, ?, ?, ?, ?, 1, ?)');
      for (const id of ids) ins.run(now, ch.name, msgId, id, digest ? (this.db.prepare('SELECT severity FROM items WHERE id = ?').get(id) || {}).severity || msg.severity : msg.severity, digest ? 1 : 0);
      if (!ids.length) ins.run(now, ch.name, msgId, null, msg.severity, digest ? 1 : 0);
      return true;
    } catch (e) {
      this.db.prepare('INSERT INTO notifications(ts, channel, item_id, severity, ok, digest, error) VALUES(?, ?, ?, ?, 0, ?, ?)').run(now, ch.name, itemId(item), msg.severity, digest ? 1 : 0, String(e.message).slice(0, 300));
      this.emit('error', { channel: ch.name, error: e.message });
      return false;
    } finally {
      this.inflight.set(ch.name, Math.max(0, (this.inflight.get(ch.name) || 1) - 1));
    }
  }

  /**
   * Send the queued items of one channel as one message. Items acked, resolved or snoozed
   * meanwhile are dropped from the queue; the rest stay queued until a send succeeds
   * (a failed send or the daily cap keeps them for the next digest).
   */
  async flushDigest(ch) {
    if (inQuiet(ch.quietHours, this.now(), this.tz)) return false;
    const rows = this.db.prepare('SELECT i.* FROM notify_pending q LEFT JOIN items i ON i.id = q.item_id WHERE q.channel = ? ORDER BY q.queued_at').all(ch.name);
    const del = this.db.prepare('DELETE FROM notify_pending WHERE channel = ? AND item_id = ?');
    const items = [];
    for (const r of rows) {
      if (!r.id) continue;
      if (r.acked_by || r.resolved_at || (r.snoozed_until && r.snoozed_until > this.now())) { del.run(ch.name, r.id); continue; }
      items.push(toItem(r));
    }
    this.db.prepare('DELETE FROM notify_pending WHERE channel = ? AND item_id NOT IN (SELECT id FROM items)').run(ch.name);
    items.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
    if (!items.length) return false;
    const capped = getMeta(this.db, `notify_capped:${ch.name}`) || 0;
    const top = items[0].severity;
    const lines = items.slice(0, 10).map(itemLine);
    if (items.length > 10) lines.push(`+${items.length - 10} more`);
    if (capped) lines.push(`(${capped} message(s) held back by the daily cap)`);
    const base = (this.cfg.publicUrl || '').replace(/\/+$/, '');
    const ok = await this.send(ch, { title: `NetSec digest: ${items.length} item(s), top ${top.toUpperCase()}`, text: lines.join('\n'), severity: top, link: base || null, items: items.map((i) => i.id), digest: true }, items, true);
    if (ok) {
      for (const i of items) del.run(ch.name, i.id);
      setMeta(this.db, `notify_capped:${ch.name}`, 0);
    }
    return ok;
  }

  /** Items waiting for a digest, per channel (for the board and tests). */
  pending(ch) {
    return this.db.prepare('SELECT COUNT(*) AS n FROM notify_pending WHERE channel = ?').get(typeof ch === 'string' ? ch : ch.name).n;
  }

  /** `cli/board.js test-notify <channel>` */
  async test(name) {
    const ch = this.channels.find((c) => c.name === name);
    if (!ch) throw new Error(`no enabled channel "${name}"`);
    await this.senders[ch.type](ch, { title: 'NetSec Board test', text: 'Test notification from NetSec Board. No action needed.', severity: 'info', items: [] });
    return true;
  }
}

module.exports = { Notifier, SENDERS, channelConfig, maskForCloud, inQuiet, lineQuota, itemLine };
