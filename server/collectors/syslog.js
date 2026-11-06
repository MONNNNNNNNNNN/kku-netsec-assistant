'use strict';
/*
 * Syslog receiver (push). UDP and TCP (octet-counting per RFC 6587, or newline framing).
 * FortiGate: `config log syslogd setting` with `set format rfc5424` (or default) and
 * `set mode reliable` (TCP). CSV and CEF formats are counted as unsupported and dropped.
 *
 * Spoofing defence: only senders on the allowlist (IPs or IPv4 CIDRs) are accepted. An
 * empty allowlist accepts nobody. Other senders are dropped and counted per IP, and each
 * allowed sender has a token-bucket rate limit (ratePerSec).
 */
const dgram = require('node:dgram');
const net = require('node:net');
const N = require('../../src/core.js');
const trust = require('../trust.js');
const { bumpSource, sourceState, updateSource } = require('../db.js');

const MAX_LINE = 16384;

function ip2int(ip) { return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0; }
function normIp(ip) { return String(ip).replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, '$1'); }
function allowed(list, ipRaw) {
  const ip = normIp(ipRaw);
  for (const a of list || []) {
    const [base, bits] = String(a).split('/');
    if (bits === undefined) { if (normIp(base) === ip) return true; continue; }
    if (!net.isIPv4(ip) || !net.isIPv4(base)) continue;
    const b = Number(bits), m = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
    if ((ip2int(ip) & m) === (ip2int(base) & m)) return true;
  }
  return false;
}

/** Parse one syslog message into {pri, facility, sev, host, app, msg, format}. */
function parseSyslog(line) {
  let s = String(line).replace(/\r?\n$/, '');
  let m = s.match(/^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$/s);
  if (m) {
    const pri = Number(m[1]);
    return { pri, facility: pri >> 3, sev: pri & 7, ts: m[2], host: m[3] === '-' ? '' : m[3], app: m[4] === '-' ? '' : m[4], msg: (m[8] || '').replace(/^\uFEFF/, ''), format: 'rfc5424' };
  }
  m = s.match(/^<(\d{1,3})>([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ?(.*)$/s);
  if (m) {
    const pri = Number(m[1]);
    return { pri, facility: pri >> 3, sev: pri & 7, ts: m[2], host: m[3], app: m[4], msg: m[5], format: 'rfc3164' };
  }
  m = s.match(/^<(\d{1,3})>(.*)$/s);
  if (m) {
    const pri = Number(m[1]);
    return { pri, facility: pri >> 3, sev: pri & 7, host: '', app: '', msg: m[2], format: 'raw' };
  }
  return { pri: 13, facility: 1, sev: 5, host: '', app: '', msg: s, format: 'none' };
}

function payloadKind(msg) {
  if (/^CEF:\d+\|/.test(msg)) return 'cef';
  if (/^date=[^,\s]+,time=/.test(msg)) return 'csv';
  if (/\b(devid|logid)=/.test(msg)) return 'fortigate';
  return 'generic';
}

class SyslogCollector {
  constructor({ cfg, db, pipeline, now = () => Date.now() }) {
    this.cfg = cfg; this.db = db; this.pipeline = pipeline; this.now = now;
    this.buckets = new Map();
    this.pending = { received: 0, dropped: 0, unsupported: 0, senders: {} };
    this.udp = null; this.tcp = null; this.flushTimer = null;
  }

  rateOk(ip) {
    const rate = this.cfg.ratePerSec || 2000;
    const now = this.now();
    let b = this.buckets.get(ip);
    if (!b) { b = { tokens: rate, at: now }; this.buckets.set(ip, b); }
    b.tokens = Math.min(rate, b.tokens + ((now - b.at) / 1000) * rate);
    b.at = now;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  drop(ip, why) {
    this.pending.dropped++;
    const k = `${normIp(ip)}${why === 'rate' ? ' (rate)' : why === 'size' ? ' (size)' : ''}`;
    this.pending.senders[k] = (this.pending.senders[k] || 0) + 1;
  }

  /** Handle one message from `ip`. Returns the event, or null if dropped. */
  handle(line, ip) {
    if (!allowed(this.cfg.allow, ip)) { this.drop(ip, 'allow'); return null; }
    if (!this.rateOk(ip)) { this.drop(ip, 'rate'); return null; }
    if (Buffer.byteLength(line) > MAX_LINE) { this.drop(ip, 'size'); return null; }
    const p = parseSyslog(line);
    const kind = payloadKind(p.msg);
    if (kind === 'cef' || kind === 'csv') { this.pending.unsupported++; return null; }
    const evt = kind === 'fortigate' ? trust.fortigate(N.parseFortiLog(p.msg), this.now()) : trust.syslog(p, normIp(ip), this.now());
    evt.trusted.sender = normIp(ip);
    this.pipeline.ingest(evt, 'syslog');
    return evt;
  }

  flushCounters() {
    const p = this.pending;
    if (!p.dropped && !p.unsupported) return;
    if (p.dropped) bumpSource(this.db, 'syslog', 'dropped', p.dropped);
    if (p.unsupported) bumpSource(this.db, 'syslog', 'unsupported', p.unsupported);
    const st = sourceState(this.db, 'syslog');
    const senders = JSON.parse(st.dropped_senders || '{}');
    for (const [k, n] of Object.entries(p.senders)) senders[k] = (senders[k] || 0) + n;
    const top = Object.fromEntries(Object.entries(senders).sort((a, b) => b[1] - a[1]).slice(0, 50));
    updateSource(this.db, 'syslog', { dropped_senders: JSON.stringify(top) });
    this.pending = { received: 0, dropped: 0, unsupported: 0, senders: {} };
  }

  tcpConnection(sock) {
    let buf = Buffer.alloc(0);
    const ip = sock.remoteAddress;
    if (!allowed(this.cfg.allow, ip)) { this.drop(ip, 'allow'); sock.destroy(); return; }
    sock.setTimeout(10 * 60000, () => sock.destroy());
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 1024 * 1024) { this.drop(ip, 'size'); sock.destroy(); return; }
      for (;;) {
        const sp = buf.indexOf(0x20);
        const head = sp > 0 && sp < 8 ? buf.subarray(0, sp).toString() : '';
        if (/^\d+$/.test(head)) { // octet counting
          const len = Number(head);
          if (buf.length < sp + 1 + len) break;
          this.handle(buf.subarray(sp + 1, sp + 1 + len).toString('utf8'), ip);
          buf = buf.subarray(sp + 1 + len);
          continue;
        }
        const nl = buf.indexOf(0x0a);
        if (nl < 0) break;
        const line = buf.subarray(0, nl).toString('utf8').replace(/\r$/, '');
        buf = buf.subarray(nl + 1);
        if (line) this.handle(line, ip);
      }
    });
    sock.on('error', () => {});
  }

  start() {
    const { bind = '127.0.0.1', port = 5514 } = this.cfg;
    const tasks = [];
    if (this.cfg.udp !== false) {
      this.udp = dgram.createSocket(net.isIPv6(bind) ? 'udp6' : 'udp4');
      this.udp.on('message', (msg, rinfo) => this.handle(msg.toString('utf8'), rinfo.address));
      this.udp.on('error', () => {});
      tasks.push(new Promise((res, rej) => { this.udp.once('error', rej); this.udp.bind(port, bind, () => { this.udp.removeListener('error', rej); res(); }); }));
    }
    if (this.cfg.tcp !== false) {
      this.tcp = net.createServer((s) => this.tcpConnection(s));
      this.tcp.maxConnections = 200;
      tasks.push(new Promise((res, rej) => { this.tcp.once('error', rej); this.tcp.listen(port, bind, res); }));
    }
    this.flushTimer = setInterval(() => this.flushCounters(), 1000);
    this.flushTimer.unref();
    updateSource(this.db, 'syslog', { status: 'listening', last_error: null });
    return Promise.all(tasks).then(() => this.address());
  }

  address() {
    return { udp: this.udp ? this.udp.address() : null, tcp: this.tcp ? this.tcp.address() : null };
  }

  stop() {
    clearInterval(this.flushTimer);
    this.flushCounters();
    if (this.udp) try { this.udp.close(); } catch { /* closed */ }
    if (this.tcp) this.tcp.close();
  }
}

module.exports = { SyslogCollector, parseSyslog, payloadKind, allowed };
