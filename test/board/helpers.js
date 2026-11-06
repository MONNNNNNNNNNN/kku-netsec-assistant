'use strict';
// Shared helpers for the board tests: temp app, login, API calls, SSE capture.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadConfig } = require('../../server/config.js');
const { createApp } = require('../../server/main.js');
const db_ = require('../../server/db.js');
const A = require('../../server/auth.js');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nsb-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Start a board on random ports. `over` is merged into the config. */
async function startBoard(over = {}, opts = {}) {
  const dataDir = over.dataDir || tmp();
  const loaded = loadConfig(null, { dataDir, listen: { host: '127.0.0.1', port: 0 }, ...over });
  if (opts.users !== false) {
    const db = db_.openDb(loaded.cfg.dataDir);
    for (const [u, role] of [['admin', 'admin'], ['op', 'operator'], ['view', 'viewer']]) {
      if (!db.prepare('SELECT 1 FROM users WHERE username = ?').get(u)) A.addUser(db, u, `${u}-password-123`, role);
    }
    db.close();
  }
  const app = await createApp(loaded, { jitter: false, runOnStart: false, batchMs: 10, log: () => {}, ...opts });
  return { app, dataDir, loaded };
}

async function login(app, user = 'admin') {
  const r = await fetch(`${app.url}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: user, password: `${user}-password-123` }) });
  if (r.status !== 200) throw new Error(`login ${user}: ${r.status}`);
  const j = await r.json();
  return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: j.csrf, user: j.user };
}

async function api(app, s, method, p, body, extra = {}) {
  const r = await fetch(`${app.url}${p}`, {
    method,
    headers: { cookie: s.cookie, ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(method !== 'GET' ? { 'x-csrf-token': s.csrf } : {}), ...extra },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let j = null;
  const text = await r.text();
  try { j = JSON.parse(text); } catch { /* not JSON */ }
  return { status: r.status, json: j, text, headers: r.headers };
}

/** Collect SSE events into an array until stop(). */
async function sse(app, s) {
  const ctl = new AbortController();
  const events = [];
  const r = await fetch(`${app.url}/api/events`, { headers: { cookie: s.cookie }, signal: ctl.signal });
  (async () => {
    const dec = new TextDecoder();
    let buf = '';
    try {
      for await (const chunk of r.body) {
        buf += dec.decode(chunk, { stream: true });
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const block = buf.slice(0, i); buf = buf.slice(i + 2);
          const ev = (block.match(/^event: (.+)$/m) || [])[1];
          const data = (block.match(/^data: (.+)$/m) || [])[1];
          if (ev) events.push({ event: ev, data: data ? JSON.parse(data) : null });
        }
      }
    } catch { /* aborted */ }
  })();
  return { events, status: r.status, stop: () => ctl.abort() };
}

async function waitFor(fn, ms = 5000, step = 25) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('waitFor: timed out');
    await sleep(step);
  }
}

module.exports = { tmp, sleep, startBoard, login, api, sse, waitFor };
