'use strict';
/*
 * Small HTTP(S) client for collectors and notifiers. Uses node:http/https directly so a
 * private CA (FortiGate/Wazuh self-signed) can be pinned with caFile, without dependencies.
 * Responses are capped (maxBytes) so a broken or hostile endpoint cannot exhaust memory.
 */
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');

function request(url, opts = {}) {
  const u = new URL(url);
  const mod = u.protocol === 'https:' ? https : http;
  const body = opts.body == null ? null : Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body));
  const headers = { ...(opts.headers || {}) };
  if (body && !Object.keys(headers).some((k) => k.toLowerCase() === 'content-type')) headers['content-type'] = 'application/json';
  if (body) headers['content-length'] = body.length;
  if (opts.basic) headers.authorization = `Basic ${Buffer.from(`${opts.basic.username}:${opts.basic.password}`).toString('base64')}`;
  const maxBytes = opts.maxBytes || 20 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    const req = mod.request(u, {
      method: opts.method || (body ? 'POST' : 'GET'),
      headers,
      ca: opts.caFile ? fs.readFileSync(opts.caFile) : undefined,
      rejectUnauthorized: opts.insecure ? false : true,
      timeout: opts.timeoutMs || 30000,
    }, (res) => {
      const chunks = [];
      let n = 0;
      res.on('data', (c) => {
        n += c.length;
        if (n > maxBytes) { req.destroy(new Error(`response larger than ${maxBytes} bytes`)); return; }
        chunks.push(c);
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json;
        try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('timeout', () => req.destroy(new Error(`timeout after ${opts.timeoutMs || 30000} ms`)));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/** Throws unless 2xx. */
async function requestOk(url, opts) {
  const r = await request(url, opts);
  if (r.status < 200 || r.status >= 300) {
    const e = new Error(`HTTP ${r.status} from ${new URL(url).host}: ${r.text.slice(0, 200)}`);
    e.status = r.status;
    throw e;
  }
  return r;
}

module.exports = { request, requestOk };
