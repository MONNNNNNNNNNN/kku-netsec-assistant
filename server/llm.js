'use strict';
/*
 * OpenAI-compatible chat client shared by the CLI and the board server.
 * Never exits the process: problems are thrown as LlmError with a stable `code`,
 * so a long-running server can show the error instead of dying.
 *
 * On-prem enforcement (ISO 27001 A.5.23): the endpoint must resolve to loopback or a
 * private range unless allowRemote; non-loopback endpoints need https unless allowHttpLan.
 */
const net = require('node:net');
const dns = require('node:dns').promises;
const crypto = require('node:crypto');

class LlmError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function ipClass(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 127) return 'loopback';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)) return 'private';
    return 'remote';
  }
  const v = String(ip).toLowerCase();
  if (v === '::1') return 'loopback';
  const m = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (m) return ipClass(m[1]);
  if (/^f[cd]/.test(v) || /^fe[89ab]/.test(v)) return 'private';
  return 'remote';
}

/** Resolve a URL's host and classify it. Throws LlmError on invalid URL or DNS failure. */
async function classifyUrl(base) {
  let u;
  try { u = new URL(String(base)); } catch { throw new LlmError('ENDPOINT_INVALID', `invalid --llm URL: ${base}`); }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  let addrs;
  try { addrs = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true })).map((a) => a.address); }
  catch (e) { throw new LlmError('ENDPOINT_DNS', `cannot resolve LLM host ${host}: ${e.message}`); }
  const classes = addrs.map(ipClass);
  const cls = classes.includes('remote') ? 'remote' : classes.every((c) => c === 'loopback') ? 'loopback' : 'private';
  return { url: u, host, addrs, cls };
}

const ENDPOINT = new Map();
/**
 * opts: { allowRemote, allowHttpLan, remoteHint, httpHint, cacheMs } — hints name the override
 * in the error text (CLI flags by default, config keys in the server). The verdict is cached
 * for cacheMs (default: process lifetime, right for the short-lived CLI; the server passes
 * 5 minutes so a host whose DNS moves to a public address is caught).
 */
async function checkEndpoint(base, opts = {}) {
  const key = `${base}|${!!opts.allowRemote}|${!!opts.allowHttpLan}`;
  const hit = ENDPOINT.get(key);
  if (hit && (opts.cacheMs == null || Date.now() - hit.at < opts.cacheMs)) return hit.r;
  const { url: u, host, addrs, cls } = await classifyUrl(base);
  const override = [];
  if (cls === 'remote') {
    if (!opts.allowRemote) throw new LlmError('ENDPOINT_REMOTE', `refused: LLM endpoint ${host} (${addrs.join(', ')}) is not on-prem (loopback or private range). Masked data would leave the network. Override with ${opts.remoteHint || '--allow-remote-llm'}.`);
    override.push('allow-remote-llm');
  }
  if (cls !== 'loopback' && u.protocol !== 'https:') {
    if (!opts.allowHttpLan) throw new LlmError('ENDPOINT_HTTP', `refused: ${u.protocol}//${host} is not loopback, so https is required. Use https or pass ${opts.httpHint || '--allow-http-lan'} for a trusted LAN.`);
    override.push('allow-http-lan');
  }
  const r = { endpoint_class: cls, endpoint_overrides: override };
  ENDPOINT.set(key, { r, at: Date.now() });
  return r;
}

/** Streamed chat completion. opts: temperature, maxTokens, timeoutMs, think, apiKey. */
async function chatRaw(base, model, messages, opts = {}) {
  const url = `${String(base).replace(/\/+$/, '')}/chat/completions`;
  const t0 = Date.now();
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(opts.apiKey ? { authorization: `Bearer ${opts.apiKey}` } : {}) },
    // stream: CPU inference can take minutes before the first byte, longer than
    // undici's 300 s headers timeout for a non-streamed reply
    // reasoning_effort "none" turns off hidden thinking (Ollama, Qwen3.x); opts.think keeps it
    body: JSON.stringify({ model, messages, temperature: opts.temperature ?? 0.2, max_tokens: opts.maxTokens ?? 2048, stream: true, ...(opts.think ? {} : { reasoning_effort: 'none' }) }),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 1800000),
  });
  if (!res.ok) throw new LlmError('LLM_HTTP', `LLM ${res.status}: ${(await res.text()).slice(0, 300)}`);
  let raw = '', buf = '';
  const dec = new TextDecoder();
  for await (const chunk of res.body) {
    buf += dec.decode(chunk, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim();
      if (data === '[DONE]') continue;
      try { raw += JSON.parse(data).choices?.[0]?.delta?.content || ''; } catch { /* keep-alive or partial */ }
    }
  }
  const text = raw.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
  return { text, ms: Date.now() - t0 };
}

/**
 * Checked + audited chat. opts.audit(record) receives one record per call (masked
 * prompt, reply, endpoint class); opts.tool and opts.cmd label the record.
 */
async function chat(base, model, messages, opts = {}) {
  const ep = await checkEndpoint(base, opts);
  const t0 = Date.now();
  const rec = { ts: new Date().toISOString(), cmd: opts.cmd, tool: opts.tool, endpoint: new URL(String(base)).host, ...ep, model, temperature: opts.temperature ?? 0.2, prompt_sha256: sha(JSON.stringify(messages)), messages };
  const audit = opts.audit || (() => {});
  try {
    const out = await chatRaw(base, model, messages, opts);
    audit({ ...rec, ms: out.ms, reply_sha256: sha(out.text), reply: out.text });
    return { ...out, ...ep };
  } catch (e) {
    audit({ ...rec, ms: Date.now() - t0, error: e.message });
    throw e;
  }
}

module.exports = { LlmError, ipClass, classifyUrl, checkEndpoint, chat, chatRaw, sha };
