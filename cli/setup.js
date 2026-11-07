'use strict';
/*
 * First-time setup wizard (`node cli/board.js setup`), also run by install.sh.
 *
 * Asks a few questions, tests each answer against the real system, and writes:
 *   netsec.json   the example config with only the answered parts changed; secrets are
 *                 env:NETSEC_* references, never values
 *   secrets.env   NAME='value' lines (systemd EnvironmentFile, Docker env_file and
 *                 process.loadEnvFile all read it), mode 0600, written atomically
 *   .env          (--compose-env, Docker mode) BOARD_BIND / SYSLOG_BIND for compose
 * The admin is not written to the database here: the password's scrypt hash goes to
 * secrets.env (NETSEC_ADMIN_HASH) and the board creates the admin on its first start. The
 * wizard therefore needs no access to the data directory (in Docker it runs as the host user
 * against the install folder only).
 *
 * Non-interactive (install.sh --non-interactive, CI): every answer comes from NETSEC_SETUP_*:
 *   LANG PORT LISTEN  SYSLOG_ALLOW SYSLOG_UDP  WAZUH_URL WAZUH_USER WAZUH_PASSWORD
 *   WAZUH_CA ZABBIX_CA (CA files for https with a private CA)
 *   ZABBIX_URL ZABBIX_TOKEN  BACKUP_DIR  NOTIFY (ntfy|telegram|line|webhook|none)
 *   NTFY_URL NTFY_TOPIC NTFY_TOKEN  TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID  LINE_TOKEN LINE_TO
 *   WEBHOOK_URL WEBHOOK_SECRET  LLM_URL LLM_MODEL  ADMIN_USER ADMIN_PASSWORD  STRICT (1: a failed test exits 1)
 */
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const A = require('../server/auth.js');
const { merge } = require('../server/config.js');
const { requestOk } = require('../server/net.js');
const { checkZabbix, wazuhHint } = require('../server/collectors/pull.js');
const { SENDERS, channelConfig } = require('../server/notify.js');
const LLM = require('../server/llm.js');
const { validEntry } = require('../server/collectors/syslog.js');

const EXAMPLE = path.join(__dirname, '..', 'netsec.example.json');

/** Parse NAME='value' / NAME="value" / NAME=value lines. */
function readSecrets(file) {
  const out = {};
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch { return out; }
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith('"') && v.endsWith('"'))) v = v.slice(1, -1);
    out[m[1]] = v;
  }
  return out;
}
/** Atomic write with a mode (temp file in the same folder, then rename). */
function writeAtomic(file, text, mode) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, text, { mode });
  fs.chmodSync(tmp, mode);
  fs.renameSync(tmp, file);
}
function writeSecrets(file, secrets) {
  const lines = ['# NetSec Board secrets (written by cli/board.js setup). Keep this file 0600 and out of git.'];
  for (const [k, v] of Object.entries(secrets)) {
    if (v === undefined || v === null || v === '') continue;
    if (/['\n\r]/.test(v)) throw new Error(`${k}: a value cannot contain a single quote or a newline`);
    lines.push(`${k}='${v}'`);
  }
  writeAtomic(file, `${lines.join('\n')}\n`, 0o600);
}

/** Line-based prompter. Lines are queued, so piped answers are never lost. */
function prompter(input, output) {
  const rl = readline.createInterface({ input, output, terminal: !!(input.isTTY && output.isTTY) });
  const queue = [], waiters = [];
  let closed = false, muted = false;
  rl.on('line', (l) => { const w = waiters.shift(); if (w) w(l); else queue.push(l); });
  rl.on('close', () => { closed = true; while (waiters.length) waiters.shift()(null); });
  const write = rl._writeToOutput.bind(rl);
  rl._writeToOutput = (s) => { if (!muted) write(s); else if (/\r|\n/.test(s)) write('\n'); };
  const next = () => (queue.length ? Promise.resolve(queue.shift()) : closed ? Promise.resolve(null) : new Promise((r) => waiters.push(r)));
  return {
    async ask(q, { def = '', secret = false } = {}) {
      const shown = secret ? (def ? ' [keep]' : '') : def ? ` [${def}]` : '';
      output.write(`${q}${shown}: `);
      muted = secret && rl.terminal;
      const l = await next();
      muted = false;
      if (secret && !rl.terminal) output.write('\n');
      if (l === null) return def;
      const v = l.trim();
      return v === '' ? def : v;
    },
    close: () => rl.close(),
  };
}

/** Answers from NETSEC_SETUP_* (non-interactive). */
function envAnswers(env) {
  return { async ask(q, { def = '', key }) { const v = env[`NETSEC_SETUP_${key}`]; return v === undefined ? def : String(v).trim(); }, close() {} };
}

async function tryTest(label, fn, out) {
  try {
    const msg = await fn();
    out.write(`  ok    ${label}${msg ? `: ${msg}` : ''}\n`);
    return true;
  } catch (e) {
    out.write(`  FAIL  ${label}: ${e.message}${e.hint ? `\n        hint: ${e.hint}` : ''}\n`);
    return false;
  }
}

/**
 * Run the wizard. opts: {cfgFile, input, output, nonInteractive, env, adminPasswordFile, composeEnv}
 * Returns {cfgFile, secretsFile, adminCreated, adminPassword, failed: [labels]}.
 */
async function setup(opts) {
  const env = opts.env || process.env;
  const out = opts.output || process.stdout;
  const cfgFile = path.resolve(opts.cfgFile);
  const dir = path.dirname(cfgFile);
  const secretsFile = path.join(dir, 'secrets.env');
  fs.mkdirSync(dir, { recursive: true });
  const example = JSON.parse(fs.readFileSync(EXAMPLE, 'utf8'));
  // install.sh (Docker) places a copy of the example first: that is not an existing config
  const existed = fs.existsSync(cfgFile) && fs.readFileSync(cfgFile, 'utf8').trim() !== fs.readFileSync(EXAMPLE, 'utf8').trim();
  const cfg = existed ? merge(example, JSON.parse(fs.readFileSync(cfgFile, 'utf8'))) : example;
  const secrets = readSecrets(secretsFile);
  const P = opts.nonInteractive ? envAnswers(env) : prompter(opts.input || process.stdin, out);
  const ask = (key, q, o = {}) => P.ask(q, { ...o, key });
  const yes = (v) => /^(y|yes|1|true|on)$/i.test(String(v));
  const failed = [];
  // https with a private CA: ask for the CA file (Enter = the system CAs); a readable well-known
  // path is offered as the default. Found when testing against a real Wazuh 4.x indexer.
  const caQuestion = async (key, q, current, candidates) => {
    const def = current || candidates.find((c) => { try { fs.accessSync(path.resolve(dir, c), fs.constants.R_OK); return true; } catch { return false; } }) || '';
    const v = await ask(key, `${q} (Enter = ${def || 'system CAs'})`, { def });
    if (v && !fs.existsSync(path.resolve(dir, v))) { out.write(`  FAIL  CA file not found: ${v}\n`); failed.push(`${key} file`); }
    return v;
  };
  // interactive: a failed test asks retry / keep / skip; non-interactive keeps (STRICT=1 exits)
  const tested = async (label, fn, retry) => {
    for (;;) {
      if (await tryTest(label, fn, out)) return 'ok';
      if (opts.nonInteractive) { failed.push(label); return 'keep'; }
      const a = (await P.ask('  [r]etry, [k]eep anyway, [s]kip this source', { def: 'r' })).toLowerCase();
      if (a.startsWith('k')) { failed.push(label); return 'keep'; }
      if (a.startsWith('s')) return 'skip';
      if (retry) await retry();
    }
  };
  out.write(`NetSec Board setup: ${cfgFile}${existed ? ' (existing values are the defaults)' : ''}\nPress Enter to keep a value or skip a question.\n\n`);

  // 1. basics
  cfg.lang = (await ask('LANG', 'Language (th/en)', { def: cfg.lang || 'th' })) === 'en' ? 'en' : 'th';
  cfg.listen.port = Number(await ask('PORT', 'Board port', { def: String(cfg.listen.port || 8480) })) || 8480;
  const listen = await ask('LISTEN', 'Open the board to the LAN? (n = this machine only, put a TLS proxy in front; y = all interfaces)', { def: cfg.listen.host === '0.0.0.0' ? 'y' : 'n' });
  cfg.listen.host = yes(listen) ? '0.0.0.0' : '127.0.0.1';

  // 2. FortiGate syslog
  out.write('\nFortiGate logs (syslog push). The FortiGate sends to this machine; only listed senders are accepted.\n');
  const allowDef = cfg.sources.syslog.enabled ? cfg.sources.syslog.allow.join(',') : '';
  const allow = await ask('SYSLOG_ALLOW', 'FortiGate source IP(s), comma-separated (empty = no syslog)', { def: allowDef });
  if (allow) {
    const list = allow.split(',').map((s) => s.trim()).filter(Boolean);
    const bad = list.filter((a) => !validEntry(a));
    if (bad.length) { out.write(`  FAIL  not an IP or CIDR: ${bad.join(', ')}; syslog left off\n`); failed.push('syslog allowlist'); } else {
      const udp = await ask('SYSLOG_UDP', 'Also accept UDP? (TCP "set mode reliable" is recommended; UDP can be forged and lost)', { def: cfg.sources.syslog.enabled && cfg.sources.syslog.udp ? 'y' : 'n' });
      Object.assign(cfg.sources.syslog, { enabled: true, allow: list, tcp: true, udp: yes(udp), bind: '0.0.0.0' });
    }
  } else cfg.sources.syslog.enabled = false;

  // 3. Wazuh
  out.write('\nWazuh (pull from the indexer, port 9200; a read-only indexer user).\n');
  const wz = cfg.sources.wazuh;
  const wzUrl = await ask('WAZUH_URL', 'Wazuh indexer URL (empty = skip)', { def: wz.enabled ? wz.url : '' });
  if (wzUrl) {
    wz.url = wzUrl;
    wz.username = await ask('WAZUH_USER', 'Indexer user', { def: wz.username || 'netsec_board_ro' });
    if (/^https:/i.test(wz.url)) wz.caFile = await caQuestion('WAZUH_CA', 'Indexer CA file (Wazuh installs use a self-signed CA)', wz.caFile, opts.docker ? ['certs/wazuh-root-ca.pem'] : ['certs/wazuh-root-ca.pem', '/etc/netsec-board/wazuh-root-ca.pem', '/etc/wazuh-indexer/certs/root-ca.pem']);
    const pw = await ask('WAZUH_PASSWORD', 'Indexer password', { def: secrets.NETSEC_WAZUH_PASSWORD || '', secret: true });
    secrets.NETSEC_WAZUH_PASSWORD = pw; wz.password = 'env:NETSEC_WAZUH_PASSWORD';
    const r = await tested('Wazuh indexer', async () => {
      const u = `${wz.url.replace(/\/+$/, '')}/${encodeURIComponent(wz.index || 'wazuh-alerts-*').replace(/%2A/g, '*')}/_search`;
      const res = await requestOk(u, { body: { size: 0 }, basic: { username: wz.username, password: pw }, caFile: wz.caFile ? path.resolve(dir, wz.caFile) : undefined, timeoutMs: 10000 }).catch((e) => { throw wazuhHint(e); });
      const total = res.json && res.json.hits && res.json.hits.total;
      return `${total && total.value !== undefined ? total.value : '?'} alert(s) in ${wz.index || 'wazuh-alerts-*'}`;
    });
    wz.enabled = r !== 'skip';
  } else wz.enabled = false;

  // 4. Zabbix
  out.write('\nZabbix (pull with an API token, Zabbix 6.4+).\n');
  const zb = cfg.sources.zabbix;
  const zbUrl = await ask('ZABBIX_URL', 'Zabbix URL (empty = skip)', { def: zb.enabled ? zb.url : '' });
  if (zbUrl) {
    zb.url = zbUrl;
    if (/^https:/i.test(zb.url)) zb.caFile = await caQuestion('ZABBIX_CA', 'CA file for the Zabbix web server', zb.caFile, []);
    const tok = await ask('ZABBIX_TOKEN', 'Zabbix API token', { def: secrets.NETSEC_ZABBIX_TOKEN || '', secret: true });
    secrets.NETSEC_ZABBIX_TOKEN = tok; zb.token = 'env:NETSEC_ZABBIX_TOKEN';
    const r = await tested('Zabbix API', async () => {
      const c = await checkZabbix({ url: zb.url, token: tok, caFile: zb.caFile ? path.resolve(dir, zb.caFile) : undefined });
      if (!c.ok) throw Object.assign(new Error(c.error), { hint: c.hint });
      return `Zabbix ${c.version}`;
    });
    zb.enabled = r !== 'skip';
  } else zb.enabled = false;

  // 5. config backups
  out.write('\nFortiGate config backups (a folder your backup job writes .conf files into).\n');
  const cd = cfg.sources.configdrop;
  // Docker: the folder is always <install dir>/backups, mounted read-only at /backups
  const bdir = opts.docker
    ? (yes(await ask('BACKUP_DIR', `Read FortiGate backups from ${path.join(env.NETSEC_HOST_DIR || '<install folder>', 'backups')}? (y/n)`, { def: cd.enabled ? 'y' : 'n' })) ? './backups' : '')
    : await ask('BACKUP_DIR', 'Backup folder (empty = skip)', { def: cd.enabled ? cd.dir : '' });
  if (bdir) {
    cd.dir = bdir;
    const abs = path.resolve(dir, bdir);
    const r = await tested('backup folder', async () => {
      if (!fs.statSync(abs).isDirectory()) throw new Error('not a folder');
      fs.accessSync(abs, fs.constants.R_OK);
      return `${fs.readdirSync(abs).filter((f) => /\.(conf|cfg|txt)$/i.test(f)).length} backup file(s)`;
    });
    cd.enabled = r !== 'skip';
  } else cd.enabled = false;

  // 6. one notification channel
  out.write('\nNotifications (one channel now; more in netsec.json later).\n');
  const type = (await ask('NOTIFY', 'Channel: ntfy, telegram, line, webhook or none', { def: 'none' })).toLowerCase();
  const ch = { name: `${type}-noc`, type, enabled: true, minSeverity: 'high' };
  if (type === 'ntfy') {
    ch.url = await ask('NTFY_URL', 'ntfy server URL', { def: 'https://ntfy.sh' });
    ch.topic = await ask('NTFY_TOPIC', 'ntfy topic', { def: 'netsec' });
    const t = await ask('NTFY_TOKEN', 'ntfy access token (empty = none)', { def: secrets.NETSEC_NTFY_TOKEN || '', secret: true });
    if (t) { secrets.NETSEC_NTFY_TOKEN = t; ch.token = 'env:NETSEC_NTFY_TOKEN'; }
  } else if (type === 'telegram') {
    const t = await ask('TELEGRAM_BOT_TOKEN', 'Telegram bot token', { def: secrets.NETSEC_TELEGRAM_BOT_TOKEN || '', secret: true });
    secrets.NETSEC_TELEGRAM_BOT_TOKEN = t; ch.botToken = 'env:NETSEC_TELEGRAM_BOT_TOKEN';
    ch.chatId = await ask('TELEGRAM_CHAT_ID', 'Telegram chat id', { def: '' });
    if (env.NETSEC_SETUP_TELEGRAM_API_BASE) ch.apiBase = env.NETSEC_SETUP_TELEGRAM_API_BASE;
  } else if (type === 'line') {
    const t = await ask('LINE_TOKEN', 'LINE channel access token', { def: secrets.NETSEC_LINE_CHANNEL_TOKEN || '', secret: true });
    secrets.NETSEC_LINE_CHANNEL_TOKEN = t; ch.channelToken = 'env:NETSEC_LINE_CHANNEL_TOKEN';
    ch.to = await ask('LINE_TO', 'LINE group/user id', { def: '' });
    Object.assign(ch, { mode: 'digest', maxPerDay: 8 });
  } else if (type === 'webhook') {
    ch.url = await ask('WEBHOOK_URL', 'Webhook URL', { def: '' });
    const s = await ask('WEBHOOK_SECRET', 'HMAC secret (empty = generate one)', { def: secrets.NETSEC_WEBHOOK_SECRET || '', secret: true });
    secrets.NETSEC_WEBHOOK_SECRET = s || require('node:crypto').randomBytes(24).toString('base64url'); ch.secret = 'env:NETSEC_WEBHOOK_SECRET';
  }
  if (SENDERS[type]) {
    const resolved = channelConfig({ ...ch, token: secrets.NETSEC_NTFY_TOKEN, botToken: secrets.NETSEC_TELEGRAM_BOT_TOKEN, channelToken: secrets.NETSEC_LINE_CHANNEL_TOKEN, secret: secrets.NETSEC_WEBHOOK_SECRET });
    const r = await tested(`${type} test message`, async () => {
      await SENDERS[type](resolved, { title: 'NetSec Board setup', text: 'Test message from the NetSec Board setup. No action needed.', severity: 'info', items: [] });
      return 'sent: check that it arrived';
    });
    if (r !== 'skip') cfg.notify.channels = [...(cfg.notify.channels || []).filter((c) => c.name !== ch.name && c.enabled !== false), ch];
  }

  // 7. optional local LLM
  out.write('\nAI explanations (optional; the board works fully without it). Only an on-prem endpoint is accepted.\n');
  const llmUrl = await ask('LLM_URL', 'LLM URL, e.g. http://127.0.0.1:11434/v1 (empty = off)', { def: cfg.llm ? cfg.llm.url : '' });
  if (llmUrl) {
    const model = await ask('LLM_MODEL', 'Model', { def: (cfg.llm && cfg.llm.model) || 'qwen2.5:3b-instruct' });
    const r = await tested('LLM endpoint class', async () => {
      const c = await LLM.classifyUrl(llmUrl);
      if (c.cls === 'remote') throw new Error('a public endpoint: logs would leave the network (set llm.allowRemote in netsec.json only if that is approved)');
      return c.cls;
    });
    cfg.llm = r === 'skip' ? null : { url: llmUrl, model, budgetPerHour: 12, autoMinSeverity: 'critical' };
  } else cfg.llm = null;

  // 8. admin (created by the board on first start from the hash)
  let adminPassword = null;
  if (!secrets.NETSEC_ADMIN_HASH) {
    const user = (await ask('ADMIN_USER', '\nAdmin user name', { def: 'admin' })) || 'admin';
    const given = opts.adminPasswordFile ? fs.readFileSync(opts.adminPasswordFile, 'utf8').trim() : env.NETSEC_SETUP_ADMIN_PASSWORD;
    adminPassword = given || A.randomPassword();
    if (adminPassword.length < 10) throw new Error('the admin password must be at least 10 characters');
    secrets.NETSEC_ADMIN_USER = user;
    secrets.NETSEC_ADMIN_HASH = A.hashPassword(adminPassword);
  }

  // write: config without secrets, secrets 0600
  delete cfg._llm_example;
  writeAtomic(cfgFile, `${JSON.stringify(cfg, null, 2)}\n`, 0o640);
  writeSecrets(secretsFile, secrets);
  if (opts.composeEnv) {
    writeAtomic(path.join(dir, '.env'), `BOARD_BIND=${cfg.listen.host === '0.0.0.0' ? '0.0.0.0' : '127.0.0.1'}\nBOARD_PORT=${cfg.listen.port}\nSYSLOG_BIND=${cfg.sources.syslog.enabled ? '0.0.0.0' : '127.0.0.1'}\n`, 0o644);
  }
  P.close();
  out.write(`\nwrote ${cfgFile}\nwrote ${secretsFile} (mode 600)\n`);
  if (adminPassword) out.write(`admin "${secrets.NETSEC_ADMIN_USER}" will be created on the board's first start, password: ${env.NETSEC_SETUP_ADMIN_PASSWORD || opts.adminPasswordFile ? '(the one you gave)' : adminPassword}\n(shown once; change it later with: node cli/board.js user passwd ${secrets.NETSEC_ADMIN_USER})\n`);
  if (failed.length) out.write(`\nnot verified: ${failed.join(', ')} (kept in the config; run "node cli/board.js check" after fixing)\n`);
  return { cfgFile, secretsFile, adminPassword, failed };
}

module.exports = { setup, readSecrets, writeSecrets };
