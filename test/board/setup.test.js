'use strict';
// The setup wizard (cli/board.js setup) and secrets.env loading: install I1-I3.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFile, spawn } = require('node:child_process');
const M = require('../../mocks/servers.js');
const { tmp } = require('./helpers.js');

const ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(ROOT, 'cli/board.js');
// a clean env: no NETSEC_* from the test process leaks into the child
const baseEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('NETSEC_')));
const run = (args, env = {}, input = null) => new Promise((resolve) => {
  const p = spawn(process.execPath, [CLI, ...args], { env: { ...baseEnv(), ...env } });
  let stdout = '', stderr = '';
  p.stdout.on('data', (d) => { stdout += d; });
  p.stderr.on('data', (d) => { stderr += d; });
  p.on('close', (code) => resolve({ code, stdout, stderr }));
  if (input !== null) p.stdin.end(input); else p.stdin.end();
});

async function mocks() {
  const wz = await M.mockWazuh({ username: 'ro_user', password: 'wz-secret-Pa55' });
  const zbx = await M.mockZabbix({ token: 'zbx-secret-T0ken' });
  const sinks = await M.mockSinks();
  return { wz, zbx, sinks, close: () => { wz.server.close(); zbx.server.close(); sinks.server.close(); } };
}

test('setup --non-interactive: tests each source live, writes env: references + a 0600 secrets.env, the admin comes from its hash', async () => {
  const m = await mocks();
  const dir = tmp();
  const cfg = path.join(dir, 'netsec.json');
  const env = {
    NETSEC_SETUP_LANG: 'en', NETSEC_SETUP_SYSLOG_ALLOW: '10.0.0.1, 10.0.0.2',
    NETSEC_SETUP_WAZUH_URL: m.wz.url, NETSEC_SETUP_WAZUH_USER: 'ro_user', NETSEC_SETUP_WAZUH_PASSWORD: 'wz-secret-Pa55',
    NETSEC_SETUP_ZABBIX_URL: m.zbx.url, NETSEC_SETUP_ZABBIX_TOKEN: 'zbx-secret-T0ken',
    NETSEC_SETUP_NOTIFY: 'ntfy', NETSEC_SETUP_NTFY_URL: `${m.sinks.url}/ntfy`, NETSEC_SETUP_NTFY_TOPIC: 'noc',
    NETSEC_SETUP_ADMIN_PASSWORD: 'setup-admin-pass-1',
  };
  try {
    const r = await run(['setup', '--config', cfg, '--non-interactive'], env);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    for (const want of ['ok    Wazuh indexer', 'ok    Zabbix API: Zabbix 7.0.5', 'ok    ntfy test message']) assert.ok(r.stdout.includes(want), `${want}\n${r.stdout}`);
    assert.equal(m.sinks.requests.filter((x) => x.url === '/ntfy').length, 1, 'the test message really went out');
    const text = fs.readFileSync(cfg, 'utf8');
    for (const s of ['wz-secret-Pa55', 'zbx-secret-T0ken', 'setup-admin-pass-1']) assert.ok(!text.includes(s), `${s} is not in netsec.json`);
    const c = JSON.parse(text);
    assert.equal(c.sources.wazuh.password, 'env:NETSEC_WAZUH_PASSWORD');
    assert.equal(c.sources.zabbix.token, 'env:NETSEC_ZABBIX_TOKEN');
    assert.deepEqual(c.sources.syslog.allow, ['10.0.0.1', '10.0.0.2']);
    assert.equal(c.sources.syslog.udp, false, 'TCP only by default');
    assert.deepEqual(c.notify.channels.map((x) => x.type), ['ntfy'], 'the example placeholders are gone');
    const secrets = path.join(dir, 'secrets.env');
    assert.equal(fs.statSync(secrets).mode & 0o777, 0o600);
    assert.match(fs.readFileSync(secrets, 'utf8'), /NETSEC_WAZUH_PASSWORD='wz-secret-Pa55'/);
    assert.ok(!r.stdout.includes('setup-admin-pass-1'), 'a given password is not echoed');
    // check: green; the admin is created from the hash by the first process that opens the DB
    const ck = await run(['check', '--config', cfg]);
    assert.equal(ck.code, 0, ck.stdout);
    assert.match(ck.stdout, /admin "admin" is created on the board's first start/);
    const init = await run(['init', '--config', cfg]);
    assert.match(init.stdout, /created the admin from secrets.env/);
    assert.match((await run(['user', 'list', '--config', cfg])).stdout, /^admin\tadmin\t/m);
    // re-run with nothing new: the secrets and the admin hash are kept
    const before = fs.readFileSync(secrets, 'utf8');
    const again = await run(['setup', '--config', cfg, '--non-interactive'], { NETSEC_SETUP_NOTIFY: 'none' });
    assert.equal(again.code, 0, again.stdout);
    assert.equal(fs.readFileSync(secrets, 'utf8'), before, 'secrets kept on a re-run');
    assert.equal(JSON.parse(fs.readFileSync(cfg, 'utf8')).sources.wazuh.enabled, true, 'answers kept as defaults');
  } finally { m.close(); }
});

test('setup reports a wrong Zabbix token with the stripped-header hint; NETSEC_SETUP_STRICT=1 exits 1', async () => {
  const m = await mocks();
  const dir = tmp();
  try {
    const r = await run(['setup', '--config', path.join(dir, 'netsec.json'), '--non-interactive'], { NETSEC_SETUP_ZABBIX_URL: m.zbx.url, NETSEC_SETUP_ZABBIX_TOKEN: 'wrong-token-123', NETSEC_SETUP_STRICT: '1' });
    assert.equal(r.code, 1);
    assert.match(r.stdout, /FAIL {2}Zabbix API: Zabbix API error: Invalid params\. Not authorized/);
    assert.match(r.stdout, /hint: .*Authorization header/);
    assert.match(r.stdout, /not verified: Zabbix API/);
  } finally { m.close(); }
});

test('setup interactive (piped answers): same result, secret answers never printed', async () => {
  const m = await mocks();
  const dir = tmp();
  const cfg = path.join(dir, 'netsec.json');
  const answers = [
    'en', '', 'n', // language, port, LAN
    '10.0.0.9', 'n', // syslog allow, UDP
    m.wz.url, 'ro_user', 'wz-secret-Pa55', // Wazuh
    '', // Zabbix: skip
    '', // backups: skip
    'none', // notifications
    '', // LLM
    'boss', // admin name
  ].join('\n') + '\n';
  try {
    const r = await run(['setup', '--config', cfg, '--stdin'], {}, answers);
    assert.equal(r.code, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /ok {4}Wazuh indexer/);
    assert.ok(!r.stdout.includes('wz-secret-Pa55'), 'the password was not echoed');
    const c = JSON.parse(fs.readFileSync(cfg, 'utf8'));
    assert.deepEqual([c.sources.syslog.allow, c.sources.wazuh.enabled, c.sources.zabbix.enabled], [['10.0.0.9'], true, false]);
    assert.match(fs.readFileSync(path.join(dir, 'secrets.env'), 'utf8'), /NETSEC_ADMIN_USER='boss'/);
    const pw = r.stdout.match(/password: (\S+)/)[1];
    assert.ok(pw.length >= 12, 'a generated password is shown once');
  } finally { m.close(); }
});

test('I1: secrets.env next to the config is loaded, so a plain `node server/main.js` resolves env: secrets', async () => {
  const dir = tmp();
  const cfg = path.join(dir, 'netsec.json');
  fs.writeFileSync(cfg, JSON.stringify({ sources: { wazuh: { password: 'env:NETSEC_I1_PW' } } }));
  fs.writeFileSync(path.join(dir, 'secrets.env'), "NETSEC_I1_PW='from-the-file'\n", { mode: 0o600 });
  const probe = `const { loadConfig } = require(${JSON.stringify(path.join(ROOT, 'server/config.js'))}); const l = loadConfig(${JSON.stringify(cfg)}); console.log(l.cfg.sources.wazuh.password, l.secretsWarning)`;
  const out = await new Promise((resolve) => execFile(process.execPath, ['-e', probe], { env: baseEnv() }, (e, so) => resolve(so.trim())));
  assert.equal(out, 'from-the-file null');
  fs.chmodSync(path.join(dir, 'secrets.env'), 0o644);
  const warn = await new Promise((resolve) => execFile(process.execPath, ['-e', probe], { env: baseEnv() }, (e, so) => resolve(so.trim())));
  assert.match(warn, /^from-the-file .*readable by group\/others/);
  // an existing environment variable wins (Docker env_file, systemd EnvironmentFile)
  const env = await new Promise((resolve) => execFile(process.execPath, ['-e', probe], { env: { ...baseEnv(), NETSEC_I1_PW: 'from-env' } }, (e, so) => resolve(so.trim())));
  assert.match(env, /^from-env /);
});

test('I2: secrets and local state are git-ignored', async () => {
  const r = await new Promise((resolve) => execFile('git', ['check-ignore', 'secrets.env', '.env', 'backups/fw.conf', 'data/board.db', 'netsec.json', 'pull-zabbix.lock'], { cwd: ROOT }, (e, so) => resolve({ code: e ? e.code : 0, out: so })));
  if (r.code === 128) return; // not a git checkout (release tarball)
  assert.equal(r.out.trim().split('\n').length, 6, r.out);
});

test('the board creates the admin from NETSEC_ADMIN_HASH only while no user exists', () => {
  const A = require('../../server/auth.js');
  const db = require('../../server/db.js').openDb(tmp());
  const env = { NETSEC_ADMIN_USER: 'boss', NETSEC_ADMIN_HASH: A.hashPassword('bootstrap-pass-1') };
  assert.equal(A.bootstrapAdmin(db, { NETSEC_ADMIN_HASH: 'not-a-hash' }), null);
  assert.equal(A.bootstrapAdmin(db, env), 'boss');
  assert.ok(A.verifyPassword('bootstrap-pass-1', db.prepare("SELECT pass_hash FROM users WHERE username = 'boss'").get().pass_hash));
  assert.equal(A.bootstrapAdmin(db, { ...env, NETSEC_ADMIN_USER: 'second' }), null, 'never a second time');
  db.close();
});

test('C2: the GHCR image namespace everywhere is the repository owner, lowercased', () => {
  const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
  const owner = read('install.sh').match(/NETSEC_REPO:-([^/]+)\//)[1];
  const want = `ghcr.io/${owner.toLowerCase()}/netsec-board`;
  for (const f of ['install.sh', 'deploy/compose.install.yaml', 'README.md']) {
    const found = [...new Set(read(f).match(/ghcr\.io\/[a-z0-9-]+\/netsec-board/g) || [])];
    assert.deepEqual(found, [want], `${f}: ${found.join(', ')}`);
  }
  assert.match(read('.github/workflows/image.yml'), /GITHUB_REPOSITORY_OWNER,,/, 'the workflow derives it, no hardcoded copy');
  assert.match(read('README.md'), new RegExp(`raw\\.githubusercontent\\.com/${owner}/kku-netsec-assistant/main/install\\.sh`));
});

test('R6: setup asks for the indexer CA: a self-signed https Wazuh fails without it and passes with it', async (t) => {
  const { execFileSync } = require('node:child_process');
  const https = require('node:https');
  const dir = tmp();
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'ca.pem')], { stdio: 'ignore' });
  } catch { return t.skip('openssl not available'); }
  const server = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'ca.pem')) }, (req, res) => {
    if (req.headers.authorization !== `Basic ${Buffer.from('ro:pw-123').toString('base64')}`) { res.writeHead(401); return res.end('{}'); }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ hits: { total: { value: 42 }, hits: [] } }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `https://127.0.0.1:${server.address().port}`;
  const env = { NETSEC_SETUP_WAZUH_URL: url, NETSEC_SETUP_WAZUH_USER: 'ro', NETSEC_SETUP_WAZUH_PASSWORD: 'pw-123', NETSEC_SETUP_NOTIFY: 'none' };
  try {
    const without = await run(['setup', '--config', path.join(dir, 'a', 'netsec.json'), '--non-interactive'], env);
    assert.match(without.stdout, /FAIL {2}Wazuh indexer: .*(certificate|self.signed)/i);
    const withCa = await run(['setup', '--config', path.join(dir, 'b', 'netsec.json'), '--non-interactive'], { ...env, NETSEC_SETUP_WAZUH_CA: path.join(dir, 'ca.pem') });
    assert.match(withCa.stdout, /ok {4}Wazuh indexer: 42 alert\(s\)/, withCa.stdout);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'b', 'netsec.json'), 'utf8')).sources.wazuh.caFile, path.join(dir, 'ca.pem'));
  } finally { server.close(); }
});

test('M1: the wizard tests Zabbix with a CA path relative to netsec.json (as the board resolves it), not to its working directory', async () => {
  const dir = tmp();
  fs.mkdirSync(path.join(dir, 'certs'));
  fs.copyFileSync('/etc/ssl/certs/ca-certificates.crt', path.join(dir, 'certs', 'z.pem'));
  const r = await run(['setup', '--config', path.join(dir, 'netsec.json'), '--non-interactive'], { NETSEC_SETUP_LANG: 'en', NETSEC_SETUP_ZABBIX_URL: 'https://127.0.0.1:9/', NETSEC_SETUP_ZABBIX_TOKEN: 'zbx-tok-123', NETSEC_SETUP_ZABBIX_CA: 'certs/z.pem' });
  assert.doesNotMatch(r.stdout, /CA file not found/);
  assert.match(r.stdout, /FAIL {2}Zabbix API/, 'the live test ran (nothing listens there)');
  assert.doesNotMatch(r.stdout, /ENOENT|no such file/, 'it found the CA file');
});

