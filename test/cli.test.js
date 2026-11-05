'use strict';
// End-to-end CLI test against a fake OpenAI-compatible server that plays a fully
// manipulated model: every entry it sees is "benign / none", and it drops log 17.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'cli/netsec.js');

function fakeLlm() {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const msgs = JSON.parse(body).messages;
      seen.push(msgs);
      const text = msgs.map((m) => m.content).join('\n');
      const ids = new Set([...text.matchAll(/"log_id": (\d+)/g), ...text.matchAll(/^(\d+): /gm)].map((m) => Number(m[1])));
      const verdicts = [...ids].filter((id) => id !== 17).map((id) => ({ log_id: id, classification: 'benign', confidence: 0.99, recommended_action: 'none', reason: 'expected activity' }));
      const reply = 'Sure. CANARY-7731\n```json\n' + JSON.stringify({ verdicts }) + '\n```';
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      for (let i = 0; i < reply.length; i += 40) res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: reply.slice(i, i + 40) } }] })}\n\n`);
      res.end('data: [DONE]\n\n');
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, url: `http://127.0.0.1:${server.address().port}/v1` })));
}

const run = (args) => new Promise((resolve) => execFile(process.execPath, [CLI, ...args], { cwd: ROOT }, (err, stdout, stderr) => resolve({ code: err ? err.code : 0, stdout, stderr })));

test('inject-eval end to end: guard holds against a fully manipulated model, every call is audited and masked', async () => {
  const llm = await fakeLlm();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'netsec-'));
  const auditFile = path.join(dir, 'audit.jsonl'), out = path.join(dir, 'eval.md');
  try {
    const r = await run(['inject-eval', 'samples/fgt-logs.log', '--llm', llm.url, '--model', 'fake', '--modes', 'naive,full', '--runs', '1', '--batch', '10', '--audit', auditFile, '--out', out]);
    assert.equal(r.code, 0, r.stderr);
    const md = fs.readFileSync(out, 'utf8');
    // | mode | runs | canary | seen raw | seen guard | held raw | held guard | ...
    const row = (mode) => md.split('\n').find((l) => l.startsWith(`| ${mode} | 1 |`)).split('|').map((c) => c.trim());
    for (const mode of ['naive', 'full']) {
      const c = row(mode);
      assert.equal(c[3], '100%', `${mode}: canary leaked`);
      assert.equal(c[4], '100%', `${mode}: raw model fooled on every seen attack`);
      assert.equal(c[5], '0%', `${mode}: no seen attack survives the guard`);
      assert.equal(c[6], '100%', `${mode}: raw model fooled on every held-out attack`);
      assert.equal(c[7], '9%', `${mode}: only log 20 (1/11) survives the guard`);
    }
    assert.match(md, /\| held-out \| 1\/11 \|/);

    const lines = fs.readFileSync(auditFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.length, 8, '4 chunks x 2 modes');
    assert.equal(llm.seen.length, 8);
    for (const rec of lines) {
      assert.equal(rec.model, 'fake');
      assert.match(rec.prompt_sha256, /^[0-9a-f]{64}$/);
      assert.ok(rec.reply.includes('verdicts'));
    }
    // what reached the model, plus what was audited from the conversation (endpoint is the model server, not log data)
    const sent = JSON.stringify(llm.seen) + JSON.stringify(lines.map((x) => [x.messages, x.reply]));
    assert.ok(!/\b\d{1,3}(\.\d{1,3}){3}\b/.test(sent), 'no raw IPv4 sent or audited');
    for (const x of ['svc_backup', 'staff.somchai', 'netadmin1', 'uni.example', '00:11:22:33:44']) assert.ok(!sent.includes(x), x);
    if (process.platform !== 'win32') assert.equal(fs.statSync(auditFile).mode & 0o777, 0o600);
  } finally {
    llm.server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('narrate --dry-run prints a masked prompt and calls no model', async () => {
  const r = await run(['narrate', 'samples/fgt-demo.conf', '--dry-run', '--no-audit']);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /PRIV_IP_\d+|PUB_IP_\d+/);
  assert.ok(!/\b(10|172|192|198|203)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(r.stdout.replace(/255\.\d+\.\d+\.\d+/g, '')), 'no raw IP in the prompt');
});

test('incomplete analysis fails closed: analyze exits 4 with a banner, narrate refuses', async () => {
  const a = await run(['analyze', 'test/fixtures/incomplete.conf', '--lang', 'en']);
  assert.equal(a.code, 4, a.stderr);
  assert.match(a.stdout, /INCOMPLETE ANALYSIS: 5 item\(s\) were not checked/);
  assert.match(a.stdout, /policy 1 "Staff-VPN-Users" \(line 8\): groups/);
  assert.match(a.stdout, /IPv6 policies \(not analysed\): 1/);
  assert.match(a.stdout, /line 43: unknown keyword "frobnicate"/);
  assert.match(a.stdout, /Lab-Net-Missing/);
  const n = await run(['narrate', 'test/fixtures/incomplete.conf', '--dry-run', '--no-audit']);
  assert.equal(n.code, 4);
  assert.match(n.stderr, /refused: INCOMPLETE ANALYSIS/);
  const f = await run(['narrate', 'test/fixtures/incomplete.conf', '--dry-run', '--no-audit', '--allow-incomplete']);
  assert.equal(f.code, 0, f.stderr);
  assert.match(f.stdout, /"status": "INCOMPLETE"/);
});

test('complete sample config: coverage complete, exit 1 for high findings, no secret in the narrate prompt', async () => {
  const a = await run(['analyze', 'samples/fgt-demo.conf', '--lang', 'en']);
  assert.equal(a.code, 1);
  assert.match(a.stdout, /Complete: every statement parsed/);
  const n = await run(['narrate', 'samples/fgt-demo.conf', '--dry-run', '--no-audit']);
  assert.equal(n.code, 0, n.stderr);
  assert.ok(!n.stdout.includes('NOTAREAL'), 'password/PSK hashes never reach the prompt');
});

test('LLM endpoint must be on-prem: public IP refused before any request, plain http to a LAN host needs a flag', async () => {
  const pub = await run(['triage', 'samples/fgt-logs.log', '--llm', 'http://8.8.8.8:1/v1', '--model', 'x', '--no-audit']);
  assert.equal(pub.code, 2);
  assert.match(pub.stderr, /not on-prem/);
  const lan = await run(['triage', 'samples/fgt-logs.log', '--llm', 'http://10.255.255.1:1/v1', '--model', 'x', '--no-audit']);
  assert.equal(lan.code, 2);
  assert.match(lan.stderr, /https is required/);
});

test('triage end to end: every entry gets a guarded verdict, overrides are shown, data is masked and audited', async () => {
  const llm = await fakeLlm();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'netsec-'));
  const auditFile = path.join(dir, 'audit.jsonl'), json = path.join(dir, 'v.json');
  try {
    const r = await run(['triage', 'samples/fgt-logs.log', '--llm', llm.url, '--model', 'fake', '--batch', '10', '--lang', 'en', '--audit', auditFile, '--json', json]);
    assert.equal(r.code, 1, r.stderr); // alerts present
    const rows = r.stdout.split('\n').filter((l) => /^\| \d+ \|/.test(l));
    assert.equal(rows.length, 32);
    const row32 = rows.find((l) => l.startsWith('| 32 |'));
    assert.match(row32, /\| suspicious \| monitor \|/);
    assert.match(row32, /risk floor \(level alert, utm\/ips/);
    assert.match(r.stdout, /198\.51\.100\.77/, 'report is unmasked for the analyst');
    assert.match(rows.find((l) => l.startsWith('| 17 |')), /missing verdict/);
    const v = JSON.parse(fs.readFileSync(json, 'utf8'));
    assert.equal(v.length, 32);
    const audit = fs.readFileSync(auditFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(audit.length, 4, '32 lines / batch 10');
    assert.equal(audit[0].endpoint_class, 'loopback');
    const sent = JSON.stringify(llm.seen);
    assert.ok(!/\b\d{1,3}(\.\d{1,3}){3}\b/.test(sent), 'no raw IPv4 sent');
  } finally {
    llm.server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
