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
