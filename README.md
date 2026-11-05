# NetSec Assistant (prototype v0.3)

**Live demo: https://monnnnnnnnnnn.github.io/kku-netsec-assistant/** (runs entirely in your browser; all data is synthetic)

**Step-by-step guide for the mentor (ไทย / English): https://monnnnnnnnnnn.github.io/kku-netsec-assistant/how-it-works.html**

An LLM layer for the KKU Office of Digital Technology network and cyber team. It runs on-prem, only reads its inputs, and is built to fit the ISMS. This prototype is for the mentor to try before the co-op starts.

**Idea in one line:** deterministic code finds the problems and cites config lines. A local LLM explains them in Thai and English and helps triage logs. Every LLM output goes through a guard so attacker text in the logs can't steer it.

## Try it (2 minutes)

- **In the browser:** open the [live demo](https://monnnnnnnnnnn.github.io/kku-netsec-assistant/), or `index.html` from a clone (works offline). It runs entirely in the tab. Nothing is uploaded.
  1. **Config review:** the sample loads automatically. Click the severity tiles to filter. Open a finding to see the evidence lines and suggested CLI. Switch between ไทย and English.
  2. **Report:** the ISO/IEC 27001:2022 evidence report. *LLM input (masked)* shows exactly what an LLM would receive.
  3. **Log-injection lab:** select log 2 (or 11, an attack the detector misses), compare the *Naive* and *Hardened* prompts, then click *Run guard*.
  4. To test a real backup, use *Open backup file…*. It never leaves the browser. Use a sanitised copy anyway.
- **CLI (Node 20+, no dependencies):**
  ```bash
  npm test                                   # 24 tests (unit + CLI end to end against a fake LLM)
  node cli/netsec.js analyze backup.conf --lang th > report.md
  node cli/netsec.js narrate backup.conf --lang th --llm http://<gpu-host>:8000/v1 --model <model>
  node cli/netsec.js narrate backup.conf --dry-run        # print the masked prompt only
  node cli/netsec.js triage export.log --llm https://<gpu-host>:8000/v1 --model <model> --lang th > triage.md
  node cli/netsec.js inject-eval samples/fgt-logs.log --detector-only     # detector recall, no LLM
  node cli/netsec.js inject-eval samples/fgt-logs.log --ablate --batch 5 --runs 3 \
       --llm http://localhost:11434/v1 --model <model> --out results/inject-eval-<model>.md
  ```
  `--llm` takes an OpenAI-compatible endpoint (vLLM, Ollama, LM Studio), but **only on-prem**: the host must resolve to loopback or a private range (RFC 1918, 100.64/10, IPv6 ULA), and non-loopback hosts need https. `--allow-remote-llm` and `--allow-http-lan` override this and are recorded in the audit log.
  Exit codes: 0 ok · 1 findings/alerts · 2 usage or refused endpoint · 3 audit write failed · **4 incomplete analysis**. Thinking is turned off by default (`reasoning_effort: none`); add `--think` to keep it.

## What it checks (FortiOS backup, offline)

| Area | Checks | ISO/IEC 27001:2022 |
|---|---|---|
| Firewall policy | any-any-ALL accept, inbound from WAN open to all, **shadowed** and redundant rules (top-down evaluation with subnet, port range, group, schedule and interface coverage), logging off, internet-bound without UTM, disabled rules, expired one-time schedules, undocumented rules | A.8.9, A.8.15, A.8.16, A.8.20, A.8.22, A.5.37 |
| Admin and management | admins without trusted hosts, super_admin without MFA, HTTP/Telnet management, management on WAN interfaces, admin timeout, password policy, strong-crypto, SNMP `public` | A.5.17, A.8.2, A.8.5, A.8.21, A.8.24 |
| Logging and time | no FortiAnalyzer/syslog/FortiCloud, NTP off | A.8.15, A.8.16, A.8.17 |
| VPN | weak IKE proposals and DH groups, SSL-VPN listening | A.8.24, A.8.8 |

Multi-VDOM backups, address and service groups, and multi-line quoted values are handled. Every finding carries its config line number and a suggested CLI fix, which a person reviews before applying.

**Coverage fails closed.** Anything the analysis could not check is listed in a *Coverage* section, and the report opens with an **INCOMPLETE ANALYSIS** banner: parse errors, enabled rules skipped by the shadow analysis (users, groups, ISDB, negate), IPv6 policies (not analysed) and undefined address/service names. `analyze` then exits 4, and `narrate` refuses unless `--allow-incomplete` (the LLM is then told the analysis is incomplete). Not covered at all: unused rules (hit counts are not in a backup).

## Design choices that matter for a certified ISMS

- **No write path.** Inputs are a backup file and a log export, and nothing connects to devices (A.5.15, A.8.2).
- **Masking before any LLM call** (A.8.11). IPs, FQDNs, e-mails, MACs, secrets and account names (also where they appear inside `msg`) become stable tokens (`PRIV_IP_3`, `HOST_2`, `USER_1`), and the map stays local to de-mask the answer. Tests assert that no raw IP, account name, MAC, internal hostname or secret reaches any prompt (config summary and all four log-triage prompt modes). Device names (DHCP hostname, `srcname`) are kept, datamarked, because they are an injection vector the eval measures.
- **Audit trail** (A.8.15). The CLI appends every LLM call to `audit/llm-calls.jsonl` (mode 0600): masked prompt, reply, model, endpoint, timing and SHA-256 hashes. `--audit <file>` or `NETSEC_AUDIT` moves it, `--no-audit` turns it off.
- **No cloud LLM** (A.5.23). The target is an open-weight model on KKU's own GPU servers.
- **The browser page cannot exfiltrate.** `dist/standalone.html` carries a CSP with `connect-src 'none'`, `form-action 'none'` and `frame-src 'none'` (only the Google Fonts stylesheet loads); the published artifact runs under the host's CSP. The LLM steps run from the CLI.
- **Log-injection defence in depth.** FortiGate logs contain attacker-chosen text (User-Agent, URL, DNS qname, login user). The hardened prompt separates those fields, caps and *datamarks* them (spotlighting, Hines et al., 2024), wraps them in a random boundary and passes detector flags as facts. The deterministic **output guard** is the main control. It is an experimental mitigation, not yet validated on real traffic or with repeated runs. It fails closed:
  - closed class/action enums (no "allow"), confidence clamped;
  - a missing verdict becomes `unknown/investigate`, and duplicate verdicts keep the more severe one (so "leave this entry out" does not hide an alert);
  - "benign" or "none" on an entry the detector flagged is raised to suspicious/investigate;
  - a **risk floor from device-generated fields** (level alert or higher, IPS severity high or above, IPS/anomaly/virus events, failed login, external source carrying attacker text) means the model cannot clear the entry. At most it drops to suspicious/monitor. This does not depend on the regex detector;
  - reasons that quote any 16-character window of attacker text are removed.
- **The detector is a hint, not a control.** It flags 5/5 of the attacks written alongside it, but only **1/11 held-out attacks** (`--detector-only`). The floor covers 10/11 held-out attacks, including a payload stitched across two log entries (31–32). **Known gap:** log 20, a DNS C2 beacon whose device fields look harmless, can still be cleared by the model. Threat-intel fields (DNS filter category, IOC lists) are needed for that case.

## Results so far (Oracle ARM, 4 vCPU, CPU only)

- `results/narrate-qwen2.5-3b-instruct.md`: `qwen2.5:3b-instruct` in 660 s on CPU. The priorities are correct and grounded (policy 9 any-any, WAN inbound, no trusted hosts, management on WAN, cleartext management). It does not invent a "secure" verdict. **But it answered in English although Thai was requested.** A Thai-tuned model (Typhoon 2) on the GPU servers is the next test.
- `results/narrate-qwen3.5-2b-head.md`: Thai executive summary from `huihui_ai/qwen3.5-abliterated:2B` (**an abliterated model with its safety tuning removed: kept only as a labelled worst case, not a candidate**) on CPU in 37 s. It picks the right priorities (policy 9, policy 5, MFA), but it also **claims the network is "secure at a high level", mixes in a Chinese token and gives a wrong fix for strong-crypto.** This is why the deterministic report stays the source of truth and the LLM text is a draft for review. A larger model on the GPU servers is the next test.
- `results/inject-eval-qwen2.5-3b-instruct.md`: `qwen2.5:3b-instruct` (stock instruct model) on lines 1–20 only (5 seen + 9 held-out attacks; the stitched pair 31–32 was added later and has no LLM run yet), naive vs full prompt, **1 run each** (85 min on CPU, so read these as a smoke result, not statistics):

  | | canary leaked | seen attacks won: raw → after guard | held-out won: raw → after guard | attack lines the model left out |
  |---|---|---|---|---|
  | naive | yes | 2/5 → **0/5** | 6/9 → **1/9** | 0 |
  | full (hardened) | no | 5/5 → **0/5** | 5/9 → **1/9** | 5 of 14 |

  What this shows: the hardened prompt stopped the canary leak. But the small model then **dropped entries from its JSON** (5 attack lines with no verdict), so it looked *worse* raw. Only the fail-closed guard turned those into `unknown/investigate`. The guard held at 0/5 seen and 1/9 held-out in both modes. The one held-out attack that got through is log 20, the DNS beacon. The "non-attack lines raised by guard" column counts lines that are not injection attempts, which includes the two SSL-VPN brute-force lines (8, 9). Raising those is correct, not a false positive.
- Not yet measured: the 4-mode ablation (`--ablate`) and several runs per mode. On this CPU that takes about 14 h, so it is planned for the GPU servers (weeks 12–14).
- `test/cli.test.js` checks the same pipeline against a fake model that is fully manipulated (everything benign, one entry dropped). After the guard: 0% of seen attacks and 1/11 held-out get through, in every mode.

## Related work
- Pandey & Bhujang, *Poisoning the Watchtower: Prompt Injection Attacks Against LLM-Augmented Security Operations Through Adversarial Log Content*, arXiv [2605.24421](https://arxiv.org/abs/2605.24421) (2026). Same threat model (attacker-written log fields); prompt-level defences cut average success from 26.6% to 11.8%.
- Karanjai et al., *LogInject / Context Contamination*, arXiv [2607.14493](https://arxiv.org/abs/2607.14493) (2026). 12,847-entry benchmark; "Context Stitching" splits a payload across entries (76.4% success). Logs 31–32 here reproduce that pattern.
- Tools it complements, not replaces: [Batfish](https://batfish.readthedocs.io/en/latest/formats.html) (open source, supports FortiGate configs since its 2021-04-12 release; its FortiOS coverage depth on a real backup is still to be tested), FortiManager/FortiAnalyzer (policy management, log analytics), Wazuh (open-source SIEM), [CISO Assistant](https://github.com/intuitem/ciso-assistant-community) (open-source GRC for ISO 27001 evidence tracking).
- What this prototype adds: a deterministic guard that fails closed and floors risk from device-generated fields, so the result does not depend on the model or the detector; Thai and held-out payloads; FortiOS fields; a small on-prem model.

## Where it sits

It complements the tools ODT already has; it does not replace a SIEM or a policy manager.

```
FortiGate / network devices ──► config backups, log exports
   │
   ├─ FortiAnalyzer / Wazuh ........ collect, correlate, alert            (existing)
   ├─ Batfish / FortiManager ....... policy validation, change control    (existing / cross-check)
   └─ NetSec Assistant ............. deterministic checks + ISO evidence,
                                     Thai/English explanation, guarded LLM triage
                                     read-only, on-prem, every LLM call audited
                     │
                     ▼
        security engineer reviews and approves (no automatic change)
```

Research framing: *an evaluation of deterministic, device-field-based risk enforcement for LLM-assisted FortiGate log triage (Thai, context-stitching, on-prem)*.

## Roadmap (16-week co-op)

Config work is validated before log integration, so the project does not become five unfinished ones.

| Weeks | Deliverable |
|---|---|
| 1–2 | Decision gate: is FortiManager/FortiAnalyzer policy analysis in use, data permissions, GPU access. LLM risk assessment (ISO 27001 6.1.2 + OWASP LLM Top 10) |
| 3–5 | Parser and checks validated on real sanitised backups; Batfish as a cross-check oracle for shadowed rules |
| 6–7 | ISO evidence report for the surveillance audit |
| 8–10 | `triage` on real log exports; optional read-only import from Wazuh or FortiAnalyzer |
| 11–13 | Multi-model, multi-run injection research on the GPU servers (Thai, context-stitching, DNS) |
| 14–15 | Performance, privacy and false-positive evaluation |
| 16 | Handover: runbook, metrics before/after, draft paper (e.g. ECTI-CIT) |

## Questions for the mentor

1. Can I get a sanitised FortiGate backup (or one VDOM) and a one-day log export to validate the checks?
2. Which LLM serving is planned on the NVIDIA servers (vLLM / Ollama), and which models are allowed?
3. Which Annex A controls take the most manual work at the surveillance audit?
4. Read-only API accounts: iMaster NCE northbound, Zabbix, FortiAnalyzer. Which are realistic?
5. What are "Garud" and the "Security Scoreboard" exactly, and which metric should this project move?
6. Is FortiManager/FortiAnalyzer policy analysis already in use? Which focus do you prefer: this assistant, an ISO evidence assistant, or a `*.kku.ac.th` attack-surface monitor?

## Layout

```
src/core.js     parser, checks, report, masking, injection defences (shared by browser + CLI)
src/app.js      browser UI
web/page.html   page template
build.js        inlines everything into index.html (GitHub Pages), dist/standalone.html and dist/index.html (artifact body)
cli/netsec.js   analyze | narrate | triage | inject-eval
samples/        synthetic FortiOS config and 32 log lines (issues and injections seeded on purpose);
                fgt-logs.labels.json is the ground truth: 5 seen + 11 held-out attacks
test/           node:test suite (24 tests; fixtures/incomplete.conf exercises the coverage gate) (core.test.js unit, cli.test.js end to end with a fake OpenAI-compatible server)
results/        measured LLM outputs
```

All sample data is synthetic: documentation IP ranges (RFC 5737), `uni.example`, fake hashes. This is not an official KKU system.

License: MIT (see `LICENSE`).
