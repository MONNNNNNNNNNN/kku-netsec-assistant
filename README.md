# NetSec Assistant + NetSec Board (prototype v0.5)

**Website: https://monnnnnnnnnnn.github.io/kku-netsec-assistant/** · **Manual (ไทย / English): [manual.html](https://monnnnnnnnnnn.github.io/kku-netsec-assistant/manual.html)** (offline copy: [docs/manual.md](docs/manual.md)) · **Browser demo of the v0.3 config review and log-injection lab: [demo.html](https://monnnnnnnnnnn.github.io/kku-netsec-assistant/demo.html)** (runs entirely in your browser; synthetic data)

**Step-by-step guide for the mentor (ไทย / English): https://monnnnnnnnnnn.github.io/kku-netsec-assistant/how-it-works.html**

An LLM layer for the KKU Office of Digital Technology network and cyber team. It runs on-prem, only reads its inputs, and is built to fit the ISMS. This prototype is for the mentor to try before the co-op starts.

**Idea in one line:** deterministic code finds the problems and cites config lines. A local LLM explains them in Thai and English and helps triage logs. Every LLM output goes through a guard so attacker text in the logs can't steer it.

## NetSec Board: live monitoring board (v0.5)

![NetSec Board, light theme](docs/screenshots/board-light.png)

A self-hosted board that **pulls and receives events automatically**: no manual imports. It shows them as a moodboard of cards you can pin, acknowledge, snooze, collapse or expand, and it pushes notifications. It runs read-only, on-prem, with zero npm runtime dependencies (Node ≥ 22.13, built-in SQLite).

**Try it (one command, no real device):**
```bash
docker compose --profile demo up -d --build      # or, without Docker: npm run demo
# open http://127.0.0.1:8480  ->  admin / demo-admin-pass   (viewer / demo-viewer-pass for read-only)
```
The demo lab plays a FortiGate, a Wazuh indexer, Zabbix, notification sinks, an adversarial LLM and a spoofing host.

**Install (one command, about a minute):**
```bash
curl -fsSL https://raw.githubusercontent.com/MONNNNNNNNNNN/kku-netsec-assistant/main/install.sh | sh
```
It uses Docker Compose if the machine has it (prebuilt `ghcr.io/monnnnnnnnnnn/netsec-board` image, amd64/arm64), otherwise Node ≥ 22.13 (no `npm install`: zero runtime dependencies) with a systemd service when run as root. A short wizard asks for the FortiGate sender IP, the Wazuh indexer URL and user, the Zabbix URL and API token, a config-backup folder, one notification channel and an optional local LLM; **it tests each answer against the real system** (Zabbix: including a web server that strips the Authorization header) and sends a test notification. It writes `netsec.json` (secrets only as `env:` references) and `secrets.env` (mode 600), prints the board URL and the admin password once, and prints the FortiGate syslog lines to paste. Re-running the installer upgrades and keeps the config and data. Options: `--docker`/`--node`, `--dir`, `--version v0.5.0`, and `--non-interactive` with `NETSEC_SETUP_*` variables for scripted installs (list in `cli/setup.js`).

<details><summary>Manual install (from a clone)</summary>

```bash
node cli/board.js setup                      # the same wizard: writes netsec.json + secrets.env (loaded automatically)
node cli/board.js check && node server/main.js   # connectivity check, then start; open http://127.0.0.1:8480
```
With Docker from the clone: `node cli/board.js setup` (or `cp netsec.example.json netsec.json` and edit it; it must exist before compose mounts it), then `mkdir -p backups && docker compose --profile prod up -d --build`. As a service: `deploy/netsec-board.service`. Behind a TLS proxy set `"trustProxy": true` (proxy on the same host) or a list of the proxy addresses: `X-Forwarded-For` is believed only from those, and only its rightmost hop.
</details>

| Source | How data arrives | Notes |
|---|---|---|
| FortiGate logs | **push**: syslog TCP/UDP 5514 (`deploy/fortigate-syslog.txt`) | Sender IP allowlist (empty = nobody); spoofed senders are dropped and counted; per-sender rate limit; CSV/CEF rejected |
| Wazuh | **pull** (cron) from the indexer `_search`, or **push** via `deploy/custom-netsec-board.py` | Read-only indexer role (`cluster_composite_ops_ro` + read on `wazuh-alerts*`) |
| Zabbix | **pull** (cron) `event.get` with `Authorization: Bearer`, or **push** via the webhook media type `deploy/zabbix-media-webhook.js` | `check` detects a web server that strips the Authorization header |
| FortiGate config | **pull** (cron) from a file-drop folder (default), or opt-in REST backup (GET before 7.6, POST from 7.6) | REST backup needs more than read-only rights, so file-drop is the default. Findings become cards; fixed findings resolve themselves |
| Anything else | **push** `POST /hooks/generic` with a bearer token | |

Schedules are cron expressions in Asia/Bangkok time (`*/2 * * * *`, `@every 30s`). To use system cron instead, set `"schedule": "external"` and run `node cli/board.js pull <source>` (`deploy/crontab.example`: it exports `secrets.env` with `set -a` and wraps each run in `flock`); the CLI only writes (never the LLM; one run per source at a time, with the same lock file the board's own runs and "Pull now" use, and a lock left by a crashed run is taken over), and the running board picks up its rows within 2 s, shows their toasts, triages them and sends their digests. Pulls look back over a 2-minute lag window and skip ids already seen, so Wazuh alerts indexed late and Zabbix events committed out of order are not lost (and not counted twice); the first Zabbix pull also loads the problems open right now. Use **either** the pull **or** the push hook for Wazuh/Zabbix, not both (`check` warns): both would count every event twice. Prefer TCP syslog (and `"udp": false`): UDP has no delivery guarantee and its sender address can be forged, so the allowlist cannot stop a spoofer on the network path. For UDP the board asks for a large receive buffer (raise `net.core.rmem_max` to let it) and shows the kernel's UDP drop counter on the syslog tile.

**Notifications:** board toasts, a bell drawer and browser notifications are always on. Optional channels: **ntfy** (self-hosted; e-mail through ntfy's forwarding), **Telegram**, **LINE** Messaging API (digest by default, hard daily cap: the Thai free plan is about 300 messages a month) and **webhook** (HMAC-signed, e.g. n8n). Rules per channel: minimum severity, sources, quiet hours, rate limit with digest overflow, re-notify only on escalation. Cloud channels only ever receive masked text (IPs, hostnames, e-mails, account names become tokens).

**LLM (optional):** the board is complete without it. "Explain" on a card queues it first; automatic triage takes only critical items, one card per call, within an hourly budget (default 12 calls/hour). Measured with `qwen2.5:3b-instruct` on 4 ARM cores: about 23 s per card, a verdict for 11 of 11 cards one at a time but only 4 of 11 in batches of 5 (`results/real-data/`). Severity comes from device fields and can only go **up** after the guarded LLM verdict, never down.

**Grouping:** repeats of one event become one card with a count. Cards group on device-generated fields only, so a brute force with thousands of random user names stays one card (and one notification); the attacker-controllable values are kept as up to 5 samples, and injection flags are never washed out by later clean repeats. Low Wazuh alerts (internet SSH scanning, rule 5710) group per rule and agent with the attacker IPs as samples; medium and above stay one card per source IP (`sources.wazuh.perSourceCardsFrom`). An acknowledged card of an event that never resolves (FortiGate, Wazuh) re-arms and notifies again when it repeats after 24 h of quiet (`board.rearmAfterHours`). Operators can remap severity per rule with `severityOverrides` (`source`, `match` regexes on device-generated fields only, so log text an attacker writes can never trigger them; a flagged event never drops below medium; `check` validates them). Above 120 new cards a minute from one source (`board.newCardsPerMinute`), further distinct events fold into one "burst of distinct events" card per attack, with a count of the distinct sources, so a distributed scan stays a handful of cards. A repeated field in a FortiGate log (a value smuggling `severity=`/`srcip=`) keeps the device's first value and flags the card. Channel rate limits and daily caps also count sends still in flight. The first pull of each source is a quiet baseline: what is already open appears as cards and toasts, without channel notifications or automatic AI (`"quietFirstRun": false` per source to change that). Live updates are batched (at most one per second), so a burst does not freeze the browser, and the board reloads its cards after every reconnect of the live stream.

**Security:** async scrypt passwords (at most 20 checks at a time), HttpOnly SameSite=Strict sessions that also end open live streams on logout, CSRF tokens, login backoff per IP (IPv6 per /64; `X-Forwarded-For` only from listed proxies, rightmost hop), at most 2 password checks at once per address with 4 slots kept for known logins, a 15-minute lock per account + address after 10 failures (the account itself only slows down, max 30 s, and never for an address it logged in from), failed/locked logins on an admin tile, viewer/operator/admin roles, strict CSP, no HTML built from strings in the UI (log fields are attacker-controlled), secrets only as references, database `0600` with 30-day retention and an audit of who viewed, pinned or acknowledged what (PDPA: treat `data/board.db` as an ISMS asset). Back it up with `node cli/board.js backup /secure/board-$(date +%F).db` (a consistent copy while the board runs, mode 600; in Docker: `docker compose exec board node cli/board.js backup /data/backup.db`, then `docker compose cp board:/data/backup.db .`); a plain `cp` of a live WAL database can give a torn copy.

**Tests:** `npm test` (130: unit, components, integration against mock vendor APIs, CLI, deploy scripts, static XSS check, a regression test for each finding of the 5-, 10- and 20-pass reviews and the privacy checks in `test/board/hardening.test.js`, an anonymous-attacker suite in `test/board/anonymous.test.js` (every route without a session, malformed requests, cookies, CSRF, hooks, login sprays, slow clients, spoofed syslog), performance: 10,000 syslog lines in about 1.5–1.8 s, API p95 under 50 ms on the Oracle ARM box) and `npm run test:e2e` (Playwright: login, live cards, pin/ack/snooze, collapse/expand, toasts, bell, filters, Explain, Thai, dark mode, 390 px phone). CI runs both on Node 22 and 24 plus a Docker compose smoke test. The mocks follow vendor documentation **and the recorded behaviour of real systems** (below).

**Verified against real systems and real data** ([report](results/real-data-eval.md), reproducible with [`lab/`](lab/README.md)):

| Integration | Tested against | Result |
|---|---|---|
| Wazuh pull | Wazuh 4.14.9 indexer, 1.37 M real alerts | every alert fetched (55,201: all up to the start, exactly the indexer's count at the end, while live alerts arrived); 0 duplicates after restart; live alert → card 13 s at a 15 s schedule; 3 real weeks → 59 cards |
| Wazuh push | the real integration (`deploy/custom-netsec-board.py`) | 438 / 439 alerts accepted; alert → card 1.3 s |
| Zabbix | Zabbix 7.0.32, API token + the real webhook media type | problem, recovery and recurrence in 3-6 s, both pull and push |
| FortiGate logs | 510,899 real lines (Splunk BOTSv1, CC0, FortiOS 5.x) | 100% parsed; 28 days → 145 cards, 31 pushes; 0 false injection flags; 5,423 lines/s |
| LLM | Ollama `qwen2.5:3b-instruct`, CPU | 23 s per card; the guard overrode the one injected card the model called benign |
| Cloud masking | 30 real cards, 48 identifiers | 0 leaks to Telegram/LINE |
| Install | `install.sh` against the real stack | 10 s install, first real card 3.6 s later |

Not yet verified: a real FortiGate device on current FortiOS, and KKU's own Wazuh/Zabbix.

![Board on real data (identifiers masked)](docs/screenshots/real-board.png)

**Prior art (searched 2026-11-06):** the pieces exist separately (Wazuh-Autopilot and SOC-Automation for LLM triage of Wazuh alerts, fortigate-log-triage, fwrule-mcp, forti-elk, Zabbix + Ollama webhook guides, vendor AI in FortiAnalyzer and ManageEngine). None combines FortiGate config and logs, Wazuh, Zabbix and syslog on one board with an on-prem LLM whose output cannot lower device-field severity, Thai output and an injection evaluation. AiSOC's reported auto-closing of alerts through injection (May 2026) shows why the guard matters.

<p><img src="docs/screenshots/board-dark.png" alt="NetSec Board, dark theme" width="68%"> <img src="docs/screenshots/board-phone.png" alt="NetSec Board on a phone" width="24%"></p>

## Config review and log-injection lab (browser demo, v0.3)

### Try it (2 minutes)

- **In the browser:** open the [live demo](https://monnnnnnnnnnn.github.io/kku-netsec-assistant/demo.html), or `demo.html` from a clone (works offline). It runs entirely in the tab. Nothing is uploaded.
  1. **Config review:** the sample loads automatically. Click the severity tiles to filter. Open a finding to see the evidence lines and suggested CLI. Switch between ไทย and English.
  2. **Report:** the ISO/IEC 27001:2022 evidence report. *LLM input (masked)* shows exactly what an LLM would receive.
  3. **Log-injection lab:** select log 2 (or 11, an attack the detector misses), compare the *Naive* and *Hardened* prompts, then click *Run guard*.
  4. To test a real backup, use *Open backup file…*. It never leaves the browser. Use a sanitised copy anyway.
- **CLI (Node 22.13+, no dependencies):**
  ```bash
  npm test                                   # all tests (see the Board section)
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
   └─ NetSec Assistant / Board ..... deterministic checks + ISO evidence, one board for
                                     FortiGate + Wazuh + Zabbix + syslog, notifications,
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
| 8–10 | `triage` on real log exports; NetSec Board sources switched on one by one (read-only accounts approved in weeks 1–2) |
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
7. For the board: how are FortiGate config backups made today (FortiManager, SCP, auto-backup)? This decides file-drop or REST. Is there a FortiAnalyzer that could forward syslog? Which LINE OA plan and which ntfy host may we use? Is a GPU available (without one, the LLM stays on demand at about 4 calls per hour)?

## Layout

```
src/core.js       parser, checks, report, masking, injection defences (shared by browser, CLI and board)
src/app.js        browser UI of the config/injection demo; web/page.html + build.js -> demo.html (GitHub Pages)
scripts/build-pages.js  the website: index.html (landing) and manual.html (TH/EN), docs/manual.md
cli/netsec.js     analyze | narrate | triage | inject-eval
server/           NetSec Board: main, http (API, SSE, hooks), auth, db (node:sqlite), cron, scheduler,
                  trust (per-source field-trust maps), pipeline, llm + llmqueue, notify, collectors/
board/            moodboard UI (vanilla JS, no build step)
cli/board.js      init | user | pull | check | test-notify | audit-export
mocks/            mock FortiGate, Wazuh indexer, Zabbix, notification sinks, LLM; lab.js runs them all
deploy/           systemd unit, crontab, FortiGate syslog commands, Zabbix webhook, Wazuh integration, Caddy
Dockerfile, compose.yaml   demo / prod / llm profiles
samples/          synthetic FortiOS config and 32 log lines (issues and injections seeded on purpose);
                  fgt-logs.labels.json is the ground truth: 5 seen + 11 held-out attacks
test/             node:test (core, CLI, board/*) and e2e/ (Playwright)
results/          measured LLM outputs
```

All sample data is synthetic: documentation IP ranges (RFC 5737), `uni.example`, fake hashes. This is not an official KKU system.

License: MIT (see `LICENSE`).
