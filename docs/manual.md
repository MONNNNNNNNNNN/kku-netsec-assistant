# NetSec Board manual

Operators: sections 1-6. Admins: 7-12, then Troubleshooting. Thai/English web version: https://monnnnnnnnnnn.github.io/kku-netsec-assistant/manual.html

## 0. About this manual

NetSec Board is a monitoring board for network and security events. It pulls and receives data from FortiGate, Wazuh and Zabbix automatically, shows each event as a card, and notifies people when something matters. It runs on-prem and only reads; it never writes to a device.

- **Operators:** read "Daily use": everything you do on the board is there.
- **Admins:** read "Install and configure" and "Troubleshooting".
- Every number in this manual was measured on real systems: see `results/real-data-eval.md`.

## 1. Daily use 1: the board

Open the board in a browser and sign in. The top area summarises; the cards are below.

| Part | What it is for |
|---|---|
| Open critical + high | How many important items nobody has acknowledged yet. Look here first. |
| By severity | Open cards per severity. |
| New items, 24 h | New cards per hour: a spike means something happened. |
| Sources | Each source's status (ok / degraded / down) with an error that says what to fix. |
| AI queue | Cards waiting for the AI, and the hourly budget. |
| Pinned / Live | Pinned cards stay on top; all other cards follow. |

Use the chips to filter by source or severity, Open / Acknowledged / All to switch views, and `/` to search.

## 2. Daily use 2: what the severity means

Severity comes only from fields the device generates. Text an attacker writes into a log can never lower it.

| Level | Meaning | What happens |
|---|---|---|
| **critical** | Act now: e.g. ransomware C2, IPS critical | All channels, automatic AI triage, never closes by itself |
| **high** | Important: brute force, Wazuh level 10-12 | Channels (default), never closes by itself |
| **medium** | Worth a look: e.g. a log that tries to instruct the AI | On the board; closes after 72 h of quiet |
| **low** | Context: e.g. SSH scanning from the internet | On the board; closes after 24 h |
| **info** | Normal: filtered out by default | - |

## 3. Daily use 3: handling cards

| Button | Effect |
|---|---|
| Expand | Show every field. Fields marked ⚠ hold text an outsider can control. |
| Pin | Keep on top. Pinned cards never auto-close. |
| Acknowledge | Someone owns it. The card moves to Acknowledged. |
| Snooze 1h / 8h / 24h | Hide for a while, with no notifications meanwhile. |

- **Recurrence:** a resolved card that happens again re-opens and notifies again.
- **Escalation:** a repeat with a higher severity clears acknowledge and snooze and notifies again.
- **Re-arm:** an acknowledged card whose event comes back after 24 h of quiet notifies again (`board.rearmAfterHours`).
- **Auto-close:** quiet low/medium cards close by themselves (24/72 h); high and critical wait for a person. Pinned cards and cards inside a snooze stay open.
- Keys: `j`/`k` move, `e` expand, `p` pin, `a` acknowledge, `/` search.

## 4. Daily use 4: how events are grouped

- Repeats of one event are one card with a count ×N.
- Values an attacker can vary (user names, URLs) are kept as up to 5 samples, so a brute force with random user names stays one card.
- Low-severity scanning from many IPs (e.g. Wazuh 5710) is one card per rule and host; medium and above stay one card per IP.
- **Burst:** above 120 new cards a minute from one source, further distinct events fold into one "burst of distinct events" card.
- **Correlated:** the same IP seen by FortiGate and Wazuh within an hour tags both cards "correlated" and raises them one level (at most high).

## 5. Daily use 5: Explain (AI)

Press "Explain (AI)" on a card: a local model (e.g. qwen2.5:3b) explains it and suggests an action, in about 23 s per card on a CPU.

- The AI can only **raise** a card's severity, never lower it.
- If the AI raises a card the device rated low/info, it shows on the board only, with no notification. A card that is medium only because its log tries to instruct the AI still counts as what the device said (so an attacker cannot trick the AI into paging the team).
- The "tried to manipulate AI" badge means the log contains text that tries to instruct the AI. Such a card is at least medium, and the guard never lets the AI call it safe.
- In real tests the model was fooled into "benign" once in 4 tries, and the guard overrode it every time.

## 6. Daily use 6: notifications

- On the board: toasts and the bell (high and above by default).
- Channels: ntfy, Telegram, LINE (digests), webhook. Each has a minimum severity, quiet hours and a daily cap.
- Cloud channels only get masked text: IPs, host and user names become tokens (e.g. `HOSTNAME_1`). Tested on 30 real cards: no leaks.
- The first pull of each source is quiet: what is already open appears as cards, without notifications.

## 7. Install and configure 1: install

One command (Linux). It uses Docker if present, otherwise Node 22.13+ with a systemd service:

```
curl -fsSL https://raw.githubusercontent.com/MONNNNNNNNNNN/kku-netsec-assistant/main/install.sh | sh
```

- The wizard asks one question at a time and **tests each answer live**: FortiGate IP, Wazuh indexer, Zabbix, backup folder, a notification channel, the LLM.
- It writes `netsec.json` (no secrets inside) and `secrets.env` (mode 600), and shows the admin password once.
- Running it again upgrades and keeps config and data; add `--reconfigure` to answer the questions again.
- Options: `sh -s -- --docker` or `--node`, `--dir /srv/netsec-board`, `--non-interactive` (with `NETSEC_SETUP_*` variables).

> Measured: install in 10 s, first real card 3.6 s after start.

## 8. Install and configure 2: FortiGate

FortiGate sends syslog to the board (TCP recommended). On the FortiGate CLI:

```
config log syslogd setting
    set status enable
    set server "<board IP>"
    set mode reliable
    set port 5514
    set format rfc5424
end
```

- Put the FortiGate's IP in `sources.syslog.allow`; any other sender is dropped.
- UDP sender addresses can be forged and packets can be lost: with TCP, set `"udp": false`.
- Config backups: let your existing backup job write `.conf` files into a folder and enable `sources.configdrop`.

## 9. Install and configure 3: Wazuh

The board reads the Wazuh indexer (port 9200) with a read-only user. The scripts are in the repo: on a Wazuh all-in-one host, clone it and run them with sudo **before** installing the board:

```
git clone https://github.com/MONNNNNNNNNNN/kku-netsec-assistant && cd kku-netsec-assistant
sudo sh lab/wazuh-prepare.sh       # read-only user netsec_board_ro; password and CA in /etc/netsec-board/
sudo sh lab/wazuh-heap.sh 4g       # only if the indexer answers HTTP 429 circuit_breaking_exception
```

- The wizard asks for the password (read it with `sudo cat /etc/netsec-board/wazuh-ro-password`) and keeps it in `secrets.env` (0600), not in `netsec.json`.
- The installer copies the indexer CA (Wazuh uses a self-signed CA) to `certs/wazuh-root-ca.pem` next to `netsec.json` when it can read it, and the wizard offers that file. In Docker the board sees only this `certs/` folder; otherwise copy it yourself: `sudo cp /etc/netsec-board/wazuh-root-ca.pem certs/`.
- Use **one of**: pull (default) or push through the integration (`deploy/custom-netsec-board.py`). With both, events count twice (`check` warns).
- Alerts reach the indexer through Filebeat: if Filebeat is stopped, the board sees no new alerts.

> Measured on Wazuh 4.14.9: every alert fetched, no duplicates after a restart, alert to card in 13 s (pull) or 1.3 s (push).

## 10. Install and configure 4: Zabbix

- Create a read-only user (User role, read on the host groups you want) and an API token for it.
- Pull: put the URL and token in `sources.zabbix`; the wizard checks it and tells you if the web server strips the Authorization header.
- Push: create a Webhook media type from `deploy/zabbix-media-webhook.js`, make sure it is **Enabled** (one created through the API starts disabled), and add an action for problem and recovery.

> Measured on Zabbix 7.0.32: problem, recovery and recurrence reach the board in 3-6 s, both pull and push.

## 11. Install and configure 5: tuning severity

`severityOverrides` in `netsec.json` match regexes on device-generated fields only, so log text can never trigger them.

```
"severityOverrides": [
  { "label": "config changes", "source": "fortigate", "match": { "logdesc": "^Configuration changed$" }, "severity": "high" },
  { "label": "core servers", "source": "wazuh", "match": { "agent.name": "^core-" }, "raise": 1 },
  { "label": "server VLAN", "source": "fortigate", "match": { "dstip": "cidr:10.20.0.0/16" }, "raise": 1 }
]
```

- `severity` sets a level (the first matching rule wins); `raise` adds levels (they add up, at most critical). An event flagged for manipulating the AI never goes below medium.
- Other knobs: `board.rearmAfterHours` (24), `board.autoResolveAfterHours` (`{"info":24,"low":24,"medium":72}`), `board.newCardsPerMinute` (120), `sources.wazuh.perSourceCardsFrom` ("medium"), `sources.<name>.minSeverity` ("low").
- After editing, run `node cli/board.js check`: it validates every rule.

## 12. Install and configure 6: users, backup and routine

| Task | Command |
|---|---|
| Add a user | `node cli/board.js user add <name> --role viewer\|operator\|admin` |
| Change a password | `node cli/board.js user passwd <name>` |
| Check config and connections | `node cli/board.js check` |
| Test a notification channel | `node cli/board.js test-notify <channel-name>` |
| Back up the database while running | `node cli/board.js backup /secure/board-$(date +%F).db` |
| AI audit trail | `node cli/board.js audit-export --since 2026-11-01` |
| Upgrade | Run the install command again |

- Roles: viewer reads; operator pins, acknowledges, snoozes and uses the AI; admin also sees the config.
- Behind a reverse proxy (Caddy) set `"cookieSecure": true` and `"trustProxy": true`.
- The database holds real IPs and user names (personal data under PDPA): kept 30 days, with an audit of who viewed or did what.

## 13. Troubleshooting

Every row here happened during the tests on real systems.

| Symptom | Cause | Fix |
|---|---|---|
| Wazuh: "out of heap memory (HTTP 429)" | The indexer heap is too small | `sudo sh lab/wazuh-heap.sh 4g` |
| Wazuh: certificate / self-signed | No CA configured | Copy the indexer root CA to `certs/wazuh-root-ca.pem` and set `sources.wazuh.caFile` to `certs/wazuh-root-ca.pem` (relative to `netsec.json`) |
| Wazuh: no new alerts | Filebeat is stopped | `systemctl start filebeat` (root) |
| An agent sends no sshd events | The agent reads journald but the host logs to `/var/log/auth.log` | Add a `/var/log/auth.log` localfile to the agent's ossec.conf |
| Zabbix: Not authorized | The web server strips the Authorization header | Apache `CGIPassAuth On`, or nginx `fastcgi_param HTTP_AUTHORIZATION $http_authorization;` |
| Zabbix webhook never arrives | The media type is disabled | Enable the media type |
| "cannot listen ... already in use" | Something else uses port 8480 | Stop it, or set `listen.port` |
| "no admin user" | Setup has not run | `node cli/board.js setup` |

## 14. What is not yet verified

- A real FortiGate on current FortiOS (tested with real BOTSv1 logs, FortiOS 5.x from 2016).
- KKU's own Wazuh and Zabbix (tested with Wazuh 4.14.9 and Zabbix 7.0.32 on one VM).
- Multi-node use and campus-scale volume.

---
Generated by scripts/build-pages.js from the same source as manual.html.
