# Real-data lab

Scripts that test NetSec Board against real systems and real, openly licensed data. Results land in `results/real-data/*.json`, and the write-up is [`results/real-data-eval.md`](../results/real-data-eval.md). None of this is part of the product install.

## Anywhere (Docker + Node ≥ 22.13)

| Experiment | Prepare | Run |
|---|---|---|
| X1: FortiGate logs (BOTSv1, CC0) | download into `lab/botsv1/` (below) | `node lab/botsv1-replay.js` |
| X4: Zabbix 7.0 | `docker compose -f lab/compose.yaml up -d zbx-db zbx-server zbx-web zbx-agent zbx-strip`, `node lab/zabbix-setup.js`, then `LAB_UID=$(id -u) LAB_GID=$(id -g) docker compose -f lab/compose.yaml up -d board-hook` | `node lab/x4-zabbix.js` |
| X5: a local LLM | Ollama with `qwen2.5:3b-instruct` on `127.0.0.1:11434` | `node lab/x5-llm.js --batch 1` (and `--batch 5`) |

BOTSv1 (CC0 1.0, [github.com/splunk/botsv1](https://github.com/splunk/botsv1)):
```bash
B=https://s3.amazonaws.com/botsdataset/botsv1/json-by-sourcetype; mkdir -p lab/botsv1 && cd lab/botsv1
curl -fsSLO $B/botsv1.fgt_event.json.gz && curl -fsSLO $B/botsv1.fgt_utm.json.gz
curl -fsSL $B/botsv1.fgt_traffic.json.gz | gunzip -c | head -n 200000 > botsv1.fgt_traffic.first200k.json   # 910 MB compressed in full
sha256sum * > SHA256SUMS
```

## With a Wazuh 4.x (all-in-one) on the same host

These steps are root-only. Read each script first: each prints what it does and changes nothing else.

| Script (as root) | What it changes |
|---|---|
| `sh lab/wazuh-prepare.sh [--push-hook]` | Starts the indexer and manager. Adds a journald localfile for sshd if missing (after backing up `ossec.conf`). Creates the read-only indexer user `netsec_board_ro`, with its password in `/etc/netsec-board/wazuh-ro-password` (0640, never printed). Copies the indexer CA to `/etc/netsec-board/`. Adds non-persistent iptables rules letting `nsb-lab0` reach 1514/1515/8480. `--push-hook` installs the integration and writes a token file. |
| `sh lab/wazuh-heap.sh 4g` | Sets `-Xms/-Xmx` in `/etc/wazuh-indexer/jvm.options` (after a backup) and restarts the indexer. Needed when every query fails with HTTP 429 `circuit_breaking_exception`. |
| `sh lab/wazuh-diag.sh` | Read-only, but starts Filebeat if it is stopped (alerts reach the indexer only through Filebeat). |

Then:
- `WAZUH_VERSION=<manager version> docker compose -f lab/compose.yaml --profile wazuh up -d victim`: sshd, nginx and the Wazuh agent, enrolled to the manager.
- `node lab/x2-wazuh.js --from <ISO time> [--live 90]`: pull completeness, grouping, latency.
- `node lab/x3-wazuh-push.js`: push through the real integration while `lab/attack.sh` runs.
- `node lab/x6-masking.js 3`: cloud masking on real cards.
- `sh lab/x7-install.sh`: the one-command install against the real stack.
- `node lab/real-screenshots.js`: masked screenshots into `docs/screenshots/real-*.png`.

`lab/attack.sh` only targets the lab victim on the isolated Docker network `nsb-lab0` (172.30.77.0/24).

## Clean up

```bash
docker compose -f lab/compose.yaml --profile wazuh down -v
```
The iptables rules disappear at the next reboot.
