#!/bin/sh
# X7: install.sh (Node mode, non-interactive) in a clean node:22.13 container on the host network,
# pointed at the REAL stack: this VM's Wazuh (read-only user, CA picked up automatically), the lab
# Zabbix 7.0, the local Ollama. Measures install time and time to the first real card (any source;
# the read-only Zabbix user sees only the lab host group, which may have no open problem).
#   sh lab/x7-install.sh          (needs lab/wazuh-prepare.sh done and the lab Zabbix up)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/results/real-data/x7-install.json"
docker run --rm --network host -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$ROOT:/src:ro" -v /etc/netsec-board:/etc/netsec-board:ro node:22.13-bookworm-slim sh -c '
set -e
export NETSEC_SETUP_LANG=en NETSEC_SETUP_NOTIFY=none NETSEC_SETUP_ADMIN_PASSWORD=x7-install-pass-1
export NETSEC_SETUP_WAZUH_URL=https://127.0.0.1:9200 NETSEC_SETUP_WAZUH_USER=netsec_board_ro
export NETSEC_SETUP_WAZUH_PASSWORD="$(cat /etc/netsec-board/wazuh-ro-password)"
export NETSEC_SETUP_ZABBIX_URL=http://127.0.0.1:18080 NETSEC_SETUP_ZABBIX_TOKEN="$(cat /src/lab/data/zabbix-token)"
export NETSEC_SETUP_LLM_URL=http://127.0.0.1:11434/v1 NETSEC_SETUP_LLM_MODEL=qwen2.5:3b-instruct
t0=$(date +%s%3N)
sh /src/install.sh --node --non-interactive --version main --dir /tmp/nb > /tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; }
t1=$(date +%s%3N)
node /tmp/nb/app/server/main.js --config /tmp/nb/netsec.json > /tmp/board.log 2>&1 &
node -e "
  const { DatabaseSync } = require(\"node:sqlite\");
  const t0 = Date.now();
  (async () => {
    for (;;) {
      try { const d = new DatabaseSync(\"/tmp/nb/data/board.db\", { readOnly: true }); const r = d.prepare(\"SELECT source, COUNT(*) AS n FROM items GROUP BY source\").all(); d.close(); if (r.length) { console.log(JSON.stringify({ firstCardsMs: Date.now() - t0, cardsBySource: r })); break; } } catch {}
      if (Date.now() - t0 > 120000) { console.log(JSON.stringify({ firstCardsMs: null })); break; }
      await new Promise((r) => setTimeout(r, 200));
    }
  })();" > /tmp/first.json
grep -q "firstCardsMs\": null" /tmp/first.json && tail -5 /tmp/board.log >&2
checks=$(grep -E "^  (ok|FAIL) " /tmp/install.log | sed "s/[0-9][0-9]* alert(s)/N alert(s)/" | tr "\n" ";")
printf "{\"installMs\": %s, \"wizardChecks\": \"%s\", \"first\": %s}\n" "$((t1 - t0))" "$checks" "$(cat /tmp/first.json)"
' > "$OUT.tmp"
node -e "const j=JSON.parse(require('fs').readFileSync('$OUT.tmp','utf8'));j.ranAt=new Date().toISOString();j.wizardChecks=j.wizardChecks.split(';').filter(Boolean).map((s)=>s.trim());require('fs').writeFileSync('$OUT',JSON.stringify(j,null,2)+'\n');console.log(JSON.stringify(j,null,1))"
rm -f "$OUT.tmp"
