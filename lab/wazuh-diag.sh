#!/bin/sh
# Read-only diagnosis of the lab victim's alerts on this VM's Wazuh manager (run as root).
#   sh lab/wazuh-diag.sh            (also starts filebeat if it is stopped, so alerts reach the indexer)
# Prints counts only for real traffic; full lines only for the lab victim (our own test data).
set -u
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
A=/var/ossec/logs/alerts/alerts.json
echo "==> services: manager $(systemctl is-active wazuh-manager), indexer $(systemctl is-active wazuh-indexer), filebeat $(systemctl is-active filebeat)"
if [ "$(systemctl is-active filebeat)" != active ]; then systemctl start filebeat && echo "    started filebeat"; fi
echo "==> agents"
/var/ossec/bin/agent_control -l 2>/dev/null | sed -n 's/.*ID: \([0-9]*\), Name: \([^,]*\), IP: [^,]*, \(.*\)/    \1 \2 \3/p'
echo "==> all alerts in $A (today): count by agent name (a noisy agent can fill any "last N" window)"
grep -o '"agent":{"id":"[0-9]*","name":"[^"]*"' "$A" | sed 's/.*"name":"//; s/"$//' | sort | uniq -c | sort -rn | sed 's/^/    /'
echo "==> lab-victim alerts (rule id, level, description), today"
grep '"name":"lab-victim"' "$A" | grep -o '"rule":{"level":[0-9]*,"description":"[^"]*","id":"[0-9]*"' | sed 's/"rule":{"level":\([0-9]*\),"description":"\([^"]*\)","id":"\([0-9]*\)"/\3 L\1 \2/' | sort | uniq -c | sort -rn | head -15 | sed 's/^/    /'
echo "==> how the manager decodes one lab sshd line (wazuh-logtest)"
printf '%s\n' '2026-11-07T03:36:28.846533+00:00 lab-victim sshd[1815]: Failed password for invalid user ue6bab0ea54fe from 172.30.77.7 port 48608 ssh2' | timeout 20 /var/ossec/bin/wazuh-logtest -q 2>&1 | grep -E "program_name|decoder|id:|level|description|No decoder" | head -12 | sed 's/^/    /'
echo "==> integration log (last 5 lines, tokens removed)"
tail -n 5 /var/ossec/logs/integrations.log 2>/dev/null | sed 's/Bearer [A-Za-z0-9]*/Bearer <token>/g; s/api_key[^ ]*/api_key <removed>/g' | sed 's/^/    /'
