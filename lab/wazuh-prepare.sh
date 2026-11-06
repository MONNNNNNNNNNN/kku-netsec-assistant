#!/bin/sh
# Prepare this VM's native Wazuh for the NetSec Board real-data lab. Run as root, read it first:
#   sudo sh lab/wazuh-prepare.sh [--with-dashboard] [--push-hook] [--board-user claudecode]
#
# It does, and prints, exactly this:
#   1. starts wazuh-indexer and wazuh-manager (and the dashboard with --with-dashboard)
#   2. makes the manager read this host's sshd journal (Ubuntu 24.04 has no /var/log/auth.log)
#   3. creates a least-privilege indexer user "netsec_board_ro" (role: cluster_composite_ops_ro +
#      read/search on wazuh-alerts-*) with a new random password, written to
#      /etc/netsec-board/wazuh-ro-password (0640, group = the board user's group; never printed)
#   4. copies the indexer root CA to /etc/netsec-board/wazuh-root-ca.pem (0644) for caFile
#   5. allows the lab Docker bridge (nsb-lab0, 172.30.77.0/24) to reach the manager (1514/1515)
#      and the board (8480), in iptables, not persisted (gone after a reboot)
#   6. --push-hook: installs deploy/custom-netsec-board.py as a Wazuh integration posting
#      level >= 7 alerts to http://127.0.0.1:8480/hooks/wazuh, with a new token in
#      /etc/netsec-board/wazuh-hook-token (0640, same group)
# It changes nothing else. ossec.conf is backed up to ossec.conf.netsec-bak.<date> before edits.
set -eu

WITH_DASHBOARD=0
PUSH_HOOK=0
BOARD_USER=claudecode
while [ $# -gt 0 ]; do
  case "$1" in
    --with-dashboard) WITH_DASHBOARD=1 ;;
    --push-hook) PUSH_HOOK=1 ;;
    --board-user) BOARD_USER="${2:?--board-user needs a name}"; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || { echo "run as root: sudo sh $0" >&2; exit 1; }
BOARD_GROUP=$(id -gn "$BOARD_USER") || { echo "no user $BOARD_USER (--board-user)" >&2; exit 1; }
secret_file() { # secret_file PATH VALUE: 0640 root:<board group>, written without echo
  install -d -m 755 /etc/netsec-board
  ( umask 027; printf '%s' "$2" > "$1" ); chown root:"$BOARD_GROUP" "$1"; chmod 640 "$1"
  echo "   wrote $1 (0640 root:$BOARD_GROUP)"
}
HERE=$(cd "$(dirname "$0")/.." && pwd)
OSSEC=/var/ossec/etc/ossec.conf
CA=/etc/wazuh-indexer/certs/root-ca.pem
say() { printf '\n==> %s\n' "$*"; }

say "1. start Wazuh services"
systemctl start wazuh-indexer
i=0; until curl -s -o /dev/null --cacert "$CA" https://127.0.0.1:9200; do i=$((i + 1)); [ $i -lt 90 ] || { echo "indexer not up: journalctl -u wazuh-indexer"; exit 1; }; sleep 2; done
systemctl start wazuh-manager
[ "$WITH_DASHBOARD" = 1 ] && systemctl start wazuh-dashboard
/var/ossec/bin/wazuh-control info | sed 's/^/   /'

say "2. sshd journal -> manager"
if grep -q '<location>journald</location>' "$OSSEC"; then
  echo "   a journald localfile exists already; left as is"
else
  cp -p "$OSSEC" "$OSSEC.netsec-bak.$(date +%Y%m%d%H%M%S)"
  # append one <ossec_config> block (ossec.conf may hold several)
  cat >> "$OSSEC" <<'EOF'

<!-- added by NetSec Board lab/wazuh-prepare.sh: this host's sshd (Ubuntu 24.04 logs to journald only) -->
<ossec_config>
  <localfile>
    <location>journald</location>
    <log_format>journald</log_format>
    <filter field="_SYSTEMD_UNIT">^ssh\.service$</filter>
  </localfile>
</ossec_config>
EOF
  echo "   added a journald localfile for ssh.service"
fi

say "3. read-only indexer user netsec_board_ro"
ADMIN_PW="${WAZUH_ADMIN_PASSWORD:-}"
if [ -z "$ADMIN_PW" ]; then
  TAR=$(find / -maxdepth 3 -name wazuh-install-files.tar 2>/dev/null | head -n 1 || true)
  if [ -n "$TAR" ]; then
    ADMIN_PW=$(tar -axf "$TAR" wazuh-install-files/wazuh-passwords.txt -O | grep -A1 "indexer_username: 'admin'" | sed -n "s/.*indexer_password: '\(.*\)'.*/\1/p")
    echo "   admin password read from $TAR"
  fi
fi
if [ -z "$ADMIN_PW" ]; then
  printf '   indexer admin password (not echoed): '; stty -echo 2>/dev/null || true; read -r ADMIN_PW; stty echo 2>/dev/null || true; echo
fi
api() { # api METHOD PATH JSON
  code=$(curl -s -o /tmp/netsec-api.out -w '%{http_code}' --cacert "$CA" -u "admin:$ADMIN_PW" -X "$1" -H 'content-type: application/json' "https://127.0.0.1:9200$2" ${3:+-d "$3"})
  case "$code" in 2*) echo "   $1 $2: $code" ;; *) echo "   $1 $2: HTTP $code $(cat /tmp/netsec-api.out)"; rm -f /tmp/netsec-api.out; exit 1 ;; esac
  rm -f /tmp/netsec-api.out
}
# 8-64 chars with upper, lower, digit and a symbol (the indexer's password policy)
RO_PW="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)-Aa1"
api PUT /_plugins/_security/api/roles/netsec_board_ro '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read","indices:data/read/search"]}]}'
api PUT /_plugins/_security/api/internalusers/netsec_board_ro "{\"password\":\"$RO_PW\",\"description\":\"NetSec Board, read-only\"}"
api PUT /_plugins/_security/api/rolesmapping/netsec_board_ro '{"users":["netsec_board_ro"]}'
n=$(curl -s --cacert "$CA" -u "netsec_board_ro:$RO_PW" 'https://127.0.0.1:9200/wazuh-alerts-*/_count' | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
echo "   check as netsec_board_ro: wazuh-alerts-* holds ${n:-?} alert(s)"
secret_file /etc/netsec-board/wazuh-ro-password "$RO_PW"
if curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" -u "netsec_board_ro:$RO_PW" -X DELETE 'https://127.0.0.1:9200/wazuh-alerts-nonexistent' | grep -q '^403$'; then echo "   check: writes are refused (403), as intended"; fi

say "4. CA for the board"
install -d -m 755 /etc/netsec-board
install -m 644 "$CA" /etc/netsec-board/wazuh-root-ca.pem
echo "   /etc/netsec-board/wazuh-root-ca.pem"

say "5. lab bridge nsb-lab0 -> manager 1514/1515, board 8480 (iptables, not persisted)"
for p in 1514 1515 8480; do
  iptables -C INPUT -i nsb-lab0 -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -i nsb-lab0 -p tcp --dport "$p" -j ACCEPT
done
echo "   ok"

if [ "$PUSH_HOOK" = 1 ]; then
  say "6. push hook integration"
  HOOK_TOKEN=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
  secret_file /etc/netsec-board/wazuh-hook-token "$HOOK_TOKEN"
  sed -i '/custom-netsec-board.py/,/<\/integration>/s#<api_key>.*</api_key>#<api_key>'"$HOOK_TOKEN"'</api_key>#' "$OSSEC"
  install -o root -g wazuh -m 750 "$HERE/deploy/custom-netsec-board.py" /var/ossec/integrations/custom-netsec-board.py
  if ! grep -q 'custom-netsec-board.py' "$OSSEC"; then
    cp -p "$OSSEC" "$OSSEC.netsec-bak.$(date +%Y%m%d%H%M%S)"
    cat >> "$OSSEC" <<EOF

<!-- added by NetSec Board lab/wazuh-prepare.sh --push-hook -->
<ossec_config>
  <integration>
    <name>custom-netsec-board.py</name>
    <hook_url>http://127.0.0.1:8480/hooks/wazuh</hook_url>
    <api_key>$HOOK_TOKEN</api_key>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
  fi
  echo "   installed"
fi

say "restart wazuh-manager (config check first)"
for t in wazuh-analysisd wazuh-logcollector; do
  /var/ossec/bin/$t -t >/dev/null 2>&1 || { echo "   $t config check failed: restore the backup in $(dirname "$OSSEC")"; exit 1; }
done
systemctl restart wazuh-manager
echo "   ok"

say "done. The board reads its secrets as file:/etc/netsec-board/wazuh-ro-password$( [ "$PUSH_HOOK" = 1 ] && printf ' and file:/etc/netsec-board/wazuh-hook-token' )"
