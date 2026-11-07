#!/bin/sh
# Raise the Wazuh indexer JVM heap (run as root). The indexer answers every request with
# HTTP 429 circuit_breaking_exception when its heap is too small for the alerts it holds.
#   sh lab/wazuh-heap.sh [SIZE=4g]
# Wazuh/OpenSearch guidance: heap = half of the RAM, at most ~32g, -Xms equal to -Xmx.
set -eu
SIZE=${1:-4g}
case "$SIZE" in *[!0-9gGmM]*|"") echo "size like 4g" >&2; exit 2 ;; esac
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
J=/etc/wazuh-indexer/jvm.options
CA=/etc/wazuh-indexer/certs/root-ca.pem
echo "==> before: $(grep -E '^-Xm[sx]' "$J" | tr '\n' ' ')"
cp -p "$J" "$J.netsec-bak.$(date +%Y%m%d%H%M%S)"
sed -i -E "s/^-Xms[0-9]+[gGmM]$/-Xms$SIZE/; s/^-Xmx[0-9]+[gGmM]$/-Xmx$SIZE/" "$J"
echo "==> after:  $(grep -E '^-Xm[sx]' "$J" | tr '\n' ' ')"
systemctl restart wazuh-indexer
i=0; until curl -s -o /dev/null --cacert "$CA" https://127.0.0.1:9200; do i=$((i + 1)); [ $i -lt 90 ] || { echo "indexer not up: journalctl -u wazuh-indexer"; exit 1; }; sleep 2; done
echo "==> indexer up with -Xmx$SIZE"
