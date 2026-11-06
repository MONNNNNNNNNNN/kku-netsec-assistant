#!/usr/bin/env python3
"""Wazuh integration: forward alerts to NetSec Board (POST /hooks/wazuh).

Install on the Wazuh manager:
  cp custom-netsec-board.py /var/ossec/integrations/custom-netsec-board.py
  chown root:wazuh /var/ossec/integrations/custom-netsec-board.py; chmod 750 ...
ossec.conf (inside <ossec_config>), then restart wazuh-manager:
  <integration>
    <name>custom-netsec-board.py</name>
    <hook_url>https://netsec-board.example.kku.ac.th/hooks/wazuh</hook_url>
    <api_key>HOOKS_WAZUH_TOKEN</api_key>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
Wazuh calls: <script> <alert_file> <api_key> <hook_url>. Standard library only.
"""
import json
import sys
import urllib.request


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: custom-netsec-board.py <alert_file> <api_key> <hook_url>", file=sys.stderr)
        return 2
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file, encoding="utf-8") as f:
        alert = json.load(f)
    req = urllib.request.Request(
        hook_url,
        data=json.dumps(alert).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:  # nosec: URL comes from ossec.conf
        return 0 if r.status == 202 else 1


if __name__ == "__main__":
    sys.exit(main())
