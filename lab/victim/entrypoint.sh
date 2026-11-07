#!/bin/sh
# start syslog (sshd -> /var/log/auth.log), sshd, nginx, then enroll and start the Wazuh agent
set -e
CONF=/var/ossec/etc/ossec.conf
grep -q '/srv/watch' "$CONF" || sed -i 's#</syscheck>#  <directories realtime="yes">/srv/watch</directories>\n  </syscheck>#' "$CONF"
grep -q 'nginx/access.log' "$CONF" || sed -i 's#</ossec_config>#  <localfile><log_format>apache</log_format><location>/var/log/nginx/access.log</location></localfile>\n</ossec_config>#' "$CONF"
sed -i 's#<address>.*</address>#<address>172.30.77.1</address>#' "$CONF"
rsyslogd
/usr/sbin/sshd
nginx
[ -s /var/ossec/etc/client.keys ] || /var/ossec/bin/agent-auth -m 172.30.77.1 -A "${AGENT_NAME:-lab-victim}"
/var/ossec/bin/wazuh-control start
touch /var/log/auth.log /var/log/nginx/access.log
exec tail -F /var/ossec/logs/ossec.log
