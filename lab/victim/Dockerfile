# Lab victim: sshd + nginx + the Wazuh agent (package; the official agent image has no arm64).
# The agent version must not be newer than the manager: build with --build-arg WAZUH_VERSION=<manager version>.
FROM debian:bookworm-slim
ARG WAZUH_VERSION
RUN test -n "$WAZUH_VERSION" && apt-get update && apt-get install -y --no-install-recommends \
      openssh-server nginx rsyslog curl gnupg ca-certificates procps \
  && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
  && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
  && apt-get update && WAZUH_MANAGER=172.30.77.1 apt-get install -y --no-install-recommends wazuh-agent=${WAZUH_VERSION}-1 \
  && apt-get clean && mkdir -p /run/sshd /srv/watch && echo "lab file" > /srv/watch/payroll.csv
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22 80
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
