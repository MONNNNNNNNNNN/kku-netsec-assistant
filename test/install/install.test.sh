#!/usr/bin/env bash
# install.sh end to end (CI job "install"; runs locally too, needs Docker):
#   1. shellcheck
#   2. Node mode in a clean node:22.13 container (the minimum version), non-root: install,
#      start, log in, re-run (upgrade) keeps the secrets and the data
#   3. Docker mode with a locally built image: install, log in
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'cd "$WORK/docker" 2>/dev/null && docker compose down -v >/dev/null 2>&1; true' EXIT
cat > "$WORK/login.js" <<'JS'
const [u, p] = process.argv.slice(2);
(async () => {
  for (let i = 0; i < 60; i++) { try { if ((await fetch(`${u}/healthz`)).ok) break; } catch { /* starting */ } await new Promise((r) => setTimeout(r, 500)); }
  const r = await fetch(`${u}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: p }) });
  console.log('login', r.status);
  process.exit(r.status === 200 ? 0 : 1);
})();
JS

echo "== shellcheck"
docker run --rm -v "$ROOT:/mnt:ro" koalaman/shellcheck:v0.10.0 /mnt/install.sh /mnt/test/install/install.test.sh

echo "== Node mode (node:22.13, non-root)"
cat > "$WORK/node.sh" <<'IN'
set -e
export NETSEC_SETUP_LANG=en NETSEC_SETUP_SYSLOG_ALLOW=10.0.0.1 NETSEC_SETUP_NOTIFY=none NETSEC_SETUP_ADMIN_PASSWORD=ci-install-pass-1
t0=$(date +%s)
sh /src/install.sh --node --non-interactive --version main --dir /tmp/nb > /tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; }
echo "node install: $(( $(date +%s) - t0 )) s"
test "$(stat -c %a /tmp/nb/secrets.env)" = 600
test "$(stat -c %a /tmp/nb/data)" = 700
node /tmp/nb/app/server/main.js --config /tmp/nb/netsec.json > /tmp/board.log 2>&1 &
node /login.js http://127.0.0.1:8480 ci-install-pass-1
before=$(sha256sum /tmp/nb/secrets.env)
sh /src/install.sh --node --non-interactive --version main --dir /tmp/nb > /tmp/rerun.log 2>&1 || { cat /tmp/rerun.log; exit 1; }
test "$before" = "$(sha256sum /tmp/nb/secrets.env)"
grep -q "configured before" /tmp/rerun.log   # an upgrade does not ask again
test -f /tmp/nb/data/board.db
echo "node re-run kept secrets and data"
IN
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$ROOT:/src:ro" -v "$WORK/node.sh:/t.sh:ro" -v "$WORK/login.js:/login.js:ro" node:22.13-bookworm-slim sh /t.sh

echo "== refuses an install folder with spaces"
if sh "$ROOT/install.sh" --node --non-interactive --dir "$WORK/with space" > "$WORK/space.log" 2>&1; then echo "accepted a folder with spaces"; exit 1; fi
grep -q "cannot contain spaces" "$WORK/space.log"

echo "== Docker mode (local image)"
docker build -q -t netsec-board-local:latest "$ROOT" >/dev/null
mkdir -p "$WORK/docker"
t0=$(date +%s)
NETSEC_IMAGE=netsec-board-local NETSEC_SETUP_LANG=en NETSEC_SETUP_NOTIFY=none NETSEC_SETUP_ADMIN_PASSWORD=ci-install-pass-2 \
  sh "$ROOT/install.sh" --docker --non-interactive --version main --dir "$WORK/docker"
echo "docker install: $(( $(date +%s) - t0 )) s"
node "$WORK/login.js" http://127.0.0.1:8480 ci-install-pass-2
echo "install tests: ok"
