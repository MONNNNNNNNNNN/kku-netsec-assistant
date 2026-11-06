#!/bin/sh
# NetSec Board installer: one command, Docker if present, otherwise Node >= 22.13 (+ systemd as root).
#
#   curl -fsSL https://raw.githubusercontent.com/MONNNNNNNNNNN/kku-netsec-assistant/main/install.sh | sh
#   ./install.sh [--docker|--node] [--dir DIR] [--version vX.Y.Z|main] [--non-interactive] [--start]
#
# Re-running it upgrades the app and keeps netsec.json, secrets.env and the data.
# It never installs system packages; it tells you the one command when something is missing.
# Overrides (tests, mirrors): NETSEC_IMAGE, NETSEC_TARBALL (file or URL), NETSEC_REPO.
set -eu

REPO="${NETSEC_REPO:-MONNNNNNNNNNN/kku-netsec-assistant}"
IMAGE="${NETSEC_IMAGE:-ghcr.io/monnnnnnnnnnnn/netsec-board}"
MODE=""
DIR=""
VERSION="${NETSEC_VERSION:-}"
NONINTERACTIVE=0
START=0
T0=$(date +%s)

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --docker) MODE=docker ;;
    --node) MODE=node ;;
    --dir) [ $# -ge 2 ] || die "--dir needs a path"; DIR="$2"; shift ;;
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift ;;
    --non-interactive) NONINTERACTIVE=1 ;;
    --start) START=1 ;;
    -h|--help) sed -n '2,10p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

[ "$(uname -s)" = "Linux" ] || die "Linux only (on macOS/Windows use: git clone, then docker compose --profile demo up)"
have() { command -v "$1" >/dev/null 2>&1; }
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1
if [ -z "$DIR" ]; then
  if [ "$IS_ROOT" = 1 ]; then DIR=/opt/netsec-board; else DIR="$HOME/netsec-board"; fi
fi

# the wizard needs a terminal; under `curl | sh` stdin is this script, so answers come from /dev/tty
if [ "$NONINTERACTIVE" = 0 ] && ! (exec </dev/tty) 2>/dev/null; then
  die "no terminal for the setup questions: run it in a shell, or use --non-interactive with NETSEC_SETUP_* variables (see cli/setup.js)"
fi

fetch() { # fetch URL FILE
  if have curl; then curl -fsSL "$1" -o "$2"; elif have wget; then wget -qO "$2" "$1"; else die "need curl or wget"; fi
}
node_ok() { # node >= 22.13
  have node || return 1
  node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=13)?0:1)' 2>/dev/null
}

# ---- mode
if [ -z "$MODE" ]; then
  if have docker && docker compose version >/dev/null 2>&1; then MODE=docker
  elif node_ok; then MODE=node
  else
    say "Neither Docker Compose v2 nor Node >= 22.13 was found. Install one, then run this again:"
    say "  Docker:  curl -fsSL https://get.docker.com | sh"
    say "  Node 22: curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs"
    exit 1
  fi
fi
[ "$MODE" = node ] && ! node_ok && die "Node >= 22.13 is required for --node (found: $(node -v 2>/dev/null || echo none))"

# ---- version: the latest release, else main
if [ -z "$VERSION" ]; then
  VERSION=$( (curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true) | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$VERSION" ] || VERSION=main
fi

mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)
SRC=""   # a clone, when run as ./install.sh (under `curl | sh`, $0 is the shell)
if [ -f "$0" ]; then SRC=$(cd "$(dirname "$0")" && pwd); fi
FROM_CLONE=0; [ -n "$SRC" ] && [ -f "$SRC/deploy/compose.install.yaml" ] && [ -f "$SRC/cli/setup.js" ] && FROM_CLONE=1
RAW="https://raw.githubusercontent.com/$REPO/$VERSION"
HOST_IP=$( (ip route get 1.1.1.1 2>/dev/null || true) | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)
[ -n "$HOST_IP" ] || HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

say "NetSec Board installer: mode $MODE, version $VERSION, folder $DIR"

if [ "$MODE" = docker ]; then
  # ---------------------------------------------------------------- Docker
  step "files"
  if [ "$FROM_CLONE" = 1 ]; then
    cp "$SRC/deploy/compose.install.yaml" "$DIR/compose.yaml"
    cp "$SRC/netsec.example.json" "$DIR/netsec.example.json"
  else
    fetch "$RAW/deploy/compose.install.yaml" "$DIR/compose.yaml"
    fetch "$RAW/netsec.example.json" "$DIR/netsec.example.json"
  fi
  mkdir -p "$DIR/backups"
  # netsec.json must exist before compose mounts it (else Docker creates a directory in its place)
  [ -f "$DIR/netsec.json" ] || { cp "$DIR/netsec.example.json" "$DIR/netsec.json"; chmod 640 "$DIR/netsec.json"; }
  TAG=$VERSION; [ "$TAG" = main ] && TAG=latest
  TAG=${TAG#v}
  cd "$DIR"
  # compose variables: keep the wizard's binds, set the image version
  touch .env
  grep -v '^NETSEC_VERSION=\|^NETSEC_IMAGE=' .env > .env.tmp || true
  printf 'NETSEC_VERSION=%s\nNETSEC_IMAGE=%s\n' "$TAG" "$IMAGE" >> .env.tmp
  mv .env.tmp .env

  step "image $IMAGE:$TAG"
  if docker image inspect "$IMAGE:$TAG" >/dev/null 2>&1 && [ -n "${NETSEC_IMAGE:-}" ]; then
    say "using the local image"
  elif ! docker compose pull -q board; then
    [ "$FROM_CLONE" = 1 ] || die "could not pull $IMAGE:$TAG (is the package public? see the README)"
    say "pull failed: building the image from this clone"
    docker build -q -t "$IMAGE:$TAG" "$SRC" >/dev/null
  fi

  step "setup"
  # the wizard runs in the image as you, writing only into $DIR (never the data volume)
  set -- docker compose run --rm --no-deps --user "$(id -u):$(id -g)" -v "$DIR:/setup" -e NETSEC_CONFIG=/setup/netsec.json -e NETSEC_HOST_DIR="$DIR"
  for v in $(env | sed -n 's/^\(NETSEC_SETUP_[A-Z_]*\)=.*/\1/p'); do set -- "$@" -e "$v"; done
  if [ "$NONINTERACTIVE" = 1 ]; then
    "$@" -T board node cli/board.js setup --config /setup/netsec.json --non-interactive --compose-env --docker
  else
    "$@" board node cli/board.js setup --config /setup/netsec.json --compose-env --docker </dev/tty
  fi
  # .env from the wizard (binds) + version lines
  grep -v '^NETSEC_VERSION=\|^NETSEC_IMAGE=' .env > .env.tmp || true
  printf 'NETSEC_VERSION=%s\nNETSEC_IMAGE=%s\n' "$TAG" "$IMAGE" >> .env.tmp
  mv .env.tmp .env
  chmod 600 secrets.env 2>/dev/null || true   # read by docker compose on the host (env_file)
  chmod 644 netsec.json                        # read by the container user; it holds no secrets

  step "start"
  docker compose up -d
  PORT=$(sed -n 's/^BOARD_PORT=//p' .env); [ -n "$PORT" ] || PORT=8480
  BIND=$(sed -n 's/^BOARD_BIND=//p' .env); [ -n "$BIND" ] || BIND=127.0.0.1
  i=0; until docker compose exec -T board node -e "fetch('http://127.0.0.1:8480/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 60 ] || die "the board did not become healthy: docker compose -f $DIR/compose.yaml logs board"; sleep 1
  done
  MANAGE="cd $DIR && docker compose logs -f board   |   upgrade: re-run this installer"
else
  # ---------------------------------------------------------------- Node
  step "app"
  NEW="$DIR/app.new"
  rm -rf "$NEW"; mkdir -p "$NEW"
  if [ -n "${NETSEC_TARBALL:-}" ]; then
    case "$NETSEC_TARBALL" in
      http*) fetch "$NETSEC_TARBALL" "$DIR/app.tgz" ;;
      *) cp "$NETSEC_TARBALL" "$DIR/app.tgz" ;;
    esac
  elif [ "$FROM_CLONE" = 1 ] && [ "$VERSION" = main ]; then
    (cd "$SRC" && tar --exclude=./node_modules --exclude=./data --exclude=./.git -czf "$DIR/app.tgz" .)
  else
    case "$VERSION" in main) ref="heads/main" ;; *) ref="tags/$VERSION" ;; esac
    fetch "https://github.com/$REPO/archive/refs/$ref.tar.gz" "$DIR/app.tgz"
  fi
  # a GitHub archive has one top folder; a local tarball made with "." does not
  if tar -tzf "$DIR/app.tgz" | head -n 1 | grep -q '^\./'; then tar -xzf "$DIR/app.tgz" -C "$NEW"; else tar -xzf "$DIR/app.tgz" -C "$NEW" --strip-components=1; fi
  rm -f "$DIR/app.tgz"
  [ -f "$NEW/cli/setup.js" ] || die "the download does not look like NetSec Board"
  rm -rf "$DIR/app.old"; [ -d "$DIR/app" ] && mv "$DIR/app" "$DIR/app.old"
  mv "$NEW" "$DIR/app"; rm -rf "$DIR/app.old"
  mkdir -p "$DIR/backups" "$DIR/data"; chmod 700 "$DIR/data"

  step "setup"
  if [ "$NONINTERACTIVE" = 1 ]; then
    node "$DIR/app/cli/board.js" setup --config "$DIR/netsec.json" --non-interactive
  else
    node "$DIR/app/cli/board.js" setup --config "$DIR/netsec.json" </dev/tty
  fi
  chmod 600 "$DIR/secrets.env"

  NODE_BIN=$(command -v node)
  PORT=$(node -p "require('$DIR/netsec.json').listen.port" 2>/dev/null || echo 8480)
  BIND=$(node -p "require('$DIR/netsec.json').listen.host" 2>/dev/null || echo 127.0.0.1)
  if [ "$IS_ROOT" = 1 ] && have systemctl && [ -d /run/systemd/system ]; then
    step "systemd service"
    id netsec >/dev/null 2>&1 || useradd --system --home "$DIR/data" --shell /usr/sbin/nologin netsec
    # the service user must be able to run node (nvm installs under a 0700 home do not work)
    su -s /bin/sh netsec -c "\"$NODE_BIN\" -v" >/dev/null 2>&1 || die "user netsec cannot run $NODE_BIN (inside a private home?). Install Node system-wide (NodeSource), then re-run."
    chown -R netsec:netsec "$DIR/data"; chmod 700 "$DIR/data"
    chown root:netsec "$DIR/netsec.json"; chmod 640 "$DIR/netsec.json"
    chown root:root "$DIR/secrets.env"; chmod 600 "$DIR/secrets.env"   # read by systemd (EnvironmentFile), not by node
    sed -e "s#/opt/netsec-board#$DIR/app#g" \
        -e "s#/etc/netsec-board/netsec.json#$DIR/netsec.json#g" \
        -e "s#/etc/netsec-board/secrets.env#$DIR/secrets.env#g" \
        -e "s#/var/lib/netsec-board#$DIR/data#g" \
        -e "s#/usr/bin/node#$NODE_BIN#g" \
        "$DIR/app/deploy/netsec-board.service" > /etc/systemd/system/netsec-board.service
    systemctl daemon-reload
    systemctl enable netsec-board >/dev/null 2>&1
    systemctl restart netsec-board
    i=0; until node -e "fetch('http://127.0.0.1:$PORT/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))" 2>/dev/null; do
      i=$((i + 1)); [ "$i" -lt 30 ] || die "the service did not become healthy: journalctl -u netsec-board -n 50"; sleep 1
    done
    MANAGE="systemctl status netsec-board   |   journalctl -u netsec-board -f   |   upgrade: re-run this installer"
  else
    MANAGE="start: node $DIR/app/server/main.js --config $DIR/netsec.json   (no systemd/root: keep it running with tmux or a user service)"
    if [ "$START" = 1 ]; then
      step "starting in the foreground (Ctrl-C stops)"
      exec node "$DIR/app/server/main.js" --config "$DIR/netsec.json"
    fi
  fi
fi

T1=$(date +%s)
URLHOST=127.0.0.1; [ "$BIND" = "0.0.0.0" ] && [ -n "$HOST_IP" ] && URLHOST=$HOST_IP
step "done in $((T1 - T0)) s"
say "Board:   http://$URLHOST:$PORT   (the admin password was shown above, once)"
say "Manage:  $MANAGE"
say "Config:  $DIR/netsec.json  (secrets in $DIR/secrets.env, mode 600); re-run this installer to change answers"
if grep -q '"syslog": {[^}]*"enabled": true' "$DIR/netsec.json" 2>/dev/null || sed -n '/"syslog"/,/}/p' "$DIR/netsec.json" | grep -q '"enabled": true'; then
  say ""
  say "FortiGate: send logs here (CLI):"
  say "  config log syslogd setting"
  say "    set status enable"
  say "    set server \"${HOST_IP:-<this host>}\""
  say "    set mode reliable"
  say "    set port 5514"
  say "    set format rfc5424"
  say "  end"
fi
