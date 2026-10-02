#!/usr/bin/env bash
# OpenNetControl installer for Ubuntu Server (22.04 / 24.04; other Debian-family systems work with a warning).
#
#   sudo ./install.sh                          # install or upgrade, listen on 0.0.0.0:8080
#   sudo ./install.sh --nginx --server-name onc.example.com   # + TLS reverse proxy (self-signed cert) on :443
#   sudo ./install.sh --demo                   # 15 simulated devices, NOT for production
#   sudo ./install.sh --uninstall [--purge]
#
# Remote one-liner (installs from GitHub):
#   curl -fsSL https://raw.githubusercontent.com/mikeehendricks/OpenNetControl/main/install.sh | sudo bash
#
# Safe to re-run: upgrades the code and keeps your data, secrets and settings.
set -Eeuo pipefail

# ------------------------------------------------------------------ defaults
APP_USER="opennetcontrol"
INSTALL_DIR="/opt/opennetcontrol"
DATA_DIR="/var/lib/opennetcontrol"
CONF_DIR="/etc/opennetcontrol"
SERVICE="opennetcontrol"
REPO_URL="https://github.com/mikeehendricks/OpenNetControl.git"
REPO_REF="main"
PORT="8080"
BIND=""                 # default decided below (127.0.0.1 with --nginx, else 0.0.0.0)
SOURCE_DIR=""
DEMO=0 NGINX=0 TRUST_PROXY=0 USE_LOCK=1 SERVER_NAME="_" NO_START=0 UNINSTALL=0 PURGE=0 SKIP_APT=0 ASSUME_YES=0
MIN_PY_MINOR=10

# ------------------------------------------------------------------ helpers
if [[ -t 1 ]]; then B=$'\e[1m' G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' N=$'\e[0m'; else B="" G="" Y="" R="" N=""; fi
step() { echo "${B}==>${N} $*"; }
ok()   { echo "  ${G}ok${N}  $*"; }
warn() { echo "  ${Y}warn${N} $*" >&2; }
die()  { echo "${R}error:${N} $*" >&2; exit 1; }
trap 'die "failed at line $LINENO (command: $BASH_COMMAND)"' ERR

usage() {
  cat <<EOF
OpenNetControl installer

Usage: sudo ./install.sh [options]

  --port N               port the app listens on                (default 8080)
  --bind ADDR            address the app binds to               (default 0.0.0.0, or 127.0.0.1 with --nginx)
  --nginx                install nginx as a TLS reverse proxy on :80/:443 (self-signed certificate)
  --server-name NAME     server_name for nginx / certificate CN (default _)
  --trust-proxy          honour X-Forwarded-For (only if YOUR OWN reverse proxy sets it; implied by --nginx)
  --demo                 enable the simulated 15-device demo + fault injection (NOT for production)
  --source DIR           install from a local checkout          (default: the directory of this script)
  --repo URL --ref REF   install from git instead                (default: $REPO_URL @ $REPO_REF)
  --install-dir DIR      application directory                  (default $INSTALL_DIR)
  --data-dir DIR         database / keys / backups              (default $DATA_DIR)
  --no-lock              install unpinned requirements.txt instead of the hash-verified requirements.lock
  --no-start             install but do not start the service
  --skip-apt             do not run apt (dependencies must already be present)
  --uninstall            stop and remove the service and application (keeps data)
  --purge                with --uninstall: also delete data, config and the service user
  -y, --yes              do not ask for confirmation
  -h, --help             this text
EOF
}

# ------------------------------------------------------------------ args
ORIG_ARGS=("$@")           # kept for the sudo re-exec below (the parser shifts "$@" away)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="${2:?}"; shift 2;;
    --bind) BIND="${2:?}"; shift 2;;
    --nginx) NGINX=1; shift;;
    --server-name) SERVER_NAME="${2:?}"; shift 2;;
    --trust-proxy) TRUST_PROXY=1; shift;;
    --demo) DEMO=1; shift;;
    --source) SOURCE_DIR="${2:?}"; shift 2;;
    --repo) REPO_URL="${2:?}"; shift 2;;
    --ref) REPO_REF="${2:?}"; shift 2;;
    --install-dir) INSTALL_DIR="${2:?}"; shift 2;;
    --data-dir) DATA_DIR="${2:?}"; shift 2;;
    --no-lock) USE_LOCK=0; shift;;
    --no-start) NO_START=1; shift;;
    --skip-apt) SKIP_APT=1; shift;;
    --uninstall) UNINSTALL=1; shift;;
    --purge) PURGE=1; shift;;
    -y|--yes) ASSUME_YES=1; shift;;
    -h|--help) usage; exit 0;;
    *) usage >&2; die "unknown option: $1";;
  esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "--port must be 1-65535"
[[ "$SERVER_NAME" =~ ^[A-Za-z0-9._*-]+$ ]] || die "--server-name contains invalid characters"
# Directories are used in rm -rf, sed, systemd units and env files while running as root, so be strict:
# absolute, a conservative charset, no "..", no trailing slash, and the path must contain "opennetcontrol" so a typo
# such as --install-dir /usr can never be wiped by --uninstall.
check_dir() {
  local name="$1" p="$2"
  [[ "$p" =~ ^/[A-Za-z0-9._/-]+$ ]]      || die "$name must be an absolute path using only letters, digits, . _ - /"
  [[ "$p" != *..* && "$p" != */ ]]        || die "$name must not contain '..' or end with '/'"
  [[ "$p" == *opennetcontrol* ]]          || die "$name must contain 'opennetcontrol' (safety guard), e.g. /opt/opennetcontrol"
  (( $(grep -o / <<<"$p" | wc -l) >= 2 )) || die "$name is too shallow: $p"
}
check_dir --install-dir "$INSTALL_DIR"; check_dir --data-dir "$DATA_DIR"
[[ "$INSTALL_DIR" != "$DATA_DIR" && "$DATA_DIR" != "$INSTALL_DIR"/* && "$INSTALL_DIR" != "$DATA_DIR"/* ]] || die "--install-dir and --data-dir must not overlap"
[[ -n "$BIND" ]] || { if (( NGINX )); then BIND="127.0.0.1"; else BIND="0.0.0.0"; fi; }
[[ "$BIND" =~ ^[0-9A-Fa-f:.]+$ ]] || die "--bind must be an IP address"

# ------------------------------------------------------------------ root
if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null && [[ -f "${BASH_SOURCE[0]:-}" ]]; then
    step "Re-running with sudo"
    exec sudo -E bash "${BASH_SOURCE[0]}" "${ORIG_ARGS[@]}"
  fi
  die "run as root (sudo ./install.sh)"
fi

# ------------------------------------------------------------------ uninstall
if (( UNINSTALL )); then
  step "Uninstalling OpenNetControl"
  if (( PURGE && ! ASSUME_YES )); then
    read -r -p "  --purge deletes ALL data ($DATA_DIR) and config ($CONF_DIR). Type 'yes' to continue: " a </dev/tty || a=no
    [[ "$a" == "yes" ]] || die "aborted"
  fi
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE.service"; systemctl daemon-reload || true
  rm -f /etc/nginx/sites-enabled/opennetcontrol /etc/nginx/sites-available/opennetcontrol
  if [[ -f /etc/nginx/sites-available/default && -z "$(ls -A /etc/nginx/sites-enabled 2>/dev/null)" ]]; then
    ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default   # restore the distro default we removed
  fi
  if command -v nginx >/dev/null && nginx -t >/dev/null 2>&1; then systemctl reload nginx 2>/dev/null || true; fi
  if [[ -d "$INSTALL_DIR" && ! -f "$INSTALL_DIR/app/opennetcontrol/__main__.py" && ! -f "$INSTALL_DIR/venv/pyvenv.cfg" ]]; then
    warn "$INSTALL_DIR does not look like an OpenNetControl install; NOT deleting it"
  else
    rm -rf "$INSTALL_DIR"
  fi
  ok "service and application removed"
  if (( PURGE )); then
    if [[ -d "$DATA_DIR" && ! -f "$DATA_DIR/opennetcontrol.db" && ! -f "$DATA_DIR/.opennetcontrol-data" ]]; then
      warn "$DATA_DIR does not look like OpenNetControl data; NOT deleting it"
    else
      rm -rf "$DATA_DIR"
    fi
    rm -rf "$CONF_DIR" /etc/ssl/opennetcontrol
    id "$APP_USER" >/dev/null 2>&1 && userdel "$APP_USER" 2>/dev/null || true
    ok "data, config and user purged"
  else
    ok "data kept in $DATA_DIR and config in $CONF_DIR (use --purge to delete)"
  fi
  exit 0
fi

# ------------------------------------------------------------------ preflight
step "Preflight checks"
[[ -r /etc/os-release ]] && . /etc/os-release || die "cannot read /etc/os-release"
if [[ "${ID:-}" == "ubuntu" ]]; then
  case "${VERSION_ID:-0}" in 22.04|24.04|25.*|26.*) ok "Ubuntu ${VERSION_ID}";;
    *) warn "Ubuntu ${VERSION_ID:-?} is not a tested release (22.04/24.04); continuing";; esac
elif [[ "${ID_LIKE:-}${ID:-}" == *debian* ]]; then
  warn "${PRETTY_NAME:-this OS} is Debian-family but not Ubuntu; continuing"
else
  die "unsupported OS (${PRETTY_NAME:-unknown}); this installer supports Ubuntu Server"
fi
command -v apt-get >/dev/null || die "apt-get not found"
command -v systemctl >/dev/null || warn "systemd not found: the service will not be installed"
[[ -d /run/systemd/system ]] || { warn "systemd is not running (container?); the service will be installed but not started"; NO_START=1; }

# find source
TMP_CLONE=""
cleanup() { [[ -n "$TMP_CLONE" ]] && rm -rf "$TMP_CLONE"; return 0; }
trap cleanup EXIT
if [[ -z "$SOURCE_DIR" ]]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
  if [[ -n "$here" && -f "$here/opennetcontrol/__main__.py" ]]; then SOURCE_DIR="$here"; fi
fi
if [[ -n "$SOURCE_DIR" ]]; then
  [[ -f "$SOURCE_DIR/opennetcontrol/__main__.py" && -f "$SOURCE_DIR/requirements.txt" ]] || die "$SOURCE_DIR is not an OpenNetControl checkout"
  ok "source: $SOURCE_DIR"
else
  NEED_GIT=1; ok "source: $REPO_URL @ $REPO_REF"
fi

if (( ! ASSUME_YES )) && [[ -t 0 ]]; then
  echo "  Install dir: $INSTALL_DIR   Data: $DATA_DIR   Listen: $BIND:$PORT   nginx: $NGINX   demo: $DEMO"
  read -r -p "  Continue? [Y/n] " a || a=y
  [[ "${a:-y}" =~ ^[Yy]?$ ]] || die "aborted"
fi
if (( DEMO )); then warn "DEMO mode enables simulated devices and fault-injection endpoints. Do not expose this to untrusted networks."; fi

# ------------------------------------------------------------------ packages
PKGS=(python3 python3-venv python3-pip ca-certificates curl openssl)
[[ "${NEED_GIT:-0}" == 1 ]] && PKGS+=(git)
(( NGINX )) && PKGS+=(nginx)
if (( SKIP_APT )); then
  step "Skipping apt (--skip-apt)"
else
  step "Installing system packages: ${PKGS[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "${PKGS[@]}" >/dev/null
  ok "packages installed"
fi
for c in python3 curl openssl; do command -v "$c" >/dev/null || die "missing dependency: $c"; done
(( NGINX )) && { command -v nginx >/dev/null || die "nginx not installed"; }
PYV="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,$MIN_PY_MINOR) else 1)" \
  || die "Python $PYV found; OpenNetControl needs >= 3.$MIN_PY_MINOR (use Ubuntu 22.04 or newer)"
python3 -c "import venv, ensurepip" 2>/dev/null || die "python3-venv is missing"
ok "Python $PYV"

# ------------------------------------------------------------------ fetch source
if [[ -z "$SOURCE_DIR" ]]; then
  step "Cloning $REPO_URL"
  TMP_CLONE="$(mktemp -d)"
  GIT_ALLOW_PROTOCOL=https:file git clone -q --depth 1 --branch "$REPO_REF" "$REPO_URL" "$TMP_CLONE/src" || die "git clone failed (private repo? use --source with a local checkout)"
  SOURCE_DIR="$TMP_CLONE/src"
  [[ -f "$SOURCE_DIR/opennetcontrol/__main__.py" ]] || die "cloned repository does not look like OpenNetControl"
fi
VERSION="$(sed -n 's/^__version__ *= *"\(.*\)"/\1/p' "$SOURCE_DIR/opennetcontrol/__init__.py" | head -1)"

# ------------------------------------------------------------------ user + dirs
step "Creating service user and directories"
if ! id "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
  ok "user $APP_USER created"
else ok "user $APP_USER exists"; fi
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
install -m 0600 -o "$APP_USER" -g "$APP_USER" /dev/null "$DATA_DIR/.opennetcontrol-data"   # marker: lets --purge know this is ours
install -d -m 0750 -o root -g "$APP_USER" "$CONF_DIR"

# ------------------------------------------------------------------ application files
step "Installing application ${VERSION:+v$VERSION }to $INSTALL_DIR"
UPGRADE=0; [[ -d "$INSTALL_DIR/app" ]] && UPGRADE=1
NEW="$INSTALL_DIR/app.new.$$"; rm -rf "$NEW"; mkdir -p "$NEW"
cp -a "$SOURCE_DIR/opennetcontrol" "$NEW/opennetcontrol"
cp -a "$SOURCE_DIR/requirements.txt" "$NEW/"
[[ -f "$SOURCE_DIR/requirements.lock" ]] && cp -a "$SOURCE_DIR/requirements.lock" "$NEW/"
for f in README.md LICENSE; do [[ -f "$SOURCE_DIR/$f" ]] && cp -a "$SOURCE_DIR/$f" "$NEW/"; done
find "$NEW" -name '__pycache__' -type d -prune -exec rm -rf {} +
chown -R root:root "$NEW"; chmod -R go-w,a+rX "$NEW"
if (( UPGRADE )); then systemctl stop "$SERVICE" 2>/dev/null || true; fi
rm -rf "$INSTALL_DIR/app.old"; [[ -d "$INSTALL_DIR/app" ]] && mv "$INSTALL_DIR/app" "$INSTALL_DIR/app.old"
mv "$NEW" "$INSTALL_DIR/app"
ok "$( ((UPGRADE)) && echo upgraded || echo installed )"

# ------------------------------------------------------------------ virtualenv + python deps
step "Creating virtualenv and installing Python dependencies"
[[ -x "$INSTALL_DIR/venv/bin/python" ]] || python3 -m venv "$INSTALL_DIR/venv"
PIP=("$INSTALL_DIR/venv/bin/pip" install -q --no-cache-dir)
"${PIP[@]}" --upgrade pip
if (( USE_LOCK )) && [[ -f "$INSTALL_DIR/app/requirements.lock" ]]; then
  # Exact versions + SHA-256 hashes: a compromised or typosquatted PyPI upload cannot be installed silently.
  "${PIP[@]}" --require-hashes -r "$INSTALL_DIR/app/requirements.lock" \
    || die "hash-verified install failed (unsupported platform/Python?). Re-run with --no-lock to use unpinned requirements."
  ok "installed from requirements.lock (hash-verified)"
else
  (( USE_LOCK )) && warn "requirements.lock not found; installing unpinned requirements"
  if ! "${PIP[@]}" --only-binary=:all: -r "$INSTALL_DIR/app/requirements.txt" 2>/dev/null; then
    warn "no prebuilt wheels for this platform; installing build tools and compiling (slower)"
    [[ "$SKIP_APT" == 1 ]] || apt-get install -y -qq --no-install-recommends build-essential python3-dev libffi-dev libssl-dev cargo pkg-config >/dev/null
    "${PIP[@]}" -r "$INSTALL_DIR/app/requirements.txt"
  fi
fi
# import the real application: catches any dependency missing from requirements.txt
( cd "$INSTALL_DIR/app" && "$INSTALL_DIR/venv/bin/python" -c "import opennetcontrol.app" ) || die "application import check failed (missing dependency?)"
ok "dependencies installed"

# ------------------------------------------------------------------ configuration
ENV_FILE="$CONF_DIR/opennetcontrol.env"
step "Writing configuration"
upsert() { # upsert KEY VALUE in env file (only managed keys; never touches others)
  local k="$1" v="$2"
  if grep -q "^$k=" "$ENV_FILE" 2>/dev/null; then sed -i "s|^$k=.*|$k=$v|" "$ENV_FILE"; else echo "$k=$v" >>"$ENV_FILE"; fi
}
if [[ ! -f "$ENV_FILE" ]]; then
  cat >"$ENV_FILE" <<EOF
# OpenNetControl settings (see README for the full list). Restart after editing:  systemctl restart $SERVICE
# Secrets (JWT key, vault key) are generated into $DATA_DIR on first start - back that directory up.
EOF
  ok "created $ENV_FILE"
else ok "keeping existing $ENV_FILE"; fi
chown root:"$APP_USER" "$ENV_FILE"; chmod 0640 "$ENV_FILE"
PREV_DEMO="$(sed -n 's/^ONC_DEMO=//p' "$ENV_FILE" 2>/dev/null | tail -1)"
if [[ "$PREV_DEMO" == "1" ]] && (( ! DEMO )); then
  warn "leaving demo mode: the simulated demo devices stay in the database (they will show as unreachable)."
  warn "  For a clean start run:  sudo ./install.sh --uninstall --purge   and install again."
fi
upsert ONC_HOST "$BIND"; upsert ONC_PORT "$PORT"; upsert ONC_DATA_DIR "$DATA_DIR"
# Security-relevant flags are set explicitly on EVERY run so re-running in a different mode can never leave
# a stale "trust X-Forwarded-For" or "demo/simulator" setting behind.
if (( NGINX || TRUST_PROXY )); then upsert ONC_TRUST_PROXY 1; else upsert ONC_TRUST_PROXY 0; fi
if (( DEMO )); then upsert ONC_DEMO 1; upsert ONC_ALLOW_SIM 1; else upsert ONC_DEMO 0; upsert ONC_ALLOW_SIM 0; fi

# ------------------------------------------------------------------ systemd
if command -v systemctl >/dev/null; then
  step "Installing systemd service"
  cat >"/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=OpenNetControl - multi-vendor AI network operations
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$INSTALL_DIR/app
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/python -m opennetcontrol
Restart=on-failure
RestartSec=3
UMask=0077
# --- sandboxing
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RemoveIPC=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1 || warn "could not enable service at boot"
  ok "service $SERVICE installed"
fi

# ------------------------------------------------------------------ nginx (optional)
if (( NGINX )); then
  step "Configuring nginx reverse proxy with TLS"
  CERT_DIR=/etc/ssl/opennetcontrol; install -d -m 0750 "$CERT_DIR"
  if [[ ! -f "$CERT_DIR/server.crt" ]]; then
    CN="$SERVER_NAME"; [[ "$CN" == "_" ]] && CN="$(hostname -f 2>/dev/null || hostname)"
    openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 397 -subj "/CN=$CN" \
      -addext "subjectAltName=DNS:$CN" -addext "basicConstraints=critical,CA:FALSE" \
      -addext "keyUsage=critical,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth" \
      -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" 2>/dev/null
    chmod 0600 "$CERT_DIR/server.key"
    ok "self-signed certificate created (replace with a real one in $CERT_DIR for production)"
  fi
  cat >/etc/nginx/sites-available/opennetcontrol <<EOF
limit_req_zone  \$binary_remote_addr zone=onc_api:10m   rate=20r/s;
limit_req_zone  \$binary_remote_addr zone=onc_login:10m rate=10r/m;
limit_conn_zone \$binary_remote_addr zone=onc_conn:10m;
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAME;
    server_tokens off;                 # per-server: Ubuntu's nginx.conf leaves it commented out, Debian's sets it globally
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;            # 'http2 on;' needs nginx>=1.25.1; this form works on Ubuntu 22.04/24.04
    listen [::]:443 ssl http2;
    server_name $SERVER_NAME;
    server_tokens off;                 # per-server: Ubuntu's nginx.conf leaves it commented out, Debian's sets it globally
    ssl_certificate     $CERT_DIR/server.crt;
    ssl_certificate_key $CERT_DIR/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    # TLS 1.2: forward-secret AEAD suites only (no static-RSA, no CBC). TLS 1.3 suites are always strong.
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_session_cache shared:ONC_TLS:10m;
    ssl_session_timeout 1h;
    ssl_session_tickets off;
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 30s;
    keepalive_timeout 30s;
    limit_conn onc_conn 40;
    limit_req zone=onc_api burst=60 nodelay;
    limit_req_status 429;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    client_max_body_size 128k;
    location = /api/auth/login {
        limit_req zone=onc_login burst=8 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;     # overwrite, never append client-supplied values
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 60s;
    }
}
EOF
  rm -f /etc/nginx/sites-enabled/default
  ln -sf /etc/nginx/sites-available/opennetcontrol /etc/nginx/sites-enabled/opennetcontrol
  nginx -t >/dev/null 2>&1 || { nginx -t; die "nginx configuration test failed"; }
  if [[ -d /run/systemd/system ]]; then systemctl enable nginx >/dev/null 2>&1 || true; systemctl restart nginx; fi
  ok "nginx configured"
fi

# ------------------------------------------------------------------ start + verify
if (( NO_START )); then
  step "Not starting the service (--no-start / no systemd)"
else
  step "Starting service"
  systemctl restart "$SERVICE"
  HC_HOST="$BIND"; [[ "$HC_HOST" == "0.0.0.0" ]] && HC_HOST=127.0.0.1; [[ "$HC_HOST" == *:* ]] && HC_HOST="[$HC_HOST]"
  up=0
  for _ in $(seq 1 40); do
    if curl -fsS --max-time 2 "http://$HC_HOST:$PORT/api/health" >/dev/null 2>&1; then up=1; break; fi
    systemctl is-active --quiet "$SERVICE" || break
    sleep 0.5
  done
  if (( ! up )); then
    journalctl -u "$SERVICE" --no-pager -n 30 >&2 || true
    die "service did not become healthy"
  fi
  ok "health check passed"
fi

# ------------------------------------------------------------------ summary
URL="http://$(hostname -I 2>/dev/null | awk '{print $1}'):$PORT"; (( NGINX )) && URL="https://${SERVER_NAME/#_/$(hostname -f 2>/dev/null || hostname)}"
echo
echo "${G}${B}OpenNetControl ${VERSION:+v$VERSION }is installed.${N}"
echo "  URL:            $URL"
echo "  Admin login:    admin   password: sudo cat $DATA_DIR/initial_admin_password.txt   (change it, then delete that file)"
(( DEMO )) && echo "  Demo users:     operator / viewer   passwords in $DATA_DIR/initial_<user>_password.txt"
echo "  Settings:       $ENV_FILE   (systemctl restart $SERVICE after editing)"
echo "  Logs:           journalctl -u $SERVICE -f"
echo "  Data & keys:    $DATA_DIR   (back this up; it holds the encrypted credential vault and its key)"
(( NGINX )) || echo "  ${Y}Note:${N} traffic is plain HTTP. Re-run with --nginx for TLS, or put your own TLS proxy in front."
echo "  Upgrade:        re-run this script.   Remove:  sudo ./install.sh --uninstall [--purge]"
