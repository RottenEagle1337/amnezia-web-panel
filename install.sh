#!/usr/bin/env bash
# Quick start of amnezia-web-panel on a Docker host.
# Creates .env with a PBKDF2 password hash (the password itself is never stored)
# and starts the container.
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null 2>&1 || { echo "Error: Docker is required"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Error: Docker Compose (plugin) is required"; exit 1; }

port_free() {
  local p=$1
  if command -v ss >/dev/null 2>&1; then
    ! ss -ltn | awk '{print $4}' | grep -qE "[:.]$p$"
  elif command -v lsof >/dev/null 2>&1; then
    ! lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 0  # nothing to check with — trust the user
  fi
}

print_links() {
  # All local IPv4 addresses: hostname -I (most Linux), fallback to `ip addr`.
  local port bind ips
  port=$(grep '^PANEL_PORT=' .env 2>/dev/null | cut -d= -f2-)
  port=${port:-8080}
  bind=$(grep '^PANEL_BIND=' .env 2>/dev/null | cut -d= -f2-)
  bind=${bind:-0.0.0.0}
  echo
  if [ "$bind" = "127.0.0.1" ]; then
    echo "The panel listens on localhost only (public VPS mode)."
    echo "Access it via an SSH tunnel from your machine:"
    echo "  ssh -L $port:localhost:$port user@<this-server>"
    echo "  then open http://localhost:$port"
    return
  fi
  ips=$(hostname -I 2>/dev/null || ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}')
  echo "The panel is available on the local network:"
  if [ -n "$ips" ]; then
    for ip in $ips; do echo "  http://$ip:$port"; done
  else
    echo "  http://<server-ip>:$port"
  fi
}

if [ -f .env ]; then
  echo ".env already exists — skipping setup."
  docker compose up -d --build
  print_links
  exit 0
fi

# --- Panel port ---
while :; do
  read -rp "Panel port [8080]: " PORT
  PORT=${PORT:-8080}
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Port number must be 1-65535."
    continue
  fi
  if port_free "$PORT"; then break; fi
  echo "Port $PORT is already in use — pick another one."
done

# --- Panel availability ---
if [ -z "${PANEL_BIND:-}" ]; then
  echo "Panel availability:"
  echo "  1) All interfaces — LAN / private network"
  echo "  2) Localhost only — public VPS, access via SSH tunnel"
  while :; do
    read -rp "Choice [1]: " MODE
    MODE=${MODE:-1}
    case "$MODE" in
      1) PANEL_BIND="0.0.0.0"; break ;;
      2) PANEL_BIND="127.0.0.1"; break ;;
      *) echo "Enter 1 or 2." ;;
    esac
  done
fi

# --- Panel password ---
GENERATED=""
read -srp "Panel password (empty — generate a strong one): " PASS
echo
if [ -z "$PASS" ]; then
  PASS=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
  GENERATED=1
fi

# --- Server address for client configs ---
GUESS=$(curl -4 -s --max-time 5 ifconfig.me || true)
echo "The public server address will be embedded into VPN client configs."
if [ -n "$GUESS" ]; then
  read -rp "Public IP/domain of the server [$GUESS]: " HOST
  HOST=${HOST:-$GUESS}
else
  read -rp "Public IP/domain of the server: " HOST
fi
[ -n "$HOST" ] || { echo "Error: server address is required"; exit 1; }

# --- The password hash is computed inside the image (no Python needed on the host) ---
echo "Building the image..."
docker compose build -q panel
HASH=$(printf '%s' "$PASS" | docker run --rm -i amnezia-web-panel:latest python -m app.passhash)
# docker compose interpolates $ in .env — escape as $$
HASH_ESCAPED=${HASH//\$/\$\$}

printf 'PANEL_PASSWORD_HASH=%s\nAWG_ENDPOINT_HOST=%s\nAWG_ENDPOINT_PORT=51820\nPANEL_PORT=%s\nPANEL_BIND=%s\n' \
  "$HASH_ESCAPED" "$HOST" "$PORT" "$PANEL_BIND" > .env
chmod 600 .env

docker compose up -d

print_links
if [ -n "$GENERATED" ]; then
  echo
  echo "Generated password (shown once, stored nowhere):"
  echo "  $PASS"
fi
unset PASS HASH HASH_ESCAPED
echo
echo "Only the password hash is stored in .env. The panel is for LAN use only."
