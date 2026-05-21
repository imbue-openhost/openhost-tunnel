#!/bin/sh
# start.sh — OpenHost tunnel supervisor.
#
# Runs two processes:
#   1. Chisel server (reverse tunnel, port 8080)
#   2. Status page server (port 3000, used as chisel --backend)
#
# When no tunnel client is connected, visitors see a status/instructions page.
# When a client connects with `chisel client ... R:3000:localhost:<local_port>`,
# the client's local app replaces the status page on the same URL.

set -eu

APP_DATA_DIR="${OPENHOST_APP_DATA_DIR:-/data/app_data/tunnel}"
AUTH_FILE="${APP_DATA_DIR}/.chisel-auth"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-tunnel}"

mkdir -p "$APP_DATA_DIR"

# Generate auth credentials on first boot
if [ ! -f "$AUTH_FILE" ]; then
    USERNAME="tunnel"
    PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    echo "${USERNAME}:${PASSWORD}" > "$AUTH_FILE"
    chmod 0600 "$AUTH_FILE"
    echo "[start.sh] Generated tunnel credentials in ${AUTH_FILE}"
fi

AUTH_CREDS="$(cat "$AUTH_FILE")"
echo "[start.sh] Tunnel auth: ${AUTH_CREDS}"
echo "[start.sh] Connect URL: https://${APP_NAME}.${ZONE_DOMAIN}"

# --- Start status page server ---
TUNNEL_URL="https://${APP_NAME}.${ZONE_DOMAIN}" \
  AUTH_CREDS="$AUTH_CREDS" \
  python3 /opt/openhost/status_server.py &
STATUS_PID=$!

# Wait for status server
sleep 1

# --- Start chisel server ---
# --reverse: allow clients to open reverse tunnels
# --backend: proxy normal HTTP to the status/tunneled app on port 3000
# --auth: require credentials
# --host 0.0.0.0 --port 8080: listen on the OpenHost-routed port
echo "[start.sh] Starting chisel server..."
chisel server \
    --reverse \
    --backend "http://127.0.0.1:3000" \
    --host 0.0.0.0 \
    --port 8080 \
    --auth "$AUTH_CREDS" \
    &
CHISEL_PID=$!

echo "[start.sh] All services started. STATUS=$STATUS_PID CHISEL=$CHISEL_PID"

# Supervise
wait -n "$STATUS_PID" "$CHISEL_PID" 2>/dev/null || true
EXIT_CODE=$?
echo "[start.sh] Child exited (code=$EXIT_CODE)."
kill "$STATUS_PID" "$CHISEL_PID" 2>/dev/null || true
wait
exit "$EXIT_CODE"
