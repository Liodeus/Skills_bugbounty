#!/bin/bash
# Starts 3 mitmproxy instances that inject X-PwnFox-Color and forward to Burp Suite.
#
# Architecture: Chrome (user N) → mitmdump:808N → Burp:8080 → target
#
# Usage:
#   ./start.sh             # Burp on default localhost:8080
#   BURP_PORT=9090 ./start.sh

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
BURP_HOST="${BURP_HOST:-localhost}"
BURP_PORT="${BURP_PORT:-8080}"
UPSTREAM="http://${BURP_HOST}:${BURP_PORT}"

declare -A COLORS=([1]="red" [2]="blue" [3]="green")
PIDS=()

for i in 1 2 3; do
  PORT=$((8080 + i))
  mitmdump -p "$PORT" \
    --mode "upstream:${UPSTREAM}" \
    --ssl-insecure \
    -s "$DIR/proxy.py" \
    --set "color=${COLORS[$i]}" \
    --quiet &
  PIDS+=($!)
  echo "[+] user${i} (${COLORS[$i]})  →  mitmdump:${PORT}  →  Burp:${BURP_PORT}"
done

echo ""
echo "Stop: kill ${PIDS[*]}"
echo "  or: pkill -f 'mitmdump -p 808'"
echo ""

wait
