#!/bin/bash
# OPTIONAL upstream proxy — NOT needed for normal use.
# The Playwright MCP identities run fully headless and direct (no proxy) by default; this
# script only matters if you deliberately want to route the 3 identities through an external
# upstream proxy (e.g. an mitmproxy/ZAP recorder you run yourself). Off unless you start it
# AND add a "proxy" block to configs/userN.json. Default = no proxy, fully direct and headless.
#
# Architecture (when used): Chrome (user N) → mitmdump:808N → optional UPSTREAM → target
#
# Usage:
#   UPSTREAM=http://localhost:8090 ./start.sh     # forward to an upstream you run
#   ./start.sh                                     # no upstream → mitmdump passes through direct

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
UPSTREAM="${UPSTREAM:-}"

PIDS=()

for i in 1 2 3; do
  PORT=$((8080 + i))
  if [ -n "$UPSTREAM" ]; then
    mitmdump -p "$PORT" --mode "upstream:${UPSTREAM}" --ssl-insecure -s "$DIR/proxy.py" --set "color=user${i}" --quiet &
    echo "[+] user${i}  →  mitmdump:${PORT}  →  upstream:${UPSTREAM}"
  else
    mitmdump -p "$PORT" --ssl-insecure -s "$DIR/proxy.py" --set "color=user${i}" --quiet &
    echo "[+] user${i}  →  mitmdump:${PORT}  →  direct"
  fi
  PIDS+=($!)
done

echo ""
echo "Stop: kill ${PIDS[*]}"
echo "  or: pkill -f 'mitmdump -p 808'"
echo ""

wait
