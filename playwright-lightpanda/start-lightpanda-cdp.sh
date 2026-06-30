#!/bin/bash
# OPTIONAL — Path A: keep Playwright MCP, point it at Lightpanda's CDP server
# instead of launching Chrome.
#
# WHY OPTIONAL / LIMITED:
#   Playwright's connectOverCDP works and navigation succeeds, BUT Lightpanda's
#   CDP does not yet implement `Accessibility.getFullAXTree`. That method is what
#   Playwright MCP's `browser_snapshot` (its core "AI sees the page" feature) calls,
#   so snapshots fail with "Protocol error (Accessibility.getFullAXTree): InvalidParams".
#   Navigation, evaluate, title and DOM queries still work.
#
#   For FULL AI control, prefer Lightpanda's native MCP server instead:
#       ./setup-lightpanda.sh
#
# What this does: launches one persistent `lightpanda serve` (CDP server) per user,
# each routed through its own mitmdump port toward Burp. Playwright MCP then connects
# to ws://127.0.0.1:922N via the `cdpEndpoint` option (see configs it generates).

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIGS="$DIR/configs"
STATE="$DIR/state"
mkdir -p "$CONFIGS" "$STATE"
BURP_PORT="${BURP_PORT:-8080}"

if [ -n "${LIGHTPANDA_BIN:-}" ] && [ -x "$LIGHTPANDA_BIN" ]; then :;
elif [ -x "$DIR/lightpanda" ]; then LIGHTPANDA_BIN="$DIR/lightpanda";
elif command -v lightpanda >/dev/null 2>&1; then LIGHTPANDA_BIN="$(command -v lightpanda)";
else echo "[!] lightpanda binary not found (see setup-lightpanda.sh)."; exit 1; fi

declare -A CDP_PORT=([1]=9221 [2]=9222 [3]=9223)
declare -A MITM_PORT=([1]=8081 [2]=8082 [3]=8083)
PIDS=()

for i in 1 2 3; do
  PORT=${CDP_PORT[$i]}
  PROXY="http://localhost:${MITM_PORT[$i]}"
  "$LIGHTPANDA_BIN" serve --host 127.0.0.1 --port "$PORT" \
    --http-proxy "$PROXY" --insecure-disable-tls-host-verification \
    --log-level warn >/tmp/lp-cdp-user${i}.log 2>&1 &
  PIDS+=($!)

  # Playwright MCP config that CONNECTS to the running Lightpanda CDP server
  # (instead of launching Chrome). userDataDir/launchOptions are intentionally
  # omitted — the browser is already running and proxy is set on Lightpanda's side.
  cat > "$CONFIGS/lightpanda-cdp-user${i}.json" <<EOF
{
  "browser": {
    "browserName": "chromium",
    "cdpEndpoint": "ws://127.0.0.1:${PORT}",
    "cdpTimeout": 30000,
    "contextOptions": { "ignoreHTTPSErrors": true }
  }
}
EOF
  echo "[+] user${i}: lightpanda serve :${PORT}  →  proxy ${PROXY}  →  Burp:${BURP_PORT}   (config: configs/lightpanda-cdp-user${i}.json)"
done

cat <<EOF

Playwright MCP entry for ~/.mcp.json (example for user1):
  "playwright-lp-user1": {
    "command": "node",
    "args": ["/path/to/@playwright/mcp/cli.js", "--config", "$CONFIGS/lightpanda-cdp-user1.json"]
  }
(repeat for user2/user3)

Stop the CDP servers: kill ${PIDS[*]}
EOF

wait
