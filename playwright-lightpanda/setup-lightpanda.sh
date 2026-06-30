#!/bin/bash
# Generates ~/.mcp.json entries for the LIGHTPANDA browser backend.
#
# This replaces Chrome with Lightpanda, controlled by AI through Lightpanda's
# NATIVE MCP server (recommended path — uses Lightpanda's own DOM dump, which is
# fully functional, unlike Playwright's accessibility snapshot).
#
# Architecture per user:
#   Claude Code → lightpanda-userN (MCP) → mitmdump:808N [X-PwnFox-Color] → Burp:8080 → target
#
# Each user is a separate `lightpanda mcp` process: its own browser engine and
# its own cookie jar, so sessions stay isolated just like the Chrome profiles.
#
# NOTE on the color overlay: Chrome showed a colored bar via initScript. Lightpanda
# is headless with no rendering engine, so there is nothing to *see*. Per-user
# identification now relies entirely on the X-PwnFox-Color header (injected by
# proxy.py, visible in Burp's HTTP history) — which is browser-agnostic and works.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
STATE="$DIR/state"            # per-user cookie jars live here
mkdir -p "$STATE"

BURP_PORT="${BURP_PORT:-8080}"

# --- locate the lightpanda binary: $LIGHTPANDA_BIN > repo-local > PATH > download hint
if [ -n "${LIGHTPANDA_BIN:-}" ] && [ -x "$LIGHTPANDA_BIN" ]; then
  : ok
elif [ -x "$DIR/lightpanda" ]; then
  LIGHTPANDA_BIN="$DIR/lightpanda"
elif command -v lightpanda >/dev/null 2>&1; then
  LIGHTPANDA_BIN="$(command -v lightpanda)"
else
  echo "[!] lightpanda binary not found. Get the nightly for your platform:"
  echo "    Linux x86_64:  curl -L -o $DIR/lightpanda https://github.com/lightpanda-io/browser/releases/download/nightly/lightpanda-x86_64-linux && chmod +x $DIR/lightpanda"
  echo "    macOS arm64:   .../lightpanda-aarch64-macos"
  echo "    or:            brew install lightpanda-io/browser/lightpanda"
  exit 1
fi
echo "[+] lightpanda: $LIGHTPANDA_BIN  ($("$LIGHTPANDA_BIN" version 2>/dev/null || echo '?'))"

declare -A PORTS=([1]=8081 [2]=8082 [3]=8083)

# --- build the mcpServers JSON block (trailing-comma-safe)
entries=""
for i in 1 2 3; do
  JAR="$STATE/user${i}.cookies.json"
  PROXY="http://localhost:${PORTS[$i]}"
  [ -n "$entries" ] && entries+=$',\n'
  entries+="$(printf '    "lightpanda-user%d": {\n      "command": "%s",\n      "args": ["mcp", "--http-proxy", "%s", "--cookie", "%s", "--cookie-jar", "%s", "--insecure-disable-tls-host-verification"]\n    }' \
      "$i" "$LIGHTPANDA_BIN" "$PROXY" "$JAR" "$JAR")"
  echo "[+] lightpanda-user${i}  →  mcp --http-proxy ${PROXY}  (cookies: ${JAR})"
done

cat <<EOF

Add to ~/.mcp.json (Lightpanda backend):

{
  "mcpServers": {
${entries}
  }
}

Then enable them in ~/.claude/settings.json:
  "enabledMcpjsonServers": ["lightpanda-user1", "lightpanda-user2", "lightpanda-user3"]

Remember:
  1. Start Burp Suite on localhost:${BURP_PORT}
  2. ./start.sh                      # launches the mitmdump proxies (shared with the Chrome backend)
  3. Restart Claude Code so it picks up the new MCP servers

Note: --insecure-disable-tls-host-verification is required because mitmdump/Burp
perform TLS interception. --cookie loads and --cookie-jar persists the per-user
cookie jar across restarts (best-effort: an unclean MCP shutdown may skip the write).
EOF
