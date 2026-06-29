#!/bin/bash
# Generates configs/ with absolute paths for the current machine.
# Run once after cloning, then point your .mcp.json to configs/userN.json.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIGS="$DIR/configs"
mkdir -p "$CONFIGS"

# Three separate headless browser identities (independent userDataDirs) for multi-account
# testing (IDOR / RBAC / cross-tenant). Fully headless, no proxy — everything runs direct.
# (If you ever want to route through an OPTIONAL upstream proxy, run ./start.sh and add a
#  "proxy" block to launchOptions below pointing at localhost:808N.)

# To enable the opt-in DOM-XSS instrument (pre-load sink hooks + postMessage wiretap,
# see SKILLS/xss/playwright-dom-debugging.md), add init/xss-instrument.js to the
# initScript array below, e.g.:
#   "initScript": ["$DIR/init/user${i}.js", "$DIR/init/xss-instrument.js"]
# then re-run this script and restart the Playwright MCP. Remove it again when done —
# it adds [XSSHOOK] console noise to every page.
for i in 1 2 3; do
  cat > "$CONFIGS/user${i}.json" <<EOF
{
  "browser": {
    "userDataDir": "/tmp/pw-chrome-user${i}",
    "launchOptions": {
      "headless": true
    },
    "contextOptions": {
      "ignoreHTTPSErrors": true
    },
    "initScript": ["$DIR/init/user${i}.js"]
  }
}
EOF
  echo "[+] configs/user${i}.json → headless identity user${i}"
done

echo ""
echo "Add to ~/.mcp.json:"
cat <<EOF
{
  "mcpServers": {
    "playwright-user1": {
      "command": "node",
      "args": ["/path/to/@playwright/mcp/cli.js", "--config", "$CONFIGS/user1.json"]
    },
    "playwright-user2": {
      "command": "node",
      "args": ["/path/to/@playwright/mcp/cli.js", "--config", "$CONFIGS/user2.json"]
    },
    "playwright-user3": {
      "command": "node",
      "args": ["/path/to/@playwright/mcp/cli.js", "--config", "$CONFIGS/user3.json"]
    }
  }
}
EOF
