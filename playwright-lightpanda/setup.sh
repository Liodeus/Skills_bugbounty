#!/bin/bash
# Generates configs/ with absolute paths for the current machine.
# Run once after cloning, then point your .mcp.json to configs/userN.json.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIGS="$DIR/configs"
mkdir -p "$CONFIGS"

BURP_PORT="${BURP_PORT:-8080}"

declare -A COLORS=([1]="red" [2]="blue" [3]="green")
declare -A PORTS=([1]="8081" [2]="8082" [3]="8083")

for i in 1 2 3; do
  cat > "$CONFIGS/user${i}.json" <<EOF
{
  "browser": {
    "userDataDir": "/tmp/pw-chrome-user${i}",
    "launchOptions": {
      "proxy": { "server": "http://localhost:${PORTS[$i]}" }
    },
    "contextOptions": {
      "ignoreHTTPSErrors": true
    },
    "initScript": ["$DIR/init/user${i}.js"]
  }
}
EOF
  echo "[+] configs/user${i}.json → proxy:${PORTS[$i]} (${COLORS[$i]})"
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
