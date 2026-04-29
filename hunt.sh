#!/bin/bash

# --- CONFIGURATION ---
TARGET_NAME=$1
SKILLS_BASE="/home/$(whoami)/Documents/Skills_bugbounty"
MASTER_CLAUDE_MD="$SKILLS_BASE/SKILLS/CLAUDE.md"
BROWSER_DIR="$SKILLS_BASE/playwright-chrome"

# Capture launch dir so the workspace lands where the user invoked the script,
# not wherever later `cd`s leave us.
INVOKED_FROM="$(pwd)"

# Helper: poll a TCP port until it's listening (timeout in seconds, default 30)
wait_for_port() {
    local port=$1 timeout=${2:-30}
    local elapsed=0
    until nc -z localhost "$port" 2>/dev/null; do
        sleep 0.2
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -gt $((timeout * 5)) ]; then
            echo "❌ Timeout waiting for port $port"
            return 1
        fi
    done
}

# 1. Validation
if [ -z "$TARGET_NAME" ]; then
    echo "Usage: hunt <target_name>"
    exit 1
fi
if [ ! -d "$BROWSER_DIR" ]; then
    echo "❌ Could not find $BROWSER_DIR"
    exit 1
fi

echo "🚀 Starting automated hunt for: $TARGET_NAME"

# 2. Launch Caido (reuse if already up)
if ! lsof -i:8080 -t >/dev/null; then
    echo "🌐 Launching Caido instance..."
    nohup caido > /tmp/caido.log 2>&1 &
    wait_for_port 8080 30 || { echo "❌ Caido failed to start (see /tmp/caido.log)"; exit 1; }
else
    echo "✅ Caido already on :8080 — reusing"
fi

# 3. Launch Playwright mitmdump (reuse if already up)
if pgrep -x mitmdump >/dev/null; then
    echo "✅ mitmdump already running — reusing"
else
    echo "🌐 Launching Playwright mitmdump..."
    # Subshell so cd doesn't leak into the parent script's cwd
    ( cd "$BROWSER_DIR" && nohup ./start.sh > /tmp/playwright-mitmdump.log 2>&1 & )
    sleep 1
    if ! pgrep -x mitmdump >/dev/null; then
        echo "❌ mitmdump failed to start (see /tmp/playwright-mitmdump.log)"
        exit 1
    fi
fi

# 4. Setup target workspace (in the dir we were invoked from)
WORKSPACE="$INVOKED_FROM/$TARGET_NAME"
echo "🏗️  Creating workspace: $WORKSPACE"
mkdir -p "$WORKSPACE"
cp "$MASTER_CLAUDE_MD" "$WORKSPACE/CLAUDE.md"

# 5. Finalize
cd "$WORKSPACE" || exit
echo "---"
echo "✅ Environment Ready!"
echo "🤖 Target: $TARGET_NAME"
echo "📜 Agent Persona: Claude.md (Impact-Focused)"
echo "🔥 Run: 'claude --dangerously-skip-permissions' to begin."

exec $SHELL
