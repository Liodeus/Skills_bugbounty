#!/bin/bash

# ── Machine-specific overrides (set these as env vars to customise) ────────────
# Directory containing this script and the Dockerfile
SKILLS_BASE="${SKILLS_BASE:-$HOME/Documents/Skills_bugbounty}"
# Where @playwright/mcp and other node_modules live
PLAYWRIGHT_MODULES="${PLAYWRIGHT_MODULES:-$HOME/Documents/node_modules}"
# Caido binary — auto-detected from PATH or $HOME/Applications, or set manually
CAIDO_BIN="${CAIDO_BIN:-}"
# Ports
CAIDO_PORT="${CAIDO_PORT:-8080}"
MITMDUMP_PORT="${MITMDUMP_PORT:-8081}"
# Docker image tag
DOCKER_IMAGE="${DOCKER_IMAGE:-hunt-claude:latest}"
# interactsh OOB token — use `isc` inside the container, token is injected automatically
INTERACTSH_TOKEN="${INTERACTSH_TOKEN:-527ac2fd-3ddf-4fe5-a189-950593b478b1}"
# Wordlists directory (SecLists or equivalent)
WORDLISTS_DIR="${WORDLISTS_DIR:-/opt/SecLists}"

# ── Derived paths (don't edit below here) ─────────────────────────────────────
TARGET_NAME=$1
MASTER_CLAUDE_MD="$SKILLS_BASE/SKILLS/CLAUDE.md"
BROWSER_DIR="$SKILLS_BASE/playwright-chrome"
DOCKERFILE="$SKILLS_BASE/Dockerfile.hunt"
INVOKED_FROM="$(pwd)"

# ── Helpers ───────────────────────────────────────────────────────────────────
wait_for_port() {
    local port=$1 timeout=${2:-30} elapsed=0
    until nc -z localhost "$port" 2>/dev/null; do
        sleep 0.2
        elapsed=$((elapsed + 1))
        [ "$elapsed" -gt $((timeout * 5)) ] && { echo "❌ Timeout waiting for port $port"; return 1; }
    done
}

find_caido() {
    [ -n "$CAIDO_BIN" ] && { echo "$CAIDO_BIN"; return; }
    command -v caido 2>/dev/null && return
    find "$HOME/Applications" -maxdepth 2 -name "caido-desktop-*.AppImage" 2>/dev/null \
        | sort -V | tail -1
}

err() { echo "  ✗ $*" >&2; }

# ── 1. Pre-flight checks (collect all errors, then fail once) ─────────────────
preflight() {
    local ok=true

    # Usage
    if [ -z "$TARGET_NAME" ]; then
        echo "Usage: hunt <target_name>" >&2
        exit 1
    fi

    echo "🔍 Pre-flight checks..."

    # Host commands
    for cmd in docker nc pgrep node; do
        command -v "$cmd" >/dev/null 2>&1 || { err "command not found: $cmd"; ok=false; }
    done

    # Docker daemon
    docker info >/dev/null 2>&1 || { err "Docker daemon not running"; ok=false; }

    # caido-mcp-server
    command -v caido-mcp-server >/dev/null 2>&1 \
        || { err "caido-mcp-server not in PATH (install it or check \$PATH)"; ok=false; }

    # Caido binary
    CAIDO=$(find_caido)
    [ -n "$CAIDO" ] \
        || { err "Caido binary not found — set CAIDO_BIN=/path/to/caido or put caido in PATH"; ok=false; }

    # Paths
    [ -f "$MASTER_CLAUDE_MD" ] \
        || { err "CLAUDE.md not found: $MASTER_CLAUDE_MD"; ok=false; }

    [ -f "$BROWSER_DIR/start.sh" ] \
        || { err "Playwright start.sh not found: $BROWSER_DIR/start.sh"; ok=false; }

    [ -f "$PLAYWRIGHT_MODULES/@playwright/mcp/cli.js" ] \
        || { err "Playwright MCP not found: $PLAYWRIGHT_MODULES/@playwright/mcp/cli.js"; ok=false; }

    [ -d "$HOME/.cache/ms-playwright" ] \
        || { err "Playwright browser cache not found: $HOME/.cache/ms-playwright"; ok=false; }

    [ -f "$HOME/.claude.json" ] \
        || { err "Claude MCP config not found: $HOME/.claude.json"; ok=false; }

    [ -d "$HOME/.claude" ] \
        || { err "Claude config dir not found: $HOME/.claude"; ok=false; }

    [ -f "$DOCKERFILE" ] \
        || { err "Dockerfile not found: $DOCKERFILE"; ok=false; }

    [ -d "$WORDLISTS_DIR" ] \
        || { err "Wordlists dir not found: $WORDLISTS_DIR (set WORDLISTS_DIR= to override)"; ok=false; }

    # Fail if anything is missing
    if [ "$ok" != true ]; then
        echo "" >&2
        echo "❌ Pre-flight failed — fix the above before running hunt." >&2
        exit 1
    fi

    echo "✅ Pre-flight passed"
}

preflight

# ── 2. Build Docker image if missing ─────────────────────────────────────────
if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo "🐳 Building $DOCKER_IMAGE (first run — takes ~2 min)..."
    docker build -f "$DOCKERFILE" -t "$DOCKER_IMAGE" "$SKILLS_BASE" \
        || { echo "❌ Docker build failed"; exit 1; }
else
    echo "✅ Docker image $DOCKER_IMAGE ready"
fi

# ── 3. Launch Caido ───────────────────────────────────────────────────────────
if ! nc -z localhost "$CAIDO_PORT" 2>/dev/null; then
    echo "🌐 Launching Caido..."
    nohup "$CAIDO" > /tmp/caido.log 2>&1 &
    wait_for_port "$CAIDO_PORT" 30 || { echo "❌ Caido failed (see /tmp/caido.log)"; exit 1; }
else
    echo "✅ Caido already on :$CAIDO_PORT — reusing"
fi

# ── 4. Launch Playwright mitmdump ─────────────────────────────────────────────
if pgrep -x mitmdump >/dev/null; then
    echo "✅ mitmdump already running — reusing"
else
    echo "🌐 Launching Playwright mitmdump..."
    ( cd "$BROWSER_DIR" && nohup ./start.sh > /tmp/playwright-mitmdump.log 2>&1 & )
    sleep 1
    pgrep -x mitmdump >/dev/null \
        || { echo "❌ mitmdump failed (see /tmp/playwright-mitmdump.log)"; exit 1; }
fi

# ── 5. Setup workspace ────────────────────────────────────────────────────────
echo "🚀 Starting hunt for: $TARGET_NAME"
WORKSPACE="$INVOKED_FROM/$TARGET_NAME"
echo "🏗️  Workspace: $WORKSPACE"
mkdir -p "$WORKSPACE"
cp "$MASTER_CLAUDE_MD" "$WORKSPACE/CLAUDE.md"

# ── 6. Run Claude inside the hunt container ───────────────────────────────────
echo "---"
echo "✅ Environment ready — launching Docker"
echo "🤖 Target:    $TARGET_NAME"
echo "🐳 Image:     $DOCKER_IMAGE (--network=host)"
echo ""

exec docker run --rm -it \
    --network=host \
    --ipc=host \
    --hostname="hunt-$(echo "$TARGET_NAME" | tr '.' '-')" \
    \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -e HOST_USER="$(id -un)" \
    -e HOST_HOME="$HOME" \
    -e HOME="$HOME" \
    -e TERM="${TERM:-xterm-256color}" \
    -e INTERACTSH_TOKEN="$INTERACTSH_TOKEN" \
    \
    -v "$HOME/.claude.json:$HOME/.claude.json:ro" \
    -v "$HOME/.claude:$HOME/.claude" \
    \
    -v "$(command -v caido-mcp-server):$(command -v caido-mcp-server):ro" \
    \
    -v "$PLAYWRIGHT_MODULES/@playwright:$PLAYWRIGHT_MODULES/@playwright:ro" \
    -v "$HOME/.cache/ms-playwright:$HOME/.cache/ms-playwright:ro" \
    \
    -v "$SKILLS_BASE:$SKILLS_BASE:ro" \
    \
    -v "$WORDLISTS_DIR:$WORDLISTS_DIR:ro" \
    \
    -v "$WORKSPACE:/workspace" \
    \
    -w /workspace \
    "$DOCKER_IMAGE"
