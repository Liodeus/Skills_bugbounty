#!/bin/bash

# --- CONFIGURATION ---
TARGET_NAME=$1

INITIAL_GOAL="Target: $TARGET_NAME
Scope: <wildcard *.tld | single host | raw request pasted below>
Creds: <none | user1=...  user2=...>
Stop condition: <run until HH:MM | none - run until the exit audit is clean, then pivot>

Start with /recon (full minimum coverage), then run the Hunting workflow
end-to-end: /xss + /ssrf first, then the pivot gate. Everything per CLAUDE.md.

Hold the line on these - they're where you drift:
- Recon output is NOT a deliverable. Flow straight from recon into hunting; do not hand back.
- A finding is a checkpoint, not a finish line (Order 1): run the what's-next sweep, bank it, keep hunting the rest of the surface.
- Never pause to ask me. Make the call, log the assumption, keep moving.
- Do not call this target \"done\" or \"barren\" until the exit audit is clean for every host (Order 2).

Go."
# Resolve the repo root from this script's REAL location, following symlinks — so the
# launcher works whether run as ./hunt.sh, hunt (the ~/.local/bin symlink), or from
# anywhere. `dirname "$0"` alone would resolve to ~/.local/bin when invoked via the symlink.
SELF="$0"
while [ -L "$SELF" ]; do
    DIR="$(cd "$(dirname "$SELF")" >/dev/null 2>&1 && pwd)"
    SELF="$(readlink "$SELF")"
    case "$SELF" in
        /*) : ;;                 # absolute target — use as-is
        *)  SELF="$DIR/$SELF" ;; # relative target — resolve against the link's dir
    esac
done
SKILLS_BASE="$(cd "$(dirname "$SELF")" >/dev/null 2>&1 && pwd)"
MASTER_CLAUDE_MD="$SKILLS_BASE/SKILLS/CLAUDE.md"
CHROME_DIR="$SKILLS_BASE/playwright-chrome"
LP_DIR="$SKILLS_BASE/playwright-lightpanda"

# Capture launch dir so the workspace lands where the user invoked the script,
# not wherever later `cd`s leave us.
INVOKED_FROM="$(pwd)"

# 1. Validation
if [ -z "$TARGET_NAME" ]; then
    echo "Usage: hunt <target_name>"
    exit 1
fi
# Need at least one browser backend present. Chrome is the default DOM engine;
# Lightpanda (playwright-lightpanda/) is additive. Either is enough to proceed.
if [ ! -d "$CHROME_DIR" ] && [ ! -d "$LP_DIR" ]; then
    echo "❌ Could not find either browser backend ($CHROME_DIR or $LP_DIR)"
    exit 1
fi

echo "🚀 Starting automated hunt for: $TARGET_NAME"

# Fully headless — nothing to launch here. HTTP testing is driven with curl; DOM/browser work
# uses the headless browser MCPs Claude Code starts from .mcp.json: @playwright/mcp (Chrome) and
# Lightpanda's native MCP — each with 3 isolated identities (see playwright-chrome/setup.sh and
# playwright-lightpanda/README.md). No proxy, no GUI tool.

# 2. Setup target workspace (in the dir we were invoked from)
WORKSPACE="$INVOKED_FROM/$TARGET_NAME"
# Guard: a plain file (or other non-dir) already sitting at the workspace path
# makes mkdir fail and every later step cascade into "Not a directory" errors.
# Fail fast with a clear message instead.
if [ -e "$WORKSPACE" ] && [ ! -d "$WORKSPACE" ]; then
    echo "❌ '$WORKSPACE' already exists and is not a directory. Remove it or pick another target name."
    exit 1
fi
echo "🏗️  Creating workspace: $WORKSPACE"
mkdir -p "$WORKSPACE"
cp "$MASTER_CLAUDE_MD" "$WORKSPACE/CLAUDE.md"

# Install hunting skills into the workspace so Claude Code can discover/invoke
# them (/ato, /idor, ...). The `*/` glob matches skill directories only, so
# SKILLS/CLAUDE.md (a file) is correctly skipped.
mkdir -p "$WORKSPACE/.claude/skills"
for skill_dir in "$SKILLS_BASE"/SKILLS/*/; do
    ln -sfn "$skill_dir" "$WORKSPACE/.claude/skills/$(basename "$skill_dir")"
done

# 2b. Register the MCP servers Claude Code should load in this workspace (.mcp.json):
#     the repo's stdio servers (httpworkbench → /ssrf, oathnet → /credential-leaks) plus
#     TWO headless DOM engines, each with 3 isolated identities: @playwright/mcp (Chrome)
#     and Lightpanda's native MCP. All run headless and direct (no proxy/Burp).
#     Opt out of either with HUNT_NO_CHROME=1 / HUNT_NO_LIGHTPANDA=1.
PW_CLI="$SKILLS_BASE/node_modules/@playwright/mcp/cli.js"
MCP_JSON="$WORKSPACE/.mcp.json"
{
    echo '{'
    echo '  "mcpServers": {'
    first=1
    emit() {  # $1=name  $2=json body
        if [ "$first" -eq 1 ]; then first=0; else echo ','; fi
        printf '    "%s": %s' "$1" "$2"
    }
    # stdio MCP servers shipped in the repo (*_mcp.js)
    for mcp_file in "$SKILLS_BASE"/*_mcp.js; do
        [ -f "$mcp_file" ] || continue
        name="$(basename "$mcp_file" _mcp.js)"
        if [ "$name" = "oathnet" ] && [ -n "${OATHNET_API_KEY:-}" ]; then
            emit "$name" "{\"command\":\"node\",\"args\":[\"$mcp_file\"],\"env\":{\"OATHNET_API_KEY\":\"$OATHNET_API_KEY\"}}"
        else
            emit "$name" "{\"command\":\"node\",\"args\":[\"$mcp_file\"]}"
        fi
    done
    # headless Chrome identities (one per generated config — @playwright/mcp over bundled Chromium)
    if [ -z "${HUNT_NO_CHROME:-}" ]; then
        if [ -f "$PW_CLI" ]; then
            for cfg in "$SKILLS_BASE"/playwright-chrome/configs/user*.json; do
                [ -f "$cfg" ] || continue
                emit "playwright-$(basename "$cfg" .json)" "{\"command\":\"node\",\"args\":[\"$PW_CLI\",\"--config\",\"$cfg\"]}"
            done
        else
            echo "⚠️  Playwright MCP cli not found ($PW_CLI) — run ./install.sh. Skipping playwright-* entries." >&2
        fi
    fi
    # headless Lightpanda identities (native `lightpanda mcp`, headless & direct — no proxy/Burp).
    # Added if the binary resolves; skipped (with a hint) otherwise. Each user gets its own cookie
    # jar for session isolation, mirroring Chrome's separate userDataDirs.
    LP_BIN=""
    if [ -z "${HUNT_NO_LIGHTPANDA:-}" ]; then
        if   [ -n "${LIGHTPANDA_BIN:-}" ] && [ -x "$LIGHTPANDA_BIN" ]; then LP_BIN="$LIGHTPANDA_BIN";
        elif [ -x "$LP_DIR/lightpanda" ];                               then LP_BIN="$LP_DIR/lightpanda";
        elif command -v lightpanda >/dev/null 2>&1;                     then LP_BIN="$(command -v lightpanda)"; fi
    fi
    if [ -n "$LP_BIN" ]; then
        mkdir -p "$LP_DIR/state"
        for i in 1 2 3; do
            JAR="$LP_DIR/state/user${i}.cookies.json"
            emit "lightpanda-user${i}" \
                "{\"command\":\"$LP_BIN\",\"args\":[\"mcp\",\"--cookie\",\"$JAR\",\"--cookie-jar\",\"$JAR\",\"--insecure-disable-tls-host-verification\"]}"
        done
    else
        echo "⚠️  lightpanda binary not found — skipping lightpanda-* entries (run ./install.sh)" >&2
    fi
    echo
    echo '  }'
    echo '}'
} > "$MCP_JSON"
echo "🔌 Wrote MCP config → $MCP_JSON"

# 3. Finalize
cd "$WORKSPACE" || exit
echo "---"
echo "✅ Environment Ready!"
echo "🤖 Target: $TARGET_NAME"
echo "📜 Agent Persona: Claude.md (Impact-Focused)"
# Write the kickoff prompt into the workspace. The launch hints (how to start
# Claude, what to paste) are printed INSIDE the tmux session below so they stay
# visible — stdout printed here is hidden once `tmux attach` takes over the screen.
printf '%s\n' "$INITIAL_GOAL" > "$WORKSPACE/GOAL.md"
echo "📝 Kickoff prompt written → $WORKSPACE/GOAL.md"

# 4. Launch a tmux session for this hunt in the target workspace. Claude is NOT
# auto-started — the session drops you at a shell in the workspace so you can
# start Claude yourself (and paste the kickoff prompt from GOAL.md when ready).
# Falls back to a plain shell when tmux isn't installed.
CLAUDE_CMD='claude --dangerously-skip-permissions'
if command -v tmux >/dev/null 2>&1; then
    # tmux session names can't contain '.' or ':'; sanitize the target name.
    SESSION="hunt-$(printf '%s' "$TARGET_NAME" | tr -c 'A-Za-z0-9_-' '_')"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "🖥️  Attaching to existing tmux session: $SESSION"
    else
        echo "🖥️  Launching tmux session: $SESSION"
        # Start the session with a startup command that prints the launch hints
        # cleanly, then execs an interactive shell. Doing it this way (rather than
        # send-keys) means the hints appear on their own — no raw echo command
        # showing in the pane. Only on a NEW session — never touch an existing one,
        # which could disrupt a Claude already running there.
        tmux new-session -d -s "$SESSION" -c "$WORKSPACE" \
            "printf '\n🔥 Start Claude:  %s\n👉 Then paste:    @GOAL.md follow this, start now\n\n' '$CLAUDE_CMD'; exec ${SHELL:-/bin/sh}"
    fi
    if [ -n "${TMUX:-}" ]; then
        # Already inside tmux — switch instead of nesting sessions.
        tmux switch-client -t "$SESSION"
    else
        exec tmux attach-session -t "$SESSION"
    fi
else
    echo "⚠️  tmux not found — falling back to a plain shell."
    echo "🔥 Start Claude:  $CLAUDE_CMD"
    echo "👉 Then paste:    @GOAL.md follow this, start now"
    exec $SHELL
fi