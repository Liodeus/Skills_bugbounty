#!/bin/bash

# --- CONFIGURATION ---
TARGET_NAME=$1

INITIAL_GOAL='Context:
- Program: [Program name]
- Target: [URL]
- My profile: I have those credentials: ... OR I don'\''t have any credentials
Goal:
Give me 10 priority spots to dig into in this app, ordered by
likelihood of an exploitable vuln. For each lead:
- The endpoint or feature involved
- The suspected vuln type
- Why you think it'\''s suspicious (observed pattern, abnormal behavior,
  broken convention, etc.)
- The fastest way to validate or rule out the lead

Constraints:
- No generic suggestions like "test for classic XSS". I want leads
  specific to this app only.
- Prioritize business logic bugs, access control, and complex chains.
  Scanners already pick up the rest.
- If you lack context on part of the app, say so rather than making
  things up.'
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
BROWSER_DIR="$SKILLS_BASE/playwright-chrome"

# Capture launch dir so the workspace lands where the user invoked the script,
# not wherever later `cd`s leave us.
INVOKED_FROM="$(pwd)"

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

# Fully headless — nothing to launch here. HTTP testing is driven with curl; DOM/browser work
# uses the headless Playwright MCPs, which Claude Code starts from .mcp.json (each a separate
# headless identity — see playwright-chrome/setup.sh). No proxy, no GUI tool.

# 2. Setup target workspace (in the dir we were invoked from)
WORKSPACE="$INVOKED_FROM/$TARGET_NAME"
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
#     the repo's stdio servers (httpworkbench → /ssrf, oathnet → /credential-leaks) and
#     the 3 headless Playwright identities (→ /xss DOM work). All run headless.
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
    # headless Playwright identities (one per generated config — skipped if not installed)
    if [ -f "$PW_CLI" ]; then
        for cfg in "$SKILLS_BASE"/playwright-chrome/configs/user*.json; do
            [ -f "$cfg" ] || continue
            emit "playwright-$(basename "$cfg" .json)" "{\"command\":\"node\",\"args\":[\"$PW_CLI\",\"--config\",\"$cfg\"]}"
        done
    else
        echo "⚠️  Playwright MCP cli not found ($PW_CLI) — run ./install.sh. Skipping playwright-* entries." >&2
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
echo $INITIAL_GOAL
echo "🔥 Run: 'claude --dangerously-skip-permissions' to begin."

exec $SHELL