#!/bin/bash
#
# install.sh — One-shot setup for the bug-bounty hunting toolkit.
#
# Installs/prepares everything hunt.sh needs:
#   1. Verifies system prerequisites (node, npm, python3, mitmdump, claude)
#   2. Installs Node dependencies (httpworkbench MCP + @playwright/mcp)
#   3. Installs the Playwright Chromium browser
#   4. Generates the playwright-chrome proxy configs (configs/userN.json)
#
# Idempotent: safe to re-run. hunt.sh auto-invokes this on first run, but you
# can also run it directly after cloning:  ./install.sh
#
# Exit codes: 0 = ready, 1 = a hard prerequisite is missing.

set -u

# Resolve the repo root from this script's own location (no hardcoded paths).
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT" || exit 1

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $*${NC}"; }
err()  { echo -e "${RED}❌ $*${NC}"; }

echo "🔧 Installing bug-bounty toolkit dependencies (root: $ROOT)"
echo

# ---------------------------------------------------------------------------
# 1. System prerequisites
# ---------------------------------------------------------------------------
# Hard requirements (cannot continue without these).
MISSING_HARD=0
for tool in node npm npx; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool present ($(command -v "$tool"))"
    else
        err "$tool is required but not found."
        MISSING_HARD=1
    fi
done

# Soft requirements (needed at hunt time, not for install) — warn with a hint.
if command -v python3 >/dev/null 2>&1; then ok "python3 present"; else
    warn "python3 not found — needed by the mitmproxy addon (proxy.py)."
fi
if command -v mitmdump >/dev/null 2>&1; then ok "mitmdump present"; else
    warn "mitmdump not found — install with:  sudo apt install -y mitmproxy   (or: pipx install mitmproxy)"
fi
if command -v claude >/dev/null 2>&1; then ok "claude CLI present"; else
    warn "claude CLI not found — install from https://claude.com/claude-code (hunt.sh launches it at the end)."
fi

if [ "$MISSING_HARD" -ne 0 ]; then
    echo
    err "Install Node.js (which provides node/npm/npx) and re-run ./install.sh"
    echo "   Kali/Debian:  sudo apt install -y nodejs npm"
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# 2. Node dependencies (httpworkbench MCP + @playwright/mcp)
# ---------------------------------------------------------------------------
echo "📦 Installing Node dependencies (npm install)..."
if npm install --no-audit --no-fund; then
    ok "Node dependencies installed (node_modules/)"
else
    err "npm install failed — check the output above."
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# 3. Playwright Chromium browser (for the @playwright/mcp servers)
# ---------------------------------------------------------------------------
echo "🌐 Installing the Playwright Chromium browser..."
if npx --yes playwright install chromium; then
    ok "Chromium installed for Playwright"
else
    warn "Playwright browser install failed — the Playwright MCP needs Chromium."
    warn "Retry manually:  npx playwright install chromium   (deps: sudo npx playwright install-deps chromium)"
fi
echo

# ---------------------------------------------------------------------------
# 4. Generate playwright-chrome proxy configs (configs/userN.json)
# ---------------------------------------------------------------------------
if [ -x "$ROOT/playwright-chrome/setup.sh" ]; then
    echo "🧩 Generating playwright-chrome configs..."
    if "$ROOT/playwright-chrome/setup.sh" >/dev/null; then
        ok "playwright-chrome configs generated (playwright-chrome/configs/)"
    else
        warn "playwright-chrome/setup.sh failed — run it manually to inspect."
    fi
else
    warn "playwright-chrome/setup.sh not found or not executable — skipping config generation."
fi
echo

# ---------------------------------------------------------------------------
# 4b. Recon CLI tools used by the /recon skill (JS discovery + secret scanners).
#     Idempotent — each tool is skipped if already on PATH.
# ---------------------------------------------------------------------------
echo "🛰️  Installing recon tools for the /recon skill..."
# go install <bin> <module@version> — skip if the binary already resolves.
go_install() {
    if command -v "$1" >/dev/null 2>&1; then ok "$1 present"; return 0; fi
    if ! command -v go >/dev/null 2>&1; then warn "go not found — cannot install $1"; return 1; fi
    echo "   • go install $2"
    if go install "$2" >/dev/null 2>&1; then ok "$1 installed"; else warn "failed to install $1 ($2)"; fi
}
# JS discovery / path extraction
go_install gau     github.com/lc/gau/v2/cmd/gau@latest
go_install katana  github.com/projectdiscovery/katana/cmd/katana@latest
go_install subjs   github.com/lc/subjs@latest
# Secret scanners
go_install gitleaks github.com/zricethezav/gitleaks/v8@latest    # canonical module path
go_install mantra   github.com/brosck/mantra@latest

# xnLinkFinder (Python) — endpoint/param extraction from JS
if command -v xnLinkFinder >/dev/null 2>&1; then
    ok "xnLinkFinder present"
elif command -v pip3 >/dev/null 2>&1; then
    echo "   • pip3 install --user xnLinkFinder"
    pip3 install --user --quiet xnLinkFinder >/dev/null 2>&1 \
        && ok "xnLinkFinder installed" || warn "failed to install xnLinkFinder (pip3)"
else
    warn "pip3 not found — cannot install xnLinkFinder"
fi

# trufflehog — go install is blocked by replace directives; use the official script.
if command -v trufflehog >/dev/null 2>&1; then
    ok "trufflehog present"
else
    echo "   • trufflehog install script → \$HOME/go/bin"
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b "$HOME/go/bin" >/dev/null 2>&1; then
        ok "trufflehog installed"
    else
        warn "failed to install trufflehog (see trufflesecurity/trufflehog install docs)"
    fi
fi
echo

# ---------------------------------------------------------------------------
# 5. Verify the stdio MCP servers (httpworkbench_mcp.js, oathnet_mcp.js, ...)
#    can be parsed and resolve their deps from node_modules/.
# ---------------------------------------------------------------------------
MCP_NAMES=()
for mcp_file in "$ROOT"/*_mcp.js; do
    [ -f "$mcp_file" ] || continue
    name="$(basename "$mcp_file" _mcp.js)"
    if node --check "$mcp_file" >/dev/null 2>&1; then
        ok "MCP server '$name' OK ($(basename "$mcp_file"))"
        MCP_NAMES+=("$name")
    else
        warn "MCP server '$name' failed to parse — check $mcp_file"
    fi
done
echo

# ---------------------------------------------------------------------------
# 6. Install the global `hunt` command (symlink on PATH → hunt.sh) so the
#    hunter can run `hunt <target>` from anywhere on the machine.
# ---------------------------------------------------------------------------
chmod +x "$ROOT/hunt.sh" 2>/dev/null
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
if ln -sfn "$ROOT/hunt.sh" "$BIN_DIR/hunt"; then
    ok "'hunt' command installed → $BIN_DIR/hunt -> $ROOT/hunt.sh"
    case ":$PATH:" in
        *":$BIN_DIR:"*) : ;;  # already on PATH — nothing to do
        *)
            warn "$BIN_DIR is not on your PATH yet. Add this line to ~/.zshrc and ~/.bashrc, then restart your shell:"
            echo "       export PATH=\"\$HOME/.local/bin:\$PATH\""
            ;;
    esac
else
    warn "Could not create the 'hunt' symlink in $BIN_DIR — run hunt.sh by its full path instead."
fi
echo

# ---------------------------------------------------------------------------
# Summary — print the resolved @playwright/mcp cli path for ~/.mcp.json wiring.
# ---------------------------------------------------------------------------
PW_CLI="$ROOT/node_modules/@playwright/mcp/cli.js"
echo "────────────────────────────────────────────────────────"
ok "Setup complete."
if [ ${#MCP_NAMES[@]} -gt 0 ]; then
    echo "   • stdio MCP servers  → registered per-target by hunt.sh (.mcp.json):"
    echo "       ${MCP_NAMES[*]}"
fi
if [ -f "$PW_CLI" ]; then
    echo "   • Playwright MCP cli → $PW_CLI"
    echo "     (point your ~/.mcp.json playwright-userN entries at this path)"
fi
echo "   Next:  hunt <target_name>   (runnable from anywhere)"
echo "────────────────────────────────────────────────────────"
