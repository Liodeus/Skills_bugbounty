#!/bin/bash
#
# install.sh — One-shot setup for the bug-bounty hunting toolkit.
#
# Installs/prepares everything hunt.sh + the skills need:
#   1. Verifies system prerequisites (node, npm, npx; soft: python3, go, claude)
#   2. Installs Node dependencies (httpworkbench MCP + @playwright/mcp)
#   3. Installs the headless Playwright Chromium browser            (→ playwright-user1/2/3)
#   3b. Installs the Lightpanda browser binary + native MCP server   (→ lightpanda-user1/2/3)
#   4. Generates the playwright-chrome headless configs (configs/userN.json)
#   4b. Installs the hunting CLI tools the skills call:
#       gau, xnLinkFinder, ugrep (/recon) · ffuf + SecLists (/ffuf-skill) ·
#       sqlmap (/sql) · curl, jq, dig (HTTP/JSON/DNS used everywhere)
#   5. Verifies the stdio MCP servers parse · 6. Installs the global `hunt` command
#
# Everything runs FULLY HEADLESS — no Burp/Caido. curl is the HTTP action surface,
# and hunt.sh wires TWO headless DOM engines into every workspace: @playwright/mcp
# over bundled Chromium, and Lightpanda's native MCP. Both run direct (no proxy).
# mitmdump is OPTIONAL (only for start.sh's upstream-proxy helper). Idempotent: safe
# to re-run. hunt.sh auto-invokes this on first run, but you can also run it directly
# after cloning:  ./install.sh
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
    warn "python3 not found — needed for xnLinkFinder, sqlmap, and the optional mitmproxy addon."
fi
if command -v go >/dev/null 2>&1; then ok "go present ($(go version 2>/dev/null | awk '{print $3}'))"; else
    warn "go not found — required to build gau & ffuf. Install:  sudo apt install -y golang-go   (or https://go.dev/dl/)"
fi
if command -v mitmdump >/dev/null 2>&1; then ok "mitmdump present (optional)"; else
    warn "mitmdump not found — OPTIONAL only (start.sh upstream-proxy helper). Everything runs headless without it.  sudo apt install -y mitmproxy"
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
# 3b. Lightpanda browser backend — native `lightpanda mcp` server + binary.
#     hunt.sh wires lightpanda-user1/2/3 (headless, direct) from this binary.
#     Idempotent: skipped if the binary already resolves ($LIGHTPANDA_BIN > repo-local > PATH);
#     otherwise the nightly for the detected platform is downloaded into the repo folder.
#     Additive only — never exits on failure (Chrome remains the default DOM engine).
# ---------------------------------------------------------------------------
LP_DIR="$ROOT/playwright-lightpanda"
if [ -d "$LP_DIR" ]; then
    echo "🐼 Setting up the Lightpanda backend (native MCP server)..."
    if [ -n "${LIGHTPANDA_BIN:-}" ] && [ -x "$LIGHTPANDA_BIN" ]; then
        :  # explicit override — use as-is
    elif [ -x "$LP_DIR/lightpanda" ]; then
        LIGHTPANDA_BIN="$LP_DIR/lightpanda"
    elif command -v lightpanda >/dev/null 2>&1; then
        LIGHTPANDA_BIN="$(command -v lightpanda)"
    else
        # No binary found — download the nightly for the detected platform.
        case "$(uname -sm)" in
            "Linux x86_64")  ASSET="lightpanda-x86_64-linux" ;;
            "Linux aarch64") ASSET="lightpanda-aarch64-linux" ;;
            "Darwin arm64")  ASSET="lightpanda-aarch64-macos" ;;
            "Darwin x86_64") ASSET="lightpanda-x86_64-macos" ;;
            *) ASSET="" ;;
        esac
        if [ -n "$ASSET" ]; then
            URL="https://github.com/lightpanda-io/browser/releases/download/nightly/$ASSET"
            echo "   • curl -fL --retry 3 -o $LP_DIR/lightpanda $URL"
            if curl -fL --retry 3 -o "$LP_DIR/lightpanda" "$URL" && chmod +x "$LP_DIR/lightpanda"; then
                LIGHTPANDA_BIN="$LP_DIR/lightpanda"
                ok "lightpanda binary downloaded"
            else
                warn "download failed — get it manually: $URL   (or: brew install lightpanda-io/browser/lightpanda)"
            fi
        else
            warn "no prebuilt lightpanda nightly for $(uname -sm) — build from source or use brew (macOS)."
        fi
    fi
    if [ -n "${LIGHTPANDA_BIN:-}" ] && [ -x "$LIGHTPANDA_BIN" ]; then
        ok "lightpanda OK ($("$LIGHTPANDA_BIN" version 2>/dev/null || echo '?'))  →  $LIGHTPANDA_BIN"
        mkdir -p "$LP_DIR/state"   # per-user cookie jars (gitignored)
        ok "lightpanda native MCP ready — hunt.sh wires lightpanda-user1/2/3"
    fi
else
    warn "playwright-lightpanda/ not found — skipping Lightpanda backend (Chrome still available)."
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
# 4b. Hunting CLI tools the skills call:
#     gau, xnLinkFinder, ugrep (/recon) · ffuf + SecLists (/ffuf-skill) ·
#     sqlmap (/sql) · curl, jq, dig (HTTP/JSON/DNS used across skills).
#     Idempotent — each tool is skipped if already on PATH.
# ---------------------------------------------------------------------------
echo "🛰️  Installing hunting CLI tools for the skills..."

# go install <bin> <module@version> — skip if the binary already resolves.
go_install() {
    if command -v "$1" >/dev/null 2>&1; then ok "$1 present"; return 0; fi
    if ! command -v go >/dev/null 2>&1; then warn "go not found — cannot install $1 (sudo apt install -y golang-go)"; return 1; fi
    echo "   • go install $2"
    if go install "$2" >/dev/null 2>&1; then ok "$1 installed"; else warn "failed to install $1 ($2)"; fi
}
# Install a system package via the available manager — skip if the binary resolves.
# $1=binary  $2=apt pkg  $3=brew pkg (defaults to $2)
pkg_install() {
    if command -v "$1" >/dev/null 2>&1; then ok "$1 present"; return 0; fi
    local brew_pkg="${3:-$2}"
    if command -v apt-get >/dev/null 2>&1; then
        echo "   • apt-get install -y $2"
        sudo apt-get install -y "$2" >/dev/null 2>&1 && ok "$1 installed" || warn "failed to install $1 (apt: $2)"
    elif command -v brew >/dev/null 2>&1; then
        echo "   • brew install $brew_pkg"
        brew install "$brew_pkg" >/dev/null 2>&1 && ok "$1 installed" || warn "failed to install $1 (brew: $brew_pkg)"
    else
        warn "$1 not found and no apt/brew — install '$2' manually"
    fi
}

# Best-effort: ensure a Go toolchain so gau & ffuf can build.
if ! command -v go >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    echo "   • apt-get install -y golang-go (needed to build gau/ffuf)"
    sudo apt-get install -y golang-go >/dev/null 2>&1 && ok "go installed" || warn "could not auto-install go — install Go then re-run"
fi

# Core HTTP / JSON / DNS utilities (curl = the headless HTTP action surface).
pkg_install curl curl
pkg_install jq   jq
pkg_install dig  dnsutils bind

# JS URL harvest + active fuzzing (Go tools).
go_install gau   github.com/lc/gau/v2/cmd/gau@latest
go_install ffuf  github.com/ffuf/ffuf/v2@latest

# notify — Discord/Slack/… alerting on confirmed findings (/report-yeswehack Step 4).
# Provider config (webhook) lives at ~/.config/notify/provider-config.yaml — NOT installed here, it's a secret.
go_install notify github.com/projectdiscovery/notify/cmd/notify@latest

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

# ugrep — fast drop-in grep used for path/secret/sink extraction over the js/ tree.
pkg_install ugrep ugrep

# sqlmap — SQL injection automation (/sql skill).
pkg_install sqlmap sqlmap

# SecLists wordlists — used by /ffuf-skill (parameter / directory / subdomain lists).
SECLISTS_DIR="$(ls -d /usr/share/seclists /usr/share/wordlists/seclists /opt/SecLists "$HOME"/SecLists 2>/dev/null | head -1)"
if [ -n "$SECLISTS_DIR" ]; then
    ok "SecLists present ($SECLISTS_DIR)"
elif command -v apt-get >/dev/null 2>&1; then
    echo "   • apt-get install -y seclists"
    if sudo apt-get install -y seclists >/dev/null 2>&1; then
        ok "SecLists installed (/usr/share/seclists)"
    else
        warn "failed to install seclists (apt) — git clone https://github.com/danielmiessler/SecLists /opt/SecLists"
    fi
else
    warn "SecLists not found — git clone https://github.com/danielmiessler/SecLists /opt/SecLists"
fi

# Go-installed binaries (gau, ffuf) land in GOPATH/bin — make sure it's on PATH at hunt time.
GOPATH_DIR="$(command -v go >/dev/null 2>&1 && go env GOPATH 2>/dev/null)"
GOBIN_DIR="${GOPATH_DIR:-$HOME/go}/bin"
case ":$PATH:" in
    *":$GOBIN_DIR:"*) : ;;
    *) warn "$GOBIN_DIR is not on PATH — gau/ffuf won't be found at hunt time. Add to ~/.zshrc & ~/.bashrc:"
       echo "       export PATH=\"$GOBIN_DIR:\$PATH\"" ;;
esac
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
# Summary.
# ---------------------------------------------------------------------------
PW_CLI="$ROOT/node_modules/@playwright/mcp/cli.js"
echo "────────────────────────────────────────────────────────"
ok "Setup complete."
if [ ${#MCP_NAMES[@]} -gt 0 ]; then
    echo "   • stdio MCP servers → auto-wired into each workspace's .mcp.json by hunt.sh:"
    echo "       ${MCP_NAMES[*]}"
fi
echo "   • headless DOM engines → auto-wired into each workspace's .mcp.json by hunt.sh"
echo "     (Lightpanda is the DEFAULT; Chrome is the fallback for JS-rendering problems):"
if [ -n "${LIGHTPANDA_BIN:-}" ] && [ -x "$LIGHTPANDA_BIN" ]; then
    echo "       • Lightpanda  → lightpanda-user1/2/3   (default · native MCP · $LIGHTPANDA_BIN)"
else
    warn "Lightpanda binary not installed — lightpanda-user1/2/3 won't be wired."
fi
if [ -f "$PW_CLI" ]; then
    echo "       • Chrome      → playwright-user1/2/3   (fallback · @playwright/mcp cli: $PW_CLI)"
else
    warn "Playwright MCP cli missing ($PW_CLI) — re-run after a successful 'npm install'."
fi
echo "   • API keys (optional): export OATHNET_API_KEY=… (/credential-leaks),"
echo "                          export PROFUNDIS_API_KEY=… (/profundis) before hunting."
echo "   Next:  hunt <target_name>   (runnable from anywhere)"
echo "────────────────────────────────────────────────────────"
