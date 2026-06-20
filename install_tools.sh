#!/usr/bin/env bash
#
# install_tools.sh — install the toolchain autohunt.py needs.
#
#   Recon (Go):   subfinder httpx katana nuclei dnsx ffuf
#   Capture:      mitmproxy (mitmdump)              [--skip-capture to skip]
#   XSS oracle:   playwright + chromium (node)      [--skip-browser to skip]
#   Misc:         jq
#
# Idempotent: anything already on PATH is left alone. Safe to re-run.
#
# Usage:
#   ./install_tools.sh                 # install everything missing
#   ./install_tools.sh --check         # just report what's present/missing
#   ./install_tools.sh --skip-browser  # skip Playwright + Chromium (heavy)
#   ./install_tools.sh --skip-capture  # skip mitmproxy
#
set -uo pipefail   # intentionally NOT -e: keep going and report failures at the end

REPO="$(cd "$(dirname "$0")" && pwd)"
CHECK_ONLY=0; SKIP_BROWSER=0; SKIP_CAPTURE=0
for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=1 ;;
    --skip-browser) SKIP_BROWSER=1 ;;
    --skip-capture) SKIP_CAPTURE=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $a (try --help)"; exit 2 ;;
  esac
done

# --- pretty output -----------------------------------------------------------
c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
ok()   { echo "${c_ok}[ok]${c_off}  $*"; }
info() { echo "${c_dim}[..]${c_off}  $*"; }
warn() { echo "${c_warn}[!!]${c_off}  $*"; }
err()  { echo "${c_err}[xx]${c_off}  $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- platform / sudo ---------------------------------------------------------
OS="$(uname -s)"
SUDO=""
if [ "$(id -u)" -ne 0 ] && have sudo; then SUDO="sudo"; fi

pkg_install() {  # pkg_install <binary-on-path> <apt-name> <brew-name>
  local bin="$1" apt="$2" brew="$3"
  have "$bin" && { ok "$bin already present ($(command -v "$bin"))"; return 0; }
  if [ "$OS" = "Darwin" ] && have brew; then
    info "brew install $brew"; brew install "$brew"
  elif have apt-get; then
    info "apt-get install $apt"; $SUDO apt-get update -qq && $SUDO apt-get install -y "$apt"
  else
    warn "don't know how to install $bin automatically — install it manually."; return 1
  fi
}

# --- Go ----------------------------------------------------------------------
ensure_go() {
  if have go; then ok "go present ($(go version | awk '{print $3}'))"; return 0; fi
  warn "Go not found — needed for the recon tools."
  [ "$CHECK_ONLY" = 1 ] && return 1
  if [ "$OS" = "Darwin" ] && have brew; then info "brew install go"; brew install go
  elif have apt-get; then info "apt-get install golang-go"; $SUDO apt-get update -qq && $SUDO apt-get install -y golang-go
  else warn "install Go manually from https://go.dev/dl/ then re-run."; return 1
  fi
  have go
}

GOBIN_DIR=""
go_bin_dir() { GOBIN_DIR="$(go env GOBIN 2>/dev/null)"; [ -n "$GOBIN_DIR" ] || GOBIN_DIR="$(go env GOPATH 2>/dev/null)/bin"; }

# tool -> go module path
GO_TOOLS=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "ffuf|github.com/ffuf/ffuf/v2@latest"
)

install_go_tools() {
  ensure_go || { warn "skipping Go tools (no Go)."; return 1; }
  go_bin_dir
  local v; v="$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')"
  case "$v" in 1.2[1-9]|1.[3-9]*|[2-9]*) : ;; *) warn "Go $v detected; nuclei v3 wants Go 1.21+. Upgrade if installs fail." ;; esac
  for entry in "${GO_TOOLS[@]}"; do
    local name="${entry%%|*}" mod="${entry#*|}"
    if have "$name"; then ok "$name already present"; continue; fi
    info "go install $name ..."
    if GO111MODULE=on go install "$mod"; then ok "installed $name"; else err "failed to install $name"; fi
  done
}

# --- mitmproxy ---------------------------------------------------------------
install_mitmproxy() {
  [ "$SKIP_CAPTURE" = 1 ] && { info "skipping mitmproxy (--skip-capture)"; return 0; }
  have mitmdump && { ok "mitmdump already present"; return 0; }
  if have pipx; then info "pipx install mitmproxy"; pipx install mitmproxy
  elif have apt-get; then
    info "installing pipx then mitmproxy"; $SUDO apt-get update -qq && $SUDO apt-get install -y pipx && pipx install mitmproxy
  elif have pip3; then info "pip3 install --user mitmproxy"; pip3 install --user mitmproxy
  else warn "no pipx/pip — install mitmproxy manually (https://mitmproxy.org)"; return 1
  fi
}

# --- playwright + chromium ---------------------------------------------------
install_playwright() {
  [ "$SKIP_BROWSER" = 1 ] && { info "skipping Playwright (--skip-browser)"; return 0; }
  if ! have node || ! have npm; then
    warn "node/npm not found — needed for the XSS-confirm oracle. Install Node 18+ (nvm or apt), then re-run."
    return 1
  fi
  # Install locally in the repo so 'node autohunt/xss-confirm.js' resolves playwright
  # (node walks up from autohunt/ to the repo-root node_modules). No global/sudo needed.
  if node -e "require.resolve('playwright')" >/dev/null 2>&1; then
    ok "playwright (node module) already present"
  else
    info "npm install playwright (repo-local)"
    ( cd "$REPO" && { [ -f package.json ] || npm init -y >/dev/null 2>&1; } && npm install playwright )
  fi
  # Download the Chromium browser binary (to ~/.cache/ms-playwright; no sudo).
  info "npx playwright install chromium"
  ( cd "$REPO" && npx playwright install chromium )
  # System libraries Chromium needs (apt under the hood → needs sudo). Best-effort.
  if [ "$OS" = "Linux" ]; then
    info "installing Chromium system deps (best-effort, may need sudo)"
    ( cd "$REPO" && $SUDO npx playwright install-deps chromium ) || \
      warn "could not install system deps automatically; if Chromium fails to launch, run: sudo npx playwright install-deps chromium"
  fi
}

# --- PATH note ---------------------------------------------------------------
ensure_path_note() {
  go_bin_dir
  [ -z "$GOBIN_DIR" ] && return 0
  case ":$PATH:" in *":$GOBIN_DIR:"*) return 0 ;; esac
  warn "$GOBIN_DIR is not on your PATH (Go tools install there)."
  local rc="$HOME/.zshrc"; [ -n "${ZDOTDIR:-}" ] && rc="$ZDOTDIR/.zshrc"
  if [ "$CHECK_ONLY" = 0 ] && [ -f "$rc" ] && ! grep -q 'go env GOPATH.*bin\|/go/bin' "$rc" 2>/dev/null; then
    echo "export PATH=\"\$PATH:$GOBIN_DIR\"" >> "$rc"
    ok "added $GOBIN_DIR to PATH in $rc — run: source $rc  (or open a new shell)"
  else
    echo "      add it with: echo 'export PATH=\"\$PATH:$GOBIN_DIR\"' >> $rc && source $rc"
  fi
}

# --- final report ------------------------------------------------------------
report() {
  echo; echo "=== toolchain status ==="
  local core=(subfinder httpx katana nuclei dnsx ffuf jq claude)
  for t in "${core[@]}"; do
    if have "$t"; then printf "  %-12s ${c_ok}present${c_off}\n" "$t"; else printf "  %-12s ${c_err}MISSING${c_off}\n" "$t"; fi
  done
  if [ "$SKIP_CAPTURE" = 0 ]; then
    if have mitmdump; then printf "  %-12s ${c_ok}present${c_off}\n" "mitmdump"; else printf "  %-12s ${c_err}MISSING${c_off}\n" "mitmdump"; fi
  fi
  if [ "$SKIP_BROWSER" = 0 ]; then
    if ( cd "$REPO" && node -e "require.resolve('playwright')" >/dev/null 2>&1 ); then
      printf "  %-12s ${c_ok}present${c_off}\n" "playwright"
    else printf "  %-12s ${c_err}MISSING${c_off}\n" "playwright"; fi
  fi
}

# --- run ---------------------------------------------------------------------
echo "install_tools.sh — repo: $REPO  (OS=$OS, sudo='${SUDO:-none}')"
if [ "$CHECK_ONLY" = 1 ]; then report; exit 0; fi

pkg_install jq jq jq
install_go_tools
install_mitmproxy
install_playwright
ensure_path_note
report

echo
ok "done. If anything shows MISSING above, see the notes printed earlier."
echo "    Next: open a new shell (for PATH), then:  python3 autohunt.py --dry-run"
