#!/usr/bin/env bash
#
# install_tools.sh — install the toolchain autohunt needs. No sudo required.
#
#   Recon:    subfinder httpx katana nuclei dnsx ffuf   (prebuilt binaries -> ~/.local/bin)
#   JSON:     jq                                          (prebuilt binary if missing)
#   Capture:  mitmproxy / mitmdump                        [--skip-capture]
#   XSS:      playwright + chromium (node, repo-local)    [--skip-browser]
#   PATH:     adds ~/.local/bin (+ ~/go/bin) to your shell rc so launches find the tools
#
# Downloads prebuilt binaries from the projects' GitHub/CDN releases — no Go, no apt, no
# sudo. The only thing that may need sudo is Chromium's system libraries (best-effort;
# you'll get the one command to run if it can't). Idempotent: re-run any time.
#
# Usage:
#   ./install_tools.sh                 install everything missing
#   ./install_tools.sh --check         report present/missing, install nothing
#   ./install_tools.sh --skip-browser  skip Playwright + Chromium (heavy)
#   ./install_tools.sh --skip-capture  skip mitmproxy
#   ./install_tools.sh --from-source   build recon tools with `go install` instead of prebuilt
#
set -uo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin"; mkdir -p "$BIN"

CHECK=0; SKIP_BROWSER=0; SKIP_CAPTURE=0; FROM_SRC=0
for a in "$@"; do case "$a" in
  --check) CHECK=1 ;;
  --skip-browser) SKIP_BROWSER=1 ;;
  --skip-capture) SKIP_CAPTURE=1 ;;
  --from-source) FROM_SRC=1 ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown arg: $a (try --help)"; exit 2 ;;
esac; done

c_ok=$'\033[32m'; c_w=$'\033[33m'; c_e=$'\033[31m'; c_d=$'\033[2m'; c_off=$'\033[0m'
ok(){   echo "${c_ok}[ok]${c_off} $*"; }
info(){ echo "${c_d}[..]${c_off} $*"; }
warn(){ echo "${c_w}[!!]${c_off} $*"; }
err(){  echo "${c_e}[xx]${c_off} $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# --- platform / arch (PD+ffuf use linux_amd64 / macOS_arm64 ; mitmproxy uses linux-x86_64) ---
case "$(uname -s)" in Linux) OST=linux; MOS=linux ;; Darwin) OST=macos; MOS=macos ;; *) OST=linux; MOS=linux ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64; MARCH=x86_64 ;; aarch64|arm64) ARCH=arm64; MARCH=arm64 ;; *) ARCH=amd64; MARCH=x86_64 ;; esac

need(){ have curl || { err "curl is required"; exit 1; }; have python3 || { err "python3 is required"; exit 1; }; }
net(){ curl -sI --max-time 12 https://github.com >/dev/null 2>&1 || { err "no network — installer needs internet"; exit 1; }; }

gh_url(){  # gh_url <owner/repo> <python-regex on asset name (case-insensitive)>
  curl -s --max-time 25 "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
   | python3 -c "import json,sys,re
d=json.load(sys.stdin); p=re.compile(sys.argv[1], re.I)
print(next((a['browser_download_url'] for a in d.get('assets',[]) if p.search(a['name'])), ''))" "$2" 2>/dev/null
}
gh_tag(){ curl -s --max-time 20 "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
   | python3 -c "import json,sys;print(json.load(sys.stdin).get('tag_name','').lstrip('v'))" 2>/dev/null; }

extract(){  # extract <archive> <destdir>
  local f="$1" d="$2"; mkdir -p "$d"
  case "$f" in
    *.zip) if have unzip; then unzip -oq "$f" -d "$d"; else python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$f" "$d"; fi ;;
    *.tar.gz|*.tgz) tar xzf "$f" -C "$d" ;;
  esac
}

dl_bin(){  # dl_bin <name> <repo> <asset-regex>   (archive containing a binary named <name>)
  local name="$1" repo="$2" rx="$3"
  have "$name" && { ok "$name present ($(command -v "$name"))"; return 0; }
  local url; url="$(gh_url "$repo" "$rx")"
  [ -z "$url" ] && { err "$name: no asset matching /$rx/ in $repo latest release"; return 1; }
  local tmp; tmp="$(mktemp -d)"; local f="$tmp/$(basename "$url")"
  if curl -fsL --max-time 180 "$url" -o "$f"; then
    extract "$f" "$tmp/x"
    local b; b="$(find "$tmp/x" -type f -name "$name" 2>/dev/null | head -1)"
    if [ -n "$b" ]; then install -m755 "$b" "$BIN/$name" && ok "installed $name ($(basename "$url"))"
    else err "$name: binary not found inside archive"; fi
  else err "$name: download failed ($url)"; fi
  rm -rf "$tmp"
}

install_jq(){
  have jq && { ok "jq present"; return 0; }
  local url; url="$(gh_url jqlang/jq "jq-${OST}-${ARCH}$")"
  [ -z "$url" ] && { warn "jq: no prebuilt asset found — install via your package manager"; return 1; }
  curl -fsL --max-time 60 "$url" -o "$BIN/jq" && chmod +x "$BIN/jq" && ok "installed jq" || err "jq install failed"
}

install_recon_src(){
  have go || { err "Go not installed — can't --from-source. Install Go or drop the flag."; return 1; }
  local mods=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/ffuf/ffuf/v2@latest"
  )
  for m in "${mods[@]}"; do info "go install $m"; GO111MODULE=on go install "$m" || err "go install failed: $m"; done
}

install_recon(){
  [ "$FROM_SRC" = 1 ] && { install_recon_src; return; }
  local rx="${OST}_${ARCH}\\.(zip|tar\\.gz)$"
  dl_bin subfinder projectdiscovery/subfinder "$rx"
  dl_bin httpx     projectdiscovery/httpx     "$rx"
  dl_bin katana    projectdiscovery/katana    "$rx"
  dl_bin nuclei    projectdiscovery/nuclei    "$rx"
  dl_bin dnsx      projectdiscovery/dnsx      "$rx"
  dl_bin ffuf      ffuf/ffuf                  "$rx"
}

install_mitm(){
  [ "$SKIP_CAPTURE" = 1 ] && { info "skipping mitmproxy (--skip-capture)"; return 0; }
  have mitmdump && { ok "mitmdump present"; return 0; }
  local ver; ver="$(gh_tag mitmproxy/mitmproxy)"
  if [ -n "$ver" ]; then
    local url="https://downloads.mitmproxy.org/${ver}/mitmproxy-${ver}-${MOS}-${MARCH}.tar.gz"
    local tmp; tmp="$(mktemp -d)"
    if curl -fsL --max-time 180 "$url" -o "$tmp/m.tgz"; then
      tar xzf "$tmp/m.tgz" -C "$tmp"
      for b in mitmdump mitmproxy mitmweb; do f="$(find "$tmp" -type f -name "$b" | head -1)"; [ -n "$f" ] && install -m755 "$f" "$BIN/$b"; done
      [ -x "$BIN/mitmdump" ] && ok "installed mitmproxy $ver" || err "mitmproxy extract failed"
      rm -rf "$tmp"; return 0
    fi
    rm -rf "$tmp"; warn "mitmproxy direct download failed → trying pip"
  fi
  if have pipx; then pipx install mitmproxy && ok "installed mitmproxy (pipx)" || err "mitmproxy pipx failed"
  elif have pip3; then pip3 install --user -q mitmproxy && ok "installed mitmproxy (pip --user)" || err "mitmproxy pip failed"
  else err "no pipx/pip — install mitmproxy manually (https://mitmproxy.org)"; fi
}

install_browser(){
  [ "$SKIP_BROWSER" = 1 ] && { info "skipping Playwright (--skip-browser)"; return 0; }
  if ! have node || ! have npm; then warn "node/npm missing — the XSS oracle needs them. Install Node 18+ and re-run."; return 1; fi
  if node -e "require.resolve('playwright')" >/dev/null 2>&1; then ok "playwright module present"
  else
    info "npm install playwright (repo-local, no sudo)"
    ( cd "$REPO" && { [ -f package.json ] || npm init -y >/dev/null 2>&1; } && npm install playwright >/dev/null 2>&1 ) \
      && ok "playwright module installed" || { err "npm install playwright failed"; return 1; }
  fi
  info "npx playwright install chromium (~/.cache/ms-playwright)"
  ( cd "$REPO" && npx playwright install chromium >/dev/null 2>&1 ) && ok "chromium downloaded" || warn "chromium download had issues — re-run if the oracle fails"
  if [ "$OST" = linux ]; then
    if sudo -n true 2>/dev/null; then
      ( cd "$REPO" && sudo npx playwright install-deps chromium >/dev/null 2>&1 ) && ok "chromium system deps installed" || warn "system-deps step failed (often already present)"
    else
      info "skipping Chromium system-deps (needs sudo). If the oracle fails to launch, run:"
      info "    sudo npx playwright install-deps chromium   (from $REPO)"
    fi
  fi
}

ensure_path(){
  case ":$PATH:" in *":$BIN:"*) ;; *) warn "$BIN is not on your current PATH" ;; esac
  local added=0 rc
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    [ -e "$rc" ] || continue
    grep -qE '^[[:space:]]*export PATH=.*\.local/bin' "$rc" && continue   # already active
    printf '\n# autohunt toolchain (recon / mitmproxy / go) on PATH\nexport PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"\n' >> "$rc"
    ok "added ~/.local/bin to PATH in $rc"; added=1
  done
  [ "$added" = 1 ] && info "open a new shell (or 'source' your rc) to pick up the PATH change."
  # autohunt.py and run.sh also add ~/.local/bin at runtime, so launches work regardless.
}

report(){
  echo; echo "=== toolchain status ==="
  local t
  for t in subfinder httpx katana nuclei dnsx ffuf jq claude; do
    if PATH="$BIN:$PATH" have "$t"; then printf "  %-11s ${c_ok}present${c_off}\n" "$t"; else printf "  %-11s ${c_e}MISSING${c_off}\n" "$t"; fi
  done
  [ "$SKIP_CAPTURE" = 0 ] && { if PATH="$BIN:$PATH" have mitmdump; then printf "  %-11s ${c_ok}present${c_off}\n" mitmdump; else printf "  %-11s ${c_e}MISSING${c_off}\n" mitmdump; fi; }
  [ "$SKIP_BROWSER" = 0 ] && { if ( cd "$REPO" && node -e "require.resolve('playwright')" >/dev/null 2>&1 ); then printf "  %-11s ${c_ok}present${c_off}\n" playwright; else printf "  %-11s ${c_e}MISSING${c_off}\n" playwright; fi; }
}

echo "install_tools.sh — repo $REPO  (os=$OST arch=$ARCH → $BIN)"
need
if [ "$CHECK" = 1 ]; then report; exit 0; fi
net
install_jq
install_recon
install_mitm
install_browser
ensure_path
report
echo
ok "done. Open a new shell (for PATH), then verify with:  python3 autohunt.py --selftest"
echo "    (anything MISSING above: see the notes printed for it; re-running is safe.)"
