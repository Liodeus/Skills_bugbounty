#!/usr/bin/env bash
#
# run.sh — one command to kick off the autohunt auto-loop.
#
# Default flow:  refresh the YesWeHack catalog  →  run the planner auto-loop over it.
#
# Usage:
#   ./run.sh                       # scrape (authed login+TOTP) then planner loop over all programs
#   ./run.sh --public-only         # scrape only public programs, then loop
#   ./run.sh --no-refresh          # skip the scrape; just run the loop on the existing catalog
#   ./run.sh --monitor             # change-detection pass instead of a hunt (alerts only)
#   ./run.sh --dashboard           # also start the dashboard (http://127.0.0.1:8675)
#   ./run.sh --dashboard --public  # expose the dashboard on 0.0.0.0 (LAN/VPN); needs AUTOHUNT_WEB_PASSWORD in .env
#   ./run.sh --every 3600 -- --only-changed   # DAEMON: re-scrape + hunt every hour until STOP
#   ./run.sh -- --program acme --model sonnet     # pass args through to autohunt.py
#
# Anything after `--` is passed verbatim to autohunt.py. Kill-switch: `touch data/hunts/STOP`.
# Fully unattended: set YWH_TOTP_SECRET (or YWH_PAT) in .env so the scrape never prompts; the
# scraper also auto-detects a non-TTY and refuses to prompt. --every makes it run forever.
#
set -uo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO"
[ -f "$REPO/.env" ] && { set -a; . "$REPO/.env"; set +a; }   # auto-load .env if present
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"            # recon tools / mitmproxy install here
PY="${PYTHON:-python3}"

PUBLIC_ONLY=0; NO_REFRESH=0; MONITOR=0; DASHBOARD=0; PUBLIC=0; EVERY=0; PASS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --public-only) PUBLIC_ONLY=1 ;;
    --no-refresh)  NO_REFRESH=1 ;;
    --monitor)     MONITOR=1 ;;
    --dashboard)   DASHBOARD=1 ;;
    --public)      PUBLIC=1 ;;
    --every)       shift; EVERY="${1:-0}" ;;
    --) shift; PASS=("$@"); break ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1 (use -- to pass args to autohunt.py; --help for usage)"; exit 2 ;;
  esac
  shift
done
case "$EVERY" in ''|*[!0-9]*) echo "--every needs an integer (seconds)"; exit 2 ;; esac

c_y=$'\033[33m'; c_g=$'\033[32m'; c_off=$'\033[0m'
warn(){ echo "${c_y}[!]${c_off} $*"; }
ok(){ echo "${c_g}[+]${c_off} $*"; }

# --- pre-flight (warn, don't fail) ---
command -v claude >/dev/null 2>&1 || { echo "ERROR: claude CLI not found on PATH."; exit 1; }
miss=(); for t in subfinder httpx katana nuclei ffuf dnsx jq node; do command -v "$t" >/dev/null 2>&1 || miss+=("$t"); done
[ ${#miss[@]} -gt 0 ] && warn "recon tools missing (reduced capability): ${miss[*]} — run ./install_tools.sh"
[ -n "${DISCORD_WEBHOOK_URL:-}" ] || warn "DISCORD_WEBHOOK_URL not set — notifications will be skipped."
[ -n "${ANTHROPIC_API_KEY:-}" ] && warn "ANTHROPIC_API_KEY is set — autohunt uses your Claude SUBSCRIPTION and ignores it (pass: -- --use-api to bill the API)."
ok "auth: Claude subscription (run \`claude\` + /login if not already)."
ok "kill-switch: touch ${REPO}/data/hunts/STOP to halt the loop gracefully."

# --- optional dashboard (background) ---
if [ "$DASHBOARD" = 1 ]; then
  DPY="$REPO/autohunt/web/.venv/bin/python"; [ -x "$DPY" ] || DPY="$PY"
  DASH_HOST=127.0.0.1
  if [ "$PUBLIC" = 1 ]; then
    DASH_HOST=0.0.0.0
    [ -n "${AUTOHUNT_WEB_PASSWORD:-}" ] || { echo "ERROR: --public needs AUTOHUNT_WEB_PASSWORD set in .env."; exit 2; }
  fi
  ok "starting dashboard → http://${DASH_HOST}:8675"
  nohup "$DPY" autohunt/web/server.py --data-dir data --host "$DASH_HOST" --port 8675 >/tmp/autohunt-web.log 2>&1 &
fi

STOPFILE="$REPO/data/hunts/STOP"

refresh() {  # returns non-zero on failure (caller decides whether to continue)
  [ "$NO_REFRESH" = 1 ] && return 0
  [ "$MONITOR" = 1 ] && return 0   # monitor doesn't need a fresh scrape
  local a=(); [ "$PUBLIC_ONLY" = 1 ] && a+=(--public-only)
  [ "$EVERY" -gt 0 ] && a+=(--non-interactive)   # daemon must never block on a prompt
  ok "refreshing catalog: $PY yeswehack_programs.py ${a[*]}"
  "$PY" yeswehack_programs.py "${a[@]}"
}

run_pass() {
  if [ "$MONITOR" = 1 ]; then
    ok "monitor pass: $PY autohunt.py --monitor ${PASS[*]}"
    "$PY" autohunt.py --monitor "${PASS[@]}"
  else
    ok "auto-loop: $PY autohunt.py --mode planner ${PASS[*]}"
    "$PY" autohunt.py --mode planner "${PASS[@]}"
  fi
}

if [ "$EVERY" -gt 0 ]; then
  ok "daemon mode — every ${EVERY}s (touch $STOPFILE to stop)"
  while :; do
    [ -f "$STOPFILE" ] && { ok "STOP present — exiting daemon."; break; }
    refresh || warn "catalog refresh failed — continuing with the existing catalog"
    run_pass || warn "pass exited non-zero — continuing"
    [ -f "$STOPFILE" ] && { ok "STOP present — exiting daemon."; break; }
    ok "sleeping ${EVERY}s…"
    sleep "$EVERY"
  done
else
  refresh || { echo "catalog refresh failed"; exit 1; }
  run_pass   # single pass
fi
