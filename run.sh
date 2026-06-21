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
#   ./run.sh --dashboard           # also start the read-only dashboard (http://127.0.0.1:8675)
#   ./run.sh -- --program acme --max-budget-usd 4 --model sonnet     # pass args through to autohunt.py
#
# Anything after `--` is passed verbatim to autohunt.py. Kill-switch: `touch data/hunts/STOP`.
#
set -uo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO"
PY="${PYTHON:-python3}"

PUBLIC_ONLY=0; NO_REFRESH=0; MONITOR=0; DASHBOARD=0; PASS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --public-only) PUBLIC_ONLY=1 ;;
    --no-refresh)  NO_REFRESH=1 ;;
    --monitor)     MONITOR=1 ;;
    --dashboard)   DASHBOARD=1 ;;
    --) shift; PASS=("$@"); break ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1 (use -- to pass args to autohunt.py; --help for usage)"; exit 2 ;;
  esac
  shift
done

c_y=$'\033[33m'; c_g=$'\033[32m'; c_off=$'\033[0m'
warn(){ echo "${c_y}[!]${c_off} $*"; }
ok(){ echo "${c_g}[+]${c_off} $*"; }

# --- pre-flight (warn, don't fail) ---
command -v claude >/dev/null 2>&1 || { echo "ERROR: claude CLI not found on PATH."; exit 1; }
miss=(); for t in subfinder httpx katana nuclei ffuf dnsx jq node; do command -v "$t" >/dev/null 2>&1 || miss+=("$t"); done
[ ${#miss[@]} -gt 0 ] && warn "recon tools missing (reduced capability): ${miss[*]} — run ./install_tools.sh"
[ -n "${DISCORD_WEBHOOK_URL:-}" ] || warn "DISCORD_WEBHOOK_URL not set — notifications will be skipped."
ok "kill-switch: touch ${REPO}/data/hunts/STOP to halt the loop gracefully."

# --- optional dashboard (background) ---
if [ "$DASHBOARD" = 1 ]; then
  DPY="$REPO/autohunt/web/.venv/bin/python"; [ -x "$DPY" ] || DPY="$PY"
  ok "starting dashboard → http://127.0.0.1:8675"
  nohup "$DPY" autohunt/web/server.py --data-dir data --port 8675 >/tmp/autohunt-web.log 2>&1 &
fi

# --- 1. refresh catalog ---
if [ "$NO_REFRESH" = 0 ] && [ "$MONITOR" = 0 ]; then
  args=(); [ "$PUBLIC_ONLY" = 1 ] && args+=(--public-only)
  ok "refreshing catalog: $PY yeswehack_programs.py ${args[*]}"
  "$PY" yeswehack_programs.py "${args[@]}" || { echo "catalog refresh failed"; exit 1; }
fi

# --- 2. run the loop (or monitor) ---
if [ "$MONITOR" = 1 ]; then
  ok "monitor pass: $PY autohunt.py --monitor ${PASS[*]}"
  exec "$PY" autohunt.py --monitor "${PASS[@]}"
else
  ok "auto-loop: $PY autohunt.py --mode planner ${PASS[*]}"
  exec "$PY" autohunt.py --mode planner "${PASS[@]}"
fi
