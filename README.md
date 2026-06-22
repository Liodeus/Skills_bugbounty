# Skills_bugbounty — autonomous YesWeHack hunting toolkit

A bug-bounty toolkit for **YesWeHack** built around Claude Code. It can run two ways:

- **Autonomous auto-loop** (`autohunt`) — pulls your program catalog, then walks it with a
  **planner** agent that inspects each target and dispatches specialized subagents *intelligently*,
  proves findings before reporting, notifies Discord, and tracks resumable state. A read-only web
  dashboard visualizes everything.
- **Manual mode** (`hunt.sh`) — spins up Caido + a browser proxy and drops you into an interactive
  Claude session with the same hunting **skills** (`/idor`, `/xss`, `/ssrf`, …).

> ⚠️ **Authorized use only.** Run this only against programs you're authorized to test (your YWH
> scope). It never auto-submits reports — a human reviews and submits. See **Safety** below.

---

## Architecture

```
yeswehack_programs.py        →  data/yeswehack/<slug>/{program.md, scope.md, raw.json}
  (catalog scraper)             + INDEX.md, state.json, CHANGES.md

autohunt.py  (the auto-loop, per program)
  ┌─ planner  (one `claude -p`, reads memory + scope)
  │     ├─ dispatches  recon   subagent   (passive surface map)        ← only what's
  │     ├─ dispatches  hunter  subagent(s) (prove ONE lead each)         warranted
  │     └─ aggregates → findings[] + leads[]
  ├─ refuter   (independent `claude -p`, strong model — drops false positives)
  ├─ scope + RATE firewall hook  (governs the planner AND all subagents)
  ├─ persistent memory  data/hunts/<slug>/memory/knowledge.json  (compounds across runs)
  └─ Discord + ledger + cost report
        → data/hunts/{ledger.jsonl, status.json, findings_index.json, alerts.jsonl, cost_report.md}

autohunt/web/server.py       →  read-only dashboard at http://127.0.0.1:8675 (live SSE)
```

The auto-loop is **precision-first**: a finding is only reported if exploitation was *executed*
against a concrete oracle (SSRF→OOB hit, IDOR→second account crosses the boundary, XSS→JS actually
fires, …) and survives an independent refuter. Everything unproven is surfaced as a **lead** for you.

---

## Pipeline (start → end)

```
SETUP (once, human)   ./install_tools.sh · claude /login · .env (YWH_TOTP_SECRET|YWH_PAT, DISCORD_WEBHOOK_URL)
      │
      ▼
./run.sh [--every N]  load .env → preflight → [start dashboard?]
      │
      ▼
1. SCRAPE   yeswehack_programs.py  (non-interactive auth: PAT / generated TOTP / cached JWT)
            └─► data/yeswehack/<slug>/{program.md,scope.md,raw.json} + state.json   (incremental)
      │
      ▼
2. LOOP     autohunt.py:  load catalog → prioritize → build_queue (--bbp-only/--only-changed/--limit/…)
   ┌─────────────────────────────  per program  ─────────────────────────────┐
   │  compute_scope → setup_workspace                                          │
   │     data/hunts/<slug>/: CLAUDE.md · TARGET.md (scope+rate caps+creds+     │
   │     memory) · .claude/{skills,agents,settings(firewall hook)} · memory/   │
   │                              │                                            │
   │                              ▼                                            │
   │  PLAN + HUNT   one `claude -p` PLANNER (planner schema)                   │
   │     ├─ reads doctrine/TARGET/memory, inspects surface                     │
   │     ├─ dispatches  recon  subagent (once) → host/endpoint/JS/param map    │
   │     ├─ dispatches  hunter subagent ×N (1 lead each, model-routed          │
   │     │    sonnet/opus) → PROVE vs oracle:                                  │
   │     │      XSS→xss-confirm.js · SSRF/blind→$AUTOHUNT_OOB ·                 │
   │     │      IDOR/RBAC→2nd account · SQLi→curl bool/time diff               │
   │     │    → writes /report-yeswehack .md when proven                       │
   │     └─ returns findings[] · leads_unverified[] · tested_ruled_out[]       │
   │                              │                                            │
   │                              ▼                                            │
   │  VERIFY   independent REFUTER (`claude -p`) re-runs each proof → drops FPs │
   │           report_path enforced · dedupe vs index + memory                 │
   │                              │                                            │
   │                              ▼                                            │
   │  NOTIFY + PERSIST   Discord (finding + report, lead digest) ·             │
   │                     memory/ · status.json · ledger.jsonl                  │
   └──────────────────────────────────────────────────────────────────────────┘
        rails (always on): scope+rate firewall · per-target & global $ caps ·
        circuit-breaker (3 fails) · usage-limit pause/resume · data/hunts/STOP
      │                                                          │
      ▼                                                          ▼
3. YOU  review data/hunts/<slug>/report_*.md                dashboard: live SSE +
        → submit on YesWeHack  (NEVER auto-submitted)        triage (STOP/dismiss/re-hunt)
```

Everything from `./run.sh` down is **headless and unattended**; `--every N` repeats the loop
(re-scrape + hunt new/changed) until you `touch data/hunts/STOP`.

---

## Quickstart

```bash
# 1. Install the toolchain (recon tools, mitmproxy, Playwright+Chromium, jq) — one time, NO sudo.
./install_tools.sh                 # prebuilt binaries → ~/.local/bin; --check to just report status
                                   # (also adds ~/.local/bin to your shell PATH)
pip install -r requirements.txt    # requests (scraper/orchestrator)

# 2. Credentials + notifications (env)
export YWH_EMAIL=you@example.com
export YWH_PASSWORD=...             # TOTP is prompted interactively if 2FA is on
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...   # optional but recommended

# 3. Kick off everything: refresh catalog → run the auto-loop
./run.sh --bbp-only -- --max-budget-usd 5 --max-total-usd 50 --oob your.canary.host

# …or step by step:
python yeswehack_programs.py            # build data/yeswehack/  (--public-only to skip login)
python autohunt.py --dry-run            # preview the prioritized queue (no spend)
python autohunt.py --mode planner --bbp-only --max-budget-usd 5 --oob your.canary.host

# 4. Watch it live (dashboard) — live SSE; triage actions enabled (--read-only to disable)
pip install -r autohunt/web/requirements.txt        # first time (or use autohunt/web/.venv)
python autohunt/web/server.py --data-dir data       # http://127.0.0.1:8675
```

From the dashboard you can also **triage**: toggle the STOP kill-switch, dismiss/reopen leads, and
queue a program for re-hunt. Start it with `--read-only` to make it view-only.

**Kill-switch:** `touch data/hunts/STOP` halts the loop before the next program.

---

## Authentication — uses your Claude subscription (not the API)

autohunt runs every `claude -p` session on **your Claude subscription** (the `claude` login / OAuth),
**not** API-key billing. So `hunter_env` **drops `ANTHROPIC_API_KEY`/`ANTHROPIC_AUTH_TOKEN` from child
sessions** by default — if you happen to have an API key exported, it's ignored so you don't burn API
credits. It never uses `--bare` (which would require an API key).

- **Prerequisite:** be logged in — run `claude` once and `/login` (Pro/Max). autohunt warns at start
  if no subscription login is detected.
- **To bill the API instead:** pass `--use-api` (keeps `ANTHROPIC_API_KEY`).
- Note: the `$` figures in the ledger / `cost_report.md` are **usage estimates**; on a subscription
  the real limit is your plan's rate limits, and `--max-budget-usd`/`--max-total-usd` act as
  estimate-based stop guards.

## Fully unattended operation

Once set up, autohunt runs with **zero human interaction** — the planner loop discovers and proves
vulnerabilities on its own. The run path has no prompts: the loop never asks for permission
(`--dangerously-skip-permissions` + a `PreToolUse` firewall that denies out-of-scope/over-rate calls
programmatically), `claude -p` reads no stdin, and there's no MCP auth.

**One-time setup (needs you, once):** `./install_tools.sh` (sudo), `claude` → `/login` (subscription).

**Make the catalog scrape non-interactive** (the only prompt that remains) by putting one of these in
`.env`:
- `YWH_TOTP_SECRET` — your 2FA base32 seed; autohunt generates the 6-digit code itself (RFC 6238).
- `YWH_PAT` — a YesWeHack personal access token (used directly, skips login + TOTP).

The scraper also auto-detects a non-TTY and **refuses to prompt** (fails fast) rather than hang.

**Launch and walk away:**
```bash
# one full headless sweep (scrape → hunt every catalogued program):
./run.sh -- --bbp-only --max-budget-usd 4 --oob your.canary.host

# continuous daemon — re-scrape + hunt new/changed programs forever, until you STOP it:
./run.sh --every 3600 -- --only-changed --bbp-only --oob your.canary.host
```
Stop any time with `touch data/hunts/STOP` (also a button in the dashboard). Safety for long runs is
built in: per-target + global `$` caps (notional "usage units" on a subscription), the scope/rate
firewall, and a **circuit-breaker** that halts on repeated auth/network failures. Findings are still
**human-gated** — autohunt writes reports + alerts Discord; you review and submit.

**What you must supply for full *proof* coverage** (otherwise these classes are surfaced as leads, not
proven — which is the safe, correct default):
- **A pollable OOB host** for `--oob` — an interactsh/OAST-style host whose request log the agent can
  query over HTTP. Blind SSRF / OOB SQLi / OOB XXE / blind RCE / blind-stored XSS are confirmed by the
  agent *reading the canary's hits*, so a write-only or DNS-only collector isn't enough. There is no
  built-in collector — bring your own. (Metadata SSRF via `169.254.169.254` still works without `--oob`.)
- **Chromium/Playwright** (from `./install_tools.sh`) — the XSS execution oracle (`xss-confirm.js`)
  needs it; without it reflected/DOM XSS stays lead-only.
- **Per-program creds** at `data/creds/<slug>.json` (≥2 accounts) — what turns IDOR / RBAC / ATO from
  leads into proven findings. No auto-signup; stage them per program you care about.

Note: `--capture caido` is a no-op stub — use `--capture mitmdump` for traffic capture.

**Hitting your Claude usage limit is handled automatically:** when a session reports a usage/rate
limit, autohunt **pauses until the window resets and retries the same target** (it reads the reset
time if present, else waits `--usage-backoff` seconds, up to `--max-usage-waits` cycles) — and pings
Discord that it's paused. So an overnight run rides through your 5-hour windows instead of failing.
The default is **`opus` (4.8) at `--effort high`** for maximum hunting quality; on a Max plan use
`--only-changed`/`--limit` to make each usage window go further, or drop to `--model sonnet` for
broader/cheaper sweeps.

## How the auto-loop works (intelligent dispatch)

Per program, one **planner** `claude -p` session:

1. **Reads memory** (`knowledge.json`) — prior recon, open leads, already-ruled-out items, past
   findings — so each run builds on the last instead of starting blind.
2. **Inspects** the surface (light probing / the `recon` subagent for wildcard expansion + JS/endpoint
   mining). On a thin surface it correctly **stops** (`no_findings`) rather than manufacturing work.
3. **Decides and dispatches** `hunter` subagents *only* for the few highest-impact, provable leads —
   in small batches to stay quiet. Each hunter proves exactly one lead against its oracle. The
   planner also **routes the model per dispatch** — cheap `sonnet` for routine/low-confidence work,
   `opus` for the few promising/complex leads — so spend follows value (recon defaults to sonnet).
4. **Verifies** each candidate with an **independent refuter** (a separate strong-model session) and
   **dedupes** across runs before anything is reported.
5. **Records** everything: report `.md` per verified finding, Discord push (findings + a tagged
   digest of unverified leads), ledger row with per-model cost, and updated memory.

**Modes & key flags**

| Flag | Meaning |
|---|---|
| `--mode planner` (default) | Planner dispatches `recon`/`hunter` subagents. `--mode single` = one monolithic agent. |
| `--monitor` | Re-probe known surface for changes → triage agent → Discord alert (no hunting). |
| `--program <slug>` / `--limit N` / `--only-changed` / `--bbp-only` | Pick & scope the queue. |
| `--max-budget-usd` / `--max-total-usd` / `--max-turns` / `--timeout` | Budget & time caps. |
| `--max-rps` (8) / `--max-conc` (10) | **Enforced** scan-tool rate/concurrency caps (anti-IPS). |
| `--model` / `--verify-model` | Planner & refuter model — **default `opus`** (4.8). The planner picks each subagent's model itself (sonnet/opus). `sonnet` for cheaper/broader sweeps. |
| `--effort` | Reasoning effort for every session — **default `high`** (`low`/`medium`/`high`/`xhigh`/`max`). |
| `--capture mitmdump` | Record traffic through a proxy for later human replay. |
| `--rate-proxy` | Route tool traffic through a mitmdump that hard-caps per-host req/s (true global ceiling). |
| `--oob <host>` | OOB canary host for SSRF/blind oracles (also added to the safe-host allowlist). |
| `--target <url> [--scope a,b]` | **Ad-hoc** mode — hunt an authorized URL not in the catalog (great for testing / one-offs). |
| `--retry-failed` | Re-run only programs whose last status is `failed`. |
| `--watch <secs>` | Repeat the run (hunt or `--monitor`) every N seconds until `data/hunts/STOP`. |
| `--selftest [--dry-run]` | Preflight: readiness + firewall sanity (+ a benign live hunt unless `--dry-run`). |

**Before your first real run:** `python autohunt.py --selftest` (or `--selftest --dry-run` for a
no-spend static check) confirms tools, auth, schemas, and the firewall are all healthy.

---

## Safety

- **Authorized engagements only**; **no auto-submission** to YesWeHack (you review + submit).
- **Scope firewall** (a `PreToolUse` hook) blocks **shell/Bash network tool calls** (curl, httpx,
  ffuf, nuclei, …) to any out-of-scope host — enforced even under `--dangerously-skip-permissions`
  and for subagent calls. The built-in `WebFetch`/`WebSearch` tools are **disabled** so Bash is the
  only network path. (Loopback/private IPs and `169.254.169.254` are intentionally allowed — the
  request originates from the in-scope target, which is how the SSRF/metadata oracle is proven.)
- **Rate firewall** (same hook) denies the common scan tools (`ffuf`/`httpx`/`nuclei`/`katana`/
  `dnsx`/`gobuster`/`feroxbuster`/`wfuzz`/`masscan`/`nmap`) that don't carry a rate/concurrency cap,
  and blocks flood patterns (`while true`/`while :`/`until false`, huge `seq`/brace ranges,
  `xargs -P`) — so the loop won't trip a WAF/IPS. For any other tool, the doctrine's ≤8 req/s rule
  (and the optional `--rate-proxy`) applies.
- **Budget caps** per target and globally; a `data/hunts/STOP` **kill-switch**.
- Inherited guardrails (doctrine): ≤8 req/s, no DoS, no mass enumeration, no destructive actions
  without a safe revert, WAF-detected → stop.

---

## Configuration (env)

| Var | Purpose |
|---|---|
| `YWH_EMAIL`, `YWH_PASSWORD` | Catalog auth (else prompted); TOTP prompted at runtime. |
| `DISCORD_WEBHOOK_URL` | Finding / lead / monitor notifications (skipped if unset). |
| `PYTHON` | Override the python interpreter `run.sh` uses (default `python3`). |

Copy **`.env.example` → `.env`** and fill it in; `run.sh` auto-loads `.env` (or `set -a && source .env`).
`.env` is gitignored.

Optional per-program credentials for authed IDOR/RBAC testing: `data/creds/<slug>.json` — copy the
template **`autohunt/creds.example.json`** (`login_url`, `notes`, `accounts[]` with ≥2 accounts). The
hunter uses it if present; default is unauthenticated surface. `data/` is gitignored.

## Outputs (`data/`, gitignored)

```
data/yeswehack/<slug>/{program.md,scope.md,raw.json}   # catalog (+ INDEX.md, state.json, CHANGES.md)
data/hunts/<slug>/
    CLAUDE.md, TARGET.md, .claude/{skills,agents,settings.json}
    memory/knowledge.json        # recon, leads, tested-ruled-out, findings, monitor baseline
    report_<class>_<slug>_<date>.md
data/hunts/{ledger.jsonl, status.json, findings_index.json, alerts.jsonl, cost_report.md, run.log, STOP}
```

## Components

| Path | Purpose |
|---|---|
| `yeswehack_programs.py` | Catalog scraper (login+TOTP, incremental, change log). |
| `autohunt.py` | The auto-loop orchestrator (planner/single/monitor). |
| `autohunt/scope_firewall.py` | `PreToolUse` scope + rate firewall hook. |
| `autohunt/doctrine.md` | Autonomous hunting doctrine (copied to each workspace `CLAUDE.md`). |
| `autohunt/agents/planner.md`, `agents/subagents/{recon,hunter}.md` | Planner prompt + native subagents. |
| `autohunt/verifier.md`, `agents/monitor-triage.md` | Refuter + change-triage prompts. |
| `autohunt/schemas/*.json`, `autohunt/findings.schema.json` | Structured-output contracts. |
| `autohunt/xss-confirm.js` | Headless-browser XSS execution oracle. |
| `autohunt/web/` | Read-only real-time dashboard (FastAPI + vanilla JS). |
| `install_tools.sh` | Installs the recon/browser/proxy toolchain. |
| `run.sh` | One-command launcher (catalog refresh → auto-loop). |
| `hunt.sh`, `playwright-chrome/`, `SKILLS/` | Manual Caido/browser mode + the technique skill library. |

## Troubleshooting

- **"recon tools missing"** — run `./install_tools.sh` (then open a new shell for the Go PATH). The
  loop still runs without them but with degraded discovery.
- **No Discord messages** — set `DISCORD_WEBHOOK_URL` and `pip install requests`.
- **Dashboard empty** — point `--data-dir` at the dir holding `yeswehack/` + `hunts/`.

## Manual mode

`hunt.sh <target>` boots Caido (`:8080`) + a Playwright/mitmproxy harness, builds a per-target
workspace from `SKILLS/CLAUDE.md` + the skills, and drops you into interactive `claude`. See
`SKILLS/` for the technique playbooks and `SKILLS/report-yeswehack` for report formatting.
