#!/usr/bin/env python3
"""autohunt — autonomous YesWeHack hunting loop.

Walks the local program catalog (produced by yeswehack_programs.py) and, per program, runs ONE
headless `claude -p` PLANNER that inspects the surface, then dispatches native Claude Code
subagents (recon, hunter) only where warranted — rather than brute-forcing a fixed pipeline.
Every finding is gated behind executed proof-of-exploitation plus an independent refuter; reports
are written locally, findings + unverified leads pushed to Discord, and resumable status recorded.
Each program keeps a persistent memory (a "mapper"/brain-dump) so runs compound instead of starting
blind. `--mode single` runs one monolithic agent instead of the planner.

A `--monitor` mode re-probes known surface for changes and asks a triage agent whether a change
warrants a human look (alert only — no auto-hunt).

Design follows Fahad Faisal's "AI Agents in Bug Bounty": a planner with specialized subagents (not
one big prompt), persistent memory, change-detection, and hard anti-slop discipline (prove it or
drop it).

Safety: per-target + global budget caps, a data/hunts/STOP kill-switch, and a PreToolUse firewall
hook that blocks out-of-scope hosts AND enforces scan-tool rate/concurrency caps (even under
--dangerously-skip-permissions, and for subagent tool calls too). No reports are auto-submitted.

Examples:
  python autohunt.py --dry-run
  python autohunt.py --program acme --mode planner --max-budget-usd 4 --model sonnet
  python autohunt.py --only-changed --model opus --verify-model opus --oob your.canary.host
  python autohunt.py --monitor                      # change-detection pass (schedule via cron/loop)
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent
AUTOHUNT = REPO / "autohunt"
CATALOG = REPO / "data" / "yeswehack"
HUNTS = REPO / "data" / "hunts"
SKILLS = REPO / "SKILLS"

DOCTRINE = AUTOHUNT / "doctrine.md"
HOOK = AUTOHUNT / "scope_firewall.py"
VERIFIER_PROMPT = AUTOHUNT / "verifier.md"
AGENTS = AUTOHUNT / "agents"
SCHEMAS = AUTOHUNT / "schemas"
FINDINGS_SCHEMA = AUTOHUNT / "findings.schema.json"

WEB_TYPES = {"web-application", "api", ""}  # "" = bare-string scope with no type → treat as web
HOST_RE = re.compile(r"^\*?\.?(?:[a-z0-9_-]+\.)+[a-z]{2,}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
RECON_KEYS = ("live_hosts", "endpoints", "js_files", "params", "tech", "suggested_focus")

VERIFIER_SCHEMA = json.dumps({
    "type": "object", "additionalProperties": False,
    "required": ["refuted", "confidence", "reason", "reproduced"],
    "properties": {
        "refuted": {"type": "boolean"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "reason": {"type": "string"},
        "reproduced": {"type": "boolean"},
    },
})

RECON_TOOLS = ["subfinder", "httpx", "katana", "nuclei", "ffuf", "dnsx", "jq", "node"]
NO_PROXY = "localhost,127.0.0.1,::1,.anthropic.com,api.anthropic.com,.claude.com,statsig.anthropic.com,sentry.io"

# Make user-local tool dirs visible to this process AND child claude -p sessions, even when the
# launching shell didn't add them (cron/nohup/non-login shells). install_tools.sh drops binaries here.
for _bindir in (str(Path.home() / ".local" / "bin"), str(Path.home() / "go" / "bin")):
    if os.path.isdir(_bindir) and _bindir not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = _bindir + os.pathsep + os.environ.get("PATH", "")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    line = f"[{now_iso()}] {msg}"
    print(line, file=sys.stderr)
    try:
        HUNTS.mkdir(parents=True, exist_ok=True)
        with (HUNTS / "run.log").open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def norm_asset(s):
    if isinstance(s, dict):
        return {"scope": s.get("scope") or "", "scope_type": s.get("scope_type") or "",
                "asset_value": s.get("asset_value") or ""}
    return {"scope": str(s), "scope_type": "", "asset_value": ""}


def extract_host(scope_value):
    v = (scope_value or "").strip()
    v = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", v)
    v = v.split("/")[0].split("@")[-1].strip()
    if v.count(":") == 1 and not v.startswith("["):
        v = v.rsplit(":", 1)[0]
    v = v.lower().rstrip(".")
    if HOST_RE.match(v) or IP_RE.match(v):
        return v
    return None


def seed_url(scope_value, host):
    base = host[2:] if host.startswith("*.") else host  # de-wildcard
    v = (scope_value or "").strip().split()[0] if scope_value else ""
    if v.lower().startswith(("http://", "https://")) and "*" not in v:
        return v
    return "https://" + base


def compute_scope(program):
    allow, seeds, out = [], [], []
    for a in program["in_assets"]:
        if a["scope_type"] not in WEB_TYPES:
            continue
        host = extract_host(a["scope"])
        if not host:
            continue
        allow.append(host)
        seeds.append(seed_url(a["scope"], host))
    for a in program["out_assets"]:
        host = extract_host(a["scope"])
        if host:
            out.append(host)
    return sorted(set(allow)), sorted(set(seeds)), sorted(set(out))


def scope_hash(program):
    sig = sorted(f"{a['scope']}|{a['scope_type']}" for a in program["in_assets"])
    return hashlib.sha256("\n".join(sig).encode()).hexdigest()[:16]


def load_catalog():
    state_path = CATALOG / "state.json"
    if not state_path.exists():
        sys.exit(f"No catalog at {state_path}. Run: python yeswehack_programs.py first.")
    try:
        state = json.loads(state_path.read_text())
    except Exception as e:
        sys.exit(f"Catalog state.json is corrupt ({e}). Re-run: python yeswehack_programs.py")
    programs = []
    for slug, entry in state.get("programs", {}).items():
        raw = {}
        rp = CATALOG / slug / "raw.json"
        if rp.exists():
            try:
                raw = json.loads(rp.read_text())
            except Exception:
                pass
        programs.append({
            "slug": slug,
            "title": entry.get("title") or raw.get("title") or slug,
            "type": entry.get("type") or raw.get("type") or "",
            "kind": entry.get("kind") or "",
            "bounty": bool(raw.get("bounty")),
            "bounty_max": raw.get("bounty_reward_max") or 0,
            "disabled": bool(raw.get("disabled")),
            "archived": bool(raw.get("archived")),
            "last_update_at": entry.get("last_update_at"),
            "in_assets": [norm_asset(s) for s in (raw.get("scopes") or [])],
            "out_assets": [norm_asset(s) for s in (raw.get("out_of_scope") or [])],
        })
    return programs


def prioritize(programs, args):
    elig = []
    for p in programs:
        if p["disabled"] or p["archived"]:
            continue
        allow, _, _ = compute_scope(p)
        if not allow:
            continue
        if getattr(args, "bbp_only", False) and not p["bounty"]:
            continue
        p["_scope_hash"] = scope_hash(p)
        elig.append(p)
    elig.sort(key=lambda p: (0 if p["bounty"] else 1, -(p["bounty_max"] or 0), p["title"].lower()))
    return elig


def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def save_json(path, obj):
    # atomic: write to a temp file then rename, so a crash mid-write can't truncate
    # status/findings/memory state (which load_json would then silently reset to {}).
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False))
    os.replace(tmp, path)


def append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def append_ledger(record):
    append_jsonl(HUNTS / "ledger.jsonl", record)


# --------------------------------------------------------------------------- #
# per-target memory ("mapper" / brain-dump)
# --------------------------------------------------------------------------- #
def mem_path(ws):
    return ws / "memory" / "knowledge.json"


def load_memory(ws):
    mem = load_json(mem_path(ws), None)
    if not isinstance(mem, dict):
        mem = {"slug": ws.name, "updated_at": None, "recon": {}, "tested_ruled_out": [],
               "leads": [], "findings": [], "monitor_baseline": {}}
    mem.setdefault("recon", {})
    for k in RECON_KEYS:
        mem["recon"].setdefault(k, [])
    for k in ("tested_ruled_out", "leads", "findings"):
        mem.setdefault(k, [])
    mem.setdefault("monitor_baseline", {})
    return mem


def save_memory(ws, mem):
    mem["updated_at"] = now_iso()
    save_json(mem_path(ws), mem)


def merge_recon(mem, recon):
    for k in RECON_KEYS:
        vals = recon.get(k) or []
        if isinstance(vals, list):
            mem["recon"][k] = sorted(set(mem["recon"][k]) | {str(v) for v in vals})[:500]


def lead_key(l):
    k = "|".join(str(l.get(x, "")).lower().strip() for x in ("vuln_class", "asset", "endpoint"))
    return k if k.strip("|") else str(l.get("title", "")).lower().strip()


def merge_leads(mem, leads):
    """Add unseen leads (status open). Return the newly-added ones (for alerting)."""
    existing = {lead_key(l): l for l in mem["leads"]}
    new = []
    for l in leads or []:
        k = lead_key(l)
        if not k:
            continue
        if k in existing:
            existing[k]["last_seen"] = now_iso()
            continue
        item = {"id": uuid.uuid4().hex[:8], "title": l.get("title", ""),
                "vuln_class": l.get("vuln_class", ""), "asset": l.get("asset", ""),
                "endpoint": l.get("endpoint", ""), "why": l.get("why_unproven") or l.get("why", ""),
                "priority": l.get("priority", "medium"), "status": "open",
                "first_seen": now_iso(), "last_seen": now_iso(), "alerted": False}
        mem["leads"].append(item)
        existing[k] = item
        new.append(item)
    return new


def set_lead_status(mem, lead, status):
    k = lead_key(lead)
    for e in mem["leads"]:
        if lead_key(e) == k:
            e["status"] = status
            e["last_seen"] = now_iso()


def record_tested(mem, items):
    seen = {t.get("what") for t in mem["tested_ruled_out"]}
    for it in items or []:
        what = it.get("what")
        if what and what not in seen:
            mem["tested_ruled_out"].append({"what": what, "why": it.get("why", ""), "run": now_iso()})
            seen.add(what)


def record_finding_mem(mem, f):
    keys = {x.get("dedupe_key") for x in mem["findings"]}
    if f.get("dedupe_key") not in keys:
        mem["findings"].append({"dedupe_key": f.get("dedupe_key"), "title": f.get("title"),
                                "severity": f.get("severity"), "report_path": f.get("report_path"),
                                "first_seen": now_iso()})


def _norm_ep(ep):
    """Normalize an endpoint for stable dedupe: drop scheme/host/query, lowercase, collapse IDs."""
    ep = str(ep or "").strip().lower()
    ep = re.sub(r"^[a-z]+://[^/]+", "", ep)          # strip scheme+host if a full URL
    ep = ep.split("?")[0].split("#")[0].rstrip("/")  # drop query/fragment/trailing slash
    ep = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}", ep)
    ep = re.sub(r"/\d+", "/{id}", ep)                # numeric path segments → {id}
    return ep or "/"


def make_dedupe_key(f):
    """Stable 'vuln_class:asset:normalized-endpoint' key (matches the schema description)."""
    return f"{str(f.get('vuln_class','')).lower()}:{str(f.get('asset','')).lower()}:{_norm_ep(f.get('endpoint',''))}"


def is_proven(f):
    """A finding counts as proven only with verified:true and non-trivial oracle + evidence."""
    return (bool(f.get("verified"))
            and len(str(f.get("oracle", "")).strip()) >= 8
            and len(str(f.get("evidence", "")).strip()) >= 8)


def memory_digest(mem):
    r = mem["recon"]
    open_leads = [l for l in mem["leads"] if l.get("status") == "open"]
    lines = ["## Memory — prior runs (read before testing; do NOT re-test ruled-out)", ""]
    lines.append(f"- Recon known: {len(r['live_hosts'])} live hosts, {len(r['endpoints'])} endpoints, "
                 f"{len(r['js_files'])} JS files, {len(r['params'])} params.")
    if open_leads:
        lines.append(f"- Open leads ({len(open_leads)}):")
        for l in open_leads[:15]:
            lines.append(f"  - {l.get('title','')} ({l.get('vuln_class','?')}) on {l.get('asset','')} {l.get('endpoint','')}")
    if mem["tested_ruled_out"]:
        lines.append(f"- Already ruled out ({len(mem['tested_ruled_out'])}) — DO NOT re-test:")
        for t in mem["tested_ruled_out"][-15:]:
            lines.append(f"  - {t.get('what','')} — {t.get('why','')}")
    if mem["findings"]:
        lines.append(f"- Prior findings ({len(mem['findings'])}):")
        for x in mem["findings"][:15]:
            lines.append(f"  - {x.get('title','')} [{x.get('severity','?')}]")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# workspace
# --------------------------------------------------------------------------- #
def setup_workspace(p, allow, seeds, out_hosts, args):
    ws = HUNTS / p["slug"]
    (ws / "memory").mkdir(parents=True, exist_ok=True)  # preserved across runs
    shutil.copy(DOCTRINE, ws / "CLAUDE.md")
    notes = ws / "memory" / "notes.md"
    if not notes.exists():  # doctrine tells the agent to read/append this; seed it
        notes.write_text("# Notes — free-form prose memory carried across runs\n")

    # Copy the skill dirs INTO the workspace (not symlink) so they're readable under cwd without
    # --add-dir, and so the conflicting manual SKILLS/CLAUDE.md never enters the agent's context.
    skills_dir = ws / ".claude" / "skills"
    if skills_dir.exists():
        shutil.rmtree(skills_dir)
    skills_dir.mkdir(parents=True, exist_ok=True)
    for child in SKILLS.iterdir():
        if child.is_dir():
            shutil.copytree(child, skills_dir / child.name, dirs_exist_ok=True)

    # Install native Claude Code subagents (recon, hunter) for planner mode.
    agents_dir = ws / ".claude" / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    for f in (AGENTS / "subagents").glob("*.md"):
        shutil.copy(f, agents_dir / f.name)

    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash",
                "hooks": [{"type": "command", "command": f"python3 {HOOK}"}]}]}}
    save_json(ws / ".claude" / "settings.json", settings)

    program_md = CATALOG / p["slug"] / "program.md"
    scope_md = CATALOG / p["slug"] / "scope.md"
    creds_path = REPO / "data" / "creds" / f"{p['slug']}.json"
    parts = []
    if program_md.exists():
        pm = program_md.read_text()
        if len(pm) > 4000:  # cap the verbose rules blob re-ingested by every session/subagent
            pm = pm[:4000] + "\n\n…(description truncated — full text in data/yeswehack/" + p["slug"] + "/program.md)…\n"
        parts.append(pm)
    if scope_md.exists():
        parts.append(scope_md.read_text())
    parts.append("## Autohunt scope (ENFORCED by firewall — stay inside)\n")
    parts.append("**In-scope hosts (allowlist):**\n" + "\n".join(f"- `{h}`" for h in allow) + "\n")
    parts.append("**Seed URLs:**\n" + "\n".join(f"- {u}" for u in seeds) + "\n")
    if out_hosts:
        parts.append("**Out-of-scope hosts (never test):**\n" + "\n".join(f"- `{h}`" for h in out_hosts) + "\n")
    rps, conc = int(args.max_rps), int(args.max_conc)
    parts.append(
        f"## Rate caps (ENFORCED by firewall — use these EXACT flags)\n"
        f"Max **{rps} req/s** per host. Scan tools are denied without their rate flag — pass:\n"
        f"`httpx -rl {rps} -t {conc}`, `nuclei -rl {rps} -c {conc}`, `katana -rl {rps} -c {conc}`, "
        f"`ffuf -rate {rps} -t {conc}`, `dnsx -rl {rps} -t {conc}`. (`subfinder` is passive — no flag.) "
        f"No `while true`, no `seq`/`{{1..N}}` ranges > 1000, no `xargs -P` above {conc}.\n")
    if args.oob:
        parts.append(f"**OOB canary host (use for SSRF/blind/RCE oracles):** `{args.oob}`\n")
    else:
        parts.append("**No OOB canary** (`--oob` not set) — blind/OOB-only classes (blind SSRF, "
                     "OOB SQLi/XXE, blind RCE/XSS) cannot be PROVEN; record them as leads.\n")
    if creds_path.exists():
        parts.append(f"**Credentials available** at `{creds_path}` — JSON with `login_url`, `notes`, "
                     f"and `accounts[]` (each: label/email/username/password/role). Read it, authenticate "
                     f"as ≥2 accounts, and prove cross-user / cross-role access (IDOR/RBAC).\n")
    else:
        parts.append("**No credentials** — unauthenticated surface only. Skip IDOR/RBAC unless a "
                     "self-signup is in scope.\n")
    parts.append(memory_digest(load_memory(ws)))
    (ws / "TARGET.md").write_text("\n".join(parts))

    prompt = (
        f"Autonomously hunt the YesWeHack program \"{p['title']}\" (slug: {p['slug']}).\n\n"
        "Follow CLAUDE.md and read TARGET.md (scope, seeds, creds, and the Memory section). Do "
        "passive discovery, prioritise high-impact leads specific to this app, and PROVE each "
        "candidate against its oracle before treating it as a finding. There is NO target count — "
        "zero proven findings is a correct outcome. Write a /report-yeswehack markdown for every "
        "verified finding, then output the required JSON (program_slug, status, summary, findings[], "
        "leads_unverified[]). Stay strictly in scope. Be fast; log dead ends as leads and move on."
    )
    (ws / "run_prompt.md").write_text(prompt)
    return ws


def hunter_env(allow, out_hosts, args, capture_env):
    env = os.environ.copy()
    if not getattr(args, "use_api", False):
        # Drive child `claude -p` sessions with the Claude SUBSCRIPTION (the `claude` login),
        # NOT API billing. If an ANTHROPIC_API_KEY is present in the shell, Claude Code would
        # prefer it (API credits); remove it so the subscription OAuth creds are used instead.
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("ANTHROPIC_AUTH_TOKEN", None)
    env["AUTOHUNT_SCOPE"] = " ".join(allow)
    env["AUTOHUNT_OUT_OF_SCOPE"] = " ".join(out_hosts)
    env["AUTOHUNT_MAX_RPS"] = str(args.max_rps)
    env["AUTOHUNT_MAX_CONC"] = str(args.max_conc)
    env["AUTOHUNT_XSS_CONFIRM"] = str((AUTOHUNT / "xss-confirm.js").resolve())
    if args.oob:
        env["AUTOHUNT_OOB"] = args.oob
        env["AUTOHUNT_SAFE_HOSTS"] = args.oob
        if getattr(args, "_oob_log", None):
            env["AUTOHUNT_OOB_LOG"] = args._oob_log   # agent greps this for its callback tokens
    env.update(capture_env)
    return env


# --------------------------------------------------------------------------- #
# capture layer (pluggable)
# --------------------------------------------------------------------------- #
def start_proxy(args, ws):
    """Start ONE mitmdump if --capture mitmdump and/or --rate-proxy is set. Returns
    (proc_or_None, env_dict); the agent's tools point HTTP(S)_PROXY at it. --rate-proxy adds
    a per-host req/s throttle addon; --capture writes a replayable flow file."""
    if args.capture == "caido":
        log("capture=caido not yet wired (needs caido-cli + claim + PAT + CA); skipping capture.")
    want_capture = args.capture == "mitmdump"
    want_rate = getattr(args, "rate_proxy", False)
    if not (want_capture or want_rate):
        return None, {}
    if not shutil.which("mitmdump"):
        log("mitmdump not on PATH — capture/rate-proxy disabled (run ./install_tools.sh).")
        return None, {}
    port = 8899
    cmd = ["mitmdump", "--mode", "regular", "--listen-port", str(port), "-q"]
    if want_capture:
        cmd += ["-w", str(ws / "traffic.flow")]
    proc_env = os.environ.copy()
    if want_rate:
        cmd += ["-s", str((AUTOHUNT / "rate_proxy.py").resolve())]
        proc_env["AUTOHUNT_MAX_RPS"] = str(args.max_rps)  # the addon reads this
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=proc_env)
    ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    for _ in range(25):
        if ca.exists():
            break
        time.sleep(0.2)
    env = {
        "HTTP_PROXY": f"http://127.0.0.1:{port}", "HTTPS_PROXY": f"http://127.0.0.1:{port}",
        "http_proxy": f"http://127.0.0.1:{port}", "https_proxy": f"http://127.0.0.1:{port}",
        "NO_PROXY": NO_PROXY, "no_proxy": NO_PROXY,
    }
    if ca.exists():
        env["CURL_CA_BUNDLE"] = str(ca)
        env["REQUESTS_CA_BUNDLE"] = str(ca)
        env["NODE_EXTRA_CA_CERTS"] = str(ca)
    log(f"proxy on :{port}" + (" [capture]" if want_capture else "") + (" [rate-throttle]" if want_rate else ""))
    return proc, env


def stop_capture(proc):
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# OOB canary (autonomous, via interactsh-client) — no manual URL pasting
# --------------------------------------------------------------------------- #
_OAST_RE = re.compile(r"\b([a-z0-9]+\.oast\.[a-z]+)\b", re.I)


def start_oob(args):
    """If `--oob auto`, launch interactsh-client, capture its generated canary host, and stream
    callbacks to a JSONL the agent can grep. Sets args.oob (the host) + args._oob_log (the file).
    Returns the client process (or None). No-op for an explicit host or when interactsh is absent."""
    if str(getattr(args, "oob", "") or "").lower() != "auto":
        return None
    if not shutil.which("interactsh-client"):
        log("--oob auto but interactsh-client not on PATH (run ./install_tools.sh) — "
            "blind/OOB classes will be recorded as leads.")
        args.oob = None
        return None
    HUNTS.mkdir(parents=True, exist_ok=True)
    logp = HUNTS / "oob_interactions.jsonl"
    errp = HUNTS / "oob_client.log"
    logp.write_text(""); errf = open(errp, "w")
    server = getattr(args, "oob_server", None)
    cmd = ["interactsh-client", "-json", "-o", str(logp), "-pi", "5"]
    if server:
        cmd += ["-s", server]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errf)
    except Exception as e:
        log(f"interactsh-client failed to start ({e}) — OOB disabled."); args.oob = None; return None
    host = None
    end = time.time() + 20
    while time.time() < end and host is None:
        m = _OAST_RE.search(errp.read_text(errors="ignore") if errp.exists() else "")
        if m:
            host = m.group(1)
        elif proc.poll() is not None:
            break
        else:
            time.sleep(0.5)
    if not host:
        log("interactsh-client did not return a canary host in time — OOB disabled.")
        stop_oob(proc); args.oob = None; return None
    args.oob = host
    args._oob_log = str(logp)
    import atexit
    atexit.register(stop_oob, proc)   # safety net if the run crashes
    log(f"OOB canary (interactsh): {host}  →  callbacks logged to {logp}")
    return proc


def stop_oob(proc):
    if proc:
        try:
            proc.terminate(); proc.wait(timeout=8)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# claude invocations
# --------------------------------------------------------------------------- #
def _scan_json(text):
    """Return the first balanced JSON object embedded in text, or None (tolerates prose)."""
    if not isinstance(text, str):
        return None
    dec = json.JSONDecoder()
    i = 0
    while True:
        j = text.find("{", i)
        if j < 0:
            return None
        try:
            obj, _ = dec.raw_decode(text, j)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        i = j + 1


_USAGE_RE = re.compile(r"usage limit|rate.?limit|limit reached|too many requests|"
                       r"resets? (?:at|in)|5-?hour limit|weekly limit|quota exceeded", re.I)
_EPOCH_RE = re.compile(r"\b(1[7-9]\d{8}|20\d{8})\b")  # 10-digit unix epoch (~2023–2033)


def _usage_limit_reset(result, stderr):
    """If the result looks like a Claude usage/rate limit, return a reset epoch (or 0 if unknown);
    else None. Gated on an actual error so a successful run mentioning 'rate limit' isn't caught."""
    text = (stderr or "")
    if isinstance(result, dict):
        if result.get("is_error") is False and isinstance(result.get("structured_output"), dict):
            return None  # clean, parsed success → definitely not a limit
        text += " " + " ".join(str(result.get(k, "")) for k in ("result", "subtype", "error", "_stderr", "_unparsed"))
    if not _USAGE_RE.search(text):
        return None
    m = _EPOCH_RE.search(text)
    return int(m.group(1)) if m else 0


def _interruptible_sleep(secs):
    """Sleep, but bail early if the STOP sentinel appears. Returns True if interrupted by STOP."""
    end = time.time() + secs
    while time.time() < end:
        if (HUNTS / "STOP").exists():
            return True
        time.sleep(min(5.0, max(0.0, end - time.time())))
    return False


_DEGEN_RETRIES = 2     # retry a transient empty/unusable "success" this many times before failing
_DEGEN_BACKOFF = 20    # seconds between those retries


def run_claude(prompt, schema, ws, env, args, max_turns, max_budget, model=None):
    cmd = ["claude", "-p", prompt,
           # Skills are copied into ws/.claude/skills (cwd-local), so no --add-dir is needed and the
           # conflicting manual SKILLS/CLAUDE.md never enters context.
           # Remove the built-in network tools so the firewalled Bash (curl/httpx/…) is the ONLY
           # network path — WebFetch/WebSearch would otherwise reach arbitrary hosts unscoped.
           "--disallowedTools", "WebFetch", "WebSearch",
           "--settings", str(ws / ".claude" / "settings.json"),
           "--permission-mode", args.permission_mode,
           "--max-turns", str(max_turns),
           "--max-budget-usd", str(max_budget),
           "--json-schema", schema,
           "--output-format", "json",
           "--session-id", str(uuid.uuid4())]
    if args.permission_mode == "bypassPermissions":
        cmd.append("--dangerously-skip-permissions")
    m = model or args.model
    if m:
        cmd += ["--model", m]
    if getattr(args, "effort", None):
        cmd += ["--effort", args.effort]

    waits = degen = 0
    while True:
        try:
            proc = subprocess.run(cmd, cwd=str(ws), env=env, capture_output=True, text=True,
                                  timeout=args.timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return {"_timeout": True, "subtype": "timeout", "total_cost_usd": max_budget}
        except FileNotFoundError:
            sys.exit("`claude` CLI not found on PATH. Install Claude Code or run with --dry-run.")

        stderr_tail = proc.stderr[-2000:]
        if not proc.stdout.strip():
            result = {"_empty": True, "subtype": "empty", "_stderr": stderr_tail}
        else:
            try:
                result = json.loads(proc.stdout)
            except json.JSONDecodeError:
                obj = _scan_json(proc.stdout)
                result = obj if obj is not None else {
                    "_unparsed": proc.stdout[-2000:], "subtype": "unparsed",
                    "total_cost_usd": max_budget, "_stderr": stderr_tail}

        # Usage-limit aware backoff: pause until the window resets and retry the SAME call,
        # rather than burning the program into "failed". (STOP aborts the wait.)
        reset = _usage_limit_reset(result, stderr_tail)
        if reset is not None and waits < args.max_usage_waits and not (HUNTS / "STOP").exists():
            waits += 1
            if reset and reset > time.time():
                wait = int(min(max(reset - time.time() + 30, 60), 6 * 3600))
            else:
                wait = int(args.usage_backoff)
            log(f"[usage] Claude usage limit hit — pausing ~{wait // 60}m then retrying "
                f"(attempt {waits}/{args.max_usage_waits}).")
            discord_send(content=f"⏳ autohunt paused — Claude usage limit; resuming in ~{max(1, wait // 60)} min.")
            if _interruptible_sleep(wait):
                log("[usage] STOP during backoff — aborting.")
                return result
            continue

        # Transient empty/unusable result (empty stdout, unparsable, or a zero-work "success" with no
        # structured output) that is NOT a timeout — almost always a momentary claude-side blip (soft
        # rate-limit / transport). Retry a few times with a short backoff before giving up.
        if (extract_structured(result) is None and not result.get("_timeout")
                and not str(result.get("subtype") or "").startswith("error_")  # max_turns/budget: don't re-burn
                and degen < _DEGEN_RETRIES and not (HUNTS / "STOP").exists()):
            degen += 1
            log(f"[retry] empty/unusable result (subtype={result.get('subtype')}, "
                f"${float(result.get('total_cost_usd') or 0):.2f}, {len(proc.stdout)}b) — "
                f"retrying in {_DEGEN_BACKOFF}s ({degen}/{_DEGEN_RETRIES}).")
            if _interruptible_sleep(_DEGEN_BACKOFF):
                return result
            continue
        return result


def extract_structured(result):
    if not isinstance(result, dict):
        return None
    so = result.get("structured_output")
    if isinstance(so, dict):
        return so
    txt = result.get("result")
    if isinstance(txt, str):
        try:
            return json.loads(txt)
        except Exception:
            return _scan_json(txt)
    return None


def phase_info(result, name):
    if not isinstance(result, dict):
        return {"name": name, "cost": 0.0, "turns": 0, "in": 0, "out": 0, "subtype": "error", "models": {}}
    u = result.get("usage") or {}
    return {"name": name, "cost": float(result.get("total_cost_usd") or 0),
            "turns": result.get("num_turns") or 0,
            "in": u.get("input_tokens", 0) or 0, "out": u.get("output_tokens", 0) or 0,
            "subtype": result.get("subtype"),
            "models": result.get("modelUsage") or result.get("model_usage") or {}}


def run_verifier(finding, ws, env, args):
    prompt = VERIFIER_PROMPT.read_text()
    for k in ("title", "vuln_class", "severity", "asset", "endpoint", "oracle", "evidence"):
        prompt = prompt.replace("{" + k + "}", str(finding.get(k, "")))
    result = run_claude(prompt, VERIFIER_SCHEMA, ws, env, args,
                        args.verify_max_turns, args.verify_budget, model=args.verify_model)
    return extract_structured(result), phase_info(result, "verify")


# --------------------------------------------------------------------------- #
# hunting: single vs pipeline
# --------------------------------------------------------------------------- #
def hunt_single(p, ws, env, args, mem):
    res = run_claude((ws / "run_prompt.md").read_text(), FINDINGS_SCHEMA.read_text(), ws, env, args,
                     args.max_turns, args.max_budget_usd)
    ph = phase_info(res, "hunt")
    s = extract_structured(res)
    if s is None:
        return {"ok": False, "verified": [], "leads": [], "tested": [], "phases": [ph],
                "subtype": ph["subtype"]}
    verified = []
    for f in s.get("findings", []):
        if is_proven(f):
            f["dedupe_key"] = make_dedupe_key(f)
            verified.append(f)
    return {"ok": True, "verified": verified, "leads": s.get("leads_unverified", []),
            "tested": s.get("tested_ruled_out", []), "phases": [ph]}


def hunt_planner(p, ws, env, args, mem):
    """Single planner session that inspects the surface, then dispatches native subagents
    (recon, hunter) only where warranted. One claude -p; subagents run inside it (governed by
    the same scope+rate firewall hook). Per-target --max-budget-usd is the global ceiling."""
    prompt = ((AGENTS / "planner.md").read_text()
              + f"\n\nProgram: \"{p['title']}\" (slug: {p['slug']}). Follow CLAUDE.md and TARGET.md.")
    res = run_claude(prompt, (SCHEMAS / "planner.schema.json").read_text(), ws, env, args,
                     args.max_turns, args.max_budget_usd)
    ph = phase_info(res, "planner")
    s = extract_structured(res)
    if s is None:
        return {"ok": False, "verified": [], "leads": [], "tested": [], "phases": [ph],
                "subtype": ph["subtype"]}
    merge_recon(mem, s.get("recon", {}))
    verified = []
    for f in s.get("findings", []):
        if is_proven(f):
            f["dedupe_key"] = make_dedupe_key(f)
            verified.append(f)
    return {"ok": True, "verified": verified,
            "leads": s.get("leads_unverified", []), "tested": s.get("tested_ruled_out", []),
            "phases": [ph]}


# --------------------------------------------------------------------------- #
# discord
# --------------------------------------------------------------------------- #
def discord_send(content=None, embeds=None, file_path=None):
    url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not url:
        return
    try:
        import requests
    except Exception:
        log("discord: `requests` not installed; skipping notification.")
        return
    payload = {}
    if content:
        payload["content"] = content[:1900]
    if embeds:
        payload["embeds"] = embeds[:10]
    for _ in range(4):
        try:
            if file_path and Path(file_path).exists():
                with open(file_path, "rb") as fh:
                    r = requests.post(url, data={"payload_json": json.dumps(payload)},
                                      files={"files[0]": (Path(file_path).name, fh)}, timeout=30)
            else:
                r = requests.post(url, json=payload, timeout=30)
            if r.status_code in (200, 204):
                return
            if r.status_code == 429:
                try:
                    time.sleep(float(r.json().get("retry_after", 2)))
                except Exception:
                    time.sleep(2)
                continue
            log(f"discord: HTTP {r.status_code} {r.text[:200]}")
            return
        except Exception as e:
            log(f"discord: send failed ({e})")
            return


def _safe_name(s):
    return re.sub(r"[^a-z0-9._-]+", "-", str(s or "").lower()).strip("-") or "x"


def write_fallback_report(ws, p, f):
    """Guarantee a viewable markdown report for a proven finding the agent didn't write one for —
    so report + Discord + web UI always have something. Returns the workspace-relative filename."""
    fname = (f"report_{_safe_name(f.get('vuln_class') or 'vuln')}_"
             f"{_safe_name(p.get('slug') or 'target')}_{now_iso()[:10]}.md")
    body = (
        f"# {f.get('title','(untitled finding)')}\n\n"
        f"- **Program:** {p.get('title','')} (`{p.get('slug','')}`)\n"
        f"- **Severity:** {f.get('severity','?')}\n"
        f"- **Class:** {f.get('vuln_class','?')}\n"
        f"- **Asset:** {f.get('asset','?')}\n"
        f"- **Endpoint:** {f.get('endpoint','?')}\n"
        f"- **Dedupe key:** `{f.get('dedupe_key','')}`\n\n"
        f"## Oracle (proof)\n\n{f.get('oracle') or '(none provided)'}\n\n"
        f"## Evidence\n\n{f.get('evidence') or '(none provided)'}\n\n"
        f"---\n_Auto-generated by autohunt: the hunter PROVED this finding (passed the oracle + the "
        f"independent refuter) but did not emit a `/report-yeswehack` file. Review and expand before submitting._\n"
    )
    (ws / fname).write_text(body)
    return fname


def notify_finding(p, f, ws):
    sev = str(f.get("severity", "?")).upper()
    emoji = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦"}.get(sev, "⬜")
    content = f"{emoji} Verified **{f.get('title','(untitled)')}** — {sev} on `{f.get('asset','')}` ({p['slug']})"
    embed = {"title": str(f.get("title", ""))[:256],
             "description": str(f.get("evidence", ""))[:1500],
             "fields": [
                 {"name": "Class", "value": str(f.get("vuln_class", "?")), "inline": True},
                 {"name": "Severity", "value": sev, "inline": True},
                 {"name": "Endpoint", "value": str(f.get("endpoint", "?"))[:200], "inline": False},
                 {"name": "Oracle (proof)", "value": str(f.get("oracle", "?"))[:600], "inline": False},
                 {"name": "Program", "value": f"{p['title']} ({p['slug']})", "inline": False}]}
    report = None
    rp = f.get("report_path")
    if rp:
        cand = (ws / rp) if not os.path.isabs(rp) else Path(rp)
        if cand.exists():
            report = str(cand)
    if os.environ.get("DISCORD_WEBHOOK_URL"):
        discord_send(content=content, embeds=[embed], file_path=report)
    else:  # no webhook — still surface the finding in the log so it isn't silently missed
        log(f"  [FINDING] {sev} {f.get('title','')} on {f.get('asset','')} — report: {rp} "
            f"(set DISCORD_WEBHOOK_URL to push to Discord)")


def notify_leads(p, leads):
    if not leads:
        return
    rows = []
    for l in leads[:12]:
        rows.append(f"• **{l.get('title','')}** ({l.get('vuln_class','?')}/{l.get('priority','?')}) "
                    f"`{l.get('asset','')}` {l.get('endpoint','')}")
    content = (f"🔎 UNVERIFIED LEADS — manual review ({p['slug']}, {len(leads)} new):\n" + "\n".join(rows))
    discord_send(content=content)


# --------------------------------------------------------------------------- #
# monitoring mode
# --------------------------------------------------------------------------- #
def probe_url(url, timeout=15):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "autohunt-monitor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(200000)
            return {"status": getattr(r, "status", r.getcode()),
                    "hash": hashlib.sha256(body).hexdigest()[:16]}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "hash": "httperror"}
    except Exception as e:
        return {"status": 0, "hash": "err:" + type(e).__name__}


def watch_urls(mem, seeds):
    urls = []
    for h in mem["recon"]["live_hosts"]:
        urls.append(h if h.startswith("http") else "https://" + h)
    urls += [u for u in mem["recon"]["endpoints"] if str(u).startswith("http")]
    urls += [u for u in mem["recon"]["js_files"] if str(u).startswith("http")]
    if not urls:
        urls = list(seeds)
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:30]


def monitor_pass(programs, args):
    targets = [p for p in programs if (not args.program or p["slug"] == args.program)]
    if args.limit:
        targets = targets[: args.limit]
    log(f"monitor: checking {len(targets)} program(s).")
    total_changes = 0
    for p in targets:
        ws = HUNTS / p["slug"]
        if not ws.exists():
            continue  # never hunted → nothing to baseline against yet
        allow, seeds, out_hosts = compute_scope(p)
        mem = load_memory(ws)
        baseline = mem["monitor_baseline"]
        urls = watch_urls(mem, seeds)
        changes = []
        for u in urls:
            cur = probe_url(u)
            old = baseline.get(u)
            baseline[u] = {**cur, "checked_at": now_iso()}
            if old is None:
                continue  # seeding pass — no alert
            if old.get("status") != cur["status"] or old.get("hash") != cur["hash"]:
                changes.append({"url": u, "old": {"status": old.get("status"), "hash": old.get("hash")},
                                "new": cur})
            time.sleep(0.3)
        save_memory(ws, mem)
        if not changes:
            continue
        log(f"  {p['slug']}: {len(changes)} change(s) detected.")
        env = hunter_env(allow, out_hosts, args, {})
        for ch in changes:
            prompt = (AGENTS / "monitor-triage.md").read_text() + "\n\nCHANGE:\n" + json.dumps(ch, ensure_ascii=False)
            res = run_claude(prompt, (SCHEMAS / "monitor.schema.json").read_text(), ws, env, args,
                             args.verify_max_turns, args.verify_budget, model=args.verify_model)
            v = extract_structured(res) or {}
            if v.get("worth_investigating"):
                total_changes += 1
                append_jsonl(HUNTS / "alerts.jsonl", {
                    "ts": now_iso(), "slug": p["slug"], "url": ch["url"],
                    "severity_guess": v.get("severity_guess"), "reason": v.get("reason", ""),
                    "suggested_action": v.get("suggested_action", "")})
                discord_send(content=(f"📡 Change worth a look on `{ch['url']}` ({p['slug']}) — "
                                      f"{v.get('severity_guess','?')}\n{v.get('reason','')[:400]}\n"
                                      f"→ {v.get('suggested_action','')[:300]}"))
            else:
                log(f"    change on {ch['url']} judged not worth investigating: {v.get('reason','')[:100]}")
    log(f"monitor: done. {total_changes} change(s) flagged for review.")
    if total_changes:
        discord_send(content=f"📡 autohunt monitor: {total_changes} change(s) flagged for review.")


# --------------------------------------------------------------------------- #
# cost report
# --------------------------------------------------------------------------- #
def new_run_cost():
    return {"by_phase": defaultdict(lambda: {"cost": 0.0, "turns": 0, "in": 0, "out": 0, "n": 0}),
            "by_program": defaultdict(float),
            "by_model": defaultdict(lambda: {"cost": 0.0, "in": 0, "out": 0}), "total": 0.0}


def add_phase_cost(rc, slug, ph):
    b = rc["by_phase"][ph["name"]]
    b["cost"] += ph["cost"]; b["turns"] += ph["turns"]; b["in"] += ph["in"]; b["out"] += ph["out"]; b["n"] += 1
    rc["by_program"][slug] += ph["cost"]
    rc["total"] += ph["cost"]
    for mname, mu in (ph.get("models") or {}).items():
        bm = rc["by_model"][mname]
        bm["cost"] += float(mu.get("costUSD", mu.get("cost", 0)) or 0)
        bm["in"] += mu.get("inputTokens", mu.get("input_tokens", 0)) or 0
        bm["out"] += mu.get("outputTokens", mu.get("output_tokens", 0)) or 0


def write_cost_report(rc):
    lines = ["# autohunt cost report", "", f"_Run at {now_iso()}_", "",
             f"**Total: ${rc['total']:.2f}**", "", "## By phase", "",
             "| Phase | calls | $ | turns | in_tok | out_tok |", "|---|---|---|---|---|---|"]
    for name, b in sorted(rc["by_phase"].items()):
        lines.append(f"| {name} | {b['n']} | {b['cost']:.2f} | {b['turns']} | {b['in']} | {b['out']} |")
    if rc["by_model"]:
        lines += ["", "## By model", "", "| Model | $ | in_tok | out_tok |", "|---|---|---|---|"]
        for name, b in sorted(rc["by_model"].items(), key=lambda x: -x[1]["cost"]):
            lines.append(f"| {name} | {b['cost']:.2f} | {b['in']} | {b['out']} |")
    lines += ["", "## By program", "", "| Program | $ |", "|---|---|"]
    for slug, c in sorted(rc["by_program"].items(), key=lambda x: -x[1]):
        lines.append(f"| {slug} | {c:.2f} |")
    (HUNTS / "cost_report.md").write_text("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
# prereqs / args / queue
# --------------------------------------------------------------------------- #
def _subscription_logged_in():
    if (Path.home() / ".claude" / ".credentials.json").exists():
        return True
    try:
        return bool(json.loads((Path.home() / ".claude.json").read_text()).get("oauthAccount"))
    except Exception:
        return False


def check_prereqs(args):
    if not args.dry_run and not shutil.which("claude"):
        sys.exit("`claude` CLI not found on PATH. Install Claude Code or use --dry-run.")
    if not args.dry_run:
        if args.use_api:
            if not os.environ.get("ANTHROPIC_API_KEY"):
                log("WARNING: --use-api set but ANTHROPIC_API_KEY is not exported.")
        elif not _subscription_logged_in():
            log("WARNING: no Claude subscription login detected — run `claude` then /login "
                "(child sessions use your subscription, not the API; pass --use-api to bill the API).")
    missing = [t for t in RECON_TOOLS if not shutil.which(t)]
    if missing:
        log(f"WARNING: recon tools missing (reduced capability): {', '.join(missing)} — run ./install_tools.sh")
    if not os.environ.get("DISCORD_WEBHOOK_URL") and not args.dry_run:
        log("WARNING: DISCORD_WEBHOOK_URL not set — notifications will be skipped.")


def parse_args():
    ap = argparse.ArgumentParser(description="Autonomous YesWeHack hunting loop (v2).")
    ap.add_argument("--program", help="Only this slug.")
    ap.add_argument("--limit", type=int, default=0, help="Process at most N programs.")
    ap.add_argument("--only-changed", action="store_true", help="Only new / scope-changed programs.")
    ap.add_argument("--bbp-only", action="store_true", help="Only programs with a bounty.")
    ap.add_argument("--rescan", action="store_true", help="Re-hunt programs already done.")
    ap.add_argument("--dry-run", action="store_true", help="Print the queue; run nothing.")
    ap.add_argument("--monitor", action="store_true", help="Change-detection pass (no hunting).")
    ap.add_argument("--mode", choices=["planner", "single"], default="planner",
                    help="planner = one planner agent dispatches recon/hunter subagents (default); "
                         "single = one monolithic agent.")
    ap.add_argument("--no-verify", action="store_true", help="Skip the independent refuter.")
    ap.add_argument("--capture", choices=["none", "mitmdump", "caido"], default="none")
    ap.add_argument("--model", default="opus", help="Planner/hunter model (default opus = 4.8; sonnet for cheaper/broader sweeps).")
    ap.add_argument("--verify-model", default="opus", help="Refuter/triage model (default opus).")
    ap.add_argument("--effort", default="high", help="Reasoning effort for every session (low|medium|high|xhigh|max; default high).")
    ap.add_argument("--permission-mode", default="bypassPermissions")
    ap.add_argument("--use-api", action="store_true",
                    help="Bill the Anthropic API (keep ANTHROPIC_API_KEY). Default: use your Claude subscription.")
    ap.add_argument("--max-turns", type=int, default=80, help="Per-session turn cap (planner + its subagents).")
    ap.add_argument("--max-budget-usd", type=float, default=5.0, help="Per-target $ ceiling (global, incl. subagents).")
    ap.add_argument("--timeout", type=int, default=3000, help="Per-session wall-clock seconds.")
    ap.add_argument("--max-total-usd", type=float, default=50.0, help="Global $ cap for the run.")
    ap.add_argument("--verify-max-turns", type=int, default=20)
    ap.add_argument("--verify-budget", type=float, default=1.5)
    ap.add_argument("--throttle", type=float, default=5.0, help="Sleep between targets.")
    ap.add_argument("--max-rps", type=float, default=8, help="Enforced max request-rate flag for scan tools.")
    ap.add_argument("--max-conc", type=float, default=10, help="Enforced max concurrency/threads flag for scan tools.")
    ap.add_argument("--oob", help="OOB canary host for SSRF/blind oracles. Pass 'auto' to "
                    "auto-provision one via interactsh-client (no manual host needed); the agent "
                    "confirms callbacks by reading $AUTOHUNT_OOB_LOG.")
    ap.add_argument("--oob-server", help="interactsh server(s) for --oob auto (default: public oast.* servers).")
    # --- ad-hoc / ops functionalities ---
    ap.add_argument("--target", help="Hunt an arbitrary authorized URL NOT in the catalog (ad-hoc mode).")
    ap.add_argument("--scope", help="Comma-separated in-scope hosts for --target (default: the target's host).")
    ap.add_argument("--retry-failed", action="store_true", help="Re-run only programs whose last status is failed.")
    ap.add_argument("--watch", type=int, default=0, metavar="SECONDS",
                    help="Repeat the run (hunt or --monitor) every N seconds until data/hunts/STOP.")
    ap.add_argument("--rate-proxy", action="store_true",
                    help="Route tool traffic through a mitmdump that hard-caps per-host req/s (true global rate ceiling).")
    ap.add_argument("--selftest", action="store_true",
                    help="Preflight: readiness report + firewall sanity + a benign live hunt (use with --dry-run for static-only).")
    ap.add_argument("--usage-backoff", type=int, default=1800,
                    help="On a Claude usage limit with no known reset time, pause this many seconds then retry (default 1800).")
    ap.add_argument("--max-usage-waits", type=int, default=10,
                    help="Max consecutive usage-limit pause/retry cycles per session before giving up (default 10).")
    return ap.parse_args()


def synthetic_program(target, scope_csv):
    """Build an in-memory program for ad-hoc `--target` runs (no catalog entry)."""
    host = extract_host(target) or (target or "target")
    if scope_csv:
        assets = [{"scope": s.strip(), "scope_type": "web-application", "asset_value": ""}
                  for s in scope_csv.split(",") if s.strip()]
    else:
        assets = [{"scope": target, "scope_type": "web-application", "asset_value": ""}]
    slug = "adhoc-" + re.sub(r"[^a-z0-9.-]+", "-", host.lower()).strip("-")
    p = {"slug": slug, "title": f"ad-hoc: {target}", "type": "adhoc", "kind": "",
         "bounty": False, "bounty_max": 0, "disabled": False, "archived": False,
         "last_update_at": None, "in_assets": assets, "out_assets": []}
    p["_scope_hash"] = scope_hash(p)
    return p


def build_queue(programs, status, args):
    q = []
    for p in programs:
        if args.program and p["slug"] != args.program:
            continue
        rec = status.get(p["slug"])
        if args.retry_failed:  # only re-run prior failures
            if rec and rec.get("status") == "failed":
                q.append(p)
            continue
        changed = (rec is None) or (rec.get("scope_hash") != p["_scope_hash"])
        if args.only_changed and not changed:
            continue
        if rec and rec.get("status") == "done" and not args.rescan and not changed:
            continue
        q.append(p)
    if args.limit:
        q = q[: args.limit]
    return q


def run_once(args):
    HUNTS.mkdir(parents=True, exist_ok=True)
    if args.target:                       # ad-hoc: hunt a URL not in the catalog
        programs = [synthetic_program(args.target, args.scope)]
    else:
        programs = prioritize(load_catalog(), args)
        if args.monitor:
            monitor_pass(programs, args)
            return

    status = load_json(HUNTS / "status.json", {})
    index = load_json(HUNTS / "findings_index.json", {})
    queue = programs if args.target else build_queue(programs, status, args)

    if not queue:
        print("Queue is empty (nothing new/changed, or all done). Use --rescan to force.")
        return

    if args.dry_run:
        print(f"Prioritized queue ({len(queue)} programs), mode={args.mode}:\n")
        for i, p in enumerate(queue, 1):
            allow, _, _ = compute_scope(p)
            tag = "BBP" if p["bounty"] else "VDP"
            print(f"{i:3}. {p['slug']}  [{tag} max=${p['bounty_max']}]  hosts={len(allow)}  "
                  f"e.g. {', '.join(allow[:3])}")
        print("\n(dry run — nothing executed)")
        return

    log(f"Run: {len(queue)} program(s). mode={args.mode} auth={'api' if args.use_api else 'subscription'} "
        f"model={args.model} effort={args.effort} verify={args.verify_model} per-target=${args.max_budget_usd} "
        f"global=${args.max_total_usd} rps≤{args.max_rps} capture={args.capture}")
    discord_send(content=f"🚀 autohunt ({args.mode}) — {len(queue)} program(s) queued.")

    oob_proc = start_oob(args)   # autonomous OOB canary via interactsh when --oob auto
    rc = new_run_cost()
    total_cost = 0.0
    consec_fail = 0
    for i, p in enumerate(queue, 1):
        if (HUNTS / "STOP").exists():
            log("STOP sentinel — halting.")
            discord_send(content="🛑 autohunt halted (STOP).")
            break
        if total_cost + args.max_budget_usd > args.max_total_usd:  # look-ahead: don't overshoot
            log(f"Global budget ${args.max_total_usd} would be exceeded by the next target — halting "
                f"(~${total_cost:.2f} spent).")
            discord_send(content=f"💰 autohunt halted — global budget ${args.max_total_usd} reached (~${total_cost:.2f}).")
            break

        allow, seeds, out_hosts = compute_scope(p)
        log(f"[{i}/{len(queue)}] {p['slug']} — {len(allow)} host(s), max ${p['bounty_max']}")
        status[p["slug"]] = {"status": "running", "started_at": now_iso(), "scope_hash": p["_scope_hash"]}
        save_json(HUNTS / "status.json", status)

        ws = setup_workspace(p, allow, seeds, out_hosts, args)
        mem = load_memory(ws)
        cap_proc, cap_env = start_proxy(args, ws)
        env = hunter_env(allow, out_hosts, args, cap_env)
        record = {"slug": p["slug"], "started_at": now_iso(), "scope_hash": p["_scope_hash"],
                  "mode": args.mode, "model": args.model}
        try:
            hr = hunt_planner(p, ws, env, args, mem) if args.mode == "planner" \
                else hunt_single(p, ws, env, args, mem)
        finally:
            stop_capture(cap_proc)

        for ph in hr["phases"]:
            add_phase_cost(rc, p["slug"], ph)
        target_cost = sum(ph["cost"] for ph in hr["phases"])

        if not hr["ok"]:
            record.update(status="failed", subtype=hr.get("subtype", "no_output"))
            log(f"  no usable output (subtype={hr.get('subtype')}, ${target_cost:.2f}) — "
                f"marked failed/retryable (re-run, or use --retry-failed)")
        else:
            record["status"] = "done"
            reported = []
            for f in hr["verified"]:
                if (HUNTS / "STOP").exists():
                    log("  STOP — aborting remaining verification.")
                    break
                if not args.no_verify:
                    verdict, vph = run_verifier(f, ws, env, args)
                    add_phase_cost(rc, p["slug"], vph)
                    target_cost += vph["cost"]
                    if verdict and verdict.get("refuted"):
                        log(f"  refuted: {f.get('title')} — {str(verdict.get('reason',''))[:120]}")
                        record_tested(mem, [{"what": f.get("dedupe_key") or f.get("title"),
                                             "why": "refuted by verifier"}])
                        continue
                # Guarantee a viewable report for every proven finding: if the agent didn't write one,
                # generate a fallback from the finding fields (report + Discord + web UI all get it).
                rp = f.get("report_path")
                cand = (ws / rp) if (rp and not os.path.isabs(rp)) else (Path(rp) if rp else None)
                if not (cand and cand.exists()):
                    f["report_path"] = write_fallback_report(ws, p, f)
                    log(f"  wrote fallback report for {f.get('title')} → {f['report_path']}")
                key = f.get("dedupe_key") or make_dedupe_key(f)
                if key in index:
                    log(f"  duplicate: {f.get('title')}")
                    continue
                index[key] = {"slug": p["slug"], "title": f.get("title"),
                              "report_path": f.get("report_path"), "first_seen": now_iso()}
                notify_finding(p, f, ws)
                record_finding_mem(mem, f)
                reported.append({"title": f.get("title"), "severity": f.get("severity"), "dedupe_key": key})

            new_leads = merge_leads(mem, hr["leads"])
            to_alert = [l for l in new_leads if not l.get("alerted")]
            notify_leads(p, to_alert)
            for l in to_alert:
                l["alerted"] = True
            record_tested(mem, hr["tested"])

            record.update(findings_count=len(hr["verified"]), verified_reported=len(reported),
                          leads_count=len(hr["leads"]), new_leads=len(new_leads), reports=reported)
            save_json(HUNTS / "findings_index.json", index)
            log(f"  done: {len(hr['verified'])} verified, {len(reported)} reported, "
                f"{len(new_leads)} new leads, ${target_cost:.2f}")

        record["total_cost_usd"] = round(target_cost, 4)
        record["phases"] = hr["phases"]
        total_cost += target_cost
        save_memory(ws, mem)
        record["finished_at"] = now_iso()
        append_ledger(record)
        status[p["slug"]] = {k: record.get(k) for k in
                             ("status", "subtype", "scope_hash", "findings_count",
                              "verified_reported", "total_cost_usd")}
        status[p["slug"]]["last_run"] = record["finished_at"]
        save_json(HUNTS / "status.json", status)

        # circuit breaker: a run of consecutive failures usually means a systemic problem
        # (auth/usage-limit/network) — stop before draining the whole queue into "failed".
        consec_fail = consec_fail + 1 if record["status"] == "failed" else 0
        if consec_fail >= 3:
            log(f"{consec_fail} consecutive failures — circuit breaker tripped, halting.")
            discord_send(content=f"⚠️ autohunt halted — {consec_fail} consecutive failures "
                         "(likely auth/usage-limit/network); remaining programs untouched.")
            break
        time.sleep(args.throttle)

    stop_oob(oob_proc)
    write_cost_report(rc)
    log(f"Run complete. ~${total_cost:.2f} total. Cost report: {HUNTS / 'cost_report.md'}")
    discord_send(content=f"✅ autohunt complete — ~${total_cost:.2f}. See cost_report.md.")


def run_selftest(args):
    """Preflight: readiness report + firewall sanity, then a benign live hunt (unless --dry-run)."""
    ok = True
    print("=== autohunt self-test ===")
    print(f"  claude CLI ........ {'ok' if shutil.which('claude') else 'MISSING (required)'}")
    ok = ok and bool(shutil.which("claude"))
    miss = [t for t in RECON_TOOLS if not shutil.which(t)]
    print(f"  recon tools ....... {'all present' if not miss else 'missing: ' + ', '.join(miss) + ' (degraded — ./install_tools.sh)'}")
    print(f"  subscription login. {'ok' if _subscription_logged_in() else 'NOT logged in (run claude /login, or --use-api)'}")
    print(f"  discord webhook ... {'set' if os.environ.get('DISCORD_WEBHOOK_URL') else 'unset (notifications skipped)'}")
    for s in (FINDINGS_SCHEMA, SCHEMAS / "planner.schema.json", SCHEMAS / "monitor.schema.json"):
        try:
            json.loads(s.read_text()); print(f"  schema {s.name:24} ok")
        except Exception as e:
            print(f"  schema {s.name:24} BAD ({e})"); ok = False

    def fw(cmd, extra):
        env = {**os.environ, "AUTOHUNT_SCOPE": "*.example.com", "AUTOHUNT_MAX_RPS": "8",
               "AUTOHUNT_MAX_CONC": "10", **extra}
        out = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": cmd}}), text=True, capture_output=True, env=env).stdout
        return bool(out.strip())  # non-empty stdout = a deny
    deny = fw("curl https://evil.com", {})
    allow = not fw("curl https://app.example.com -s", {})
    ratecap = fw("nuclei -u https://app.example.com", {})
    print(f"  firewall scope .... {'ok (out-of-scope denied)' if deny else 'FAIL'}")
    print(f"  firewall in-scope . {'ok (in-scope allowed)' if allow else 'FAIL'}")
    print(f"  firewall rate ..... {'ok (uncapped scan denied)' if ratecap else 'FAIL'}")
    ok = ok and deny and allow and ratecap

    if args.dry_run:
        print("\n" + ("PASS (static checks)" if ok else "FAIL (see above)"))
        return 0 if ok else 1
    if not shutil.which("claude"):
        print("\nFAIL — claude CLI required for the live hunt.")
        return 1

    print("\nRunning a benign live hunt against example.com (small spend)…")
    args.max_budget_usd = min(args.max_budget_usd, 1.0)
    args.max_turns = min(args.max_turns, 20)
    args.model = args.verify_model = "sonnet"
    args.no_verify = True
    args.capture, args.rate_proxy, args.oob = "none", False, None
    p = synthetic_program("https://example.com", "example.com")
    allow, seeds, out = compute_scope(p)
    ws = setup_workspace(p, allow, seeds, out, args)
    mem = load_memory(ws)
    hr = hunt_planner(p, ws, hunter_env(allow, out, args, {}), args, mem)
    save_memory(ws, mem)
    cost = sum(ph["cost"] for ph in hr["phases"])
    recon_n = sum(len(mem["recon"].get(k, [])) for k in RECON_KEYS)
    live_ok = hr["ok"] and cost > 0
    print(f"  planner ran ....... {'ok' if hr['ok'] else 'FAIL'} (${cost:.2f}, recon items: {recon_n})")
    ok = ok and live_ok
    print("\n" + ("PASS — pipeline healthy." if ok else "FAIL (see above)"))
    return 0 if ok else 1


def main():
    args = parse_args()
    check_prereqs(args)
    if args.selftest:
        sys.exit(run_selftest(args))
    if args.watch:
        log(f"watch mode — repeating every {args.watch}s (touch {HUNTS / 'STOP'} to stop).")
        while True:
            run_once(args)
            if (HUNTS / "STOP").exists():
                log("STOP present — ending watch loop.")
                break
            time.sleep(args.watch)
    else:
        run_once(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted.")
        sys.exit(130)
