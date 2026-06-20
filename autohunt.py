#!/usr/bin/env python3
"""autohunt — autonomous YesWeHack hunting loop.

Walks the local program catalog (produced by yeswehack_programs.py) and, per program,
spawns ONE budget-capped, scope-firewalled headless `claude -p` session that discovers,
tests, and PROVES vulnerabilities, writes a report, and emits structured findings. An
optional independent verifier refutes each candidate; survivors are reported + pushed to
Discord. Status is tracked in a resumable ledger.

The hunting intelligence is reused, not reimplemented: each session loads the autonomous
doctrine (autohunt/doctrine.md) as CLAUDE.md plus the repo's hunt skills.

Safety: per-target --max-turns/--max-budget-usd/timeout, a global --max-total-usd, a
data/hunts/STOP kill-switch, and a PreToolUse scope-firewall hook that blocks out-of-scope
hosts even under --dangerously-skip-permissions. No reports are auto-submitted to YWH.

Usage examples:
  python autohunt.py --dry-run                 # show the prioritized queue, run nothing
  python autohunt.py --program acme --max-budget-usd 1
  python autohunt.py --only-changed            # scan new / scope-changed programs
  python autohunt.py --limit 5 --model sonnet
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent
AUTOHUNT = REPO / "autohunt"
CATALOG = REPO / "data" / "yeswehack"
HUNTS = REPO / "data" / "hunts"
SKILLS = REPO / "SKILLS"

DOCTRINE = AUTOHUNT / "doctrine.md"
SCHEMA = AUTOHUNT / "findings.schema.json"
HOOK = AUTOHUNT / "scope_firewall.py"
VERIFIER_PROMPT = AUTOHUNT / "verifier.md"

WEB_TYPES = {"web-application", "api", ""}  # "" = bare-string scope with no type → treat as web
HOST_RE = re.compile(r"^\*?\.?(?:[a-z0-9_-]+\.)+[a-z]{2,}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

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
    """Return a clean host/wildcard from a scope string, or None if it isn't one."""
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
    v = (scope_value or "").strip()
    if v.lower().startswith(("http://", "https://")):
        return v.split()[0]
    base = host[2:] if host.startswith("*.") else host
    return "https://" + base


def compute_scope(program):
    """(allow_hosts, seed_urls, out_hosts) for a program — web/api assets only."""
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
    state = json.loads(state_path.read_text())
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
            continue  # no web/api hosts to test
        if args.bbp_only and not p["bounty"]:
            continue
        p["_scope_hash"] = scope_hash(p)
        elig.append(p)
    elig.sort(key=lambda p: (0 if p["bounty"] else 1, -(p["bounty_max"] or 0), p["title"].lower()))
    return elig


# --------------------------------------------------------------------------- #
# ledger / state
# --------------------------------------------------------------------------- #
def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def save_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False))


def append_ledger(record):
    HUNTS.mkdir(parents=True, exist_ok=True)
    with (HUNTS / "ledger.jsonl").open("a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------- #
# workspace
# --------------------------------------------------------------------------- #
def setup_workspace(p, allow, seeds, out_hosts, args):
    ws = HUNTS / p["slug"]
    ws.mkdir(parents=True, exist_ok=True)
    shutil.copy(DOCTRINE, ws / "CLAUDE.md")

    skills_dir = ws / ".claude" / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    for child in SKILLS.iterdir():
        if child.is_dir():
            link = skills_dir / child.name
            try:
                if link.is_symlink() or link.exists():
                    link.unlink()
                link.symlink_to(child)
            except OSError:
                pass

    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash",
                "hooks": [{"type": "command", "command": f"python3 {HOOK}"}]}]}}
    save_json(ws / ".claude" / "settings.json", settings)

    # TARGET.md = catalog program.md + scope.md + the enforced autohunt scope block
    program_md = (CATALOG / p["slug"] / "program.md")
    scope_md = (CATALOG / p["slug"] / "scope.md")
    creds_path = REPO / "data" / "creds" / f"{p['slug']}.json"
    parts = []
    if program_md.exists():
        parts.append(program_md.read_text())
    if scope_md.exists():
        parts.append(scope_md.read_text())
    parts.append("## Autohunt scope (ENFORCED by firewall — stay inside)\n")
    parts.append("**In-scope hosts (allowlist):**\n" + "\n".join(f"- `{h}`" for h in allow) + "\n")
    parts.append("**Seed URLs:**\n" + "\n".join(f"- {u}" for u in seeds) + "\n")
    if out_hosts:
        parts.append("**Out-of-scope hosts (never test):**\n" + "\n".join(f"- `{h}`" for h in out_hosts) + "\n")
    if args.oob:
        parts.append(f"**OOB canary host (use for SSRF/blind oracles):** `{args.oob}`\n")
    if creds_path.exists():
        parts.append(f"**Credentials available** at `{creds_path}` — use them for authed IDOR/RBAC "
                     f"testing (need ≥2 accounts to prove cross-user access).\n")
    else:
        parts.append("**No credentials** — unauthenticated surface only. Skip IDOR/RBAC unless you "
                     "find a self-signup that's in scope.\n")
    (ws / "TARGET.md").write_text("\n".join(parts))

    prompt = (
        f"Autonomously hunt the YesWeHack program \"{p['title']}\" (slug: {p['slug']}).\n\n"
        "Follow CLAUDE.md in this directory and read TARGET.md for the scope, seed URLs, and any "
        "credentials. Do passive discovery, prioritise high-impact leads specific to this app, and "
        "PROVE each candidate against its oracle before treating it as a finding. Write a "
        "/report-yeswehack markdown for every verified finding, then output the required JSON "
        "(program_slug, status, summary, findings[], leads_unverified[]). Stay strictly within the "
        "in-scope allowlist and the guardrails. Your budget is limited — be fast and decisive; if a "
        "lead shows no signal quickly, log it as a lead and move on."
    )
    (ws / "run_prompt.md").write_text(prompt)
    return ws


def hunter_env(allow, out_hosts, args, capture_env):
    env = os.environ.copy()
    env["AUTOHUNT_SCOPE"] = " ".join(allow)
    env["AUTOHUNT_OUT_OF_SCOPE"] = " ".join(out_hosts)
    safe = []
    if args.oob:
        env["AUTOHUNT_OOB"] = args.oob
        safe.append(args.oob)
    if safe:
        env["AUTOHUNT_SAFE_HOSTS"] = " ".join(safe)
    env.update(capture_env)
    return env


# --------------------------------------------------------------------------- #
# capture layer (pluggable)
# --------------------------------------------------------------------------- #
def start_capture(mode, ws):
    """Return (proc_or_None, env_dict). Passive upstream proxy logging the agent's traffic."""
    if mode == "none":
        return None, {}
    if mode == "caido":
        log("capture=caido not yet wired (needs caido-cli + instance claim + PAT + CA import); "
            "running WITHOUT capture. Use --capture mitmdump or set up caido-cli manually.")
        return None, {}
    if mode == "mitmdump":
        if not shutil.which("mitmdump"):
            log("capture=mitmdump but mitmdump not on PATH; running without capture.")
            return None, {}
        port = 8899
        flow = ws / "traffic.flow"
        proc = subprocess.Popen(
            ["mitmdump", "--mode", "regular", "--listen-port", str(port), "-w", str(flow), "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        for _ in range(25):  # mitmdump generates the CA on first start
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
        log(f"capture=mitmdump on :{port} → {flow}")
        return proc, env
    return None, {}


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
# claude invocations
# --------------------------------------------------------------------------- #
def run_claude(prompt, schema, ws, env, args, max_turns, max_budget):
    cmd = ["claude", "-p", prompt,
           "--add-dir", str(SKILLS),
           "--settings", str(ws / ".claude" / "settings.json"),
           "--permission-mode", args.permission_mode,
           "--max-turns", str(max_turns),
           "--max-budget-usd", str(max_budget),
           "--json-schema", schema,
           "--output-format", "json",
           "--session-id", str(uuid.uuid4())]
    if args.permission_mode == "bypassPermissions":
        cmd.append("--dangerously-skip-permissions")
    if args.model:
        cmd += ["--model", args.model]
    try:
        proc = subprocess.run(cmd, cwd=str(ws), env=env, capture_output=True, text=True,
                              timeout=args.timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"_timeout": True}
    except FileNotFoundError:
        sys.exit("`claude` CLI not found on PATH. Install Claude Code or run with --dry-run.")
    if not proc.stdout.strip():
        return {"_empty": True, "_stderr": proc.stderr[-2000:]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        # fall back: last JSON object in stdout
        m = re.findall(r"\{.*\}", proc.stdout, re.DOTALL)
        if m:
            try:
                return json.loads(m[-1])
            except Exception:
                pass
        return {"_unparsed": proc.stdout[-2000:], "_stderr": proc.stderr[-2000:]}


def extract_structured(result):
    """Pull the findings object from a claude --output-format json result."""
    if not isinstance(result, dict):
        return None
    so = result.get("structured_output")
    if isinstance(so, dict):
        return so
    txt = result.get("result")
    if isinstance(txt, str):
        m = re.search(r"\{.*\}", txt, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


def run_verifier(finding, ws, env, args):
    prompt = VERIFIER_PROMPT.read_text()
    for k in ("title", "vuln_class", "severity", "asset", "endpoint", "oracle", "evidence"):
        prompt = prompt.replace("{" + k + "}", str(finding.get(k, "")))
    result = run_claude(prompt, VERIFIER_SCHEMA, ws, env, args,
                        max_turns=args.verify_max_turns, max_budget=args.verify_budget)
    verdict = extract_structured(result)
    cost = result.get("total_cost_usd", 0) if isinstance(result, dict) else 0
    return verdict, (cost or 0)


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
    for attempt in range(4):
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


def notify_finding(p, f, ws):
    sev = f.get("severity", "?").upper()
    emoji = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦"}.get(sev, "⬜")
    content = f"{emoji} Verified **{f.get('title','(untitled)')}** — {sev} on `{f.get('asset','')}` ({p['slug']})"
    embed = {
        "title": f.get("title", "")[:256],
        "description": (f.get("summary") or f.get("evidence", ""))[:1500],
        "fields": [
            {"name": "Class", "value": str(f.get("vuln_class", "?")), "inline": True},
            {"name": "Severity", "value": sev, "inline": True},
            {"name": "Endpoint", "value": str(f.get("endpoint", "?"))[:200], "inline": False},
            {"name": "Oracle (proof)", "value": str(f.get("oracle", "?"))[:500], "inline": False},
            {"name": "Program", "value": f"{p['title']} ({p['slug']})", "inline": False},
        ],
    }
    report = None
    rp = f.get("report_path")
    if rp:
        cand = (ws / rp) if not os.path.isabs(rp) else Path(rp)
        if cand.exists():
            report = str(cand)
    discord_send(content=content, embeds=[embed], file_path=report)


# --------------------------------------------------------------------------- #
# prereqs
# --------------------------------------------------------------------------- #
def check_prereqs(args):
    if not args.dry_run and not shutil.which("claude"):
        sys.exit("`claude` CLI not found on PATH. Install Claude Code or use --dry-run.")
    missing = [t for t in RECON_TOOLS if not shutil.which(t)]
    if missing:
        log(f"WARNING: recon tools not on PATH (hunter will have reduced capability): {', '.join(missing)}")
    if not os.environ.get("DISCORD_WEBHOOK_URL") and not args.dry_run:
        log("WARNING: DISCORD_WEBHOOK_URL not set — notifications will be skipped.")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def parse_args():
    ap = argparse.ArgumentParser(description="Autonomous YesWeHack hunting loop.")
    ap.add_argument("--program", help="Hunt only this slug.")
    ap.add_argument("--limit", type=int, default=0, help="Process at most N programs.")
    ap.add_argument("--only-changed", action="store_true", help="Only new / scope-changed programs.")
    ap.add_argument("--bbp-only", action="store_true", help="Only programs with a bounty.")
    ap.add_argument("--rescan", action="store_true", help="Re-hunt even programs already done.")
    ap.add_argument("--dry-run", action="store_true", help="Print the queue and plan; run nothing.")
    ap.add_argument("--no-verify", action="store_true", help="Skip the independent verifier pass.")
    ap.add_argument("--capture", choices=["none", "mitmdump", "caido"], default="none",
                    help="Passive traffic-capture proxy for later human review (default none).")
    ap.add_argument("--model", default="opus", help="Model for the hunter (e.g. opus, sonnet).")
    ap.add_argument("--permission-mode", default="bypassPermissions",
                    help="claude permission mode (default bypassPermissions; hook enforces scope).")
    ap.add_argument("--max-turns", type=int, default=60, help="Per-target turn cap.")
    ap.add_argument("--max-budget-usd", type=float, default=4.0, help="Per-target $ cap.")
    ap.add_argument("--timeout", type=int, default=2400, help="Per-target wall-clock seconds.")
    ap.add_argument("--max-total-usd", type=float, default=50.0, help="Global $ cap for the whole run.")
    ap.add_argument("--verify-max-turns", type=int, default=20, help="Per-finding verifier turn cap.")
    ap.add_argument("--verify-budget", type=float, default=1.5, help="Per-finding verifier $ cap.")
    ap.add_argument("--throttle", type=float, default=5.0, help="Seconds to sleep between targets.")
    ap.add_argument("--oob", help="OOB canary host for SSRF/blind oracles (e.g. abc.oast.pro).")
    return ap.parse_args()


def build_queue(programs, status, args):
    q = []
    for p in programs:
        if args.program and p["slug"] != args.program:
            continue
        rec = status.get(p["slug"])
        changed = (rec is None) or (rec.get("scope_hash") != p["_scope_hash"])
        if args.only_changed and not changed:
            continue
        if rec and rec.get("status") == "done" and not args.rescan and not changed:
            continue  # resume: skip completed & unchanged
        q.append(p)
    if args.limit:
        q = q[: args.limit]
    return q


def main():
    args = parse_args()
    check_prereqs(args)
    HUNTS.mkdir(parents=True, exist_ok=True)
    status = load_json(HUNTS / "status.json", {})
    index = load_json(HUNTS / "findings_index.json", {})

    programs = prioritize(load_catalog(), args)
    queue = build_queue(programs, status, args)

    if not queue:
        print("Queue is empty (nothing new/changed, or all done). Use --rescan to force.")
        return

    if args.dry_run:
        print(f"Prioritized queue ({len(queue)} programs):\n")
        for i, p in enumerate(queue, 1):
            allow, seeds, _ = compute_scope(p)
            tag = "BBP" if p["bounty"] else "VDP"
            print(f"{i:3}. {p['slug']}  [{tag} max=${p['bounty_max']}]  hosts={len(allow)}  "
                  f"e.g. {', '.join(allow[:3])}")
        print("\n(dry run — nothing executed)")
        return

    log(f"Starting run over {len(queue)} program(s). model={args.model} "
        f"per-target cap=${args.max_budget_usd}/{args.max_turns}t/{args.timeout}s "
        f"global=${args.max_total_usd} verify={'off' if args.no_verify else 'on'} capture={args.capture}")
    discord_send(content=f"🚀 autohunt run started — {len(queue)} program(s) queued.")

    total_cost = 0.0
    for i, p in enumerate(queue, 1):
        if (HUNTS / "STOP").exists():
            log("STOP sentinel present — halting loop.")
            discord_send(content="🛑 autohunt halted (STOP sentinel).")
            break
        if total_cost >= args.max_total_usd:
            log(f"Global budget ${args.max_total_usd} reached — halting.")
            discord_send(content=f"💰 autohunt halted — global budget ${args.max_total_usd} reached.")
            break

        allow, seeds, out_hosts = compute_scope(p)
        log(f"[{i}/{len(queue)}] {p['slug']} — {len(allow)} host(s), max bounty ${p['bounty_max']}")
        status[p["slug"]] = {"status": "running", "started_at": now_iso(),
                             "scope_hash": p["_scope_hash"]}
        save_json(HUNTS / "status.json", status)

        ws = setup_workspace(p, allow, seeds, out_hosts, args)
        cap_proc, cap_env = start_capture(args.capture, ws)
        env = hunter_env(allow, out_hosts, args, cap_env)

        record = {"slug": p["slug"], "started_at": now_iso(), "scope_hash": p["_scope_hash"],
                  "model": args.model}
        try:
            result = run_claude((ws / "run_prompt.md").read_text(), SCHEMA.read_text(), ws, env,
                                args, args.max_turns, args.max_budget_usd)
        finally:
            stop_capture(cap_proc)

        if result.get("_timeout"):
            record.update(status="failed", subtype="timeout")
        elif result.get("_empty") or result.get("_unparsed"):
            record.update(status="failed", subtype="unparsed",
                          error=(result.get("_stderr") or result.get("_unparsed", ""))[:500])
        else:
            cost = float(result.get("total_cost_usd") or 0)
            total_cost += cost
            subtype = result.get("subtype")
            record.update(subtype=subtype, num_turns=result.get("num_turns"),
                          total_cost_usd=cost, session_id=result.get("session_id"))
            structured = extract_structured(result)
            if structured is None:
                # hit a cap (max-turns/budget) or errored before emitting JSON → retryable
                record["status"] = "failed"
                log(f"  no structured output (subtype={subtype}) — marked failed/retryable")
                structured = {}
            else:
                record["status"] = "done"
            verified = [f for f in structured.get("findings", []) if f.get("verified")]
            leads = structured.get("leads_unverified", [])
            record["leads_count"] = len(leads)

            reported = []
            for f in verified:
                # independent verifier (refuter)
                if not args.no_verify:
                    verdict, vcost = run_verifier(f, ws, env, args)
                    total_cost += vcost
                    if verdict and verdict.get("refuted"):
                        log(f"  refuted: {f.get('title')} — {verdict.get('reason','')[:120]}")
                        continue
                # dedupe across runs
                key = f.get("dedupe_key") or f"{f.get('vuln_class')}:{f.get('asset')}:{f.get('endpoint')}"
                if key in index:
                    log(f"  duplicate (already seen): {f.get('title')}")
                    continue
                index[key] = {"slug": p["slug"], "title": f.get("title"),
                              "report_path": f.get("report_path"), "first_seen": now_iso()}
                notify_finding(p, f, ws)
                reported.append({"title": f.get("title"), "severity": f.get("severity"),
                                 "dedupe_key": key, "report_path": f.get("report_path")})

            record["findings_count"] = len(verified)
            record["verified_reported"] = len(reported)
            record["reports"] = reported
            save_json(HUNTS / "findings_index.json", index)
            log(f"  done: {len(verified)} verified, {len(reported)} new reported, "
                f"{len(leads)} leads, ${cost:.2f}")

        record["finished_at"] = now_iso()
        append_ledger(record)
        status[p["slug"]] = {k: record.get(k) for k in
                             ("status", "subtype", "scope_hash", "findings_count",
                              "verified_reported", "total_cost_usd", "session_id")}
        status[p["slug"]]["last_run"] = record["finished_at"]
        save_json(HUNTS / "status.json", status)
        time.sleep(args.throttle)

    log(f"Run complete. Spent ~${total_cost:.2f} across {len(queue)} program(s).")
    discord_send(content=f"✅ autohunt run complete — ~${total_cost:.2f} spent.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted.")
        sys.exit(130)
