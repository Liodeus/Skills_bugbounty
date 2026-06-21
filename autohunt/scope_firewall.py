#!/usr/bin/env python3
"""PreToolUse hook: scope + rate firewall for autonomous hunts.

Claude Code runs this before every tool call (stdin = hook JSON), INCLUDING tool calls
made by subagents (the input then carries agent_id/agent_type). For Bash tools it (1)
extracts target hosts and DENIES anything outside the per-target allowlist, and (2)
enforces throughput caps on noisy recon/scan tools so the loop never trips a WAF/IPS.
Hooks run even under --dangerously-skip-permissions, so both are enforced regardless of
permission mode. Denials carry a corrective message so the agent re-issues correctly.

Config comes from env (set by the orchestrator per target):
  AUTOHUNT_SCOPE          space/comma-separated in-scope host patterns
                          (exact 'app.example.com' or wildcard '*.example.com')
  AUTOHUNT_OUT_OF_SCOPE   explicit out-of-scope hosts (always denied)
  AUTOHUNT_SAFE_HOSTS     extra always-allowed hosts (OOB canary, capture proxy, …)
  AUTOHUNT_MAX_RPS        max request-rate flag value allowed for scan tools (e.g. 8)
  AUTOHUNT_MAX_CONC       max concurrency/threads flag value allowed (e.g. 10)

Heuristic, defense-in-depth — not a perfect sandbox. Scope catches obvious off-target
calls; rate enforces that every scan tool carries a conservative rate/concurrency cap.
If the rate envs are unset, rate checks are skipped (safe for manual/dev use).
"""
import ipaddress
import json
import os
import re
import shlex
import sys

ALWAYS_SAFE = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"}
# 169.254.169.254 is the cloud-metadata IP — allowed because confirming SSRF to it
# is a legitimate in-scope oracle (the request originates from the in-scope target).

# Tokens that look host-ish but are tool subcommands/keywords, not targets.
NOISE = {"http", "https", "www"}

# Bare tokens ending in these are filenames (wordlists/outputs), not target hosts.
FILE_EXT = {"txt", "json", "js", "html", "htm", "csv", "md", "log", "xml", "yml", "yaml",
            "conf", "cfg", "ini", "png", "jpg", "jpeg", "gif", "pdf", "zip", "gz", "tar",
            "out", "tmp", "bak", "lst", "dic", "har", "map", "css", "php", "py", "sh"}


def load_patterns(var):
    raw = os.environ.get(var, "")
    out = []
    for tok in re.split(r"[\s,]+", raw.strip()):
        if not tok:
            continue
        # normalise: strip scheme, path, port, userinfo, leading wildcard dot
        tok = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", tok)
        tok = tok.split("/")[0].split("@")[-1]
        tok = tok.rsplit(":", 1)[0] if tok.count(":") == 1 and not tok.startswith("[") else tok
        out.append(tok.lower().rstrip("."))
    return [p for p in out if p]


def host_matches(host, pattern):
    host = host.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    if pattern.startswith("."):
        base = pattern[1:]
        return host == base or host.endswith("." + base)
    return host == pattern


def extract_hosts(command):
    """Best-effort: pull candidate target hosts/IPs out of a shell command."""
    hosts = set()
    # 1) Full URLs (exclude shell metachars so `curl https://x; echo` doesn't grab "x;")
    for m in re.finditer(r"https?://([^\s/'\"|>);&`]+)", command):
        hosts.add(m.group(1))
    # 2) Common target flags: -u/-d/--url/--host/--target/--domain <value>
    for m in re.finditer(
        r"(?:--url|--host|--target|--domain|-u|-d|-H(?=\s+Host))\s+['\"]?([^\s'\"|>);&`]+)",
        command,
    ):
        hosts.add(m.group(1))
    # 3) Bare domain/IP-looking tokens (must contain a dot and a TLD-ish tail or be an IP)
    for m in re.finditer(r"(?<![\w.@/-])((?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,})(?![\w-])", command):
        hosts.add(m.group(1))
    for m in re.finditer(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])", command):
        hosts.add(m.group(1))

    cleaned = set()
    for h in hosts:
        h = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", h)
        h = h.split("/")[0].split("@")[-1].strip("[]")
        h = h.rstrip(";&|`'\")")  # strip trailing shell metachars (defense-in-depth)
        h = h.rsplit(":", 1)[0] if h.count(":") == 1 and not h.startswith("[") else h
        h = h.lower().rstrip(".")
        if not h or h in NOISE:
            continue
        if "." in h and h.rsplit(".", 1)[1] in FILE_EXT:
            continue  # wordlist/output filename, not a host
        cleaned.add(h)
    return cleaned


# Noisy scan/fuzz tools → the flags that cap their request rate and concurrency.
# "rate" empty = tool has no rate flag (enforce concurrency only). Passive OSINT
# tools (subfinder) are intentionally absent → not rate-governed (no target traffic).
RATE_TOOLS = {
    "ffuf":        {"rate": ["-rate"],             "conc": ["-t"]},
    "httpx":       {"rate": ["-rl", "-rate-limit"], "conc": ["-t", "-threads"]},
    "nuclei":      {"rate": ["-rl", "-rate-limit"], "conc": ["-c", "-concurrency"]},
    "katana":      {"rate": ["-rl", "-rate-limit"], "conc": ["-c", "-concurrency"]},
    "dnsx":        {"rate": ["-rl", "-rate-limit"], "conc": ["-t", "-threads"]},
    "feroxbuster": {"rate": ["--rate-limit"],       "conc": ["-t", "--threads"]},
    "gobuster":    {"rate": [],                      "conc": ["-t", "--threads"]},
    "wfuzz":       {"rate": [],                      "conc": ["-t"]},
    "masscan":     {"rate": ["--rate"],             "conc": []},
    "nmap":        {"rate": ["--max-rate"],         "conc": []},
}


def flag_value(toks, aliases):
    """Return (present, value|None) for the first matching flag alias in toks."""
    for i, t in enumerate(toks):
        for a in aliases:
            if t == a and i + 1 < len(toks):
                try:
                    return True, float(toks[i + 1])
                except ValueError:
                    return True, None
            if t.startswith(a + "="):
                try:
                    return True, float(t.split("=", 1)[1])
                except ValueError:
                    return True, None
    return False, None


def rate_violation(segment, max_rps, max_conc):
    try:
        toks = shlex.split(segment)
    except ValueError:
        toks = segment.split()
    if not toks:
        return None
    tool = toks[0].split("/")[-1]
    spec = RATE_TOOLS.get(tool)
    if not spec:
        return None
    if spec["rate"]:
        present, val = flag_value(toks, spec["rate"])
        if not present:
            return f"`{tool}` needs a rate cap — add `{spec['rate'][0]} {int(max_rps)}` (WAF/IPS guard)."
        if val is not None and val > max_rps:
            return f"`{tool}` {spec['rate'][0]}={int(val)} exceeds the rate cap — use `{spec['rate'][0]} {int(max_rps)}` or lower."
    if spec["conc"]:
        present, val = flag_value(toks, spec["conc"])
        if not present:
            return f"`{tool}` needs a concurrency cap — add `{spec['conc'][0]} {int(max_conc)}`."
        if val is not None and val > max_conc:
            return f"`{tool}` {spec['conc'][0]}={int(val)} exceeds the concurrency cap — use `{spec['conc'][0]} {int(max_conc)}` or lower."
    return None


def flood_violation(command, max_conc):
    m = re.search(r"xargs\b[^|;]*?-P\s*=?\s*(\d+)", command)
    if m and int(m.group(1)) > max_conc:
        return f"`xargs -P {m.group(1)}` exceeds the concurrency cap {int(max_conc)}."
    if re.search(r"\bwhile\s+(true|:)(\s|;|$)", command) or re.search(r"\buntil\s+false\b", command):
        return "unbounded loop (`while true` / `while :` / `until false`) is not allowed (DoS/rate risk)."
    for m in re.finditer(r"\bseq\b([^;|&\n]*)", command):
        nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
        if nums and max(nums) > 1000:
            return f"large `seq` range ({max(nums)}) — no mass enumeration (≤5–10 IDs is proof)."
    m = re.search(r"\{\d+\.\.(\d+)\}", command)
    if m and int(m.group(1)) > 1000:
        return f"large brace range up to {m.group(1)} — no mass enumeration."
    return None


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}))
    sys.exit(0)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # can't parse → don't block

    if data.get("tool_name") != "Bash":
        sys.exit(0)

    command = (data.get("tool_input") or {}).get("command", "")
    if not command:
        sys.exit(0)

    # ---- scope check ----
    allow = load_patterns("AUTOHUNT_SCOPE")
    if allow:
        deny_pats = load_patterns("AUTOHUNT_OUT_OF_SCOPE")
        safe = set(load_patterns("AUTOHUNT_SAFE_HOSTS")) | ALWAYS_SAFE
        offenders = []
        for host in extract_hosts(command):
            if host in safe:
                continue
            try:  # private/loopback IPs are safe (local tooling, OOB listeners)
                ip = ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback:
                    continue
            except ValueError:
                pass
            if any(host_matches(host, p) for p in deny_pats):
                offenders.append(host)
            elif not any(host_matches(host, p) for p in allow):
                offenders.append(host)
        if offenders:
            deny("SCOPE FIREWALL: blocked — host(s) not in the in-scope allowlist: "
                 + ", ".join(sorted(set(offenders)))
                 + ". Only test in-scope assets. If a host is actually in scope it may be a wildcard "
                 "the orchestrator didn't expand — note it as a lead instead.")

    # ---- rate check (skipped unless the orchestrator set the caps) ----
    max_rps = float(os.environ.get("AUTOHUNT_MAX_RPS") or 0)
    max_conc = float(os.environ.get("AUTOHUNT_MAX_CONC") or 0)
    if max_rps or max_conc:
        max_rps = max_rps or 8.0
        max_conc = max_conc or 10.0
        for seg in re.split(r"\|\||&&|[|;&\n]", command):
            v = rate_violation(seg, max_rps, max_conc)
            if v:
                deny("RATE FIREWALL: " + v + " (caps protect against WAF/IPS bans).")
        v = flood_violation(command, max_conc)
        if v:
            deny("RATE FIREWALL: " + v)

    sys.exit(0)  # passed scope + rate (or undeterminable) → normal flow


if __name__ == "__main__":
    main()
