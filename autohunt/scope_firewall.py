#!/usr/bin/env python3
"""PreToolUse hook: scope firewall for autonomous hunts.

Claude Code runs this before every tool call (stdin = hook JSON). For Bash tools
it extracts target hosts from the command and DENIES anything not covered by the
per-target allowlist. Hooks run even under --dangerously-skip-permissions, so this
enforces scope regardless of permission mode. It only ever *denies*; in-scope/
undeterminable commands are passed through to the normal permission flow.

Allowlist comes from env (set by the orchestrator per target):
  AUTOHUNT_SCOPE          space/comma-separated in-scope host patterns
                          (exact 'app.example.com' or wildcard '*.example.com')
  AUTOHUNT_OUT_OF_SCOPE   explicit out-of-scope hosts (always denied)
  AUTOHUNT_SAFE_HOSTS     extra always-allowed hosts (OOB canary, capture proxy, …)

Heuristic, defense-in-depth — not a perfect sandbox. It catches the obvious
"curl https://not-in-scope.com" mistakes; file-fed tool inputs it can't see rely
on the doctrine's scope discipline.
"""
import ipaddress
import json
import os
import re
import sys

ALWAYS_SAFE = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"}
# 169.254.169.254 is the cloud-metadata IP — allowed because confirming SSRF to it
# is a legitimate in-scope oracle (the request originates from the in-scope target).

# Tokens that look host-ish but are tool subcommands/keywords, not targets.
NOISE = {"http", "https", "www"}


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
    # 1) Full URLs
    for m in re.finditer(r"https?://([^\s/'\"|>)\\]+)", command):
        hosts.add(m.group(1))
    # 2) Common target flags: -u/-d/--url/--host/--target/--domain <value>
    for m in re.finditer(
        r"(?:--url|--host|--target|--domain|-u|-d|-H(?=\s+Host))\s+['\"]?([^\s'\"|>)\\]+)",
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
        h = h.rsplit(":", 1)[0] if h.count(":") == 1 and not h.startswith("[") else h
        h = h.lower().rstrip(".")
        if not h or h in NOISE:
            continue
        cleaned.add(h)
    return cleaned


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

    allow = load_patterns("AUTOHUNT_SCOPE")
    deny = load_patterns("AUTOHUNT_OUT_OF_SCOPE")
    safe = set(load_patterns("AUTOHUNT_SAFE_HOSTS")) | ALWAYS_SAFE

    if not allow:
        sys.exit(0)  # no scope configured → don't enforce (manual/dev use)

    offenders = []
    for host in extract_hosts(command):
        if host in safe:
            continue
        # private/loopback IPs are safe (local tooling, OOB listeners)
        try:
            if ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback:
                continue
        except ValueError:
            pass
        if any(host_matches(host, p) for p in deny):
            offenders.append(host)
            continue
        if not any(host_matches(host, p) for p in allow):
            offenders.append(host)

    if offenders:
        reason = (
            "SCOPE FIREWALL: blocked — host(s) not in the program's in-scope allowlist: "
            + ", ".join(sorted(set(offenders)))
            + ". Only test in-scope assets. If this host is actually in scope, it may be a "
            "wildcard the orchestrator didn't expand; note it as a lead instead."
        )
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }))
        sys.exit(0)

    sys.exit(0)  # in scope (or undeterminable) → pass through


if __name__ == "__main__":
    main()
