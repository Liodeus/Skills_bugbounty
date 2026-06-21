#!/usr/bin/env python3
"""Reflection LM for GEPA, on the Claude SUBSCRIPTION (no API key).

GEPA calls reflection_lm(prompt: str) -> str to propose improved component text from the reflective
dataset. We satisfy that with a `claude -p` subprocess (subscription OAuth, API key dropped).
"""
import json
import os
import subprocess


def make_reflection_lm(model="opus", timeout=420):
    def reflect(prompt: str) -> str:
        env = dict(os.environ)
        env.pop("ANTHROPIC_API_KEY", None)        # use the subscription, not API billing
        env.pop("ANTHROPIC_AUTH_TOKEN", None)
        cmd = ["claude", "-p", prompt, "--model", model,
               "--output-format", "json", "--max-turns", "1",
               "--permission-mode", "bypassPermissions", "--dangerously-skip-permissions",
               "--disallowedTools", "WebFetch", "WebSearch", "Bash"]
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True,
                               timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return ""
        out = (r.stdout or "").strip()
        try:
            return json.loads(out).get("result", "") or ""
        except Exception:
            return out
    return reflect


if __name__ == "__main__":
    f = make_reflection_lm()
    print(f("Reply with exactly the single word: REFLECTOK")[:200])
