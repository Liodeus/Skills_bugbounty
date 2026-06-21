"""mitmproxy addon — hard per-host request-rate ceiling for autohunt `--rate-proxy`.

A true global throttle: regardless of which tool the agent uses, every request through this
proxy is delayed so each host receives at most AUTOHUNT_MAX_RPS requests/second. Complements the
PreToolUse rate firewall (which only governs known scan-tool flags) by enforcing rate at the
network layer. Loaded via `mitmdump -s rate_proxy.py` by autohunt.start_proxy().
"""
import asyncio
import os
import threading
import time
from collections import defaultdict

RPS = float(os.environ.get("AUTOHUNT_MAX_RPS") or 8)
_GAP = (1.0 / RPS) if RPS > 0 else 0.0
_next = defaultdict(float)          # host -> earliest allowed send time
_lock = threading.Lock()


async def request(flow):
    """Per-host token bucket. Reserve a slot under the lock, then await (non-blocking) the gap
    so other hosts/flows aren't serialised."""
    if _GAP <= 0:
        return
    host = flow.request.pretty_host
    with _lock:
        now = time.monotonic()
        slot = max(now, _next[host])
        _next[host] = slot + _GAP
        wait = slot - now
    if wait > 0:
        await asyncio.sleep(wait)
