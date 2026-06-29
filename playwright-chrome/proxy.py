"""
mitmproxy script - tags requests with an identity header and strips HTTP/2 forbidden headers.
Only used by the OPTIONAL start.sh upstream-proxy helper; not part of the default headless flow.

Usage (via mitmdump):
    mitmdump -p 8081 --ssl-insecure -s proxy.py --set color=user1
    # add --mode upstream:http://localhost:8090 only if you run your own upstream proxy
"""

import sys
from mitmproxy import http, ctx

# Headers forbidden in HTTP/2 (cause 502 when forwarded to an H2 upstream)
H2_FORBIDDEN = {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection"}

COLOR = "red"

def load(loader):
    loader.add_option("color", str, "red", "PwnFox color to inject (red, blue, green, orange, ...)")

def configure(updates):
    global COLOR
    if "color" in updates:
        COLOR = ctx.options.color

def request(flow: http.HTTPFlow):
    flow.request.headers["X-PwnFox-Color"] = COLOR
    for h in H2_FORBIDDEN:
        flow.request.headers.pop(h, None)
