#!/usr/bin/env python3
"""Sync YesWeHack programs (description + scope) into per-program markdown files.

Pulls every program visible to the authenticated user from api.yeswehack.com and
writes <out-dir>/<slug>/{program.md,scope.md,raw.json}, an INDEX.md and a
CHANGES.md. State is tracked in state.json so re-runs only refetch programs whose
`last_update_at` changed, and scope additions/removals are recorded in CHANGES.md.

Auth (verified against tchenu/yeswehack-sdk):
  POST /login        {email, password}      -> token (2FA off) and/or totp_token
  POST /account/totp {code, token}          -> final bearer token
All requests send `Authorization: Bearer <token>`.
"""

import argparse
import base64
import hashlib
import hmac
import re
import struct
import getpass
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


def _totp_now(secret, digits=6, period=30, t=None):
    """RFC 6238 TOTP (SHA-1) from a base32 secret — for unattended login (no `input`)."""
    s = re.sub(r"\s+", "", secret).upper()
    s += "=" * (-len(s) % 8)
    key = base64.b32decode(s)
    counter = int((time.time() if t is None else t) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

API_BASE = "https://api.yeswehack.com"
USER_AGENT = "yeswehack-programs-sync/1.0 (+Skills_bugbounty)"
TOKEN_SAFETY_MARGIN = 120  # treat token as expired this many seconds before its exp


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def log(msg):
    print(msg, file=sys.stderr)


def esc(s):
    """Escape pipes so values are safe inside markdown tables."""
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def program_kind(p):
    if p.get("bounty"):
        return "Bug Bounty (BBP)"
    if p.get("vdp"):
        return "VDP"
    t = p.get("type") or ""
    if t == "bug-bounty":
        return "Bug Bounty (BBP)"
    if t.startswith("vdp"):
        return "VDP"
    return t.upper() if t else "Unknown"


def bounty_str(d):
    if d.get("bounty"):
        lo = d.get("bounty_reward_min") or 0
        hi = d.get("bounty_reward_max") or 0
        return f"${lo} – ${hi}"
    if d.get("vdp"):
        return "No bounty (VDP)"
    return "—"


def norm_scope(s):
    """Normalize a scope entry (dict or bare string) to (asset, type, criticality)."""
    if isinstance(s, dict):
        return (
            s.get("scope") or "",
            s.get("scope_type_name") or s.get("scope_type") or "—",
            s.get("asset_value") or "—",
        )
    return (str(s), "—", "—")


def scope_sig(scope_list):
    """Stable signature set for a scope array, for diffing across runs."""
    sigs = set()
    for s in scope_list or []:
        if isinstance(s, dict):
            sigs.add(f"{s.get('scope', '')}|{s.get('scope_type', '')}")
        else:
            sigs.add(f"{s}|")
    return sorted(sigs)


# --------------------------------------------------------------------------- #
# YesWeHack API client
# --------------------------------------------------------------------------- #
class YWHClient:
    def __init__(self, token_path, public_only=False, throttle=0.3, non_interactive=False):
        self.non_interactive = non_interactive
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
        self.token_path = token_path
        self.public_only = public_only
        self.throttle = throttle
        self.token = None

    # ---- auth ---- #
    @staticmethod
    def _jwt_exp(token):
        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return int(payload.get("exp", 0))
        except Exception:
            return 0

    def _load_cached_token(self):
        try:
            data = json.loads(self.token_path.read_text())
            token = data.get("token")
            if token and self._jwt_exp(token) - TOKEN_SAFETY_MARGIN > time.time():
                return token
        except Exception:
            pass
        return None

    def _save_cached_token(self, token):
        try:
            self.token_path.write_text(json.dumps({"token": token, "exp": self._jwt_exp(token)}))
            self.token_path.chmod(0o600)
        except Exception as e:
            log(f"[auth] Warning: could not cache token: {e}")

    def _credentials(self):
        email = os.environ.get("YWH_EMAIL")
        password = os.environ.get("YWH_PASSWORD")
        if self.non_interactive:
            if not email or not password:
                raise SystemExit("[auth] non-interactive: set YWH_EMAIL and YWH_PASSWORD "
                                 "(or YWH_PAT, or use --public-only).")
            return email, password
        email = email or input("YesWeHack email: ").strip()
        password = password or getpass.getpass("YesWeHack password: ")
        return email, password

    def _set_token(self, token):
        self.token = token
        self.session.headers["Authorization"] = f"Bearer {token}"

    def authenticate(self, force_reauth=False):
        if self.public_only:
            return
        pat = os.environ.get("YWH_PAT")
        if pat:  # personal access token → use directly, no login/TOTP (fully unattended)
            log("[auth] Using YWH_PAT.")
            self._set_token(pat.strip())
            return
        if not force_reauth:
            cached = self._load_cached_token()
            if cached:
                log("[auth] Reusing cached token.")
                self._set_token(cached)
                return

        email, password = self._credentials()
        resp = self.session.post(
            f"{API_BASE}/login", json={"email": email, "password": password}, timeout=30
        )
        if resp.status_code not in (200, 201):
            raise SystemExit(f"[auth] Login failed: HTTP {resp.status_code} — {resp.text[:300]}")
        data = resp.json()
        token = data.get("token")
        totp_token = data.get("totp_token")

        if not token and totp_token:
            secret = os.environ.get("YWH_TOTP_SECRET")
            if secret:
                code = _totp_now(secret)
                log("[auth] TOTP code generated from YWH_TOTP_SECRET.")
            elif self.non_interactive:
                raise SystemExit("[auth] 2FA required but no YWH_TOTP_SECRET set "
                                 "(non-interactive). Set YWH_TOTP_SECRET or YWH_PAT.")
            else:
                code = input("YesWeHack TOTP code: ").strip()
            resp = self.session.post(
                f"{API_BASE}/account/totp", json={"code": code, "token": totp_token}, timeout=30
            )
            if resp.status_code not in (200, 201):
                raise SystemExit(f"[auth] TOTP failed: HTTP {resp.status_code} — {resp.text[:300]}")
            token = resp.json().get("token")

        if not token:
            raise SystemExit("[auth] No token returned from login/TOTP.")
        self._set_token(token)
        self._save_cached_token(token)
        log("[auth] Authenticated.")

    # ---- requests ---- #
    def get(self, path, params=None, max_tries=4):
        url = path if path.startswith("http") else f"{API_BASE}{path}"
        reauthed = False
        resp = None
        for attempt in range(1, max_tries + 1):
            resp = self.session.get(url, params=params, timeout=30)
            if resp.status_code == 401 and not self.public_only and not reauthed:
                log("[http] 401 — re-authenticating.")
                self.authenticate(force_reauth=True)
                reauthed = True
                continue
            if (resp.status_code == 429 or resp.status_code >= 500) and attempt < max_tries:
                wait = int(resp.headers.get("Retry-After") or min(2 ** attempt, 30))
                log(f"[http] {resp.status_code} on {url} — retry in {wait}s ({attempt}/{max_tries})")
                time.sleep(wait)
                continue
            return resp
        return resp

    def list_programs(self, page_size=100):
        items, page = [], 1
        while True:
            resp = self.get("/programs", params={"page": page, "resultsPerPage": page_size})
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("items", []))
            nb_pages = (data.get("pagination") or {}).get("nb_pages", 1)
            log(f"[list] page {page}/{nb_pages} ({len(items)} programs so far)")
            if page >= nb_pages:
                break
            page += 1
            time.sleep(self.throttle)
        return items

    def get_detail(self, slug):
        resp = self.get(f"/programs/{slug}")
        resp.raise_for_status()
        return resp.json()


# --------------------------------------------------------------------------- #
# Markdown rendering
# --------------------------------------------------------------------------- #
def render_program_md(d):
    slug = d.get("slug", "")
    lines = [
        f"# {d.get('title', slug)}",
        "",
        f"- **Slug**: `{slug}`",
        f"- **Type**: {program_kind(d)}",
        f"- **Bounty**: {bounty_str(d)}",
        f"- **Reports**: {d.get('reports_count') or 0}",
        f"- **Avg first response**: {d.get('average_first_response_time') or '—'}",
        f"- **Last updated**: {d.get('last_update_at') or '—'}",
        f"- **URL**: https://yeswehack.com/programs/{slug}",
    ]
    flags = [f for f in ("disabled", "archived") if d.get(f)]
    if flags:
        lines.append(f"- **State**: ⚠️ {', '.join(flags)}")
    lines.append("")
    for heading, key in (
        ("Description / Rules", "rules"),
        ("Qualifying vulnerabilities", "qualifying_vulnerability"),
        ("Non-qualifying vulnerabilities", "non_qualifying_vulnerability"),
        ("Account access", "account_access"),
    ):
        val = d.get(key)
        if val and str(val).strip():
            lines += [f"## {heading}", "", str(val).strip(), ""]
    return "\n".join(lines).rstrip() + "\n"


def render_scope_md(d):
    title = d.get("title", d.get("slug", ""))
    lines = [f"# Scope — {title}", "", "## In scope", ""]
    in_scope = d.get("scopes") or []
    if in_scope:
        lines += ["| Asset | Type | Criticality |", "|---|---|---|"]
        for s in in_scope:
            asset, t, crit = norm_scope(s)
            lines.append(f"| {esc(asset)} | {esc(t)} | {esc(crit)} |")
    else:
        lines.append("_None listed._")
    lines += ["", "## Out of scope", ""]
    out_scope = d.get("out_of_scope") or []
    if out_scope:
        lines += ["| Asset | Type |", "|---|---|"]
        for s in out_scope:
            asset, t, _ = norm_scope(s)
            lines.append(f"| {esc(asset)} | {esc(t)} |")
    else:
        lines.append("_None listed._")
    return "\n".join(lines).rstrip() + "\n"


def render_index(meta, generated_at):
    total = len(meta)
    bbp = sum(1 for m in meta if "BBP" in m["kind"])
    other = total - bbp
    lines = [
        "# YesWeHack Programs",
        "",
        f"_Synced {generated_at} — {total} programs ({bbp} BBP, {other} VDP/other)._",
        "",
        "| Program | Type | Bounty | In-scope | Last updated |",
        "|---|---|---|---|---|",
    ]
    for m in sorted(meta, key=lambda x: x["title"].lower()):
        link = f"[{esc(m['title'])}](./{m['slug']}/program.md)"
        lines.append(
            f"| {link} | {esc(m['kind'])} | {esc(m['bounty'])} | {m['in_count']} | {esc(m['last_update_at'])} |"
        )
    return "\n".join(lines) + "\n"


def build_changes_section(changes, generated_at):
    parts = []
    if changes["new"]:
        parts.append(f"### New programs ({len(changes['new'])})")
        for title, kind, bounty, n, slug in sorted(changes["new"]):
            parts.append(f"- **{title}** ({kind}, {bounty}) — {n} assets — `./{slug}/`")
    if changes["scope"]:
        parts.append(f"### Scope changes ({len(changes['scope'])})")
        for title, added, removed, slug in sorted(changes["scope"]):
            a = ", ".join(f"`{x.split('|')[0]}`" for x in added) or "none"
            r = ", ".join(f"`{x.split('|')[0]}`" for x in removed) or "none"
            parts.append(f"- **{title}** (`./{slug}/`): +{len(added)} added ({a}), −{len(removed)} removed ({r})")
    if changes["archived"]:
        parts.append(f"### Archived / no longer listed ({len(changes['archived'])})")
        for title, slug in sorted(changes["archived"]):
            parts.append(f"- **{title}** (`{slug}`)")
    if changes["other"]:
        parts.append(f"### Other updates ({len(changes['other'])})")
        for title, slug in sorted(changes["other"]):
            parts.append(f"- **{title}** (`./{slug}/`)")
    if not parts:
        return ""
    return f"## {generated_at}\n\n" + "\n".join(parts) + "\n"


def prepend_changes(changes_path, section):
    header = "# Changes\n"
    old_body = ""
    if changes_path.exists():
        txt = changes_path.read_text()
        old_body = txt[len(header):] if txt.startswith(header) else "\n" + txt
    changes_path.write_text(header + "\n" + section.rstrip() + "\n" + old_body)


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
def load_state(path):
    try:
        return json.loads(path.read_text()).get("programs", {})
    except Exception:
        return {}


def save_state(path, programs, generated_at):
    # atomic write so a crash can't truncate the catalog (autohunt hard-fails on corrupt state.json)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps({"generated_at": generated_at, "programs": programs}, indent=2, ensure_ascii=False))
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args():
    default_out = Path(__file__).resolve().parent / "data" / "yeswehack"
    p = argparse.ArgumentParser(description="Sync YesWeHack programs (scope + description) to markdown.")
    p.add_argument("--out-dir", default=str(default_out), help=f"Output directory (default: {default_out})")
    p.add_argument("--public-only", action="store_true", help="Anonymous; public programs only (no login).")
    p.add_argument("--force", action="store_true", help="Refetch/rewrite all programs, ignore last_update_at.")
    p.add_argument("--page-size", type=int, default=100, help="Programs per list page (default 100).")
    p.add_argument("--throttle", type=float, default=0.3, help="Seconds between detail calls (default 0.3).")
    p.add_argument("--limit", type=int, default=0, help="Only process the first N programs (testing).")
    p.add_argument("--re-auth", action="store_true", help="Ignore cached token; force fresh login + TOTP.")
    p.add_argument("--non-interactive", action="store_true",
                   help="Never prompt — require YWH_EMAIL/PASSWORD + YWH_TOTP_SECRET (or YWH_PAT). "
                        "Auto-enabled when stdin is not a TTY.")
    return p.parse_args()


def main():
    args = parse_args()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    state_path = out_dir / "state.json"
    token_path = out_dir / ".token.json"

    old_state = load_state(state_path)
    non_interactive = args.non_interactive or not sys.stdin.isatty()
    client = YWHClient(token_path, public_only=args.public_only, throttle=args.throttle,
                       non_interactive=non_interactive)
    client.authenticate(force_reauth=args.re_auth)

    programs = client.list_programs(page_size=args.page_size)
    if args.limit:
        programs = programs[: args.limit]

    listed_slugs, new_state, index_meta = set(), {}, []
    changes = {"new": [], "scope": [], "other": [], "archived": []}
    counts = {"new": 0, "updated": 0, "unchanged": 0, "failed": 0}

    for i, item in enumerate(programs, 1):
        slug = item.get("slug")
        if not slug:
            continue
        listed_slugs.add(slug)
        title = item.get("title", slug)
        last_update = item.get("last_update_at")
        prev = old_state.get(slug)
        changed = args.force or prev is None or prev.get("last_update_at") != last_update

        if not changed:
            counts["unchanged"] += 1
            new_state[slug] = prev
            index_meta.append(_index_row(slug, prev, item))
            continue

        log(f"[fetch] ({i}/{len(programs)}) {slug}")
        try:
            detail = client.get_detail(slug)
        except requests.HTTPError as e:
            counts["failed"] += 1
            log(f"[warn] {slug}: detail fetch failed ({e}); keeping previous data")
            if prev:
                new_state[slug] = prev
                index_meta.append(_index_row(slug, prev, item))
            continue

        # The list item carries fields the detail omits (last_update_at,
        # average_first_response_time); merge, letting the detail's truthy values win.
        meta = dict(item)
        meta.update({k: v for k, v in detail.items() if v not in (None, "", [])})

        prog_dir = out_dir / slug
        prog_dir.mkdir(parents=True, exist_ok=True)
        (prog_dir / "program.md").write_text(render_program_md(meta))
        (prog_dir / "scope.md").write_text(render_scope_md(detail))
        (prog_dir / "raw.json").write_text(json.dumps(detail, indent=2, ensure_ascii=False))

        in_sig = scope_sig(detail.get("scopes"))
        entry = {
            "title": detail.get("title", title),
            "type": detail.get("type", item.get("type")),
            "kind": program_kind(detail),
            "bounty": bounty_str(detail),
            "last_update_at": last_update,
            "in_scope": in_sig,
            "out_of_scope": scope_sig(detail.get("out_of_scope")),
        }
        new_state[slug] = entry
        index_meta.append(_index_row(slug, entry, item))

        if prev is None:
            counts["new"] += 1
            changes["new"].append((entry["title"], entry["kind"], entry["bounty"], len(in_sig), slug))
        else:
            counts["updated"] += 1
            added = sorted(set(in_sig) - set(prev.get("in_scope", [])))
            removed = sorted(set(prev.get("in_scope", [])) - set(in_sig))
            if added or removed:
                changes["scope"].append((entry["title"], added, removed, slug))
            else:
                changes["other"].append((entry["title"], slug))

        time.sleep(args.throttle)

    for slug, prev in old_state.items():
        if slug not in listed_slugs:
            changes["archived"].append((prev.get("title", slug), slug))

    generated_at = now_iso()
    (out_dir / "INDEX.md").write_text(render_index(index_meta, generated_at))
    save_state(state_path, new_state, generated_at)

    section = build_changes_section(changes, generated_at)
    if section:
        prepend_changes(out_dir / "CHANGES.md", section)

    print(
        f"\nDone. new={counts['new']} updated={counts['updated']} "
        f"unchanged={counts['unchanged']} archived={len(changes['archived'])} failed={counts['failed']}"
    )
    print(f"Output: {out_dir}")


def _index_row(slug, entry, item):
    entry = entry or {}
    return {
        "slug": slug,
        "title": entry.get("title") or item.get("title", slug),
        "kind": entry.get("kind") or program_kind(item),
        "bounty": entry.get("bounty") or bounty_str(item),
        "in_count": len(entry.get("in_scope", [])),
        "last_update_at": entry.get("last_update_at") or item.get("last_update_at") or "—",
    }


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nInterrupted.")
        sys.exit(130)
