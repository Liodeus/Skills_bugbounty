"""Read-only accessors over the autohunt file contract.

Mirrors the shapes produced by yeswehack_programs.py (catalog) and autohunt.py (hunts):
  <data>/yeswehack/{state.json, CHANGES.md, <slug>/{program.md,scope.md,raw.json}}
  <data>/hunts/{ledger.jsonl, status.json, findings_index.json, cost_report.md, run.log,
                alerts.jsonl, STOP, <slug>/{memory/knowledge.json, report_*.md}}

Nothing here writes. Everything is parameterized by `data_dir` so the dashboard plugs into
any autohunt data directory.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import markdown as md


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _read_text(path: Path) -> str:
    try:
        return path.read_text()
    except Exception:
        return ""


def _iter_jsonl(path: Path):
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except Exception:
        return


def _md(text: str) -> str:
    return md.markdown(text or "", extensions=["tables", "fenced_code", "sane_lists"])


def vuln_class_from_key(key: str) -> str:
    return (key or "").split(":", 1)[0] or "other"


SEVERITIES = ["critical", "high", "medium", "low", "info"]


class DataStore:
    def __init__(self, data_dir: str):
        self.root = Path(data_dir).resolve()
        self.catalog = self.root / "yeswehack"
        self.hunts = self.root / "hunts"

    # ---- low-level ---- #
    def watch_paths(self):
        return {
            "status": self.hunts / "status.json",
            "ledger": self.hunts / "ledger.jsonl",
            "findings": self.hunts / "findings_index.json",
            "alerts": self.hunts / "alerts.jsonl",
            "catalog": self.catalog / "state.json",
            "changes": self.catalog / "CHANGES.md",
        }

    def _catalog_state(self):
        return _load_json(self.catalog / "state.json", {"programs": {}})

    def _status(self):
        return _load_json(self.hunts / "status.json", {})

    def _findings_index(self):
        return _load_json(self.hunts / "findings_index.json", {})

    def _knowledge(self, slug: str):
        return _load_json(self.hunts / slug / "memory" / "knowledge.json", {})

    def _all_knowledge(self):
        out = {}
        if self.hunts.exists():
            for d in self.hunts.iterdir():
                kp = d / "memory" / "knowledge.json"
                if kp.exists():
                    out[d.name] = _load_json(kp, {})
        return out

    def _ledger(self):
        return list(_iter_jsonl(self.hunts / "ledger.jsonl"))

    def _alerts(self):
        return list(_iter_jsonl(self.hunts / "alerts.jsonl"))

    def _raw(self, slug: str):
        return _load_json(self.catalog / slug / "raw.json", {})

    # ---- API surfaces ---- #
    def overview(self):
        cat = self._catalog_state().get("programs", {})
        status = self._status()
        kn = self._all_knowledge()
        sev_counts = defaultdict(int)
        findings_total = 0
        for k in kn.values():
            for f in k.get("findings", []):
                findings_total += 1
                sev_counts[(f.get("severity") or "info").lower()] += 1
        open_leads = sum(1 for k in kn.values() for l in k.get("leads", []) if l.get("status") == "open")
        spent = sum(float(r.get("total_cost_usd") or 0) for r in self._ledger())
        last_run = max((r.get("finished_at") or "" for r in self._ledger()), default="")
        hunted = sum(1 for s in status.values() if s.get("status") == "done")
        return {
            "programs_total": len(cat),
            "programs_hunted": hunted,
            "programs_with_status": len(status),
            "findings_total": findings_total,
            "findings_by_severity": {s: sev_counts.get(s, 0) for s in SEVERITIES},
            "open_leads": open_leads,
            "total_cost_usd": round(spent, 2),
            "last_run": last_run,
            "monitor_alerts": len(self._alerts()),
            "stop": (self.hunts / "STOP").exists(),
        }

    def programs(self):
        cat = self._catalog_state().get("programs", {})
        status = self._status()
        kn = self._all_knowledge()
        rows = []
        for slug, c in cat.items():
            raw = self._raw(slug)
            hosts = len([s for s in (raw.get("scopes") or [])
                         if (s.get("scope_type") if isinstance(s, dict) else "") in ("web-application", "api", "")])
            st = status.get(slug, {})
            k = kn.get(slug, {})
            rows.append({
                "slug": slug,
                "title": c.get("title") or slug,
                "type": c.get("type") or "",
                "bounty": bool(raw.get("bounty")),
                "bounty_max": raw.get("bounty_reward_max") or 0,
                "hosts": hosts,
                "status": st.get("status") or "—",
                "findings": st.get("verified_reported") or len(k.get("findings", [])) or 0,
                "open_leads": sum(1 for l in k.get("leads", []) if l.get("status") == "open"),
                "cost": float(st.get("total_cost_usd") or 0),
                "last_run": st.get("last_run") or "",
                "last_update_at": c.get("last_update_at") or "",
            })
        rows.sort(key=lambda r: (0 if r["bounty"] else 1, -(r["bounty_max"] or 0), r["title"].lower()))
        return rows

    def program(self, slug: str):
        if slug not in self._catalog_state().get("programs", {}) and not (self.hunts / slug).exists():
            return None
        raw = self._raw(slug)
        k = self._knowledge(slug)
        reports = []
        wsdir = self.hunts / slug
        if wsdir.exists():
            reports = sorted(p.name for p in wsdir.glob("report_*.md"))
        runs = [r for r in self._ledger() if r.get("slug") == slug]
        return {
            "slug": slug,
            "program_html": _md(_read_text(self.catalog / slug / "program.md")),
            "scopes": raw.get("scopes") or [],
            "out_of_scope": raw.get("out_of_scope") or [],
            "recon": k.get("recon", {}),
            "leads": k.get("leads", []),
            "tested_ruled_out": k.get("tested_ruled_out", []),
            "findings": k.get("findings", []),
            "monitor_baseline": k.get("monitor_baseline", {}),
            "reports": reports,
            "runs": runs,
        }

    def findings(self):
        out = []
        for slug, k in self._all_knowledge().items():
            for f in k.get("findings", []):
                out.append({
                    "slug": slug,
                    "title": f.get("title"),
                    "severity": (f.get("severity") or "info").lower(),
                    "vuln_class": vuln_class_from_key(f.get("dedupe_key", "")),
                    "report_path": f.get("report_path"),
                    "first_seen": f.get("first_seen"),
                    "dedupe_key": f.get("dedupe_key"),
                })
        order = {s: i for i, s in enumerate(SEVERITIES)}
        out.sort(key=lambda f: (order.get(f["severity"], 99), f.get("first_seen") or ""))
        return out

    def leads(self):
        out = []
        for slug, k in self._all_knowledge().items():
            for l in k.get("leads", []):
                out.append({**l, "slug": slug})
        pr = {"high": 0, "medium": 1, "low": 2}
        out.sort(key=lambda l: (0 if l.get("status") == "open" else 1,
                                pr.get((l.get("priority") or "medium").lower(), 1)))
        return out

    def runs(self):
        return list(reversed(self._ledger()))  # newest first

    def severity_matrix(self):
        """program × severity counts for the heatmap."""
        rows = []
        for slug, k in self._all_knowledge().items():
            counts = defaultdict(int)
            for f in k.get("findings", []):
                counts[(f.get("severity") or "info").lower()] += 1
            if sum(counts.values()):
                rows.append({"slug": slug, **{s: counts.get(s, 0) for s in SEVERITIES}})
        rows.sort(key=lambda r: -sum(r[s] for s in SEVERITIES))
        return rows

    def cost(self):
        by_phase = defaultdict(lambda: {"cost": 0.0, "turns": 0, "in": 0, "out": 0, "n": 0})
        by_program = defaultdict(float)
        by_day = defaultdict(float)
        for r in self._ledger():
            by_program[r.get("slug", "?")] += float(r.get("total_cost_usd") or 0)
            day = (r.get("finished_at") or "")[:10]
            if day:
                by_day[day] += float(r.get("total_cost_usd") or 0)
            for ph in r.get("phases", []) or []:
                b = by_phase[ph.get("name", "?")]
                b["cost"] += float(ph.get("cost") or 0); b["turns"] += ph.get("turns") or 0
                b["in"] += ph.get("in") or 0; b["out"] += ph.get("out") or 0; b["n"] += 1
        return {
            "by_phase": [{"name": k, **v} for k, v in sorted(by_phase.items(), key=lambda x: -x[1]["cost"])],
            "by_program": [{"slug": k, "cost": round(v, 4)} for k, v in sorted(by_program.items(), key=lambda x: -x[1])],
            "by_day": [{"day": k, "cost": round(v, 4)} for k, v in sorted(by_day.items())],
            "total": round(sum(by_program.values()), 2),
        }

    def changes(self):
        return {
            "scope_changes_html": _md(_read_text(self.catalog / "CHANGES.md")),
            "monitor_alerts": list(reversed(self._alerts())),
        }

    def report_html(self, slug: str, filename: str):
        # path-sanitise: must be a report_*.md inside this slug's workspace
        if not filename.startswith("report_") or not filename.endswith(".md") or "/" in filename or "\\" in filename:
            return None
        base = (self.hunts / slug).resolve()
        target = (base / filename).resolve()
        if base not in target.parents or not target.exists():
            return None
        return _md(_read_text(target))
