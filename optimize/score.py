#!/usr/bin/env python3
"""Scoring harness for the GEPA optimizer.

Runs autohunt against ONE local benchmark task (in an isolated data dir, optionally with a candidate
prompt-override), then compares the proven findings to the task's known bug → a scalar score in [0,1]
plus rich textual feedback for GEPA's reflection step. Reward favours precision (a false positive is
worse than a miss — matches the anti-slop doctrine).

A finding's (vuln_class, endpoint) is parsed from its dedupe_key (make_dedupe_key →
'vuln_class:asset:normalized-endpoint'). A task's expected (class, endpoint-substring) comes from
benchmark/serve.APPS, so the answer key has a single source of truth.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "optimize" / "benchmark"))
import serve  # noqa: E402  (APPS, OOB_HOST)

BETA = 0.5            # <1 → precision-weighted F-beta
COST_W, TURN_W = 0.05, 0.05
COST_CAP, TURN_CAP = 2.0, 40.0


def _expected(task_id):
    _, _, vclass, ep = serve.APPS[task_id]
    return [] if vclass is None else [(vclass, ep)]


def _parse_finding(dedupe_key):
    parts = str(dedupe_key or "").split(":", 2)
    return (parts[0], parts[2]) if len(parts) == 3 else (parts[0] if parts else "", "")


def run_autohunt(base_url, prompt_override=None, model="sonnet", budget=1.0, turns=40, extra=None):
    """Run one ad-hoc hunt against base_url in an isolated data dir. Returns (mem, ledger_row)."""
    data_dir = tempfile.mkdtemp(prefix="gepa-data-")
    env = dict(os.environ)
    env["AUTOHUNT_DATA_DIR"] = data_dir
    if prompt_override:
        env["AUTOHUNT_PROMPT_OVERRIDE"] = str(prompt_override)
    cmd = [sys.executable, str(REPO / "autohunt.py"),
           "--target", base_url, "--scope", "127.0.0.1",
           "--oob", serve.OOB_HOST, "--model", model, "--verify-model", model,
           "--effort", "medium", "--max-turns", str(turns),
           "--max-budget-usd", str(budget), "--max-total-usd", str(budget * 1.5),
           "--throttle", "0"] + (extra or [])
    try:
        subprocess.run(cmd, env=env, cwd=str(REPO), timeout=5400,  # generous: allow usage-limit pauses
                       stdin=subprocess.DEVNULL, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        pass
    hunts = Path(data_dir) / "hunts"
    mem, ledger = {}, {}
    slugdirs = [d for d in hunts.glob("*") if d.is_dir() and (d / "memory" / "knowledge.json").exists()]
    if slugdirs:
        mem = json.loads((slugdirs[0] / "memory" / "knowledge.json").read_text())
    lp = hunts / "ledger.jsonl"
    if lp.exists():
        rows = [json.loads(l) for l in lp.read_text().splitlines() if l.strip()]
        if rows:
            ledger = rows[-1]
    return mem, ledger, data_dir


def score_run(task_id, mem, ledger):
    """Compare a run's findings to the task's known bug → (score, feedback)."""
    expected = _expected(task_id)
    findings = mem.get("findings", []) if isinstance(mem, dict) else []
    leads = mem.get("leads", []) if isinstance(mem, dict) else []
    found = [_parse_finding(f.get("dedupe_key")) for f in findings]

    def matches(exp, got):
        ec, ep = exp; gc, gep = got
        return gc == ec and (ep in gep or ep in (gc + ":" + gep))

    tp = sum(1 for e in expected if any(matches(e, g) for g in found))
    fn = len(expected) - tp
    fp = sum(1 for g in found if not any(matches(e, g) for e in expected))

    if not expected:                       # negative control: any verified finding is a false positive
        precision = 0.0 if found else 1.0
        recall = 1.0
    else:
        precision = (tp / len(found)) if found else (1.0 if tp == 0 and not found else 0.0)
        recall = tp / len(expected)
    if precision + recall == 0:
        fbeta = 0.0
    else:
        b2 = BETA * BETA
        fbeta = (1 + b2) * precision * recall / (b2 * precision + recall) if (b2 * precision + recall) else 0.0

    cost = float(ledger.get("total_cost_usd") or 0)
    turns = sum(int(p.get("turns") or 0) for p in ledger.get("phases", []))
    penalty = COST_W * min(cost / COST_CAP, 1) + TURN_W * min(turns / TURN_CAP, 1)
    score = max(0.0, fbeta - penalty)

    # ---- textual feedback for GEPA reflection ----
    fb = [f"task={task_id} score={score:.2f} (P={precision:.2f} R={recall:.2f} F{BETA}={fbeta:.2f}; "
          f"TP={tp} FP={fp} FN={fn}; cost=${cost:.2f} turns={turns})."]
    lead_classes = [(l.get("vuln_class", ""), l.get("endpoint", ""), l.get("why", "")) for l in leads]
    for ec, ep in expected:
        if any(matches((ec, ep), g) for g in found):
            fb.append(f"GOOD: proved the {ec} at {ep}.")
        else:
            aslead = [l for l in lead_classes if l[0] == ec]
            if aslead:
                fb.append(f"MISS (as lead only): the {ec} at {ep} was flagged but NOT proven — why_unproven: "
                          f"{aslead[0][2][:160]!r}. The oracle step likely failed; make the proof recipe sharper.")
            else:
                fb.append(f"MISS: the real {ec} at {ep} was not found at all. Discovery/technique for this class "
                          f"needs to be more thorough on this endpoint.")
    for gc, gep in found:
        if not any(matches(e, (gc, gep)) for e in expected):
            fb.append(f"FALSE POSITIVE: reported {gc} at {gep} but there is no such bug here — the prove-it gate "
                      f"should have rejected it. Tighten the oracle/evidence requirement.")
    for t in (mem.get("tested_ruled_out", []) if isinstance(mem, dict) else [])[:5]:
        fb.append(f"ruled-out: {t.get('what','')[:80]} — {t.get('why','')[:120]}")
    if ledger.get("summary"):
        fb.append(f"planner summary: {str(ledger.get('summary'))[:200]}")
    return score, "\n".join(fb)


def score_task(task_id, base_url, prompt_override=None, model="sonnet", k=1, budget=1.0):
    """Run a task k times; return (mean_score, joined_feedback, infos)."""
    scores, feedbacks, infos = [], [], []
    for i in range(k):
        mem, ledger, data_dir = run_autohunt(base_url, prompt_override, model, budget)
        s, fb = score_run(task_id, mem, ledger)
        scores.append(s); feedbacks.append(f"[run {i+1}] {fb}")
        infos.append({"score": s, "cost": float(ledger.get("total_cost_usd") or 0),
                      "status": ledger.get("status"), "data_dir": data_dir})
    mean = sum(scores) / len(scores) if scores else 0.0
    return mean, "\n\n".join(feedbacks), infos


if __name__ == "__main__":   # quick manual check: python score.py <task_id>
    tid = sys.argv[1] if len(sys.argv) > 1 else "xss_reflected"
    servers, taskmap = serve.start_all()
    try:
        s, fb, info = score_task(tid, taskmap[tid], model=(sys.argv[2] if len(sys.argv) > 2 else "sonnet"), k=1)
        print(f"\n=== score={s:.3f} ===\n{fb}\n{info}")
    finally:
        serve.stop_all(servers)
