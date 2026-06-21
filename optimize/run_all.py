#!/usr/bin/env python3
"""Comprehensive GEPA run: optimize every MEASURABLE prompt component against the local benchmark.

Groups (only components the benchmark can validly score, with a real held-out split):
  - agents : the class-agnostic agent prompts (doctrine, verifier, planner, recon, hunter), optimized
             jointly with cross-class train/val (improving these improves ALL classes).
  - skill_*: one SKILL.md per class that has 2 benchmark apps (xss, sql, ssrf, ssti, rce/cmdi),
             trained on the primary app and validated on the variant.

Skills with no benchmark app (idor, rbac, ato, xxe, bxss, waf-bypass, ffuf-skill, report-yeswehack)
are NOT optimized — there's no deterministic signal to score them, and optimizing blind would overfit.

Writes each group's best_candidate to optimize/out/<group>/<component> and a held-out baseline-vs-
optimized comparison to optimize/out/_report.json. Adoption stays a human review step (read the report,
copy clear winners into the live files, commit).

Run:  optimize/.venv/bin/python optimize/run_all.py [--k 2 --heldout-k 2 --budget-scale 1.0]
"""
import argparse
import json
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "optimize"))
sys.path.insert(0, str(REPO / "optimize" / "benchmark"))
import serve                                            # noqa: E402
import gepa                                             # noqa: E402
from adapter import AutohuntAdapter, load_seed, stage   # noqa: E402
from reflect_lm import make_reflection_lm               # noqa: E402
from score import score_task                            # noqa: E402

GROUPS = [
    {"name": "agents",
     "components": ["doctrine.md", "verifier.md", "agents/planner.md",
                    "agents/subagents/recon.md", "agents/subagents/hunter.md"],
     "train": ["xss_reflected", "sqli", "ssrf", "cmdi", "secret"],
     "val": ["xss_reflected2", "sqli2", "ssti", "safe"], "budget": 20},
    {"name": "skill_xss", "components": ["SKILLS/xss/SKILL.md"],
     "train": ["xss_reflected"], "val": ["xss_reflected2", "xss_dom"], "budget": 6},
    {"name": "skill_sql", "components": ["SKILLS/sql/SKILL.md"],
     "train": ["sqli"], "val": ["sqli2"], "budget": 6},
    {"name": "skill_ssrf", "components": ["SKILLS/ssrf/SKILL.md"],
     "train": ["ssrf"], "val": ["ssrf2"], "budget": 6},
    {"name": "skill_ssti", "components": ["SKILLS/ssti/SKILL.md"],
     "train": ["ssti"], "val": ["ssti2"], "budget": 6},
    {"name": "skill_rce", "components": ["SKILLS/rce/SKILL.md"],
     "train": ["cmdi"], "val": ["cmdi2"], "budget": 6},
]


def heldout(taskmap, best, val, model, k):
    ov = tempfile.mkdtemp(prefix="gepa-best-")
    stage(best, ov)
    rows = []
    try:
        for tid in val:
            bs, _, _ = score_task(tid, taskmap[tid], prompt_override=None, model=model, k=k)
            op, _, _ = score_task(tid, taskmap[tid], prompt_override=ov, model=model, k=k)
            rows.append({"task": tid, "baseline": round(bs, 3), "optimized": round(op, 3)})
    finally:
        shutil.rmtree(ov, ignore_errors=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=2)
    ap.add_argument("--heldout-k", type=int, default=2)
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--reflection-model", default="opus")
    ap.add_argument("--budget-scale", type=float, default=1.0)
    ap.add_argument("--only", default="", help="comma group names to run (default: all)")
    args = ap.parse_args()

    groups = [g for g in GROUPS if not args.only or g["name"] in args.only.split(",")]
    out = REPO / "optimize" / "out"
    out.mkdir(parents=True, exist_ok=True)
    refl = make_reflection_lm(args.reflection_model)
    servers, taskmap = serve.start_all()
    report = []
    try:
        for g in groups:
            print(f"\n########## GROUP {g['name']} ##########", flush=True)
            try:
                seed = load_seed(g["components"])
                adapter = AutohuntAdapter(taskmap, model=args.model, k=args.k, budget=1.0)
                res = gepa.optimize(
                    seed_candidate=seed,
                    trainset=[{"id": t} for t in g["train"]],
                    valset=[{"id": t} for t in g["val"]],
                    adapter=adapter, reflection_lm=refl,
                    candidate_selection_strategy="pareto", reflection_minibatch_size=1,
                    max_metric_calls=max(2, int(g["budget"] * args.budget_scale)), use_merge=False)
                best = res.best_candidate
                gdir = out / g["name"]
                for k, v in best.items():
                    p = gdir / k
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(v)
                rows = heldout(taskmap, best, g["val"], args.model, args.heldout_k)
                base = round(sum(r["baseline"] for r in rows) / len(rows), 3)
                opt = round(sum(r["optimized"] for r in rows) / len(rows), 3)
                changed = [k for k in best if best[k] != seed[k]]
                report.append({"group": g["name"], "changed": changed, "heldout": rows,
                               "baseline_avg": base, "optimized_avg": opt, "delta": round(opt - base, 3)})
                print(f"[{g['name']}] baseline={base} optimized={opt} delta={opt-base:+.3f} changed={changed}", flush=True)
            except Exception as e:
                report.append({"group": g["name"], "error": str(e), "trace": traceback.format_exc()[-800:]})
                print(f"[{g['name']}] ERROR: {e}", flush=True)
            (out / "_report.json").write_text(json.dumps(report, indent=2))   # checkpoint after each group
    finally:
        serve.stop_all(servers)

    print("\n=== SUMMARY (held-out baseline → optimized) ===")
    for r in report:
        if "error" in r:
            print(f"  {r['group']:12} ERROR: {r['error'][:60]}")
        else:
            tag = "  <-- ADOPT (review diff)" if r["delta"] > 0.05 and r["changed"] else ""
            print(f"  {r['group']:12} {r['baseline_avg']:.3f} -> {r['optimized_avg']:.3f}  Δ={r['delta']:+.3f}{tag}")
    print(f"\ncandidates + report in {out}")


if __name__ == "__main__":
    main()
