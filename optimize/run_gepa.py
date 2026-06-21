#!/usr/bin/env python3
"""Drive GEPA over autohunt's prompt files against the local benchmark.

Run with the optimize venv:  optimize/.venv/bin/python optimize/run_gepa.py [flags]

  --components  comma list of component keys to optimize, or "all"  (default: hunter only)
  --train/--val comma task ids (val = held-out)                     (default: xss_reflected / ssti)
  --budget      max_metric_calls (each call = one full hunt ≈ $0.5-1, minutes)
  --model       rollout model (sonnet=cheap search; opus=final)     (default: sonnet)

Writes result.best_candidate to optimize/out/<key> (NOT over the live files) and prints a
baseline-vs-optimized comparison on the held-out tasks. Adoption is a manual, diff-reviewed step.
"""
import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "optimize"))
sys.path.insert(0, str(REPO / "optimize" / "benchmark"))
import serve                                  # noqa: E402
import gepa                                   # noqa: E402
from adapter import AutohuntAdapter, load_seed, component_keys, stage  # noqa: E402
from reflect_lm import make_reflection_lm     # noqa: E402
from score import score_task                  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--components", default="agents/subagents/hunter.md")
    ap.add_argument("--train", default="xss_reflected")
    ap.add_argument("--val", default="ssti")
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--reflection-model", default="opus")
    ap.add_argument("--k", type=int, default=1)
    ap.add_argument("--budget", type=int, default=6)
    ap.add_argument("--minibatch", type=int, default=1)
    args = ap.parse_args()

    keys = component_keys() if args.components == "all" else [k for k in args.components.split(",") if k]
    seed = load_seed(keys)
    train = [{"id": t} for t in args.train.split(",") if t]
    val = [{"id": t} for t in args.val.split(",") if t]
    print(f"optimizing {len(keys)} component(s): {keys}")
    print(f"train={[i['id'] for i in train]} val={[i['id'] for i in val]} "
          f"budget={args.budget} model={args.model} reflection={args.reflection_model}")

    servers, taskmap = serve.start_all()
    try:
        adapter = AutohuntAdapter(taskmap, model=args.model, k=args.k, budget=1.0)
        res = gepa.optimize(
            seed_candidate=seed, trainset=train, valset=val, adapter=adapter,
            reflection_lm=make_reflection_lm(args.reflection_model),
            candidate_selection_strategy="pareto",
            reflection_minibatch_size=args.minibatch,
            max_metric_calls=args.budget, use_merge=False,
        )
        best = res.best_candidate
        out = REPO / "optimize" / "out"
        out.mkdir(parents=True, exist_ok=True)
        for k, v in best.items():
            p = out / k
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(v)
        (out / "_result.json").write_text(json.dumps(
            {"components": list(best.keys()), "val": [i["id"] for i in val]}, indent=2))
        print(f"\nbest_candidate ({len(best)} files) → {out}")

        print("\n=== held-out comparison (baseline vs optimized) ===")
        ov = tempfile.mkdtemp(prefix="gepa-best-")
        stage(best, ov)
        try:
            for inst in val:
                tid = inst["id"]
                bs, _, _ = score_task(tid, taskmap[tid], prompt_override=None, model=args.model, k=args.k)
                os_, _, _ = score_task(tid, taskmap[tid], prompt_override=ov, model=args.model, k=args.k)
                flag = "↑" if os_ > bs + 1e-6 else ("=" if abs(os_ - bs) <= 1e-6 else "↓ REGRESSION")
                print(f"  {tid:16} baseline={bs:.3f}  optimized={os_:.3f}  {flag}")
        finally:
            shutil.rmtree(ov, ignore_errors=True)
    finally:
        serve.stop_all(servers)


if __name__ == "__main__":
    main()
