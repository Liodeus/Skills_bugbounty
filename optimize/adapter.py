#!/usr/bin/env python3
"""GEPAAdapter that optimizes autohunt's prompt files against the local benchmark.

A "component" is one prompt file, keyed by its path in the AUTOHUNT_PROMPT_OVERRIDE mirror layout
(doctrine.md, verifier.md, agents/..., SKILLS/<name>/SKILL.md). evaluate() stages a candidate into a
temp override dir (full repo tree copied, then candidate files overwritten — so resources/unoptimized
prompts stay at baseline) and runs each benchmark task through score.py.
"""
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "optimize"))
from score import score_task  # noqa: E402
from gepa.core.adapter import GEPAAdapter, EvaluationBatch  # noqa: E402

# component key (override-relative path) -> repo source path.
# SKILLS/* live at the repo root; doctrine.md/verifier.md/agents/* live under autohunt/.
def _repo_path(key):
    return (REPO / key) if key.startswith("SKILLS/") else (REPO / "autohunt" / key)


def component_keys():
    keys = ["doctrine.md", "verifier.md", "agents/planner.md", "agents/monitor-triage.md",
            "agents/subagents/recon.md", "agents/subagents/hunter.md"]
    keys += [f"SKILLS/{d.name}/SKILL.md" for d in sorted((REPO / "SKILLS").iterdir())
             if d.is_dir() and (d / "SKILL.md").exists()]
    return keys


def load_seed(keys=None):
    """Read current prompt files into a {component_key: text} seed candidate."""
    return {k: _repo_path(k).read_text() for k in (keys or component_keys())}


def stage(candidate, ov):
    """Materialize a full prompt mirror at `ov`: baseline repo trees + candidate overwrites."""
    ov = Path(ov)
    if ov.exists():
        shutil.rmtree(ov)
    ov.mkdir(parents=True)
    shutil.copytree(REPO / "SKILLS", ov / "SKILLS")
    shutil.copytree(REPO / "autohunt" / "agents", ov / "agents")
    shutil.copy(REPO / "autohunt" / "doctrine.md", ov / "doctrine.md")
    shutil.copy(REPO / "autohunt" / "verifier.md", ov / "verifier.md")
    for key, text in candidate.items():           # candidate may be a subset; overwrite those
        p = ov / key
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return ov


class AutohuntAdapter(GEPAAdapter):
    def __init__(self, taskmap, model="sonnet", k=1, budget=1.0):
        self.taskmap = taskmap      # {task_id: base_url}
        self.model = model
        self.k = k
        self.budget = budget

    def evaluate(self, batch, candidate, capture_traces=False):
        ov = tempfile.mkdtemp(prefix="gepa-ov-")
        stage(candidate, ov)
        outputs, scores, trajs = [], [], []
        try:
            for inst in batch:
                tid = inst["id"]
                s, fb, _info = score_task(tid, self.taskmap[tid], prompt_override=ov,
                                          model=self.model, k=self.k, budget=self.budget)
                outputs.append({"task": tid, "score": s, "feedback": fb})
                scores.append(s)
                trajs.append({"task": tid, "score": s, "feedback": fb})
        finally:
            shutil.rmtree(ov, ignore_errors=True)
        return EvaluationBatch(outputs=outputs, scores=scores,
                               trajectories=(trajs if capture_traces else None))

    def make_reflective_dataset(self, candidate, eval_batch, components_to_update):
        trajs = eval_batch.trajectories or []
        recs = {}
        for comp in components_to_update:
            recs[comp] = [{
                "Inputs": {"task": t["task"], "note": "autohunt run against a local app with one known bug"},
                "Generated Outputs": f"score={t['score']:.2f}",
                "Feedback": t["feedback"],
            } for t in trajs] or [{"Inputs": {}, "Generated Outputs": "", "Feedback": "no runs in minibatch"}]
        return recs
