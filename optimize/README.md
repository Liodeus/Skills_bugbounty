# optimize/ — GEPA prompt optimizer for autohunt

Uses [GEPA](https://github.com/gepa-ai/gepa) (reflective prompt evolution + Pareto selection) to
improve autohunt's prompt files by **measuring** them against a deterministic local benchmark — not
by guessing. Runs on the Claude **subscription** (rollouts and the reflection LM both shell to
`claude -p`; no API key).

## What gets optimized
Each prompt file is one GEPA "component": `autohunt/doctrine.md`, `autohunt/verifier.md`,
`autohunt/agents/{planner,monitor-triage}.md`, `autohunt/agents/subagents/{recon,hunter}.md`, and the
13 `SKILLS/*/SKILL.md` (19 total). Candidates run via `AUTOHUNT_PROMPT_OVERRIDE` — **the live files are
never touched** during a run.

## How it scores (the metric must be deterministic to be valid)
`benchmark/serve.py` hosts tiny local vulnerable apps on `127.0.0.1`, one provable bug each
(reflected/DOM XSS, SQLi, SSRF→OOB/metadata mock, SSTI, cmdi, secret-in-JS) plus a **negative**
control app. `score.py` runs autohunt against a task, compares the *proven* findings (parsed from the
real `make_dedupe_key`) to the known bug → **precision-weighted F-beta − cost/turns**, and synthesizes
textual feedback (missed bug / false positive / refuter reason / why_unproven) for GEPA's reflection.
DOM-XSS uses the real `xss-confirm.js` exit code as ground truth.

## Setup
```bash
python3 -m venv optimize/.venv
optimize/.venv/bin/pip install -r requirements-optimize.txt
./install_tools.sh          # recon tools + node Playwright/Chromium (the hunts need them)
```

## Run
```bash
# smoke (one component, tiny budget) — proves the loop, ~minutes, a few $ of usage:
optimize/.venv/bin/python optimize/run_gepa.py \
  --components agents/subagents/hunter.md --train xss_reflected --val ssti --budget 4

# full build (all 19 components) — heavy: each metric call is a full hunt:
optimize/.venv/bin/python optimize/run_gepa.py --components all \
  --train xss_reflected,sqli,ssrf,cmdi,secret --val xss_dom,ssti,safe \
  --budget 150 --model sonnet --reflection-model opus
```
Outputs go to `optimize/out/<component>` (gitignored) with a baseline-vs-optimized held-out comparison.

## Cost / caveats
- **Each metric call = one full hunt** (~$0.5–1, minutes). Budget accordingly; use `--model sonnet`
  for search, validate finalists on opus. `--k` repeats per candidate denoise agent stochasticity.
- **Toy apps ≠ real targets.** The negative control + held-out split + precision weighting fight
  overfitting, but **adoption is manual**: review `optimize/out/*` diffs and copy only sensible,
  non-regressing edits into the live files, then commit. Nothing is auto-adopted.
- Benchmark is `127.0.0.1`-only; no external traffic.

## Files
`benchmark/serve.py` (apps + OOB/metadata mock) · `score.py` (metric + feedback) ·
`adapter.py` (GEPAAdapter, component↔file map, candidate staging) · `reflect_lm.py` (subscription
reflection LM) · `run_gepa.py` (driver). Hooks in `autohunt.py`: `AUTOHUNT_PROMPT_OVERRIDE`,
`AUTOHUNT_DATA_DIR`.
