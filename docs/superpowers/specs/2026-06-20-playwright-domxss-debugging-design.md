# Playwright-Driven DOM-XSS Debugging — Design

**Date:** 2026-06-20
**Status:** Implemented
**Owner:** Liodeus

## Problem

The `/xss` skill's DOM-XSS step (Step 4) was static-analysis only: "grep for sinks,
grep for sources, use DOM Invader/ast-grep." The toolkit ships a Playwright MCP (3
Caido-proxied browser instances) and CLAUDE.md defines Playwright Mode 3 (DOM Hunter)
and Mode 2 (XSS Validator) — but the skill gave the AI no concrete way to *use* the
live browser to find sinks or test postMessage handlers. The AI could open a page but
not instrument it.

## Goal

Give the AI copy-paste, verified browser instrumentation to:
1. **Hook dangerous sinks** (innerHTML/eval/document.write/setAttribute/…) and log every
   write with a stack trace → see what data reaches a sink and from which app code.
2. **Wiretap + fuzz postMessage** — enumerate `message` handlers, flag missing/weak origin
   checks, replay crafted messages and watch which sink fires.
3. **Trace source→sink** — seed a marker into `location.hash`/`search`/`name`/`referrer`,
   confirm it reaches a sink (taint hit) with the proving stack.
4. **Capture console/error/CSP** — spot blocked-but-present sinks (CSP violations) and
   leaked data.

## Key technical constraint: injection timing

DOM-XSS hooks must be installed **before** the code that uses the sink runs. Two vectors:

| Sink/handler fires | Vector | Rationale |
|---|---|---|
| Later event (postMessage, hashchange, click) — common case | `browser_evaluate` snippet | Hook first, then trigger the source. |
| Initial page load | Playwright `initScript` | `browser_evaluate` runs post-load — too late. |

Decision (user-approved): **support both.** Snippets are the default; an opt-in init
script covers load-time sinks.

## Architecture

**Shared data model** — all techniques write to one global for uniform retrieval:
```js
window.__xss = { sinks: [], messages: [], listeners: [], taint: [], csp: [] }
```
Read back via `browser_evaluate` (`JSON.stringify(window.__xss)`) or `browser_console_messages`
(records mirror to console with a `[XSSHOOK]` prefix). Snippet and init-script variants share
the schema, so they're interchangeable downstream.

### New files
- `SKILLS/xss/playwright-dom-debugging.md` — reference doc. Per-technique: *when → snippet →
  read results → interpret (real vs noise)*. Plus a combined workflow and a gotchas list
  (frozen prototypes, Trusted Types, cross-origin frames, re-trigger).
- `playwright-chrome/init/xss-instrument.js` — opt-in pre-load instrument. Same hooks +
  `addEventListener('message')` wiretap (records handler source, `checksOrigin`,
  `weakOriginCheck`) + passive message log + `securitypolicyviolation` capture. Idempotent,
  ring-buffered (cap 500/channel), all hooks `try/catch` and preserve passthrough.

### Edited files
- `SKILLS/xss/SKILL.md` — Step 4 gains a lean pointer to the reference doc (SKILL.md stays
  concise).
- `playwright-chrome/setup.sh` — commented example showing how to add `xss-instrument.js` to
  the `initScript` array (enable = one uncomment + MCP restart). No default behavior change.

## Design choices

- **Stack traces on every sink capture** — the source→sink path is the deliverable, not just
  "a sink exists." `new Error().stack` sliced to the relevant frames.
- **Taint over guesswork** — `window.__xssMarkers` holds seeded markers; any sink value
  containing one is auto-promoted to `window.__xss.taint`, the confirmed-flow channel.
- **Noise control** — framework-internal writes are expected; the doc tells the AI to filter
  by "does the value carry my marker / does the stack point into app code." setAttribute hook
  only flags dangerous attributes (`on*`, `src`, `href`, `srcdoc`, `formaction`, `xlink:href`).
- **Weak-origin-check heuristic** — regex flags `origin` compared with
  `indexOf/includes/startsWith/endsWith/match/RegExp` (the `target.com.evil.com` class).
- **Opt-in, not default** — the init script adds `[XSSHOOK]` console noise to every page, so
  it's not wired into the default configs; the hunter enables it only for load-time sinks.

## Verification

All artifacts validated before commit:
- `node --check` on the init script and all 4 embedded `js` snippets in the doc.
- Functional test (mock DOM): sink hook captures `innerHTML` + `setAttribute(onerror)` + `eval`,
  taint tracks seeded marker through `innerHTML` and `eval`, and passthrough is intact
  (real innerHTML still set, real eval still called).
- Functional test (mock EventTarget): init-script wiretap records exactly the app's 2 message
  handlers (no self-registration), sets `checksOrigin` correctly, flags the 1 weak-origin
  handler, and the passive logger records a received message.

## Out of scope (YAGNI)
- No changes to `bxss` (can link later if the live render-confirm proves useful there).
- No auto-enabling of the init script or auto-restart of the MCP.
- No exfiltration/PoC-hosting helper — the doc points back to Caido + report skill for that.
