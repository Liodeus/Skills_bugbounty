# Client-Side Template Injection (CSTI) — AngularJS, Vue, React

Read this when user-controlled data lands **inside a framework-managed template binding**
rather than a plain HTML sink. Frameworks that compile templates in the browser (AngularJS,
client-rendered Vue) can be talked into executing expressions; frameworks that auto-escape
text (Vue v3, React) still have explicit "render raw HTML" sinks. CSTI often evades string
WAFs because the payload is framework expression syntax (`{{ }}`), not `<script>`.

Companion to `/xss` Chain 6 (AngularJS) and Chain 12. Reuses the framework sink regexes in
[`dom-sinks.txt`](../recon/dom-sinks.txt) and the fingerprint from `/recon`.

> First, **fingerprint the framework** (`/recon` step: Angular / Vue / React / Vite detection).
> The whole methodology below is framework-specific — don't guess.

## AngularJS (1.x) — sandbox-escape CSTI

Legacy pages binding user data in an AngularJS context evaluate `{{ }}` expressions. Modern
AngularJS removed the expression sandbox (≥1.6) but many sites still ship old versions where
the sandbox is escapable.

- **Classic execution** (version-dependent): `{{constructor.constructor('alert(1)')()}}`
- **WAF-evading** (no literal `alert`, hex-escaped, no direct identifier — from the field):
  ```
  {{constructor.constructor('pro\x6dpt(1)')()}}
  ```
  `\x6d` decodes to `m` → `prompt`; the constructor-chain reaches `Function` without naming
  `eval`/`alert`. Tune the escape to the target's AngularJS version (sandbox shapes changed
  across 1.0→1.5); keep a version→payload table handy.
- **Bypassing `ng-non-bindable` / `ngSanitize`**: `ng-bind-html`, `$sce.trustAsHtml`,
  `$compile`, and `bypassSecurityTrustHtml` (Angular 2+) each have their own bypass surface —
  see the framework-sink block in [`dom-sinks.txt`](../recon/dom-sinks.txt).

## Vue — template compilation sinks

Vue interpolates `{{ }}` **only inside templates it compiles**. Two distinct cases:

- **Vue 2** — if user input lands inside a string passed to a compiled template (the
  `template:` option, `render`, or `v-html`), `{{ }}` expressions evaluate. Classic gadgets
  reach the constructor chain:
  ```
  {{_vue.constructor.prototype.$options._scopeId='x';...}}     // shape varies; version-specific
  {{constructor.constructor('alert(1)')()}}
  ```
  `v-html` renders raw HTML (script tags don't fire, but event-handler attributes on inert
  elements like `<img onerror>` do) — a separate XSS sink already in `dom-sinks.txt`.
- **Vue 3** — auto-escaping is stricter and there's no global `$options` gadget like v2, but:
  - `v-html` still renders raw HTML (same `<img onerror>`-class sink).
  - **dynamically compiled templates** (`compile()` / a `template:` string built from user
    input) re-introduce full `{{ }}` evaluation — that's the v3 CSTI path.

Detection tells the two apart: `v-html` is in the bundle's attributes; `compile(`/`template:`
in JS is the dynamic-compilation hole.

## React — there is no CSTI, but there's `dangerouslySetInnerHTML`

React escapes `{}` interpolation by design, so classic CSTI does **not** apply. The sink is:

- **`dangerouslySetInnerHTML={{ __html: userInput }}`** — raw HTML injection. `<script>` won't
  fire (React's semantics), but `<img src=x onerror=...>` and other event-handler injection do.
  Already a `dom-sinks.txt` marker (`dangerouslySetInnerHTML`).

So for React: skip `{{ }}` probing entirely; hunt `dangerouslySetInnerHTML` + `href`/`src`
sinks (`javascript:` URIs in href survive React's escaping only if built unsafely).

## Detection

```bash
# framework sinks already shipped in dom-sinks.txt ("Framework sanitizer bypass" block)
ugrep -aErni -f .claude/skills/recon/dom-sinks.txt js/ \
  | ugrep -E 'bypassSecurityTrust|ng-bind-html|\[innerHTML\]|\$compile|v-html|dangerouslySetInnerHTML'
# dynamic template compilation (Vue CSTI prerequisite)
ugrep -aonE "(compile|template|render)\s*(:|\()" js/
```

Cross with the `/recon` framework fingerprint to pick the right payload family before firing.

## Proof (headless Playwright)

Install the sink hook from [`playwright-dom-debugging.md`](playwright-dom-debugging.md) §1,
navigate with the CSTI payload in the binding source, and read `window.__xss.sinks` /
`.taint` — a hit whose `value` carries your marker and whose `stack` points into the framework
proves execution. As everywhere in `/xss`, prove with a visible effect (title set, beacon to
HTTPWorkbench) rather than relying on a headless `alert()`.

## Cross-links

- `/xss` Chain 6 (AngularJS) + Chain 12 (this) — the canonical chain entries.
- [`dom-sinks.txt`](../recon/dom-sinks.txt) framework-sink block — the regex surface.
- `/recon` — framework fingerprint that gates which payload family applies.
