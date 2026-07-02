---
name: xs-leaks
description: "Use when the user is testing for cross-site leaks (XS-Leaks): inferring cross-origin state via side channels — frame counting (window.length), error-event oracles (onload/onerror on script/img/link/iframe/object), timing attacks (connection-pool / socket exhaustion, Performance API / Resource Timing, execution timing), browser-cache probing, navigation oracles (redirect counting, CSP-violation, download detection, history.length), id-attribute focus oracle, element leaks (media/image/getComputedStyle), window references (opener/closed), postMessage broadcasts, and XS-Search binary-search exfiltration. Also when a target lacks COOP / COEP / CORP / X-Frame-Options / frame-ancestors / Fetch-Metadata (Sec-Fetch-*) enforcement and a response's shape, status, or timing differs by victim state (logged-in, admin, search-has-results). Taxonomy per xsleaks.dev."
---

# /xs-leaks - Cross-Site Leaks Hunting

You are assisting **Liodeus (YesWeHack)**. XS-Leaks abuse tiny cross-origin side channels the browser *doesn't* block — the count of frames a page opens, whether a subresource loads or errors, how long a response takes — to infer **private state about the logged-in victim** from an attacker-controlled page. **The bounty is never "there's an oracle" — it's the sensitive fact the oracle exfiltrates**: is the victim an admin, does their inbox contain "acquisition", is a given email registered, what's in their private search results (XS-Search). Deanonymization and private-data disclosure are the paydirt; a status-code oracle with nothing sensitive behind it is informative.

## Core Philosophy

An XS-Leak needs three ingredients — if any is missing, there's no bug:
1. **A state-dependent response** — the target returns something *observably different* depending on the victim's private state (logged-in vs out, admin vs user, search hit vs miss, resource exists vs not).
2. **A cross-origin observable** — that difference leaks through a channel the browser exposes cross-origin: `window.length`, an `onload`/`onerror` event, load timing, cache presence, a `postMessage`, a redirect count.
3. **No isolation defense** — the target is missing `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `X-Frame-Options`/CSP `frame-ancestors`, or `Sec-Fetch-*` origin checks that would sever the channel.

You hunt by finding a state-dependent endpoint (ingredient 1), then walking the oracle catalog (ingredient 2) for one that survives the target's headers (ingredient 3).

## Tooling — this class is browser-side, not `curl`

`curl` **cannot** mount these oracles: they are same-origin-policy side channels that only exist inside a real browser's cross-origin context. Use the **headless browser** (Chrome via `playwright-userN` — needed for `window.length`, `performance` API, event timing, popups; Lightpanda's partial Web-API coverage usually can't). Build a small **attacker HTML page** that frames/opens/loads the target and reads the oracle, serve it from a controlled origin (**HTTPWorkbench MCP** instance or a local file on a *different* origin than the target), and drive it in the headless browser while the target session is authenticated.

`curl` still does the setup: fingerprint the target's isolation headers, enumerate state-dependent endpoints, and confirm the response actually differs by state (fetch the endpoint as user1 vs user2 vs unauth and diff status/length/redirect).

## Step 0 — fingerprint isolation headers (with `curl`)

Read what the target already sends; missing headers = open channels:

| Header | If present | If missing → oracle enabled |
|---|---|---|
| `Cross-Origin-Opener-Policy: same-origin` | popup handle (`opener`/`length`) severed | `window.length` / frame-count / `window.open` / `opener` oracles work |
| `Cross-Origin-Resource-Policy: same-origin` | subresource blocked cross-site | `<img>`/`<script>`/`<link>` error-event oracle works |
| `Cross-Origin-Embedder-Policy: require-corp` | forces CORP on all subresources | error-event / element-leak oracles work |
| `X-Frame-Options` / CSP `frame-ancestors` | can't iframe | iframe frame-counting, id-attribute focus, event oracles work |
| `Sec-Fetch-*` **enforced server-side** (Resource Isolation Policy) | cross-site requests stripped/rejected | request reaches origin → any oracle works |
| `Cache-Control: no-store` on the dynamic response | not cached | (with cache) cache-probing oracle works |
| `Timing-Allow-Origin` absent | no sizes via Performance API | present/`*` → transfer/body sizes leak (sharper cache/redirect timing) |
| SameSite=Strict on session | request unauth cross-site | Lax/None → session rides cross-site, oracles work |

**Fetch-Metadata as a server-side defense:** the header trio only helps if the *origin acts on it*. A Resource Isolation Policy denies when `Sec-Fetch-Site: cross-site` **and** it's not a user-initiated top-level navigation (`Sec-Fetch-Mode: navigate` + `Sec-Fetch-User: ?1`). If the target reflects state regardless of `Sec-Fetch-*`, the check isn't enforced → oracles live. (Fetch-Metadata rides HTTPS only.)

**Browser secure defaults you can't turn off:** HTTP-cache **partitioning** (per top-site) kills the classic cross-site cache probe — but not subdomain requests or top-level navigations. A target shipping COOP+COEP+CORP+`frame-ancestors 'none'`+enforced Fetch-Metadata is largely immune — note it and pivot. Gaps are your entry.

## Oracle catalog (ingredient 2)

Taxonomy follows the **XS-Leaks wiki** (xsleaks.dev — terjanq, NDevTK, et al.). Pick the oracle that survives the target's isolation headers (Step 0).

### Frame counting — `window.length`
The number of subframes (`iframe`/`frame`) in a cross-origin window **is readable cross-origin**. Open the target in a popup or embed it, read `win.length`:
* Search page that renders one result-frame per hit → `window.length` = result count → **XS-Search** (below).
* A page that embeds an extra frame only when logged-in / admin / has-a-profile-field → binary state leak. (Real-world: Facebook, GitHub private-data leaks.)
```js
const w = window.open('https://target/search?q=secret'); // or an <iframe>
setTimeout(() => { leak(w.length); w.close(); }, 1500);
```
Blocked by COOP (popup handle severed) or `X-Frame-Options`/`frame-ancestors` (iframe). **SameSite=Lax still allows the popup navigation**, so Lax alone does not save it.

### Error events — status / content-type / existence
Load the target as a cross-origin subresource; the event that fires leaks a predicate about the response:

| Element | Leaks |
|---|---|
| `<script src>` | HTTP status, response parses as JS |
| `<img>` | status, valid image format |
| `<link rel=stylesheet>` | status, valid CSS |
| `<iframe onload>` | status, content-type |
| `<video>`/`<audio>` | media validity/format |
| `<object data>` / `<embed>` | **fallback renders on error** → existence oracle without JS events |

```js
const s = document.createElement('script');
s.src = 'https://target/api/order/1337';      // exists? admin-only?
s.onload  = () => leak('reached-200-like');
s.onerror = () => leak('error/404/redirect/wrong-type');
document.body.appendChild(s);
```
Blocked by **CORP** (`same-origin`) and **COEP**. Also defeated by unpredictable resource URLs.

### Timing attacks
Response time differs by state (cache hit, DB work on a match, redirect-chain length, request count). Time a `fetch(url,{mode:'no-cors',credentials:'include'})` or an `<img>`/iframe `onload`. Timing is **noisy** — always sample many times and compare against a known-negative baseline. Reliable channels:

* **Connection-pool / socket exhaustion** — the cleanest, most cross-browser timing oracle: the browser has a global socket cap (~256). Open ~255 hanging requests to unrelated hosts to saturate the pool; send the target request on the next socket; then time a probe request to another host — it can't start until a socket frees, i.e. until the *target* request finishes. The probe's delay = the target's response time. No browser bug needed.
* **Performance API (Resource Timing)** — `performance.getEntriesByName(url)` / `getEntries()`:
  * `transferSize === 0 && decodedBodySize > 0` → **served from cache**; `transferSize > 0` → network.
  * A **missing** entry → the request was blocked/redirected (Chromium: blocked-by-`X-Frame-Options` embeds don't appear → framing-protection detector).
  * With `Timing-Allow-Origin: *` you also get body/transfer sizes; without it, only ms-precision duration.
* **Execution / hybrid timing** — measure event-loop or rendering stall the target work induces.

### Cache probing (browser HTTP cache)
Detect whether a state-specific resource is in the victim's cache → leaks "victim visited page X / triggered code path Y". Cleaner than raw timing via the **AbortController error trick**:
```js
async function ifCached(url){
  const c = new AbortController();
  setTimeout(() => c.abort(), 9);                 // abort ~9ms in
  try { await fetch(url,{mode:'no-cors',signal:c.signal}); return true; } // finished < 9ms = cached
  catch { return false; }                          // aborted = network = not cached
}
```
Variants: force an error only on the *cached* copy (malformed `Range`/header), or CORS-origin-reflection (a cached `Access-Control-Allow-Origin` triggers a CORS error when re-fetched from another origin). **HTTP cache partitioning** (per top-site) neutralizes the classic cross-site version — but partitioning does **not** cover subdomains or top-level navigations, so those still leak.

### Navigations
Observe *whether / where* a cross-origin navigation happens:
* **Download detection** — a response with `Content-Disposition: attachment` does **not** navigate the frame (window stays same-origin, readable); a normal render throws cross-origin → distinguishes the two states.
* **Redirect counting** — browsers cap redirects (~20). Pre-burn 19 redirects toward the target; if it adds one more the cap trips with a network error → detects a state-dependent redirect. (Twitter XS-Search: navigation/redirect only fired when a private search had results.)
* **CSP-violation oracle** — host the attacker page under a strict `connect-src`/`form-action`; if the target navigation redirects cross-site it fires a `securitypolicyviolation` event whose `blockedURI` leaks the redirect destination.
* **URL-length / URI-limit** — pad a redirecting URL to one char below the browser limit; a state-dependent extra redirect char overflows → detectable error.
* **`history.length`** — deltas after a scripted navigation leak whether/how many navigations occurred.

### ID attribute (focus oracle)
A URL fragment `#id` auto-focuses the focusable element with that id. Frame the target with `src=…/page#candidateId`; if the element exists it gains focus → your page's `window.onblur` fires. Brute-forcing ids leaks which element rendered (real-world: an OTP/PIN stored as a button `id`).
```js
onblur = () => leak('element #candidateId exists');
const ifr = document.createElement('iframe');
ifr.src = 'https://target/page#secretId';
document.body.appendChild(ifr);
```

### Element leaks (readable cross-origin properties)
Properties of embedded cross-origin content that are readable and vary by state:
* **Media** — `HTMLMediaElement.duration`/`buffered`, `videoWidth`/`videoHeight`, `getVideoPlaybackQuality().totalVideoFrames`.
* **Images** — `naturalWidth`/`height` = 0 (or `img.decode()` rejects) on invalid/blocked load → existence/format oracle.
* **Cross-origin stylesheets** — `getComputedStyle()` reads styles the target applied → infer state-dependent CSS.
* **Scripts** — overwrite a built-in the target script calls (e.g. `Array.prototype.push`) to capture the arguments a cross-origin script passes.
* **PDF viewer / `<object>`** — Chrome PDF params + `<object data=…>fallback</object>` rendering the fallback on error.

### Window references
Cross-origin window handles expose a few readable bits:
* `win.length` (frame count — above).
* `win.opener` — `null` vs defined, and **COOP flips it** (`unsafe-none` vs `same-origin`) → detect COOP/auth state if it's set state-dependently.
* `win.closed`, named-window collisions — leak navigation/existence behavior.

### postMessage broadcasts
A target that `postMessage`s with `targetOrigin = '*'` broadcasts to any embedder/opener. Listen and read private data directly — or use the *presence/absence* of a message ("loaded" only for an existing user) as the oracle:
```js
addEventListener('message', e => leak(e.data));   // no origin check on their send = you receive it
```
This overlaps `/xss` — grep recon's `postMessage` inventory (sender-wildcard-leak pass) and hand execution-capable handlers to `/xss`.

## XS-Search — turn a boolean oracle into data exfiltration

The high-impact escalation. If a search/filter endpoint gives a per-query oracle (frame count, timing, or hit/miss event), **binary-search the victim's private data**:
1. Confirm the oracle distinguishes "search returned ≥1 result" from "0 results" for the *victim's* authenticated data.
2. Query attacker-chosen predicates against the victim's private corpus: `q=creditcard 4111`, `q=email a*`, `q=role:admin`.
3. Character-by-character / prefix binary search to extract a secret token, private message content, or confirm membership.
4. Demonstrate extracting one concrete private value (a real substring of the victim's data) — that's the PoC that makes it a real finding, not a theoretical channel.

## Build the PoC (headless browser)

1. Stand up an attacker origin (HTTPWorkbench instance or a file served on a different host/port than the target).
2. Write the attacker HTML: it opens/embeds the target with `credentials:'include'` semantics (the victim's cookies ride if SameSite allows), reads the chosen oracle, and beacons the leaked bit back to your callback.
3. In the headless browser (`playwright-userN`, Chrome), load the target session as the "victim" identity, then navigate to the attacker page; capture the oracle readings + a screenshot/console log proving the private fact was inferred.
4. Run the negative case too (victim in the *other* state) to show the oracle flips — a one-sided reading proves nothing.

## Verify before reporting

1. **Oracle is real & stable:** ≥N samples, clear separation between the two victim states, negative baseline included (timing especially).
2. **Cross-origin for real:** attacker page is a genuinely different origin from the target; the leak is *not* just a same-origin read.
3. **Session actually rides:** the victim's authenticated cookie is sent on the cross-site request (SameSite=Strict on the session usually kills this — check, and if so the bug likely dies).
4. **Sensitive fact leaked:** you inferred something private (admin status, membership, a private search substring, deanonymization) — not just "a 404 vs 200". Then hand to `/report-yeswehack`.

## Chains & handoff

* `postMessage` to `'*'` leaking data → confirm/exploit in `/xss` (shared recon inventory).
* State oracle that reveals which account is logged in → **deanonymization**; if it enables session/CSRF follow-on → `/csrf` / `/ato`.
* XS-Search extracting a token/reset code → **ATO** → `/ato`.
* Blocked by a WAF on the attacker-page callback → `/waf-bypass`; but note XS-Leak defenses are *response headers* on the target, not a WAF — missing COOP/CORP/`frame-ancestors` is the actual precondition.

## Key Considerations

* **SameSite=Lax (default) is not full protection:** top-level GET navigations still send the cookie, so popup/`window.open` and top-level-navigation oracles often survive Lax. `Strict` on the session cookie is what usually neutralizes the class — always check the cookie's SameSite first.
* The **defense is isolation headers, not input validation** — frame the report around the missing `COOP`/`CORP`/`frame-ancestors`/Fetch-Metadata check and the sensitive state it exposes.
* Chrome behavior is the reference (state partitioning, COOP, cache partitioning evolve) — use `playwright-userN`; verify the oracle on the current headless Chrome, don't assume an old technique still fires.
* Keep impact honest: many XS-Leaks are **medium** (a single-bit state oracle). It becomes **high** when it deanonymizes, reveals admin/role, or (XS-Search) reconstructs private content — lead the report with that fact, at the scale it affects.
* Don't mass-query the victim's search endpoint at scale to brute a secret — prove the extraction on a short known value and stop (the no-mass-enumeration guardrail in `CLAUDE.md` applies to XS-Search too).
