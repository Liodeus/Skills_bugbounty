---
name: cache-poisoning
description: "Use when the user is testing for web cache poisoning or web cache entanglement: unkeyed input abuse, cache-key manipulation, cache-key injection, cache-key normalization discrepancies, unkeyed query string/params, parameter cloaking, fat-GET, unkeyed request method, internal/blind cache poisoning, secondary cache keys (Vary), cache deception (path-mapping/delimiter/encoded-delimiter/path-traversal), X-Forwarded-* / X-Host poisoning, or CPDoS (cache-poisoned DoS incl. cacheable-redirect DoS). Also when a CDN/reverse-proxy (Cloudflare, Akamai, Fastly, Varnish, CloudFront, nginx) sits in front and a response is shared across users."
---

# /cache-poisoning - Web Cache Poisoning Hunting

You are assisting **Liodeus (YesWeHack)**, whose cache reports include an unkeyed `X-Forwarded-Host` reflected into a cached `<script src>` → stored-XSS-for-everyone, cache deception exposing another user's account page, and a CPDoS that pinned a `400` on the home page for every visitor. **Cache poisoning turns a self-only reflection into a mass, persistent, unauthenticated attack** — one poisoned response is served to every subsequent visitor until the entry expires. That mass factor is what promotes a medium reflection to a critical.

## Core Philosophy

The whole class hinges on one gap: **an input that changes the response but is NOT part of the cache key.** The cache stores your poisoned response under the *victim's* key and replays it to them.

Two families:
- **Cache poisoning** — you inject something (a header, a param, a bad value) that (a) is reflected/impactful in the response AND (b) is *unkeyed*, so the entry is shared. Attacker → cache → victims.
- **Cache deception** — you trick the cache into storing a *dynamic, auth'd* page (someone's account/profile) as if it were a static asset, then read it unauthenticated. Victim → cache → attacker.

Everything below is confirming those two shapes with `curl`.

## First: fingerprint the cache

You can't poison what you can't see. Every attack below needs a **cache oracle** — an explicit HIT/MISS signal so you know when a response came from cache vs origin. Before anything, read the response headers you already captured (or fetch fresh):

| Signal | Meaning |
|---|---|
| `X-Cache: HIT` / `MISS` / `Age: N` | There **is** a cache; `Age` climbing across requests = served from cache |
| `CF-Cache-Status: HIT/MISS/DYNAMIC` | Cloudflare — `DYNAMIC` = not cached (yet) |
| `X-Cache: HIT from ...` (Varnish), `X-Served-By`, `X-Timer` (Fastly) | Vendor fingerprint |
| `Cache-Control: public, max-age=...` | Cacheable; `private`/`no-store` = harder but check anyway (headers lie) |
| `Vary: <header>` | Those headers **are** keyed — pick unkeyed ones instead |
| `Age` resets to 0 after your request | You just wrote the cache — your poison may be live |

### Precondition gate — is there a *shared* cache at all?

**This skill only applies if a cache actually stores and re-serves a response across requests. Confirm that before spending any time on payloads — don't run the rest of the skill on an uncached target.**

The confirmation test (do this first, per URL family):
1. Fetch the target twice with the **same** cache-buster: `curl -s -D- 'https://t/path?cb=<rand>' -o /dev/null` ×2.
2. A cache exists **iff** the 2nd response shows a HIT signal: `X-Cache: HIT`, `CF-Cache-Status: HIT`, a climbing `Age`, or an identical `Age`/timing on the 2nd hit. Vendor headers (`X-Served-By`, `X-Timer`, `Via`) confirm a proxy is in path.
3. **No HIT ever, `CF-Cache-Status: DYNAMIC`/absent, `Cache-Control: no-store`/`private` AND no HIT observed** → there is no shared cache on this endpoint. **Stop — cache poisoning doesn't apply here.** Try other path families / static-looking paths first (a site often caches `/`, `/assets/*`, marketing pages but not `/api/*`); if *nothing* on the in-scope surface caches, pivot to another class/target per the `CLAUDE.md` pivot gate. Don't fuzz unkeyed headers against an origin with no cache — there's no key to poison.

Fingerprinting the cache is not optional groundwork you can skip because a target "looks CDN-fronted": a CDN in front does **not** imply the dynamic endpoint you're testing is cached. Confirm a real HIT on the *specific* endpoint family first.

**Cache-buster discipline:** always test with a unique junk query param (`?cb=<random>`) so you poison *your own* key first and never accidentally serve garbage to real users. Confirm the reflection on your busted key, then — and only then — remove the buster to check if the real key is poisonable.

## The core loop (unkeyed input detection)

1. Request the target twice with a cache-buster: `GET /path?cb=1` — note `X-Cache`/`Age`, confirm it caches (2nd = HIT).
2. Add **one** candidate unkeyed input carrying a canary, keep the same buster:
   `curl 'https://t/path?cb=1' -H 'X-Forwarded-Host: canary.attacker.com'`
3. Look for the canary in the response body (absolute URLs, `<link>`, `<script src>`, redirects, `Location`, meta tags, JSON config).
4. **Prove it's unkeyed:** re-request the *same* `?cb=1` **without** the header. If the canary is *still there* (served from cache), the input is unkeyed → **poisonable**. If it's gone, the header was keyed (or not cached) — move on.
5. Escalate the canary to real impact (XSS payload host, open-redirect, bad resource) and demonstrate a victim request (buster only, no header) returns the poison.

Only step 4 separates a boring reflection from a finding. Never skip it.

## Unkeyed input candidates (test these headers)

Prime suspects — reflected by frameworks/CDNs, usually unkeyed:

* `X-Forwarded-Host` — #1 win; reflected into absolute URLs, password-reset links, `<base>`, canonical tags
* `X-Forwarded-Scheme` / `X-Forwarded-Proto` — force `http` → redirect loop / mixed-content / CPDoS
* `X-Forwarded-For`, `X-Real-IP` — reflected into logs, "your IP" widgets, sometimes ACL bypass
* `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`
* `X-Original-URL`, `X-Rewrite-URL`, `X-Override-URL` — path override → serve/cache a different page
* `X-Forwarded-Port`, `X-Forwarded-Prefix` — resource path rewrite
* Duplicate/ambiguous `Host` header, absolute-URI request line
* Custom app headers surfaced by recon (grep the JS for `req.headers[...]`, `X-` reads)

Use **Param Miner–style** discovery: fuzz a large header wordlist against a cacheable endpoint and diff responses/status/length for any that changes the *cached* output. `ffuf`/`/ffuf-skill` with `-H "FUZZ: canary"` over a header list, watching for reflected canary or status/length shifts.

### Gadgets — where an unkeyed input becomes impact

An unkeyed input is only a bug when it lands in a **gadget**. Once you've confirmed one is unkeyed, hunt for it reflected into:

* **A resource URL** (`<script src>`, `<link href>`, `@import`) → point it at attacker JS/CSS → **XSS/CSS-injection for every visitor** (works cross-page if many pages import the poisoned resource).
* **An open redirect / `Location`** → persistent redirect of all traffic (chain into OAuth/SAML → ATO).
* **A JSONP callback** → poison the callback name → executes.
* **DOM-consumed config/i18n JSON** (e.g. `{"Show more":"<svg onload=alert(1)>"}`) → client-side sink fires (hand to `/xss`).
* **CSS-without-doctype / RPO (relative-path overwrite)** — reflect into a response the browser can be coerced to parse as CSS.
* **A password-reset / verification link host** (via `X-Forwarded-Host`) → ATO.

Kettle's framing: cache context **redefines exploitability** — treat "unexploitable" self-XSS, encoded-only XSS, and resource-reflection as *real* bugs here, because the cache serves your one poisoned response to everyone.

## Cache-key flaws — Web Cache Entanglement (Kettle, 2020)

When no unkeyed *header* pans out, the cache **key computation itself** is the attack surface: any input the origin reads but the key omits (or normalizes away) is poisonable. To hunt these you need a **header-based cache buster** — a keyed header (`Origin`, `Accept-Encoding`, `Cookie`, `Accept`) unique per test — so you can vary the *query* while still isolating your own key (Param Miner injects these; `-H "Origin: cb-<rand>"`).

* **Fully unkeyed query string:** the cache ignores the whole query. Detect: same path, different `?junk` → still HIT (query-based busters won't isolate you — switch to a header buster). Exploit: inject the payload in *any* param — it reflects and is served to all. Bypass query-busting via path normalization: `GET //?<payload>` caches at `GET //`, `GET /%2F?...`, or a `PURGE`-then-repopulate.
* **Unkeyed query params (parameter cloaking):** cache and origin disagree on which params/delimiters count. Concrete bypasses:
  * **Varnish** regex param-strip broken by a `?` inside a value: `GET /?q=help?_=<payload>&!&search=1`
  * **Akamai** double-`?`: `GET /en?x=1?akamai-transform=<payload>`
  * **Ruby on Rails** semicolon delimiter (`;` ≡ `&` to Rails, opaque to the cache): `GET /jsonp?callback=legit&utm_content=x;callback=alert(1)//` — pollute a JSONP callback while the cache keys only the "clean" prefix.
* **Fat GET:** send a request **body on a GET**. The cache keys the URL only; Varnish (no builtin.vcl), Cloudflare, and `Rack::Cache` let the origin read body params. `GET /path` + `Content-Type: application/x-www-form-urlencoded` + `param=<payload>` in the body → the URL-keyed entry now serves body-controlled content.
* **Unkeyed request method:** a `POST` (or exotic verb) cached under a `GET` key. `POST /view/shop` with a poisoning body → later `GET /view/shop` replays the poisoned response (persistent XSS on every visitor).
* **Cache-key normalization discrepancies:** the cache normalizes the key differently than the origin parses the request.
  * Encoded delimiter normalized in-key but not forwarded: `GET /%3fproduct=...` (the `%3f` = `?` is decoded into the key but the origin still treats it as a real query delimiter) → a broken/poisoned redirect cached globally.
  * **Encoded-vs-unencoded XSS collision** (the big one): a browser auto-URL-encodes query metacharacters, but the cache key normalizes encoded ≡ unencoded, so `/?x=%22%3E%3Cscript%3E…` and `/?x="><script>…` **share one key**. You send the raw (executing) form once; every victim whose browser sends the encoded form is served your cached executing response — turns "unexploitable" self-/encoded-XSS into stored XSS for all.
* **Cache-key injection:** the key is built by concatenating a keyed input without escaping its delimiter, so you smuggle payload into the *victim's* key.
  * **Akamai** `__` delimiter: inject via a keyed header — `Origin: '-alert(1)-'__` lands in the key as `...__Origin='-alert(1)-'__`; two requests with the same effective key but your payload → `GET /?x=2__Origin='-alert(1)-'` executes for the victim.
  * **Cloudflare** default key `${header:origin}::${scheme}://${host}${uri}` — historically delimiter-injectable (now escaped); still probe custom key configs.
* **Internal cache poisoning (blind):** application/fragment caches (WP Rocket, WP Super Cache, Rails fragment cache) with no classic key — poison pages you *can't* directly reach (e.g. an intranet whose external access redirects; a broken redirect caches an error page internally). Detect blindly: mixed old/new canaries in one response, your canary surfacing on *uninjected* pages, inconsistent hostnames. **Only ever use attacker-controlled hostnames** for these unintended hits so you never poison real internal pages destructively.

## Cache deception (read others' data)

Trick the cache into storing an authenticated dynamic page as a static asset, then read it as the attacker. (Original class: Omer Gil, 2017; generalized path/delimiter taxonomy: PortSwigger *"Gotta Cache 'em all"*, Black Hat USA 2024.) The root cause is always **cache and origin disagreeing on where the "file" ends** — the origin routes on a prefix and ignores the suffix; the cache sees a static extension and stores.

**Discrepancy types to exploit:**
* **Path mapping** — REST origins ignore trailing path segments the cache treats as a filename: `/user/123/profile/wcd.css` → origin serves `/user/123/profile`, cache stores `…/wcd.css`.
* **Delimiter discrepancy** — framework path delimiters the cache doesn't honor: Spring matrix `;` (`/profile;foo.css` → origin `/profile`), Rails format `.` , others. Origin truncates at the delimiter; cache keeps the full `.css` path.
* **Encoded delimiters** (defeat browser normalization — the victim's browser sends them verbatim): `%3F` (?), `%23` (#), `%00` (null — OpenLiteSpeed), `%0A` (LF), `%09` (tab), `%2F` (/). E.g. `/myaccount%3Fwcd.css` — cache applies `.css` rule to the encoded path, then decodes to `/myaccount?wcd.css` so the origin routes on `/myaccount`.
* **Static-directory path traversal** — encoded dot-segment that the cache stores under a cached dir but the origin resolves back to the dynamic page: `/assets/..%2Fprofile` → cache caches under `/assets` rule, origin resolves to `/profile` and returns private data.

**Detection ladder (with `curl`, authenticated):**
1. Find a page returning **your** private data (`/account`, `/api/me`, `/settings`).
2. Add a junk segment: `/account/aaa` → same private response as `/account`? (origin ignores the suffix — path-mapping candidate).
3. Add a delimiter instead: `/account;aaa` (or `/account%3Faaa`) → still your account page? (delimiter/encoded discrepancy found).
4. Append a **static extension**: `/account;aaa.css` → response now shows `X-Cache: HIT` (2nd request) / static `Cache-Control` → **cached**.
5. Request the **same crafted URL as the attacker / unauthenticated** — victim data comes back → confirmed leak. Prove with a real second identity (victim visits the link → attacker replays it → reads victim PII). **Stop at one record.**

Static extensions CDNs force-cache: `.css .js .png .jpg .svg .ico .woff .txt .json` — vendor-specific; read the `Cache-Control` on a known static file to learn the rule.

## CPDoS (cache-poisoned denial of service)

Poison an *error* into the cache so every visitor gets it:

* **HHO (HTTP Header Oversize):** oversized `X-Forwarded-Host`/junk header → origin `400`, cached as `400` for all.
* **HMC (HTTP Meta Character):** header with `\n`, `\r`, control char → origin errors, cached.
* **HMO (HTTP Method Override):** `X-HTTP-Method-Override: POST` on a GET → error cached.
* **Cacheable-redirect DoS (Kettle):** a cacheable redirect that reflects the query into `Location` and *adds* a char (e.g. Cloudflare `/login?x=abc` → `Location: /login/?x=abc`). Pad the query to the URI length limit so the extra `/` overflows it → the origin errors and the error caches for everyone. (Filters that block query-reflecting redirects are bypassable via URL-encoding the padding — `?x=%6cong…` decodes in `Location` but looks different to the filter.)
* Illegal `X-Forwarded-Scheme`/oversized path → cached redirect loop / 4xx.

CPDoS is DoS-shaped — **prove it without keeping it live**: demonstrate on *your own* cache-buster key that a poisoned error is stored and re-served, capture request+response, and do **not** poison the real (shared) key. One busted-key PoC is enough; never pin an error on a page real users hit (that violates the no-DoS guardrail in `CLAUDE.md`).

## Verify before reporting

1. **Reproduce clean:** poison via `curl` on `?cb=<rand>`, then fetch the same URL **without** the injected input and confirm the poison is served from cache (`Age`>0 / `X-Cache: HIT`).
2. **Second-identity confirm:** the victim view (fresh session / different IP where feasible) must receive the poisoned response — a HIT in *your own* session proves only reflection, not sharing.
3. **Impact confirm:** XSS payload actually executes (load in headless browser, per `/xss`), redirect actually lands on attacker origin, or deception actually returns another user's data.
4. **Scope + safety:** in scope, and you never poisoned a shared key on a real user-facing page. Then hand to `/report-yeswehack`.

## Chains & handoff

* Unkeyed header reflected into a script/resource URL → **XSS for every visitor** → confirm execution in `/xss`, report as stored/mass XSS.
* Unkeyed `X-Forwarded-Host` in a password-reset email link → **ATO** → `/ato`.
* Cache deception exposing account pages → **mass PII / IDOR-shaped leak** → `/report-yeswehack` (critical framing).
* Open-redirect made persistent via cache → chain into OAuth/SAML → `/ato`.
* Behind a WAF/CDN that blocks the header probe → adapt via `/waf-bypass`, never abandon the header fuzz.

## Key Considerations

* **The cache key is the whole game.** Enumerate what's keyed (`Vary`, observed behavior) vs unkeyed; the win is always an *impactful* input that's *unkeyed*.
* Headers lie — a `Cache-Control: private` response can still be cached by a misconfigured CDN rule for a static-looking path. Test, don't assume.
* Poison lifetime = `max-age`/`Age` window; note it in the report (how long victims are affected) — it's part of the impact.
* Always use a cache-buster while hunting; only touch the real shared key to *confirm* poisonability, briefly, then let it expire. Never leave a shared key poisoned.
* Different edge nodes cache independently (geo/PoP) — a HIT for you may be a MISS elsewhere. Map PoPs before claiming reach: Cloudflare's `/cdn-cgi/trace` (and `colo=` field), regional resolver lookups. Note reach honestly rather than over- or under-claiming.
* **Secondary cache keys (`Vary`) narrow the victim pool, rarely kill the bug.** `Vary: User-Agent` → only matching browsers get served (claim a common UA); `Accept-Encoding`, `Accept-Language`, `Cookie` similarly segment — victims sharing that keyed value still get poisoned. Quantify the affected segment in the report.
* **Header-based cache busters** are the key to unmasking *query* flaws: when query params are (fully or partly) unkeyed, a `?cb=` buster can't isolate you — use a unique keyed header (`Origin`, `Accept-Encoding`, `Cookie`) as the buster instead so you can safely vary the query on your own key.
