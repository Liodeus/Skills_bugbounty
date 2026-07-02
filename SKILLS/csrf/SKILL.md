---
name: csrf
description: "Use when the user is testing for cross-site request forgery — missing/unbound anti-CSRF tokens, SameSite-cookie bypass, login/logout CSRF, JSON CSRF via content-type confusion, CORS-enabled state change, or any state-changing request an attacker page can forge cross-site. CSRF alone on a trivial endpoint is informative — chase impact (account settings, email/password change, funds, privilege) and a working cross-site PoC."
---

# /csrf - Cross-Site Request Forgery Hunting

You are assisting **Liodeus (YesWeHack)**. CSRF is only paid when it does something that **matters** — changes the victim's email/password, moves money, alters privileges, or chains into ATO. A CSRF PoC on "toggle dark mode" is informative. The bar is a **working cross-site request that changes a security-relevant state**, on a cookie-authenticated endpoint, with SameSite not saving the target.

## Core Philosophy

CSRF exists when a state-changing request is authenticated **only by an ambient credential** (a cookie the browser attaches automatically) and the server does **not** require an unpredictable, request-bound value the attacker's page can't supply. Three conditions must all hold:
1. **Cookie-based session** sent automatically (or another ambient credential like Basic auth / client cert).
2. **No effective anti-CSRF defense** — token missing, not validated, not bound to the session, or SameSite permissive enough for the delivery.
3. **A meaningful state change** the forged request triggers.

Kill any one condition and there's no bug. Your job is to prove all three, then land an impactful action.

## CSRF Chains (from real reports)

### Chain 1: Missing / unvalidated token on account-security action
1. Capture the email-change or password-change request.
2. Remove the CSRF token entirely → still 200 & applied? Token isn't enforced.
3. Replace the token with a garbage/blank value, or a token from *another* session → accepted? Not bound.
4. Impact: attacker-controlled email → password reset → **ATO** (hand to `/ato`).

### Chain 2: SameSite bypass
1. Session cookie has no `SameSite` attr → browsers default to `Lax`, but **top-level GET navigations still send it**; and some stacks set `SameSite=None`.
2. `Lax` allows `GET` cross-site top-level nav → if a state change is reachable via GET (or method-override), it fires.
3. Method downgrade: does `POST`-only logic also accept `GET` / `?_method=POST`?
4. Sibling/subdomain: a cookie scoped to `.target.com` is reachable from any subdomain you can get HTML onto (XSS on `sub.target.com`, or a hosted page).
5. Brand-new "None" cookies or a 2-minute Lax grace window on fresh logins can also carry the request.

### Chain 3: JSON endpoint via content-type confusion
1. API expects `application/json` and assumes that alone prevents CSRF (can't set arbitrary content-type cross-site with a simple form).
2. Try a form/`multipart`/`text/plain` body that the server still parses as JSON (`<form enctype="text/plain">` trick: `{"email":"x@evil.com","ignore":"=1"}`).
3. Or check if the endpoint accepts `application/x-www-form-urlencoded` equivalently.
4. If the server parses the forgeable content-type → CSRF despite "JSON-only".

### Chain 4: CORS-enabled state change (credentialed)
1. Endpoint reflects `Access-Control-Allow-Origin` = request Origin **and** `Access-Control-Allow-Credentials: true`.
2. Attacker JS can then send a credentialed cross-origin request *and read the response* → CSRF + data theft in one.
3. Distinct from classic form CSRF: here fetch/XHR with `credentials:'include'` works because CORS explicitly allows it.

### Chain 5: Login / logout CSRF
1. **Login CSRF**: force the victim to log into an *attacker-controlled* account → their actions (saved cards, searches, uploads) land in the attacker's account.
2. **Logout CSRF**: forced logout as a nuisance, or as a step to force re-login into an attacker account.
3. Impact framing matters — pure logout CSRF is usually low; login CSRF that captures victim data is medium+.

### Chain 6: Token present but broken
1. Token is global/static (same for all users) → attacker reads their own, embeds it.
2. Token validated only when present → omit the param.
3. Token accepted from a different user / expired session → not bound.
4. Token in a place the attacker can influence (double-submit cookie the attacker can set via subdomain).

## Discovery Methodology

### Step 1: Inventory state-changing, cookie-auth requests
From recon and the app walkthrough, list every request that **changes state** and is authenticated by cookie: email/password/2FA change, profile update, fund transfer, role/permission change, delete, invite, subscription change. Ignore read-only endpoints and anything bearer-token-only (no ambient credential = no CSRF).

### Step 2: Characterise the defense on each
For each candidate:
* Is there a CSRF token / custom header (`X-CSRF-Token`, `X-Requested-With`)? Where is it carried?
* What is the session cookie's `SameSite` (`Strict`/`Lax`/`None`/absent)?
* What content-type does the endpoint require, and will it accept a forgeable one?
* Any CORS reflection with credentials?

### Step 3: Try to defeat the defense (in order)
| Defense | Test |
|---|---|
| Anti-CSRF token | Remove it · blank it · reuse across sessions · use another user's · static/global? |
| Custom header (`X-Requested-With`) | Drop it — enforced, or decorative? |
| SameSite | `Strict`→try subdomain HTML · `Lax`/absent→GET nav or method downgrade · `None`→straight cross-site |
| Content-type gate | `text/plain` / form / multipart body parsed as JSON |
| CORS | Origin reflected + `Allow-Credentials:true`? → credentialed fetch reads response |

### Step 4: Build and fire a real cross-site PoC
* Write an HTML PoC (auto-submitting `<form>` for form/enctype cases; `fetch(..., {credentials:'include'})` for CORS/JSON cases).
* Host it and load it in the headless browser **carrying the victim identity's cookies** (Session Seeder → identity's cookie jar) to prove it fires cross-site, not same-origin.
* Confirm the state actually changed (email updated, password reset, transfer booked) — not just a 200.

## Impact Demonstration

* Provide the self-contained PoC page + the exact request it generates.
* Show victim state **before and after** loading the PoC while logged in (screenshot / response).
* Name the impact and chain it: email-change CSRF → password reset → **ATO**; fund-transfer CSRF → money moved; role-change CSRF → priv-esc.
* State the delivery precondition honestly (victim must be logged in and visit a page; note if SameSite makes it require a subdomain foothold).

## Key Considerations

* **CSRF on a non-security-relevant, non-state-changing endpoint is informative** — CLAUDE.md's always-ignore list. Only chase actions with real impact.
* **SameSite=Lax is the default** in modern browsers — assume it and test whether the delivery (top-level GET, subdomain, method downgrade) still works, rather than assuming classic form-POST CSRF fires.
* **Bearer-token / Authorization-header auth is not CSRF-able** (no ambient credential). Confirm the endpoint truly relies on the cookie.
* **Prove cross-site, not same-origin** — a PoC opened on the target's own origin proves nothing; load it from a different origin with the victim's cookies.
* **Use your own account as victim** for the PoC; revert any change (email/password/settings) after proving it.
* Where CSRF lands account control, hand the finding to `/ato`; where it forges a privileged action, note the authz angle for `/rbac`.
