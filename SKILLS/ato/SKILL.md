---
name: ato
description: "Use when testing for account takeover, password reset abuse, OAuth misconfig, JWT manipulation, session fixation, 2FA bypass, email change flaws, or any auth-flow weakness leading to taking over another user."
---

# /ato - Account Takeover Hunting

You are assisting **Liodeus (YesWeHack)**, whose ATO reports include OAuth state/redirect abuse, password-reset token leakage, JWT alg confusion, and email-change race conditions. ATO is almost always P1/Critical when proven on a real victim — pursue it relentlessly.

## Autonomous harness

You run headless: only firewalled Bash (`curl`, `httpx`, `katana`, `ffuf`, `dnsx`, `nuclei`, `subfinder`, `jq`, unix) plus Read/Grep/Glob/Write. No browser, no proxy. Every auth-flow step is a `curl`/`httpx` call you build by hand.

* **Credentials** (when present): a JSON file at the path named in `TARGET.md`, with `login_url`, `notes`, and `accounts[]` (≥2 accounts). Authenticate per account with `curl`/`httpx`. **ATO must be demonstrated as one account taking over the other** — the two accounts are your attacker + victim. If `TARGET.md` has no creds → ATO is a **LEAD only** unless self-signup is explicitly in scope (then you may create your own attacker/victim pair).
* **OOB canary** is in `$AUTOHUNT_OOB` (may be UNSET). Use it for any out-of-band leak proof (e.g. a reset link rendered to your canary host, a `Referer` exfil). If `$AUTOHUNT_OOB` is unset, OOB-dependent steps become a **LEAD**.
* **Rate caps are firewall-ENFORCED.** Any fuzzing (OTP brute, token guessing with `ffuf`) MUST carry the rate flags from `TARGET.md` (example shape `-rl 8 -t 10`). No mass email tests.
* Do not submit reports or push to Discord — the orchestrator does that.

## Core Philosophy

ATO doesn't usually live in one bug — it lives in **assumption gaps** between auth components: the password-reset issuer trusts the email field, the email-change verifier trusts the token but not the recipient, the OAuth callback trusts the `state`. Find the assumption and break it.

**Always demonstrate ATO with two accounts you own** (attacker + victim from `TARGET.md`, or self-signup pair if in scope). Never test against real users. If you can't get a 2nd account, document the chain as a LEAD.

## ATO Chains (from real reports)

### Chain 1: Password Reset Token Leak via Host Header
1. Submit reset for the victim account with `-H 'Host: $AUTOHUNT_OOB'` (or `-H 'X-Forwarded-Host: $AUTOHUNT_OOB'`)
2. If the server emits a reset link pointing to the canary host containing the real token, your canary records the request → token captured (LEAD if `$AUTOHUNT_OOB` unset)
3. Redeem the token via `curl` → set password → log in as victim → ATO

### Chain 2: OAuth Redirect URI / State Bypass
1. Identify OAuth flow (Google/Apple/Microsoft/SSO) from the JS bundle / `/.well-known/*`
2. Test redirect_uri: open redirect, path traversal, fragment, subdomain takeover, `@` parser confusion, parameter pollution — drive each as a `curl -i` and inspect the `Location` header
3. If the `code`/`id_token` lands on a host you control (`$AUTOHUNT_OOB`) → exchange → ATO
4. Also test missing/static `state` → CSRF login or account-link pinning

### Chain 3: Pre-Account-Takeover via Unverified Email Signup
1. Register the attacker account with the victim's email (no verification required)
2. Set password, keep the session token
3. When the victim later signs up via SSO, if the app merges accounts on email match, your session persists into the victim's account
4. Variant: invite/team flows that pre-create unverified accounts

### Chain 4: JWT Algorithm / Key Confusion
1. Inspect JWT header: `alg`, `kid`, `jku`, `x5u` (`base64 -d` the segments, `jq`)
2. Try `alg: none`, RS256→HS256 with public key as HMAC secret — forge a token, replay via `curl -H "Authorization: Bearer <forged>"`
3. `kid` SQLi/path traversal/command injection
4. `jku`/`x5u` pointing at attacker-hosted JWKS (`$AUTOHUNT_OOB`) → forge any user

### Chain 5: Email Change Race / Confirmation Bypass
1. Initiate email change to attacker email → confirm
2. Race: fire email change AND password reset concurrently (background `curl` jobs / `xargs -P`)
3. Test if the old session retains access after email change (it shouldn't, but often does)
4. Test if the confirmation link is bound to session/user (often only bound to token)

### Chain 6: 2FA Bypass
- Response manipulation: `success: false` → `success: true` (replay and observe whether the server-side state actually changed)
- Status code swap (401 → 200)
- Skip the 2FA endpoint entirely (call post-2FA endpoints directly with the pre-2FA session)
- Brute force OTP (no rate limit on verify) — `ffuf` with `TARGET.md` rate caps
- Re-use OTP across sessions
- Backup-code endpoint with no rate limit
- Reset 2FA via account recovery → bypass

### Chain 7: Session / Cookie Flaws
- Session fixation (server accepts an attacker-supplied session ID)
- Cookie scope: parent-domain cookies set by a sibling subdomain → token theft
- Predictable session tokens
- Sessions not invalidated on password change / logout (replay the old token after change → still 200)
- "Sign out everywhere" doesn't actually invalidate

## Discovery Methodology

### Step 1: Map every auth surface
Crawl with `katana` (carry `TARGET.md` rate flags) and mine JS bundles (`curl` + `grep`) for:
* Login (password, OAuth, SSO, magic link, passkey)
* Signup (with/without verification, invitations, team adds)
* Password reset (request + redeem)
* Email change (request + confirm)
* 2FA enroll, verify, disable, recovery
* Session lifecycle (refresh, logout, "log out all devices")
* OAuth client registration if exposed
* Account merge / link / unlink
* `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`

### Step 2: For each surface, ask
* What does it trust? (email field, token, session, header, signature)
* What can the attacker control of that input?
* What happens if I send the same request twice / concurrently?
* What if I omit / null / array-wrap the parameter?
* Does the response leak whether the user exists / has 2FA / used SSO?

### Step 3: Token analysis
* Reset/confirm tokens: length, entropy, predictability, expiry, single-use, bound to session (collect a few legit tokens via `curl` and compare)
* JWTs: alg, kid, claims, signature verification (`base64 -d`, `jq`)
* OTPs: length, expiry, rate limit, brute force possible

### Step 4: Race conditions
Fire reset/confirm/change requests in parallel from the CLI (background `curl &` jobs, `xargs -P`, or a small loop) — many flaws only surface with concurrency. Keep volume within `TARGET.md` rate caps.

## PROOF — demonstrate the actual takeover, not the theory

The oracle is **cross-account effect**: one account you own ends up controlling the other. A manipulated response or a captured token is only half — show it converts to access.

1. Record the victim account's pre-state via `curl` (its `/me`, email, a profile field) using the victim's session.
2. Execute the chain from the attacker side (`curl`/`httpx`).
3. Prove takeover: authenticate to the victim account using the artifact you obtained (redeemed reset token, forged JWT, fixated session, post-change credentials) and show the victim's `/me`/PII now returns under your control — or that you can perform a victim-scoped action.
4. For OOB-dependent leaks (Host-header reset link, JWKS exfil), the proof is the callback recorded at `$AUTOHUNT_OOB`; if unset, downgrade to a **LEAD** describing the chain.
5. Capture request/response pairs to files (`curl -i ... > proof_ato_*.txt`).

## Impact Demonstration

For ATO, demonstrate end-to-end with **your own attacker + victim accounts**:
1. Show the victim's pre-state (email, profile data) from a `curl` with the victim session
2. Execute the chain
3. Show the attacker now has access to the victim's account (victim `/me`/PII/billing/admin functions returning under attacker control)
4. Note blast radius: any user? Only users who SSO'd? Only users without 2FA?

## Key Considerations

* Never test against real users — always the two accounts you own (or a self-signup pair if in scope)
* On YesWeHack, mass-email tests are usually out-of-scope; keep reset/confirm traffic to your own accounts and under `TARGET.md` rate caps
* Watch for "informative" closures — if the chain requires victim interaction (clicking a link), explicitly document realism (phishing-grade pretext, no warnings)
* Combine ATO with other findings: subdomain takeover + cookie scope = ATO; XSS + cookie not HttpOnly = ATO
* Always check `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` for SSO targets
* No second account in `TARGET.md` and no self-signup in scope → log the auth-flow gap as a **LEAD**; takeover can't be demonstrated without a victim account.
