---
description: "Account Takeover (ATO) hunting methodology. TRIGGER: user is testing for account takeover, password reset abuse, OAuth misconfig, JWT manipulation, session fixation, 2FA bypass, email change flaws, or any auth-flow weakness leading to taking over another user."
---

# /hunt-ato - Account Takeover Hunting

You are assisting **Liodeus (YesWeHack)**, whose ATO reports include OAuth state/redirect abuse, password-reset token leakage, JWT alg confusion, and email-change race conditions. ATO is almost always P1/Critical when proven on a real victim — pursue it relentlessly.

## Core Philosophy

ATO doesn't usually live in one bug — it lives in **assumption gaps** between auth components: the password-reset issuer trusts the email field, the email-change verifier trusts the token but not the recipient, the OAuth callback trusts the `state`. Find the assumption and break it.

**Always demonstrate ATO with two accounts you own** (attacker + victim). Never test against real users. If you can't get a 2nd account, document the chain and request triage assistance.

## ATO Chains (from real reports)

### Chain 1: Password Reset Token Leak via Host Header
1. Submit reset for victim with `Host: attacker.com` (or `X-Forwarded-Host`)
2. Server emails victim a link pointing to attacker.com containing the real token
3. If victim clicks (or token is in Referer to attacker assets), capture token
4. Redeem token → set password → ATO

### Chain 2: OAuth Redirect URI / State Bypass
1. Identify OAuth flow (Google/Apple/Microsoft/SSO)
2. Test redirect_uri: open redirect, path traversal, fragment, subdomain takeover, `@` parser confusion, parameter pollution
3. Steal `code` or `id_token` → exchange → ATO
4. Also test missing/static `state` → CSRF login or account-link pinning

### Chain 3: Pre-Account-Takeover via Unverified Email Signup
1. Register account with victim's email (no verification required)
2. Set password, enable persistent session
3. Victim later signs up via SSO — if app merges accounts on email match, your session persists into victim's account
4. Variant: invite/team flows that pre-create unverified accounts

### Chain 4: JWT Algorithm / Key Confusion
1. Inspect JWT header: `alg`, `kid`, `jku`, `x5u`
2. Try `alg: none`, RS256→HS256 with public key as HMAC secret
3. `kid` SQLi/path traversal/command injection
4. `jku`/`x5u` pointing at attacker-hosted JWKS → forge any user

### Chain 5: Email Change Race / Confirmation Bypass
1. Initiate email change to attacker email → confirm
2. Race: change email AND password reset simultaneously
3. Test if old session retains access after email change (it shouldn't, but often does)
4. Test if confirmation link is bound to session/user (often only bound to token)

### Chain 6: 2FA Bypass
- Response manipulation: `success: false` → `success: true`
- Status code swap (401 → 200)
- Skip the 2FA endpoint entirely (call post-2FA endpoints directly)
- Brute force OTP (no rate limit on the verify endpoint)
- Re-use OTP across sessions
- Backup-code endpoint with no rate limit
- Reset 2FA via account recovery → bypass

### Chain 7: Session / Cookie Flaws
- Session fixation (server accepts attacker-supplied session ID)
- Cookie scope: parent-domain cookies set by sibling subdomain → XSS on `lab.target.com` steals `target.com` session
- Predictable session tokens
- Sessions not invalidated on password change / logout
- "Sign out everywhere" doesn't actually invalidate

## Discovery Methodology

### Step 1: Map every auth surface
* Login (password, OAuth, SSO, magic link, passkey)
* Signup (with/without verification, invitations, team adds)
* Password reset (request + redeem)
* Email change (request + confirm)
* 2FA enroll, verify, disable, recovery
* Session lifecycle (refresh, logout, "log out all devices")
* OAuth client registration if exposed
* Account merge / link / unlink

### Step 2: For each surface, ask
* What does it trust? (email field, token, session, header, signature)
* What can the attacker control of that input?
* What happens if I send the same request twice / concurrently?
* What if I omit / null / array-wrap the parameter?
* Does the response leak whether the user exists / has 2FA / used SSO?

### Step 3: Token analysis
* Reset/confirm tokens: length, entropy, predictability, expiry, single-use, bound to session
* JWTs: alg, kid, claims, signature verification
* OTPs: length, expiry, rate limit, brute force possible

### Step 4: Race conditions
Use `ffuf`, Turbo Intruder, or a quick async script to fire reset/confirm/change requests in parallel — many flaws only surface with concurrency.

## Impact Demonstration

For ATO, demonstrate end-to-end with **your own attacker + victim accounts**:
1. Show victim's pre-state (email, profile data, screenshot)
2. Execute the chain
3. Show attacker now has access to victim's account (PII, billing, content, admin functions)
4. Note blast radius: any user? Only users who SSO'd? Only users without 2FA?

## Key Considerations

* Never test against real users — always two accounts you own
* If the program is on YesWeHack, mass-email tests are usually out-of-scope; isolate to your own inbox
* Watch for "informative" closures — if the chain requires victim interaction (clicking a link), explicitly document realism (phishing-grade pretext, no warnings)
* Combine ATO with other findings: subdomain takeover + cookie scope = ATO; XSS + cookie not HttpOnly = ATO
* Always check `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` for SSO targets
