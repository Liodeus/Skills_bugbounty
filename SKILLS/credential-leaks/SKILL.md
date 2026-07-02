---
name: credential-leaks
description: "Use when the user is hunting leaked credentials via OathNet MCP (breach DBs + infostealer logs) — searching by domain or email pattern, triaging by recency & impact, validating carefully (anti-bot bypass, WAF, 2FA side-effects), and reporting responsibly without enumerating third-party accounts. Use during recon and whenever a target needs auth coverage."
---

# Credential Leaks — Cheatsheet

Hunt for leaked credentials and turn them into actionable bug bounty findings — without crossing the line into unauthorized access of third-party accounts.

---

## 1. When to use

Run this every time you start working on a new target with an authentication surface.
Leaked creds give you:
- A short list of valid usernames (zero-effort enumeration).
- Default / shared passwords across multiple accounts (systemic findings).
- Internal hostnames leaked via stealer URL fields (recon multiplier).
- A reportable issue even if **none** of the creds are still valid (lack of monitoring / forced reset is the bug).

---

## 2. OathNet MCP — primary tool

The local MCP wrapper at `mcp-servers/oathnet-mcp/` calls `https://oathnet.org/api/service`. API key is hard-coded in `src/index.js`. Tools available:

| Tool | Purpose |
|---|---|
| `oathnet_init_search_session` | Start a 60-min session — pass the resulting `search_id` to subsequent calls to save quota |
| `oathnet_search_credentials` | Breach DB lookup — historical password leaks |
| `oathnet_search_stealer_logs` | Infostealer logs — recent malware-stolen creds + cookies + URLs (highest signal) |
| `oathnet_search_subdomains` | Subdomain enum from `/v2/stealer/subdomain` (returns full list — see "MCP fix" below) |
| `oathnet_multi_search` | Composite: breach + stealer + subdomains in one call |

### Standard workflow

```text
1. oathnet_init_search_session query=<domain>            → get session_id
2. oathnet_multi_search target=<domain>                  → 100 stealer hits cap
3. If interesting, drill into specific patterns:
   oathnet_search_credentials query=*@<domain>           → email-bound leaks
   oathnet_search_stealer_logs query=<specific_subdomain>
```

### Query patterns that work

| Query | Hits |
|---|---|
| `chmura.orange.pl` | matches the URL field of stealer entries |
| `*@centertel.pl` | matches breach DB entries with that email pattern |
| `dro.orange-business.com` | exact subdomain match in stealer entries |
| `https://target.tld/specific/path` | URL-bound matches (rare but precise) |

### MCP fix — subdomain enum was buggy

The vanilla wrapper used to return only 6 hostnames extracted as a side effect of breach/stealer record fields. The correct endpoint is `GET /v2/stealer/subdomain?domain=...` and returns the full list (e.g. 111 for `orange.pl`). Patch already applied in `mcp-servers/oathnet-mcp/src/index.js` — the function now hits the dedicated endpoint, then unions with the legacy field-harvest as fallback.

If results suddenly drop, re-test with curl directly:

```bash
curl -sk \
  -H "x-api-key: $OATHNET_API_KEY" \
  "https://oathnet.org/api/service/v2/stealer/subdomain?domain=<target>" \
  | jq -r '.data.subdomains[]'
```

---

## 4. Reading the results

### Breach DB vs Stealer logs

| | Breach DB | Stealer logs |
|---|---|---|
| Source | Public dumps (LinkedIn, Adobe…) | Active malware exfiltrating browser vaults |
| Recency | Often years old | Often weeks old |
| Cleartext password | Sometimes | **Almost always** |
| URL context | Rare | Yes (URL the cred was typed into) |
| Cookies / browser state | No | Sometimes |

**Stealer logs are gold.** A cred indexed 30 days ago that the company hasn't rotated = direct evidence of zero infostealer monitoring.

### Fields that matter

- `📅 Pwned` — when the malware stole the cred (most relevant date).
- `📅 Indexed` — when OathNet ingested it.
- `🦠 Log ID` — same ID across multiple entries = same victim machine, **same infected user**. One Log ID with 50 entries = one admin's full credential vault leaked.
- `🌐 URL` — exact URL where the cred was typed. Reveals subdomains, paths, login form types (e.g. `/console/j_security_check` = WebLogic, `/webSSO/auth/...` = custom Java SSO).
- `📧 Email domains` — distinguishes employee accounts (`@corp.com`) from customer accounts (`@gmail.com`, `@wanadoo.fr`).

---

## 5. Triage by criticality

Rank findings before testing. High-impact candidates:

### 🔴 Default / well-known passwords on admin endpoints

Look for cred pairs where the password is `<service-name>`, the URL points to an admin console, and pwned date is recent.

```
weblogic / weblogic     → /console/j_security_check  (WebLogic admin, RCE one-shot)
admin / zenoss          → /:8080                      (Zenoss monitoring)
admin / NewLuxmundi     → rhev3.*                     (RHEV virtualization mgmt)
hscroot / ibm1234       → hmc2pro.*                   (IBM HMC mainframe mgmt)
admin / ssp123 ×3       → :8084 spectrum protect      (shared default → systemic)
```

If the same password hits **multiple users** at different subdomains → **systemic default credential**, much more reportable than a single user mistake.

### 🟠 Internal employee accounts (AD format)

Watch for `tp\username` (NTLM/Kerberos), `corp\user`, or `domain\user` patterns. These are direct Active Directory creds → if validated, that's a domain account compromise (lateral movement potential implied, even if you don't pivot).

### 🟡 Same victim, large vault

One Log ID with dozens of entries = one infected admin / power user. Don't test the creds — but **document the vault** as a "single point of compromise" finding. The fix isn't password rotation, it's IR for that user's machine and tokens.

### 🟢 Customer accounts on B2B / SaaS portals

Useful for showing the **lack of monitoring**: list 10 stealer-log creds with pwned dates spanning the last 6 months for the same customer-facing portal → "no infostealer IOC monitoring".

### Patterns that scream "default password"

- `<Company>2024@@`, `<Company>2025!`, `<Service>123!`
- The exact same password on N different usernames at the same login URL
- Username pattern like `[a-z]{4}[0-9]{4}-svc1` with shared password = bulk-provisioned subcontractor accounts

When you spot N>1 users with the same password, you don't need to test all of them — testing one + showing the others in the leak is enough for the report.

---

## 6. Validation — pre-flight checklist

Before sending **any** credential to a real auth endpoint:

- [ ] Asset is **explicitly** in the program scope (`*.target.tld` or specific host listed).
- [ ] You're not about to spam SMS / email to the victim's real contact (check the auth response shape on a *fake* user first — what does the server return when 2FA triggers? does it actually send an SMS at step 1 or only at step 2?).
- [ ] You have a clear stop condition: **one valid auth = stop**, write up, never enumerate further.
- [ ] You're not going to navigate the authenticated session, read data, change settings, or click anything beyond the auth response.

### Establish auth shape with a fake user

Always do this first:

```bash
# Send a clearly-fake credential and observe the response
curl ... -d "user=qqqqqqqq_invalid&pass=invalid"
```

You learn:
- Does the server distinguish "user not found" from "wrong password"? (user enumeration → separate finding)
- Does it return any data on a valid username at step 1 (mobile number, account type, etc.)?
- Does step 1 already trigger SMS/email to the user, or only step 2?

### Then test the leaked cred

Send exactly **one** real cred. Observe the response, document the HTTP exchange (status, headers, key cookies, redirects), **stop**.

---

## 7. Anti-bot / WAF — common obstacles

### Trust-bundle / invisible CAPTCHA

Pattern (real example from `dro.orange-business.com`):

```js
postTrustBundle("/trustBundle", {login: ...}, function (callTrustBundle) {
  if (callTrustBundle) {
    _trustjs.verifyRequest(callback, captchaCallback);  // invisible challenge
  } else {
    submit();
  }
});

// On error:
$("form").append('<input name="trustBundleError" value="..."/>');
$("form").append('<input name="trustBundleKo" value="true"/>');
submit();
```

**Bypass via graceful degradation** — append the error flags yourself instead of solving the challenge:

```
trustBundleError=NetworkError
trustBundleKo=true
```

Most apps accept this fallback so legitimate users with adblock / corporate proxies aren't blocked. Worth trying before reaching for a headless browser. **Always confirm against the program's rules** — bypassing anti-fraud is a finding in itself if no scope clause excludes it.

### F5 BIG-IP ASM "Request Rejected"

Signature : tiny HTML body (180–250 bytes) with `Your support ID is: <numeric>`. Often a combination of:

- Geo-allowlist (only target country IP ranges)
- IP reputation (datacenter / cloud egress IPs → blocked)
- TLS/JA3 fingerprint
- Path-based blocking on `/auth`, `/login`, `/admin`

Common attempts that **don't** work in this case:
- Different User-Agent
- HTTP/1.1 vs HTTP/2
- Cookie replay of the F5 `TS<id>` challenge cookie
- Adding `X-Forwarded-For: 1.1.1.1` (F5 strips/ignores)

Right move: document, don't fight the WAF. Note that the surface is unreachable from a non-allowlisted IP and pivot to other in-scope assets.

### Cloudflare / Akamai bot management

If a real browser is genuinely required (rare for cred testing), use the local headless browser MCPs — **Lightpanda by default**, Chrome only as a fallback if Lightpanda can't render the page (one per identity):

```
mcp__lightpanda-user1__*     # default — try first
mcp__lightpanda-user2__*
mcp__lightpanda-user3__*
mcp__playwright-user1__*     # fallback — only if Lightpanda fails to render
mcp__playwright-user2__*
mcp__playwright-user3__*
```

Each runs fully headless. Use only if HTTP-level testing is blocked.

---

## 8. The big "no" — third-party account access

A confirmed login response (`302`, session cookie issued, `success: OK` header) is **enough proof for the report**. You do not need to:

- Follow the post-auth redirect.
- Open the session in a browser to "see what's there".
- Look at customer files, contracts, devices, billing, etc.
- Test horizontal escalation (try other accounts in the same tenant).

Even with explicit asset-level scope, **the credential belongs to a real human** (employee, customer, subcontractor). Standard YWH / HackerOne language:

> "You must not access, modify, delete, or exfiltrate any data belonging to Orange or third parties. Once a vulnerability is confirmed (e.g., a successful authentication), you must immediately stop and report."

If the user pushes past this line, push back once, explicitly. The report quality is identical whether you stopped at the 302 or browsed the dashboard — the only difference is your legal exposure.

---

## 9. Reporting — what makes a strong write-up

### Always reportable, even with zero validated creds

> "**N credentials targeting `target.tld` exposed in infostealer logs, with pwned dates spanning the last X months. The lack of forced reset for impacted accounts indicates no continuous infostealer-IOC monitoring.**"

This alone is a Medium / High finding (CWE-521 weak password storage practices, OWASP A07:2021 Identification and Authentication Failures). You don't need to test a single cred to file it.

### High-quality write-up checklist

- **Tone and shape** : start with high-level description, then technical chain, risks, recommendations, references.
- **Sample dataset** : 5–10 anonymized entries with `username`, `password (truncated)`, `URL`, `pwned date`, `Log ID prefix`. Anonymize partial passwords (`Hil********`).
- **Patterns identified** : default password reuse, AD username format, recent dates.
- **Validation evidence** (if performed in scope) : the **single** HTTP request/response showing auth success. Redact the full session cookie value.
- **Recommendations** :
  1. Forced password reset for all impacted users.
  2. Continuous infostealer-IOC monitoring (HIBP, OathNet, IntelX, vx-underground).
  3. MFA enforcement on the auth path (not "device-trusted bypass").
  4. Detect & block default initial passwords during account provisioning.
  5. Generic auth error message (no `"compte n'est pas autorisé"` differentiation).
- **References** :
  - CWE-521 — Weak Password Requirements
  - CWE-798 — Use of Hard-coded Credentials
  - OWASP A07:2021 — Identification & Authentication Failures
  - NIS2 Directive (EU operators of essential services)
  - For PL targets : Polish Penal Code Art. 267 § 1 (cite as the reason for non-active testing of out-of-scope creds)

---

## 10. Quick reference — full search session

```
# 1. Init session
oathnet_init_search_session query="orange-business.com"
  → search_id: 95821af6-7b81-...

# 2. Multi search (uses session)
oathnet_multi_search target="orange-business.com"
  → 100 stealer hits, breach DB, subdomains

# 3. Drill into highest-value subdomain
oathnet_search_stealer_logs query="dro.orange-business.com" search_id=95821af6...
  → 100 hits, recent stealer logs

# 4. Resolve test surface (skip NXDOMAIN)
for h in <hosts>; do dig +short "$h"; done

# 5. Establish baseline (fake user)
curl ... -d "user=fake&pass=fake"

# 6. Validate ONE cred (highest signal: most recent + plausible default)
curl ... -d "user=<leaked_user>&pass=<leaked_pass>"
  → 302 + session cookie = stop

# 7. Write report
```

---

## 11. Decision tree

```
Got a target?
└── In scope?
    ├── No → don't search (or only for IOC if disclosure path exists)
    └── Yes
        ├── Run oathnet_multi_search
        ├── Got hits?
        │   ├── No → note "no public exposure" (still useful in report)
        │   └── Yes
        │       ├── Triage: default pwd? AD employee? customer?
        │       ├── Resolve target hosts (filter NXDOMAIN)
        │       ├── Establish auth shape with fake user
        │       ├── Test ONE high-value cred
        │       │   ├── 302 / success → stop, write report
        │       │   ├── Auth error → try next pattern (max 3)
        │       │   └── WAF / anti-bot → document, pivot
        │       └── Write report (tested or untested)
        └── Out of scope → report as IOC threat-intel via responsible disclosure
            (cert@target.tld, CSIRT, security.txt)
```
