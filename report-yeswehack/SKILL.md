---
description: "YesWeHack bug bounty report writing methodology. TRIGGER: user is writing, drafting, or polishing a report for YesWeHack platform; needs CVSS scoring guidance, severity calibration, scope justification, or YesWeHack-specific submission format."
---

# /write-report-yeswehack - YesWeHack Report Writing

You are assisting **Liodeus (YesWeHack)** with writing reports for submission on the YesWeHack platform. YesWeHack triagers value: **clear reproduction, demonstrated impact, accurate CVSS, scope confirmation**. Reports that get fast-triaged share a structure — replicate it.

## Core Philosophy

A good YesWeHack report:
1. **Triagers can reproduce in <5 minutes** with the steps you provide
2. **Severity matches CVSS reality** — no inflated scores, no underclaiming
3. **Impact is demonstrated, not asserted** — "This allows ATO" + screenshot beats "This could allow ATO"
4. **Scope is confirmed up-front** — link to the asset in the program scope
5. **The ask is implicit:** triager reads, validates, accepts, pays. No "what does this allow?" follow-up.

If a report needs a clarification round, you wrote it wrong.

## Report Structure (YesWeHack)

YesWeHack's submission form has these fields. Fill each precisely:

### 1. Title
Format: `[Vulnerability type] in [feature/endpoint] allows [impact]`

Examples:
* `[Reflected XSS] in /search endpoint allows session hijack via document.cookie exfiltration`
* `[IDOR] on PATCH /api/v1/orders/{id} allows arbitrary order modification cross-tenant`
* `[SSRF] in PDF export feature allows AWS metadata access and IAM credential theft`

Avoid: vague titles, vendor-name-only titles, missing impact clause.

### 2. Scope
Confirm asset is in program scope. Format:
> **Scope:** `https://app.target.com` — listed in program scope as "Main application" (asset ID: 12345 if visible)

Add CWE: e.g. `CWE-79: Cross-site Scripting (Reflected)`.

### 3. Severity / CVSS
Use CVSS 3.1 (or 4.0 if program uses it). Be honest:

| Vector | Score | Severity |
|---|---|---|
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Critical |
| AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | 9.0 | Critical |
| AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 | High |
| AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 | Medium |
| AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N | 4.3 | Medium |

Tips:
* `UI:R` (User Interaction Required) drops self-XSS / clickjacking-required by ~2 points — be honest about this
* `S:C` (Scope: Changed) means impact crosses security boundary (e.g., XSS that affects another tenant) — only use when justified
* `PR:N` only if truly unauthenticated — most bugs are PR:L
* Always justify your CVSS in 1 sentence: "AV:N because exploitable over the internet, PR:N because no auth required, UI:N because no victim interaction."

### 4. Description
2-3 sentences. What is the bug, in plain language.

> The `/api/v1/orders/{id}` endpoint accepts PATCH requests but does not verify that the authenticated user owns the order specified in the path. This allows any authenticated user to modify orders belonging to other users, including changing the shipping address and order contents.

### 5. Steps to Reproduce
Numbered, exact. Use code blocks for requests. Include:
* Required preconditions (have an account, log in, etc.)
* Exact requests with full headers (redact your session token if you want; triager will re-create)
* Expected vs actual response

Template:
```
**Preconditions:**
- Two accounts: Account A (attacker, ID: 100) and Account B (victim, ID: 200)
- Account B has order ID 5000 with shipping address "123 Victim St"

**Steps:**
1. Log in as Account A. Capture session cookie.
2. As Account A, send the following request:
   ```http
   PATCH /api/v1/orders/5000 HTTP/2
   Host: app.target.com
   Cookie: session=<account_A_session>
   Content-Type: application/json
   
   {"shipping_address": "1 Attacker Lane"}
   ```
3. Server responds 200 OK.
4. Log in as Account B, navigate to /orders/5000 — shipping address now shows "1 Attacker Lane".

**Expected:** 403 Forbidden — Account A does not own order 5000.
**Actual:** 200 OK, modification succeeds.
```

### 6. Proof of Concept
Include:
* Screenshots: before, the request, the response, after (4 images max)
* Video if the bug is dynamic / multi-step (Loom unlisted, or attached MP4)
* Curl command for instant repro
* Any necessary scripts (sqlmap one-liner, custom Python snippet — keep brief)

```bash
curl -X PATCH https://app.target.com/api/v1/orders/5000 \
  -H "Cookie: session=..." \
  -H "Content-Type: application/json" \
  -d '{"shipping_address":"1 Attacker Lane"}'
```

### 7. Impact
Concrete consequences. Not "this could lead to" — what it actually does.

> **Impact:**
> - Any authenticated user can modify any other user's order, including:
>   - Shipping address (allows physical product theft)
>   - Order contents (allows financial fraud — replace expensive items with cheap ones, return for refund)
>   - Order status (e.g., mark another user's order as cancelled)
> - Affects all ~N orders in the system (sequential IDs verified up to 5005).
> - No rate limiting on PATCH endpoint — exploitation can be automated at scale.

### 8. Remediation Suggestion
Brief, specific. Triagers appreciate this — it shows you understand the bug.

> **Remediation:**
> Add an ownership check in the PATCH `/api/v1/orders/{id}` handler: verify that `order.user_id == current_user.id` (or that the user has admin privileges) before applying any modification. Alternatively, scope the SQL update query: `UPDATE orders SET ... WHERE id = ? AND user_id = ?`.

### 9. References
* CWE link: `https://cwe.mitre.org/data/definitions/639.html`
* OWASP guide if relevant: `https://owasp.org/www-project-api-security/`
* If similar public bug: link a HackerOne / YesWeHack hacktivity report

### 10. Attachments
* Screenshots (PNG, named: `01-victim-order-before.png`, `02-attacker-request.png`, etc.)
* Video (MP4, ≤ 30s ideally, narrated or annotated)
* Burp/Caido session export if helpful
* Any scripts (`.py`, `.sh`)

## Severity Calibration on YesWeHack

YesWeHack uses CVSS 3.1 / 4.0 with program-specific overrides. General rules:
* **Critical (9.0-10.0):** unauth RCE, unauth ATO, mass PII leak, full DB access
* **High (7.0-8.9):** auth ATO via chain, SSRF to cloud creds, stored XSS in admin context, business-critical IDOR
* **Medium (4.0-6.9):** reflected XSS with auth, IDOR exposing limited PII, CSRF on impactful action, blind SSRF without internal access proven
* **Low (0.1-3.9):** open redirect, missing security headers, info disclosure of non-sensitive data

**Avoid these classifications** unless the program explicitly accepts them:
* Self-XSS (informative usually)
* CSRF without state-changing impact
* Missing flags on cookies that contain no session data
* Tabnabbing
* Theoretical/unexploitable bugs
* Defense-in-depth missing controls
* Subdomain takeover without proof of vulnerable DNS record

## YesWeHack-specific Tips

* **Use the platform's "Reproduction steps" sections** — don't put steps in description
* **Add CVSS via the UI calculator** — don't just paste a vector string in text
* **Tag with the right asset** — un-tagged reports go to a generic queue
* **Use the BugBountyTriagers' "duplicate-prevention"**: search hacktivity for the same endpoint before submitting
* **Anonymous reporting:** if program is on YWH and you want anonymity, the platform supports it — don't include personal info in screenshots
* **Webhook bounties / target tags:** programs often have higher payouts for specific assets — verify before submitting
* **Comm timing:** YWH triagers often respond within 24-48h on weekdays. Don't bump after 12 hours.

## Anti-patterns (will get you closed as N/A or informative)

* "I think this might be a vulnerability because..." — submit only confirmed bugs
* No reproduction steps, just a screenshot
* No impact section / impact is "could potentially"
* Inflated CVSS (assigning C:H/I:H/A:H to a low-impact bug)
* Out-of-scope assets (always check before submission)
* Self-XSS / requires-victim-clicks-attacker-link without realistic chain
* Theoretical bugs ("if the developer set X to Y, then...")
* Reports that are actually 5 different bugs in one — submit separately

## Template (paste into YesWeHack)

```markdown
## Summary
[1-2 sentences: what the bug is and what it allows]

## Scope
- **Asset:** [URL/asset, link to scope]
- **CWE:** [CWE-XXX: name]

## Severity
- **CVSS 3.1:** [score] ([vector])
- **Justification:** [1 sentence]

## Steps to Reproduce
**Preconditions:** [accounts, setup]

1. [Step 1 with request]
2. [Step 2 with response]
...

**Expected:** [what should happen]
**Actual:** [what happens]

## Proof of Concept
[Screenshots, video link, curl]

## Impact
[Concrete consequences, scale, exploitability]

## Remediation
[Specific fix suggestion]

## References
- [CWE link]
- [Other refs]
```

## Key Considerations

* Reports on YesWeHack get rated by triagers — clean, well-structured reports unlock higher-quality bounties on subsequent submissions (reputation)
* Many YesWeHack programs require GDPR-aware impact framing for European targets — emphasize personal data exposure where relevant
* If the program is in private mode, **never disclose findings publicly** until the program allows it
* Use the platform's encrypted comms for sensitive PoC material (credentials, tokens)
* When uncertain about severity, lean conservative — triagers will upgrade if warranted; downgrades feel adversarial
