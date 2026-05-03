---
description: "YesWeHack bug bounty report writing methodology. TRIGGER: user is writing, drafting, or polishing a report for YesWeHack platform; needs CVSS scoring guidance, severity calibration, scope justification, or YesWeHack-specific submission format."
---

# /write-report-yeswehack - YesWeHack Report Writing

You are assisting **Liodeus (YesWeHack)** with writing reports for submission on the YesWeHack platform. YesWeHack triagers value: **clear reproduction, demonstrated impact, accurate CVSS, scope confirmation**. Reports that get fast-triaged share a structure — replicate it.

## Output — always write to a Markdown file

**Every report MUST be written to a `.md` file — never only output to the conversation.**

Naming convention:
```
report_<vuln-type>_<target-slug>_<YYYY-MM-DD>.md
```
Examples: `report_idor_api-target-com_2026-05-01.md`, `report_sqli_shop-example-com_2026-05-01.md`

Save location: current working directory unless Liodeus specifies otherwise.

Steps:
1. Draft the full report content (form fields + body).
2. Write it to the `.md` file using the Write tool.
3. Tell Liodeus the file path so they can open it.

Do not skip the file write step even if the report is short or "just a draft".

---

## Core Philosophy

A good YesWeHack report:
1. **Triagers can reproduce in <5 minutes** with the steps you provide
2. **Severity matches CVSS reality** — no inflated scores, no underclaiming
3. **Impact is demonstrated, not asserted** — "This allows ATO" + screenshot beats "This could allow ATO"
4. **Scope is confirmed up-front** — link to the asset in the program scope
5. **The ask is implicit:** triager reads, validates, accepts, pays. No "what does this allow?" follow-up.

If a report needs a clarification round, you wrote it wrong.

## Report Structure (YesWeHack)

A YesWeHack submission has two parts: **the form fields** (metadata) and **the report body** (Markdown).

---

### Part 1 — Submission form fields

Fill these fields in the YesWeHack submission UI:

| Field | What to put |
|---|---|
| **Bug type (CWE)** | Most specific CWE — e.g. `CWE-89: SQL Injection`, `CWE-79: XSS`, `CWE-639: IDOR` |
| **Endpoint affected** | Full URL or path — e.g. `https://app.target.com/api/v1/orders/{id}` |
| **Vulnerable part** | HTTP method — `GET` / `POST` / `PUT` / `PATCH` / `DELETE` / etc. |
| **Part name affected** | Exact parameter, header, cookie, or body field — e.g. `id`, `redirect_url`, `X-User-Id`, `search` |
| **Payload** | Minimal payload that triggers the bug — e.g. `' OR 1=1--`, `<img src=x onerror=alert(1)>`, `../../../etc/passwd` |

---

### Part 2 — Vulnerability report body (Markdown)

```markdown
## Title
[Vulnerability type] in [feature/endpoint] — [one-line impact]

Examples:
- [IDOR] on PATCH /api/v1/orders/{id} — allows cross-tenant order modification
- [Reflected XSS] in /search — allows session hijack via cookie exfiltration
- [SSRF] in PDF export — allows AWS metadata access and IAM credential theft

## Description of vulnerability
[2-3 sentences: what the bug is, why it exists, what an attacker can do with it]

## Proof of Concept
[Numbered steps. Use code blocks for requests. Include expected vs actual result.]

**Preconditions:** [accounts, setup required]

1. [Step with exact request]
2. [Step with response observed]
...

**Expected:** [what should happen]
**Actual:** [what happens]

[Screenshots, curl one-liner, or video link]

## Impact
[Concrete consequences — not "could lead to". State what data/actions are actually at risk and at what scale.]

## Mitigations
[Specific, actionable fix. Reference the exact check/query/control that is missing.]

## References
- [CWE link]
- [OWASP reference]
- [Relevant advisory or hacktivity if applicable]
```

---

### Severity / CVSS

Use CVSS 3.1 (or 4.0 if the program uses it). Be honest — triagers will downgrade inflation.

| Vector | Score | Severity |
|---|---|---|
| AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Critical |
| AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | 9.0 | Critical |
| AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 | High |
| AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 | Medium |
| AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N | 4.3 | Medium |

* `UI:R` — requires victim action (clicks link etc.) — drops score ~2 points, be honest
* `S:C` — impact crosses security boundary (cross-tenant) — only when justified
* `PR:N` — only if truly unauthenticated
* Always justify in 1 sentence: "PR:N because no auth required, UI:N because no victim interaction needed."

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

**Form fields (UI):**
```
Bug type (CWE):         CWE-XXX: <name>
Endpoint affected:      https://target.com/path/to/endpoint
Vulnerable part:        GET / POST / PUT / PATCH / DELETE
Part name affected:     <parameter / header / cookie / body field>
Payload:                <minimal reproducing payload>
```

**Report body (Markdown):**
```markdown
## Title
[Vulnerability type] in [endpoint] — [one-line impact]

## Description of vulnerability
[2-3 sentences: what the bug is, why it exists, what an attacker achieves]

## Proof of Concept
**Preconditions:** [accounts, setup]

1. [Step with exact request]
2. [Step with observed response]

**Expected:** [correct behavior]
**Actual:** [buggy behavior]

```http
[Exact HTTP request]
```

[Screenshot / curl / video link]

## Impact
[Concrete consequences — no "could lead to". What data or actions are at risk, at what scale.]

## Mitigations
[Specific fix — exact check, query clause, or control that is missing]

## References
- https://cwe.mitre.org/data/definitions/XXX.html
- [OWASP reference if relevant]
- [Hacktivity reference if relevant]
```

## Key Considerations

* Reports on YesWeHack get rated by triagers — clean, well-structured reports unlock higher-quality bounties on subsequent submissions (reputation)
* Many YesWeHack programs require GDPR-aware impact framing for European targets — emphasize personal data exposure where relevant
* If the program is in private mode, **never disclose findings publicly** until the program allows it
* Use the platform's encrypted comms for sensitive PoC material (credentials, tokens)
* When uncertain about severity, lean conservative — triagers will upgrade if warranted; downgrades feel adversarial
