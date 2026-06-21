---
name: report-yeswehack
description: "Use when writing, drafting, or polishing a bug bounty report in YesWeHack format, or needing CVSS scoring, severity calibration, scope justification, or YesWeHack-specific submission formatting. Headless: compute CVSS inline and Write the report .md — never submit."
---

# /report-yeswehack - YesWeHack Report Writing

You write YesWeHack-format reports. YesWeHack triagers value: **clear reproduction, demonstrated impact, accurate CVSS, scope confirmation**. Reports that get fast-triaged share a structure — replicate it.

## Headless / autonomous note (READ FIRST)

You are in an autonomous headless harness:
* **No YesWeHack UI.** There is no submission form, no CVSS calculator widget, and no hacktivity to browse. **Compute the CVSS score inline from the vector string yourself** (see the CVSS table below — it maps the common vectors to scores), and write the vector + score directly into the report body.
* **You do not submit anything.** Do not open the platform, do not push to Discord. Your only output is the report `.md` file on disk — the orchestrator/human handles submission.
* **No "search hacktivity for dupes" step** — you can't browse it. Note possible-dupe risk in the report if you have local evidence, but don't attempt to look it up online.
* The "form fields" below are still the right metadata to capture — write them as a block at the top of the `.md` file so whoever submits can paste them in.

## Output — always write to a Markdown file

**Every report MUST be written to a `.md` file with the Write tool — never only output to the conversation.**

Naming convention:
```
report_<vuln-type>_<target-slug>_<YYYY-MM-DD>.md
```
Examples: `report_idor_api-target-com_<YYYY-MM-DD>.md`, `report_sqli_shop-example-com_<YYYY-MM-DD>.md`
(use today's actual date in the filename)

Save location: current working directory unless specified otherwise.

Steps:
1. Draft the full report content (form-field block + body).
2. Compute the CVSS score inline from your vector string.
3. Write it to the `.md` file using the Write tool.
4. Report the file path back so the orchestrator/human can pick it up.

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

Capture these as a block at the top of the `.md` (whoever submits pastes them into the YesWeHack form):

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

[Copy-pasteable curl one-liner + the exact response snippet that proves the bug.
For XSS: the `node "$AUTOHUNT_XSS_CONFIRM" ... --nonce <N>` command and its execution-confirmed output.
For blind/OOB: the `$AUTOHUNT_OOB` canary hit.]

## Impact
[Concrete consequences — not "could lead to". State what data/actions are actually at risk and at what scale.]

## Mitigations
[Specific, actionable fix. Reference the exact check/query/control that is missing.]

## References
- [CWE link]
- [OWASP reference]
- [Relevant advisory if applicable]
```

---

### Severity / CVSS

Use CVSS 3.1 (or 4.0 if the program uses it). Be honest — triagers will downgrade inflation.
**There is no calculator UI here — derive the score from the vector yourself.** Build the vector
from the metrics, then map it with the table below (and the metric notes under it); write both
the full vector string and the resulting score/severity into the report body.

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

* **Keep reproduction steps in a dedicated "Proof of Concept" section** — don't bury them in the description.
* **Write the CVSS vector AND computed score into the body** — there's no UI calculator; the human submitter needs both spelled out so they can re-enter them.
* **Name the affected asset** in the form-field block so the submitter tags the right one (un-tagged reports go to a generic queue).
* **Dupe risk:** you can't browse hacktivity headlessly — if you have local signal that a finding may be known, note it; otherwise leave dupe-checking to submission time.
* **No personal info in screenshots/PoC** — keep the report anonymizable.
* **Asset multipliers:** some programs pay more for specific assets — if you know the asset tier from program notes, mention it; don't go look it up online.

## Anti-patterns (will get you closed as N/A or informative)

* "I think this might be a vulnerability because..." — submit only confirmed bugs
* No reproduction steps, just a screenshot
* No impact section / impact is "could potentially"
* Inflated CVSS (assigning C:H/I:H/A:H to a low-impact bug)
* Out-of-scope assets (always check before submission)
* Self-XSS / requires-victim-clicks-attacker-link without realistic chain
* Theoretical bugs ("if the developer set X to Y, then...")
* Reports that are actually 5 different bugs in one — submit separately

## Template (write this to the `.md` file)

Write the form-field block at the top, then the Markdown body underneath, all in one `.md` file.

**Form fields (for whoever submits):**
```
Bug type (CWE):         CWE-XXX: <name>
Endpoint affected:      https://target.com/path/to/endpoint
Vulnerable part:        GET / POST / PUT / PATCH / DELETE
Part name affected:     <parameter / header / cookie / body field>
Payload:                <minimal reproducing payload>
Affected asset:         <asset name/tag from program scope>
CVSS:                   <vector string>  →  <score> (<severity>)
```

**Report body (Markdown):**
```markdown
## Title
[Vulnerability type] in [endpoint] — [one-line impact]

## Severity
CVSS 3.1: [full vector string] = [score] ([severity])
[1-sentence justification: e.g. "PR:N because no auth required, UI:N because no victim interaction needed."]

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

[Exact HTTP response snippet proving the bug — status line + the fields that prove it.
For XSS, include the xss-confirm.js oracle command + its "execution confirmed" output.
For blind/OOB, include the $AUTOHUNT_OOB canary hit.]

## Impact
[Concrete consequences — no "could lead to". What data or actions are at risk, at what scale.]

## Mitigations
[Specific fix — exact check, query clause, or control that is missing]

## References
- https://cwe.mitre.org/data/definitions/XXX.html
- [OWASP reference if relevant]
```

## Key Considerations

* Proof goes in-band, as text: exact request + response, the xss-confirm.js oracle output for XSS, the `$AUTOHUNT_OOB` callback for blind/OOB. There is no screenshot/video tooling here — make the textual evidence airtight.
* Reports get rated by triagers — clean, well-structured reports build reputation and unlock higher-quality bounties on subsequent submissions.
* Many YesWeHack programs require GDPR-aware impact framing for European targets — emphasize personal data exposure where relevant.
* Keep findings confidential — write to the `.md` only; do not disclose anywhere. The orchestrator/human handles submission and any sensitive-comms handling.
* When uncertain about severity, lean conservative — triagers will upgrade if warranted; downgrades feel adversarial.
