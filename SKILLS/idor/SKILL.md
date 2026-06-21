---
name: idor
description: "Use when testing for insecure direct object reference (IDOR), broken object level authorization (BOLA), ID enumeration, UUID prediction, or any cross-tenant / cross-user data access."
---

# /idor - IDOR / BOLA Hunting

You are assisting **Liodeus (YesWeHack)**, whose IDOR reports include UUID v1 prediction, HTTP-method swap bypass, GraphQL node-id enumeration, and multi-tenant boundary breaks. **IDORs are easy to find but uninteresting unless they expose PII or admin functions** — chase impact, not just access.

## Autonomous harness

You run headless: only firewalled Bash (`curl`, `httpx`, `katana`, `ffuf`, `dnsx`, `nuclei`, `subfinder`, `jq`, unix) plus Read/Grep/Glob/Write. No browser, no proxy. Every request is a `curl`/`httpx` call you build by hand.

* **Credentials** (when present): a JSON file at the path named in `TARGET.md`, with `login_url`, `notes`, and `accounts[]` (≥2 accounts). Authenticate with `curl`/`httpx` against `login_url`, capture the session cookie/token per account, and reuse it. **IDOR needs ≥2 accounts.** If `TARGET.md` has no creds → IDOR is a **LEAD only** (note the candidate endpoints, skip active cross-user testing) unless self-signup is explicitly in scope.
* **Rate caps are firewall-ENFORCED.** Scan tools (`ffuf`, `katana`, `httpx`, `nuclei`) MUST carry the rate flags from `TARGET.md` (example shape `-rl 8 -t 10`). Never mass-enumerate: **5–10 sequential IDs is proof, never bulk-extract.**
* Do not submit reports or push to Discord — the orchestrator does that.

## Core Philosophy

IDOR is the simplest bug class but the most easily dismissed. The bar is:
1. **Cross-user / cross-tenant** — read or act on data belonging to a user/tenant you do not control
2. **Real impact** — PII, financial, auth, content; not "I can read another user's display name color"
3. **Reproducible** — both accounts yours, both IDs documented, both request/response pairs captured

## IDOR Chains (from real reports)

### Chain 1: Integer ID enumeration → mass PII
1. Find endpoint like `/api/users/123/profile` returning email/phone
2. Confirm user 123 ≠ you, and the request **with account B's token** returns 200 with account A's data
3. Document scale: enumerate 5–10 sequential IDs quietly; report "I tested 5 sequential IDs, all returned other users' PII; full enumeration would expose all N users"
4. **Stop at proof. Do not mass-extract.**

### Chain 2: UUID v1 / weak UUID prediction
1. Identify UUID format — v1 has timestamp + MAC, predictable
2. Generate predicted UUIDs around your own (custom v1 generator using observed timestamps)
3. If those resolve cross-account → IDOR despite "non-guessable IDs"

### Chain 3: HTTP method swap
1. Endpoint `/api/users/{id}` requires auth + ownership for GET
2. Try `-X DELETE`, `-X PUT`, `-X PATCH` — sometimes only GET is checked
3. Try PROPFIND, OPTIONS for WebDAV stacks
4. Try `-H 'X-HTTP-Method-Override: DELETE'` on a POST

### Chain 4: GraphQL node-id / global-id enumeration
1. Decode base64 node IDs (`Relay`-style: `User:123` → `VXNlcjoxMjM=`)
2. Increment integer portion, re-encode (`echo -n 'User:124' | base64`)
3. Query `node(id: "...")` via `curl` — many resolvers don't re-check authz on the global resolver
4. Variant: union types — query `... on User { email }` on what was ostensibly a different type

### Chain 5: Wrapped / nested IDs
1. `POST /api/orders { "user_id": 1, "items": [...] }` — does it check user_id matches session?
2. Bulk endpoints: `{ "ids": [1,2,3,4,5] }` — does it filter to ones you own?
3. Filters: `?filter[user]=other-user-id` — server-trusted filters
4. Includes/expands: `?include=user.email` on an object you partly own

### Chain 6: Tenant ID injection
1. Multi-tenant SaaS: requests carry tenant ID in header / subdomain / path
2. Swap tenant ID — sometimes only the auth check uses your token, but data lookup uses the supplied tenant
3. Subdomain swap: `https://acme.app.com/api/x` → `https://other.app.com/api/x` with same cookie
4. Header forgery: `-H 'X-Tenant-ID: ...'`, `X-Org-ID`, `X-Account-ID`

### Chain 7: File / blob access
1. URLs like `/files/{uuid}/download`, `/api/attachments/{id}`
2. Pre-signed S3/GCS URLs — check if they leak in responses to other users
3. Direct S3 paths from JS — `bucket.s3.amazonaws.com/users/123/avatar.png` — sometimes bucket lists or other users' folders are readable
4. Variant: thumbnail/transcode services that bypass auth

### Chain 8: Email / username lookup endpoints
1. `/api/check-email?email=...` returning whether user exists is enum, not always rewarded
2. `/api/users/by-email?email=...` returning the user object → IDOR

## Discovery Methodology

### Step 1: Authenticate two accounts
Read `TARGET.md` → load the creds JSON. For each of accounts A and B, authenticate via `curl`/`httpx` against `login_url` and store the resulting cookie/token (e.g. `-c cookies_A.txt` / `-c cookies_B.txt`, or capture the bearer from the JSON response). Confirm each session works with a `/me`-style call. Record both user IDs. **All testing is: act as account B, target account A's resources.**

### Step 2: Map every object reference
Crawl the app surface as account A (`katana` with the rate flags from `TARGET.md`, plus `curl` against documented endpoints). Mine JS bundles (`curl` the bundle URLs, `grep` for `/api/`, route strings, ID params). Capture every request that contains an ID, UUID, slug, filename, or token in path/query/body/header. For each:
* What kind of ID? (int, UUID v1/v4, slug, hash, base64, JWT)
* Where does it appear? (URL, header, body, GraphQL var)
* Is it your ID, or scoped to you?

### Step 3: For each ID-bearing endpoint, test the matrix
Build each as a `curl`/`httpx` call. The oracle is **cross-boundary access**, not a 200 from your own session.

| Variant | Test |
|---|---|
| Same endpoint, A's ID, **B's token** | Should 403/404, not return A's data |
| Same endpoint, no auth | Should 401 |
| Method swap | GET→PUT/DELETE/PATCH/POST (`-X`) |
| Wrapping | array, object, null, duplicate param |
| Path traversal in ID | `../`, `..%2f`, double-encode |
| Format swap | int→string, UUID→int, base64→raw |
| Header override | `-H 'X-User-ID: ...'`, `X-Account`, `X-Tenant` |
| Verb tunneling | `?_method=DELETE`, `-H 'X-HTTP-Method-Override: DELETE'` |

### Step 4: Look for "obviously skipped" authz
* Bulk endpoints, batch APIs, "export" endpoints
* Internal admin endpoints in JS (`/api/internal/*`, `/api/admin/*`)
* Old API versions (`/v1/...` when current is v3 — older versions often missing checks)
* Mobile-only endpoints (`/m/api/*`)
* GraphQL fields not exposed in UI but exposed in introspection / types

## PROOF — cross-boundary access is the only oracle

A 200 from your **own** session proves nothing. The proof is reading or acting on account A's resource using account B's credentials.

1. Authenticate as A, fetch A's resource — record A's ID and the data it returns (this is the "victim" baseline).
2. Authenticate as B (separate cookie/token), request **A's** resource with **B's** session.
3. If B's session returns A's data (or successfully mutates A's object) → confirmed IDOR. Capture both request/response pairs (`curl -i` output): the A-baseline and the B-as-A cross-access.
4. Scale claim: enumerate 5–10 sequential/predicted IDs with B's session; if they return other users' data, state the estimated full range — do **not** dump.

Capture proof to files (`curl -i ... > proof_idor_A.txt` / `proof_idor_B_as_A.txt`) so the orchestrator can reproduce.

## Impact Demonstration

* Show: A's baseline response, the exact cross-account request (B's token, A's ID), the response leaking A's data
* Quantify scale: "Sequential IDs 100-105 tested with account B, all returned other users' data. Full range estimated at ~2M based on signup counter visible in /stats."
* Categorize the data: PII (email, phone, address), financial (orders, balances), auth (tokens, password hashes), content (private docs)

## Key Considerations

* **Never enumerate at scale.** 5-10 sequential IDs is proof. Mass extraction is illegal and out-of-scope on every program. Keep `ffuf`/`httpx` enumeration under the `TARGET.md` rate caps.
* IDORs that only return your own data with a different ID format aren't bugs.
* "I can read another user's username" is usually informative. "I can read another user's email + DOB + phone" is high.
* Combine IDOR with auth bypass / IDOR with self-signup → unauth IDOR → critical.
* Always check **rate limits** on the IDOR endpoint — if limited, that bounds your enumeration claim.
* No creds in `TARGET.md` and no self-signup in scope → log candidate endpoints as a **LEAD**; cross-account access can't be proven without a second account.
