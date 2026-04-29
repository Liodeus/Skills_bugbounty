---
description: "IDOR / BOLA hunting methodology. TRIGGER: user is testing for insecure direct object reference, broken object level authorization, ID enumeration, UUID prediction, or any cross-tenant / cross-user data access."
---

# /hunt-idor - IDOR / BOLA Hunting

You are assisting **Liodeus (YesWeHack)**, whose IDOR reports include UUID v1 prediction, HTTP-method swap bypass, GraphQL node-id enumeration, and multi-tenant boundary breaks. **IDORs are easy to find but uninteresting unless they expose PII or admin functions** — chase impact, not just access.

## Core Philosophy

IDOR is the simplest bug class but the most easily dismissed. The bar is:
1. **Cross-user / cross-tenant** — show data belonging to a user/tenant you do not control
2. **Real impact** — PII, financial, auth, content; not "I can read another user's display name color"
3. **Reproducible** — both accounts yours, both IDs documented, screenshots before and after

## IDOR Chains (from real reports)

### Chain 1: Integer ID enumeration → mass PII
1. Find endpoint like `/api/users/123/profile` returning email/phone
2. Confirm user 123 ≠ you, and request returns 200 with their data
3. Document scale: enumerate 1..N quietly; report "I tested 5 sequential IDs, all returned other users' PII; full enumeration would expose all N users"
4. **Stop at proof. Do not mass-extract.**

### Chain 2: UUID v1 / weak UUID prediction
1. Identify UUID format — v1 has timestamp + MAC, predictable
2. Generate predicted UUIDs around your own
3. If those resolve → IDOR despite "non-guessable IDs"
4. Tools: `uuid` library, custom v1 generator using observed timestamps

### Chain 3: HTTP method swap
1. Endpoint `/api/users/{id}` requires auth + ownership for GET
2. Try DELETE, PUT, PATCH — sometimes only GET is checked
3. Try PROPFIND, OPTIONS for WebDAV stacks
4. Try `X-HTTP-Method-Override: DELETE` on a POST

### Chain 4: GraphQL node-id / global-id enumeration
1. Decode base64 node IDs (`Relay`-style: `User:123` → `VXNlcjoxMjM=`)
2. Increment integer portion, re-encode
3. Query `node(id: "...")` — many resolvers don't re-check authz on the global resolver
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
4. Header forgery: `X-Tenant-ID`, `X-Org-ID`, `X-Account-ID`

### Chain 7: File / blob access
1. URLs like `/files/{uuid}/download`, `/api/attachments/{id}`
2. Pre-signed S3/GCS URLs — check if they leak in responses to other users
3. Direct S3 paths from JS — `bucket.s3.amazonaws.com/users/123/avatar.png` — sometimes bucket lists or other users' folders are readable
4. Variant: thumbnail/transcode services that bypass auth

### Chain 8: Email / username lookup endpoints
1. `/api/check-email?email=...` returning whether user exists is enum, not always rewarded
2. `/api/users/by-email?email=...` returning the user object → IDOR

## Discovery Methodology

### Step 1: Two accounts, always
Set up account A (attacker) and account B (victim). Document both IDs, both sessions. All testing happens A-trying-to-access-B.

### Step 2: Map every object reference
Browse the app as A. Capture every request that contains an ID, UUID, slug, filename, or token in path/query/body/header. Build a list. For each:
* What kind of ID? (int, UUID v1/v4, slug, hash, base64, JWT)
* Where does it appear? (URL, header, body, GraphQL var)
* Is it your ID, or scoped to you?

### Step 3: For each ID-bearing endpoint, test the matrix
| Variant | Test |
|---|---|
| Same endpoint, B's ID, A's session | Should 403/404, not return B's data |
| Same endpoint, no auth | Should 401 |
| Method swap | GET→PUT/DELETE/PATCH/POST |
| Wrapping | array, object, null, duplicate param |
| Path traversal in ID | `../`, `..%2f`, double-encode |
| Format swap | int→string, UUID→int, base64→raw |
| Header override | `X-User-ID`, `X-Account`, `X-Tenant` |
| Verb tunneling | `?_method=DELETE`, `X-HTTP-Method-Override` |

### Step 4: Look for "obviously skipped" authz
* Bulk endpoints, batch APIs, "export" endpoints
* Internal admin endpoints in JS (`/api/internal/*`, `/api/admin/*`)
* Old API versions (`/v1/...` when current is v3 — older versions often missing checks)
* Mobile-only endpoints (`/m/api/*`)
* GraphQL fields not exposed in UI but exposed in introspection / types

## Impact Demonstration

* Show object before access, the request, the response with B's data, B's account verifying the data is theirs
* Quantify scale: "Sequential IDs 100-105 tested, all returned other users' data. Full range estimated at ~2M based on signup counter visible in /stats."
* Categorize the data: PII (email, phone, address), financial (orders, balances), auth (tokens, password hashes), content (private docs)

## Key Considerations

* **Never enumerate at scale.** 5-10 sequential IDs is proof. Mass extraction is illegal and out-of-scope on every program.
* IDORs that only return your own data with a different ID format aren't bugs.
* "I can read another user's username" is usually informative. "I can read another user's email + DOB + phone" is high.
* Combine IDOR with auth bypass / IDOR with self-signup → unauth IDOR → critical.
* Always check **rate limits** on the IDOR endpoint — if limited, that bounds your enumeration claim.
* Triage will replicate. Give exact IDs, exact requests, both your accounts.
