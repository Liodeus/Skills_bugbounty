---
name: rbac
description: "Use when testing role-based access control, broken function level authorization, horizontal/vertical privilege escalation, admin endpoint abuse, or role/permission boundaries."
---

# /rbac - RBAC / Broken Function Level Authorization Hunting

You are assisting **Liodeus (YesWeHack)**, whose RBAC reports include user→admin endpoint access, viewer→editor permission bleed, frontend-only role gating, and GraphQL field-level missing authz. RBAC bugs are often confused with IDOR — the distinction matters: **IDOR = wrong object; RBAC = wrong action**.

## Autonomous harness

You run headless: only firewalled Bash (`curl`, `httpx`, `katana`, `ffuf`, `dnsx`, `nuclei`, `subfinder`, `jq`, unix) plus Read/Grep/Glob/Write. No browser, no proxy. Every replay is a `curl`/`httpx` call you build by hand.

* **Credentials** (when present): a JSON file at the path named in `TARGET.md`, with `login_url`, `notes`, and `accounts[]` (≥2 accounts, ideally different roles). Authenticate per account with `curl`/`httpx`, capture each session cookie/token, reuse it. **RBAC needs ≥2 accounts** (a low-priv and a high-priv, or two roles to compare). If `TARGET.md` has no creds → RBAC is a **LEAD only** (inventory the role-gated endpoints, skip active replay) unless self-signup is explicitly in scope.
* **Rate caps are firewall-ENFORCED.** `ffuf`/`katana`/`httpx`/`nuclei` MUST carry the rate flags from `TARGET.md` (example shape `-rl 8 -t 10`). No mass enumeration.
* Do not submit reports or push to Discord — the orchestrator does that.

## Core Philosophy

RBAC bugs almost always come from **enforcement happening at the wrong layer**:
- The frontend hides a button but the API endpoint accepts the request
- Some routes have a middleware decorator, others don't (the new one the dev forgot)
- The check exists but only validates "logged in", not "is admin"
- Admin endpoints exist parallel to user endpoints with the same shape; one is locked, the other isn't

**The methodology is brute and exhaustive: enumerate every endpoint, replay each as every role you hold.**

## RBAC Chains (from real reports)

### Chain 1: Frontend-only role gating
1. As the high-priv account, capture the actual admin API calls (mine the JS bundle for the endpoints, hit them with `curl` to see the request shape)
2. Replay those exact calls with the **low-priv** account's token/cookie
3. If they succeed → RBAC bug. The frontend was the only enforcement.

### Chain 2: Forgotten endpoint variant
1. App has `/api/v2/users/{id}/role` — properly authz'd
2. Old `/api/v1/users/{id}/role` still mounted, no role check
3. Or `/api/internal/users/...` exists with weaker auth (intended for service-to-service)

### Chain 3: GraphQL field-level RBAC
1. Introspect schema (`curl` a `__schema` query), list every Query/Mutation
2. As low-priv user, attempt every admin-shaped Mutation (`deleteUser`, `setRole`, `impersonate`)
3. Check field-level: `query { user(id: 1) { email passwordHash auditLog } }` — middleware authz'd the query but not the field
4. Check union/interface fragments: `... on AdminUser { ... }`

### Chain 4: Role manipulation in profile / signup
1. Signup with extra body fields: `{ "email": "...", "role": "admin" }`
2. Profile update: `PATCH /me { "role": "admin", "isAdmin": true, "permissions": ["*"] }`
3. Mass-assignment / over-posting in REST or GraphQL inputs
4. JWT / cookie that contains the role, signed but with `alg=none` or RS→HS confusion

### Chain 5: Multi-tenant role bleed
1. You're an admin in tenant A
2. Endpoint `/api/admin/users` — does it filter by tenant?
3. Sometimes it returns ALL users across all tenants (admin role check passes, tenant scope missing)
4. Variant: `/api/admin/users?tenant_id=B` — does it accept a tenant override?

### Chain 6: Workflow / state-bypass RBAC
1. State machine: draft → review → published. Only editors can publish.
2. As viewer, set state directly: `PATCH /post/123 { "state": "published" }`
3. Or: skip steps — go from draft straight to a state that should be unreachable
4. Approvals: self-approve, approve-own-request, approve in a state that doesn't allow it

### Chain 7: Indirect privilege via "self" endpoints
1. Low-priv has access to `/me`, `/me/sessions`, `/me/api-keys`
2. Create an API key for `/me` — can it call admin endpoints?
3. Some apps inherit privilege from impersonation tokens
4. Look at `act_as`, `assume_role`, `switch_user` features

## Discovery Methodology

### Step 1: Authenticate each role you hold
Read `TARGET.md` → load the creds JSON. For each account in `accounts[]`, authenticate via `curl`/`httpx` against `login_url` and store the session per role (`cookies_low.txt`, `cookies_admin.txt`, or per-role bearer tokens). Confirm each with a `/me`-style call and note its role. If self-signup gives only one role, work with that plus the highest role available in the creds; infer admin shape from the JS bundle.

### Step 2: Build the endpoint inventory
* Crawl as the **highest** role you hold (`katana` with `TARGET.md` rate flags), capturing every endpoint
* Mine JS bundles with `curl` + `grep` for endpoints, route strings, role names, permission strings not exposed to lower roles
* GraphQL: `curl` an introspection query, list all operations
* Swagger / OpenAPI: `curl /swagger`, `/openapi.json`, `/api/docs`, `/v3/api-docs`

### Step 3: The replay matrix
For every endpoint that requires elevated privilege, replay it as each role via `curl`/`httpx`. The oracle is **a lower-privilege session succeeding at a higher-privilege action**.

| Test | Expected | Bug? |
|---|---|---|
| Replay as low-priv account | 403 | 200 = vert priv esc |
| Replay as anonymous (no token) | 401 | 200 = unauth = critical |
| Replay as different-tenant admin | 403 | 200 = tenant bleed |
| Replay with tampered body (`role: admin`) | ignored | role applied = mass-assignment |
| Replay with role header / claim removed | 403 | 200 = trust boundary issue |

### Step 4: Look for the asymmetric pair
For every "view" endpoint, look for the matching "modify" endpoint and test it. For every list endpoint, check the create/delete partner. Devs often protect the obvious one and forget the partner.

### Step 5: Check JWT / session claims
* Decode the JWT (base64 the segments with `jq` / `base64 -d`) — is `role` / `permissions` / `scope` in there?
* Try forging: alg confusion, weak HMAC secret, kid manipulation
* Try downgrade attacks: present an old token issued when you had a different role
* Refresh-token flow: does refresh re-fetch role from DB or copy from old token?

## PROOF — a lower role succeeding is the only oracle

A 200 from the **admin** session proves nothing — that's the intended path. The proof is the **low-priv (or anonymous) session** performing the privileged action.

1. Establish the baseline: confirm the action is gated — replay as anonymous → 401, and confirm the admin session → 200 (this shows the endpoint normally requires privilege).
2. Replay the **exact** privileged request with the low-priv account's token/cookie.
3. If the low-priv session returns 200 and the action takes effect → confirmed vertical priv-esc. For state-changing actions, verify the effect actually landed (re-read the object, ideally with the admin/other session) — not just the 200.
4. Capture both request/response pairs (`curl -i ... > proof_rbac_admin.txt` / `proof_rbac_lowpriv.txt`) so the orchestrator can reproduce.

For destructive-shaped actions (delete user, set role, refund): if a 200 with a missing check can be shown without consuming the side effect, prefer that; otherwise fire once against your own test resource and document.

## Impact Demonstration

* Low-priv session executing the admin action successfully + the result confirmed (re-read showing the state changed)
* Document the action: did it actually mutate state? (delete user, set role, refund, etc.)
* Show what the role normally requires (the admin baseline call returning 200, anon returning 401/403)
* Categorize: vertical (low → high), horizontal (peer → peer with role separation), tenant (cross-tenant admin)

## Key Considerations

* RBAC ≠ IDOR. Don't conflate them in reports — programs care about the distinction
* `403` on an endpoint doesn't mean it's safe — try the partner endpoints, the older versions, the GraphQL equivalent
* "The frontend hides it" is **never** a defense. Every program knows this; lean into it
* Some apps have role hierarchies; check transitively — `support` might inherit from `admin` in some flows
* If you find one missing-authz endpoint, expect to find more — same dev, same pattern, same blind spot
* Combine with IDOR for max impact: RBAC bug lets you call delete-user; IDOR lets you target any user
* No second role in `TARGET.md` and no self-signup in scope → log the role-gated endpoints as a **LEAD**; vertical priv-esc can't be proven with a single role.
