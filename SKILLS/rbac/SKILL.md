---
description: "RBAC / privilege escalation hunting methodology. TRIGGER: user is testing role-based access control, broken function level authorization, horizontal/vertical privilege escalation, admin endpoint abuse, or role/permission boundaries."
---

# /hunt-rbac - RBAC / Broken Function Level Authorization Hunting

You are assisting **Liodeus (YesWeHack)**, whose RBAC reports include user→admin endpoint access, viewer→editor permission bleed, frontend-only role gating, and GraphQL field-level missing authz. RBAC bugs are often confused with IDOR — the distinction matters: **IDOR = wrong object; RBAC = wrong action**.

## Core Philosophy

RBAC bugs almost always come from **enforcement happening at the wrong layer**:
- Frontend hides a button but the API endpoint accepts the request
- Some routes have a middleware decorator, others don't (the new one the dev forgot)
- The check exists but only validates "logged in", not "is admin"
- Admin endpoints exist parallel to user endpoints with the same shape; one is locked, the other isn't

**The methodology is brute and exhaustive: enumerate every endpoint, replay each as every role.**

## RBAC Chains (from real reports)

### Chain 1: Frontend-only role gating
1. Log in as low-priv user; observe UI hides "Delete user", "Manage billing", "Invite admin"
2. Open DevTools → Network → log in to a separate browser as admin → grab the actual admin API calls
3. Replay those exact calls with low-priv session
4. If they succeed → RBAC bug. The frontend was the only enforcement.

### Chain 2: Forgotten endpoint variant
1. App has `/api/v2/users/{id}/role` — properly authz'd
2. Old `/api/v1/users/{id}/role` still mounted, no role check
3. Or `/api/internal/users/...` exists with weaker auth (intended for service-to-service)

### Chain 3: GraphQL field-level RBAC
1. Introspect schema, list every Query/Mutation
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

### Step 1: Acquire all roles
Get one account per role: `viewer`, `editor`, `admin`, `owner`, `billing`, `support`. If self-signup only gives one role, ask the program for higher roles or work with what you have plus inference (admin = inverse of low-priv).

### Step 2: Build the endpoint inventory
* Walk the app as the highest role you have, capturing every request (Burp/Caido)
* Walk again as each lower role
* Mine JS bundles for endpoints not exposed in UI to your role
* GraphQL: introspect, list all operations
* Swagger / OpenAPI: check `/swagger`, `/openapi.json`, `/api/docs`, `/v3/api-docs`

### Step 3: The replay matrix
For every endpoint that requires elevated privilege:
| Test | Expected | Bug? |
|---|---|---|
| Replay as low-priv user | 403 | 200 = vert priv esc |
| Replay as anonymous | 401 | 200 = unauth = critical |
| Replay as different-tenant admin | 403 | 200 = tenant bleed |
| Replay with tampered body (`role: admin`) | ignored | role applied = mass-assignment |
| Replay with role header / claim removed | 403 | 200 = trust boundary issue |

### Step 4: Look for the asymmetric pair
For every "view" endpoint, look for the matching "modify" endpoint and test it. For every list endpoint, check the create/delete partner. Devs often protect the obvious one and forget the partner.

### Step 5: Check JWT / session claims
* Decode the JWT — is `role` / `permissions` / `scope` in there?
* Try forging: alg confusion, weak HMAC secret, kid manipulation
* Try downgrade attacks: present an old token issued when you had a different role
* Refresh-token flow: does refresh re-fetch role from DB or copy from old token?

## Impact Demonstration

* Two screenshots: low-priv session executing the admin action successfully + the result visible to a real admin
* Document the action: did it actually mutate state? (delete user, set role, refund, etc.)
* Show what the admin role normally requires (UI screenshot of "Admins only" gating)
* Categorize: vertical (low → high), horizontal (peer → peer with role separation), tenant (cross-tenant admin)

## Key Considerations

* RBAC ≠ IDOR. Don't conflate them in reports — programs care about the distinction
* `403` on an endpoint doesn't mean it's safe — try the partner endpoints, the older versions, the GraphQL equivalent
* "The frontend hides it" is **never** a defense. Every program knows this; lean into it
* Some apps have role hierarchies; check transitively — `support` might inherit from `admin` in some flows
* If you find one missing-authz endpoint, expect to find more — same dev, same pattern, same blind spot
* Combine with IDOR for max impact: RBAC bug lets you call delete-user; IDOR lets you target any user
