---
name: business-logic
description: "Use when the user is testing application/business-logic flaws — workflow & state-machine bypass, price/quantity/currency manipulation, coupon & discount abuse, negative/overflow amounts, race conditions on limited resources, trust-boundary violations between client and server, multi-step process step-skipping, or abusing an intended feature to reach an unintended outcome. Complements /idor and /rbac (authorization) and /ato (auth flows) — this is about logic the app *intends* to enforce but doesn't."
---

# /business-logic - Business Logic Vulnerability Hunting

You are assisting **Liodeus (YesWeHack)**. Business logic is the **highest bounty-per-find class** and the one AI scanners miss almost entirely — there is no signature for "the app let me pay -1 items" or "I skipped the payment step." The bug is always in the gap between what the developer *assumed* about the flow and what the server *actually enforces*.

## Core Philosophy

Logic bugs have no payload. You find them by **modelling the intended flow, then violating an assumption the server forgot to re-check**:
1. **Map the intended state machine** — every step, every value the app expects the client to send, every invariant ("total = sum of items", "step 3 requires step 2", "one coupon per order").
2. **Break one assumption at a time** — reorder steps, replay a consumed token, send a value the UI can't produce (negative, zero, huge, wrong currency, someone else's ID).
3. **Prove it changed a real outcome** — money moved, a paid feature unlocked, a limit was exceeded, a workflow gate was skipped. No outcome change = not a bug.

Server-trust is the root cause: the client is not a trust boundary. Anything the browser computes (price, discount, role, quantity, "is_admin", "already_paid") is an input you control.

## Business Logic Chains (from real reports)

### Chain 1: Price / total manipulation
1. Add item to cart, intercept the checkout/confirm request.
2. Look for client-supplied money fields: `price`, `amount`, `total`, `unit_price`, `currency`, `shipping`.
3. Lower the price, zero it, or send a cheaper item's price for an expensive item — does the server recompute or trust it?
4. **Currency swap**: pay 100 in a weaker currency while charged as USD; or omit `currency` and let it default.
5. Confirm the order actually completes at the manipulated price (check the receipt/invoice, not just the 200).

### Chain 2: Negative / overflow quantity
1. Quantity or amount fields: send `-1`, `0`, `0.001`, `9999999999`, `1e10`, or a string.
2. Negative quantity → refund/credit to your balance (classic "buy -5 items, get money").
3. Integer overflow on `quantity * price` wrapping to a small/negative total.
4. Fractional units where only integers are expected (`0.1` of a licensed seat).

### Chain 3: Coupon / discount / referral abuse
1. Apply one coupon, then replay the apply-coupon request → stacking the same code N times.
2. Combine mutually-exclusive codes; apply a code after the order is priced.
3. Self-referral: refer your own second account for the signup bonus in a loop.
4. Reuse a single-use code across accounts, or race two applies before the "used" flag is written (→ `/rce`-style race, see Chain 6).

### Chain 4: Workflow / state-machine step-skip
1. Multi-step flow (cart → address → payment → confirm; or KYC step1 → step2 → approved).
2. Complete step 1, then request the **final** step's endpoint directly, skipping payment/verification.
3. Replay the "success" callback (e.g. payment-provider return URL) without an actual payment.
4. Go backwards: re-open a finalized order and mutate it; edit a submitted-and-locked record.
5. Force a state the UI never offers: `status=approved`, `paid=true`, `kyc_verified=1` in the body.

### Chain 5: Quota / limit / entitlement bypass
1. Free-tier limit (N API calls, N projects, 1 seat) — is it enforced server-side per request, or just hidden in the UI?
2. Create the (N+1)th resource by calling the create endpoint directly.
3. Toggle a paid feature flag client-side (`"plan":"pro"`, `"features":["export"]`) and see if the backend honors it.
4. Downgrade-then-keep: subscribe, use a premium action, cancel/refund, retain the artifact.

### Chain 6: Race conditions on limited resources
1. Any "consume once" or "balance ≥ amount" check: gift cards, one-time coupons, wallet withdrawals, seat claims, voting.
2. Fire the same request in parallel (burst 10-50 near-simultaneous) before the state write lands → double-spend / over-withdraw / multi-claim.
3. Tools: HTTP/2 single-packet attack, or a tight parallel `curl` burst. Prove the invariant broke (balance went negative, code used twice).
4. Keep bursts small — this is proof, not load testing (see guardrails).

### Chain 7: Parameter tampering on identity/ownership of an action
1. Actions that act "on behalf of": `POST /transfer {"from":"me","to":"x","amount":10}` — swap `from` to a victim.
2. `owner_id`, `account_id`, `seller_id`, `created_by` fields the server should derive from the session but instead trusts from the body.
3. (Where this crosses into authorization, confirm cross-user with `/idor` / `/rbac`.)

## Discovery Methodology

### Step 1: Enumerate money- and state-changing flows
Prioritise anything touching **money, entitlements, or a multi-step gate**: checkout, subscriptions, wallets/credits, refunds, transfers, coupons, invites/referrals, KYC/onboarding, order/ticket lifecycle, voting/limits. These are where logic bugs pay.

### Step 2: Model the intended flow, then list its invariants
For each flow, write down (one line each in your working file):
* The ordered steps and which endpoint drives each.
* Every value the client sends that the server *should* own (price, total, role, status, owner, quantity, currency, discount).
* The invariants the app assumes: "total = Σ items", "one coupon", "payment before fulfilment", "N ≤ plan limit", "consume once".

### Step 3: Violate one invariant at a time
| Assumption | Test |
|---|---|
| Client price is trustworthy | Lower / zero / negative it; recompute check |
| Quantity is a positive int | `-1`, `0`, huge, fractional, string |
| Coupon used once | Replay apply; stack; race two applies |
| Steps run in order | Call final step directly; replay success callback |
| Limit enforced server-side | Create N+1 via API; flip plan flag in body |
| Consume-once is atomic | Parallel burst before the write lands |
| Action's owner = session | Swap `from`/`owner_id`/`account_id` in body |

### Step 4: Timebox and diff outcomes
For each violation, capture the request + response **and** the resulting state (receipt, balance, entitlement, record status). A 200 is not proof; a **changed real outcome** is. If a flow yields no signal after its top vectors, log what you tried and move to the next money/state flow.

## Impact Demonstration

* Show the intended flow, the single assumption you broke, and the **outcome delta**: price paid vs charged, balance before/after, a paid feature you shouldn't have, a limit you exceeded, a gate you skipped.
* Quantify money where possible ("purchased a $499 plan for $0.01", "withdrew $X twice from a $X balance").
* For races, show the invariant broken (used-twice code, negative balance) with the parallel requests + timestamps.
* State whose money/resource is at risk — yours (safe PoC) vs the platform vs other users.

## Key Considerations

* **The client is never a trust boundary.** Any value the browser computes is attacker-controlled input.
* **Prove with your own account / resource.** Manipulate *your* order, race *your* gift card, self-refer *your* second account. Never fire money-moving PoCs against real users (see CLAUDE.md *When testing destructive-shaped actions*).
* **Races are proof, not load.** A small parallel burst that demonstrates the double-spend is enough — no sustained flooding, no DoS.
* **Revert side effects.** If a test leaves your account in a paid/altered state, undo it or note it; don't leave real charges dangling.
* Business-logic bugs are **program-specific** — record on the per-program memory which flows exist and which paid, so you go straight there next time.
* Where the flaw is really missing authorization (someone else's object/role), confirm cross-user via `/idor` or `/rbac`; where it's an auth-flow weakness, hand to `/ato`. This skill owns the *logic* gap, not the authz gate.
