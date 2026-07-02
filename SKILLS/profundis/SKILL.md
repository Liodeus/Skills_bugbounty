---
name: profundis
description: "Use when the user is doing passive asset discovery during recon with the Profundis API (api.profundis.io) — 3 distinct modes to discover subdomains/hosts/DNS. CREDIT-BASED (paid). Prefer Host search & DNS search (1 credit/page + powerful raw_query filtering) over Subdomain enumeration (ceil(results/100) credits). ALWAYS estimate-first on subdomains so you don't drain the wallet."
---

# Profundis — Asset Recon (api.profundis.io)

**Credit-based paid service.** 3 modes with different **sources** and **costs**. Picking the right one = save the wallet AND filter better. Docs: https://docs.profundis.io/

```bash
export PROFUNDIS_API_KEY="Ahsb5GINDyN2fscmxEJTZRQw4378gLHomPmHZbkkzGiNQJmyZbVSzNhKOIMi8Ttn"
```
Auth (all endpoints): header `X-API-KEY: $PROFUNDIS_API_KEY`, method `POST`, JSON body.

## 🔭 The 3 modes — which to choose

| Mode | Endpoint | Data source | Filtering | Cost | When |
|---|---|---|---|---|---|
| **Subdomain enumeration** | `/api/v2/common/data/subdomains` | aggregates **tools** (subfinder & co.) | none (just `domain`) | **`ceil(results/100)` credits** (can be expensive) | fast exhaustive subdomain list for a domain |
| **Host search** | `/api/v2/common/data/hosts` | **certstream / Certificate Transparency** + Profundis scan data | **rich `raw_query`** (dozens of fields) | **1 credit / call (= /page)** | precise filtering (tech, port, cert, IP, ASN…), often **cheaper** |
| **DNS search** | `/api/v2/common/data/dns` | **DNS records only** | `raw_query` (host, type, resolution) | **1 credit / call (= /page)** | DNS pivots (A/CNAME/MX/TXT…), resolutions |

👉 **Cost rule**: for a large domain, `subdomains` can cost dozens of credits (`ceil(n/100)`). `hosts`/`dns` = **1 credit/page** + `raw_query` to target → often **much cheaper and more surgical**. Prefer hosts/dns when you know what you're looking for.

## Other useful endpoints (swagger v2)

All `POST /api/v2/common/data/...`, auth `X-API-KEY`.

| Endpoint | Body | Returns | Usage |
|---|---|---|---|
| `/domains` | `{"domain":"..."}` | `{domain, results:[{hosts:[], ip, ports:[]}]}` | **shortcut**: all hosts/IPs/ports/ASN of a domain, no `raw_query` or pagination |
| `/vhosts` | like hosts (`raw_query`...) | `VhostData` (cert_subj, san, cert_org, not_before/after, port, resolution) | vhosts by **certificate/SAN** |
| `/whois` | `{"domain":"..."}` | whois | whois record |
| `/asn/details` | ASN | ASN details | ranges/org of an ASN |
| `/ip/intelligence` | IP | IP intel | geo/ASN/reputation of an IP |
| `/data/hosts/favicons` | `raw_query` + `max_favicons` | favicon hashes | favicon pivot |

> For "all hosts of a domain", `/domains {"domain":"x.com"}` is often the simplest (1 call, no dedup). `host:*.x.com` via `/hosts` gives more detail (port/cert/tech) but needs pagination + dedup.

## Response format (hosts/dns/vhosts)

Envelope: `{"data":[...], "total":N, "relation":"eq", "took":ms, "profundis_quotas":{...}}`.
- `total` = number of **records** (≠ unique hosts; lots of host×port×timestamp duplicates → **dedupe on `host`**).
- `HostData`: `host, port, protocol, resolution, resolved_ips[], ip_country_code/ip_city/ip_state, as_name/as_number, status_code/status_code_message/status_code_range, title, technologies[], cpes[], headers[], header_server_name, content_length, favicon_hash, cert_subj/cert_issuer_cn/cert_subj_org/cert_trusted/cert_expired, is_waf_or_cdn/waf_or_cdn_type[], analytics_tags[], timestamp/date_checked, transport_proto`.
- `DNSData`: `host, type` (A/AAAA/CNAME/MX/TXT/NS…), `value`, `as_levels[]`, `timestamp`.

## Limits & pagination (quota returned in `profundis_quotas`)
- `results_per_page` ≤ **50** (`MaxResultsPerQuery`) otherwise `E1013`.
- `page` ≤ 100 (API max) **but** capped by the account **quota** `MaxPagination` (e.g. **10** here → 500 records max accessible per query).
- Account quotas (example tier 2): `MaxQueryPerDay/Month:2700`, `MaxResultsPerDay/Month:5000`, `MaxSubdomainsEnumPerMonth:50000`, `MaxFiltersPerQuery:5`, `MaxTimeoutPerQuery:25`.
- **Short rate limit**: headers `x-ratelimit-limit:1` / `x-ratelimit-remaining` / `x-ratelimit-reset` → **~1 req per window** ⇒ space out calls (~20-25s) or retry-loop on `429`.
- Full hosts/dns/vhosts params: `raw_query, include, aggregate, results_per_page, page, order_by, direction, time_frame, max_favicons`. (⚠️ `aggregate:true` observed returning `data:[]` → don't rely on it for dedup; dedupe client-side on `host`.)
- ⚠️ The **SSE stream (`Accept: text/event-stream`) can return 000** (buffered). Use plain JSON mode without `Accept: text/event-stream`.

---

## 1) Subdomain enumeration (`/subdomains`) — tool aggregation

Body: `domain` (required), `estimate` (bool), `limit` (int).

### 💰 Cost & ESTIMATE-FIRST (mandatory here)
- Billing = **`ceil(returned_subdomains / 100)`** credits. estimate ≈ **1 credit**. Free cap 300.
- **ALWAYS** preview the count before paying:
```bash
# Step 1 — ESTIMATE (~1 credit): how many?
curl -s -X POST \
  "https://api.profundis.io/api/v2/common/data/subdomains" \
  -H "X-API-KEY: $PROFUNDIS_API_KEY" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","estimate":true,"limit":200}'
# → real cost = ceil(count/100). Decide BEFORE.

# Step 2 — REAL ENUMERATION, BOUNDED by limit (no estimate = billed)
curl -s -X POST \
  "https://api.profundis.io/api/v2/common/data/subdomains" \
  -H "X-API-KEY: $PROFUNDIS_API_KEY" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","limit":100}'    # limit=100 → 1 credit max
```
> ⚠️ Never without `limit` on an unknown domain (risk `limit:"max"` = draining the wallet). `{"domain","estimate":true}` alone returned `E9999 missing fields` live → keep an integer `limit`. Streaming: `-H "Accept: text/event-stream" -N`.

---

## 2) Host search (`/hosts`) — certstream/CT + scan, powerful filtering

Body: `raw_query` (required), `include` (`"all"` or `"host,resolution,port,..."`), `aggregate` (bool), `results_per_page` (int), `page` (int). **1 credit / call (page).**

```bash
curl -s -X POST \
  "https://api.profundis.io/api/v2/common/data/hosts" \
  -H "X-API-KEY: $PROFUNDIS_API_KEY" -H "content-type: application/json" \
  -d '{"raw_query":"host:*.example.com","include":"all","aggregate":false,"results_per_page":50,"page":1}'
```

### `raw_query` query language (Host search)
Operators: `AND` `OR` `NOT`, parentheses `()`, wildcard `*`, quotes `"..."` (values with spaces), comparators `<` `>` (numeric fields).

| Field | Usage / example |
|---|---|
| `host` | `host:*.example.com`, `host:sub.*.xyz` |
| `port` | `port:80`, `port:84*`, `port<8080` |
| `protocol` | `protocol:smtp`, `protocol:http*` |
| `status_code` / `status_code_range` / `status_code_message` | `NOT status_code:503`, `status_code_range:200` |
| `title` | `title:"Node Exporter"` |
| `technologies` | `technologies:jquery*`, `NOT technologies:cloudflare` |
| `headers` | `headers:"Set-Cookie: PHPSESSID=*"` |
| `header_server_name` | `header_server_name:nginx* AND port:8080` |
| `favicon_hash` | `favicon_hash:"3236809339"` (murmur3) |
| `cert_subj` / `cert_issuer_cn` / `cert_subj_org` | `cert_subj:*.example.com`, `cert_subj_org:*some-company*` |
| `resolution` | `resolution:"103.21.*"`, `resolution:"*.elb.us-east-1.amazonaws.com"` |
| `ip_country_code` / `ip_city` / `ip_state` | `ip_country_code:US`, `ip_city:"New Delhi"` |
| `as_name` / `as_number` | `as_name:"TEAMINTERNET-AS*"`, `NOT as_number:"13335"` |
| `analytics_tags` | `analytics_tags:*` |
| `content_length` | `content_length<2000` |

Complex example: `host:*.example.com AND (protocol:"https" OR status_code:"400") AND NOT technologies:cloudflare`

**Recon use cases**: find an org's hosts by certificate (`cert_subj_org:*orange*`), by favicon, by tech (spot a CMS/version), by ASN/IP range, by server header — far more targeted than plain enumeration.

---

## 3) DNS search (`/dns`) — DNS records only

Same body (`raw_query`, `include`, `aggregate`, `results_per_page`, `page`). **1 credit / call (page).** Fields: `host`, `type` (A/AAAA/CNAME/MX/TXT/NS…), `resolution`.

```bash
curl -s -X POST \
  "https://api.profundis.io/api/v2/common/data/dns" \
  -H "X-API-KEY: $PROFUNDIS_API_KEY" -H "content-type: application/json" \
  -d '{"raw_query":"host:*.example.com AND type:CNAME","include":"all","aggregate":false,"results_per_page":50,"page":1}'
```
**Use cases**: DNS pivots (CNAME → subdomain takeover candidates), MX/TXT (mail/SPF), IP resolutions, infra mapping.

---

## Cost control (hosts/dns)
- Each call = **1 credit**, **per page**. So: the **narrowest** possible `raw_query` + a reasonable `results_per_page` + **only paginate when necessary**.
- `aggregate:true` groups results (useful to count/see diversity before paginating in detail).
- No unbounded pagination loop: each extra `page` = +1 credit.

## Error codes (all endpoints)
| HTTP | code | meaning | action |
|---|---|---|---|
| 400 | `E9999` | invalid body / missing field | check `raw_query`/`domain`(+`limit`) |
| 402 | `Q2014` | out of credits (nothing billed) | top up / stop |
| 429 | — | `Limit exceeded` (rate limit) | space out calls |

## Recon integration
- Complements OathNet (`oathnet_search_subdomains`) and manual recon; add discovered assets to the **in-scope target list**.
- Recommended pipeline: `dns`/`hosts` (targeted, 1 credit) to explore/filter → `subdomains` (estimate first) only if you want the exhaustive list.

## ⚠️ Wallet guardrails (summary)
1. **subdomains**: `estimate:true` FIRST, then `limit`; never `"max"` blind.
2. **hosts/dns**: 1 credit/page → narrow `raw_query`, bounded `results_per_page`, paginate sparingly.
3. `402` → stop. `429` → space out.
4. One domain/one query per call; no unbounded loop.
