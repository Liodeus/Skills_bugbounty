---
name: profundis
description: Recon via Profundis API (api.profundis.io) — 3 modes distincts pour découvrir sous-domaines/hosts/DNS. PAYANT à crédits. Préférer Host search & DNS search (1 crédit/page + filtrage raw_query puissant) à Subdomain enumeration (ceil(résultats/100) crédits). TOUJOURS estimate-first sur subdomains pour ne pas vider le wallet. Use for passive asset discovery during recon.
---

# Profundis — Recon d'actifs (api.profundis.io)

**Service payant à crédits.** 3 modes aux **sources** et **coûts** différents. Choisir le bon = économiser le wallet ET mieux filtrer. Doc : https://docs.profundis.io/

```bash
export PROFUNDIS_API_KEY="Ahsb5GINDyN2fscmxEJTZRQw4378gLHomPmHZbkkzGiNQJmyZbVSzNhKOIMi8Ttn"
```
Auth (tous les endpoints) : header `X-API-KEY: $PROFUNDIS_API_KEY`, méthode `POST`, body JSON.

## 🔭 Les 3 modes — lequel choisir

| Mode | Endpoint | Source des données | Filtrage | Coût | Quand |
|---|---|---|---|---|---|
| **Subdomain enumeration** | `/api/v2/common/data/subdomains` | agrège des **outils** (subfinder & co.) | aucun (juste `domain`) | **`ceil(résultats/100)` crédits** (peut être cher) | liste rapide exhaustive de sous-domaines d'un domaine |
| **Host search** | `/api/v2/common/data/hosts` | **certstream / Certificate Transparency** + données de scan Profundis | **`raw_query` riche** (dizaines de champs) | **1 crédit / appel (= /page)** | filtrage précis (techno, port, cert, IP, ASN…), souvent **moins cher** |
| **DNS search** | `/api/v2/common/data/dns` | **enregistrements DNS uniquement** | `raw_query` (host, type, resolution) | **1 crédit / appel (= /page)** | pivots DNS (A/CNAME/MX/TXT…), résolutions |

👉 **Règle de coût** : pour un gros domaine, `subdomains` peut coûter des dizaines de crédits (`ceil(n/100)`). `hosts`/`dns` = **1 crédit/page** + `raw_query` pour cibler → souvent **bien moins cher et plus chirurgical**. Privilégier hosts/dns quand on sait ce qu'on cherche.

## Autres endpoints utiles (swagger v2)

Tous `POST /api/v2/common/data/...`, auth `X-API-KEY`.

| Endpoint | Body | Retour | Usage |
|---|---|---|---|
| `/domains` | `{"domain":"..."}` | `{domain, results:[{hosts:[], ip, ports:[]}]}` | **raccourci** : tous les hosts/IP/ports/ASN d'un domaine, sans `raw_query` ni pagination |
| `/vhosts` | comme hosts (`raw_query`...) | `VhostData` (cert_subj, san, cert_org, not_before/after, port, resolution) | vhosts par **certificat/SAN** |
| `/whois` | `{"domain":"..."}` | whois | enregistrement whois |
| `/asn/details` | ASN | détails ASN | ranges/orga d'un ASN |
| `/ip/intelligence` | IP | intel IP | géo/ASN/réputation IP |
| `/data/hosts/favicons` | `raw_query` + `max_favicons` | hashes favicon | pivot favicon |

> Pour "tous les hosts d'un domaine", `/domains {"domain":"x.com"}` est souvent le plus simple (1 appel, pas de dédup). `host:*.x.com` via `/hosts` donne plus de détail (port/cert/techno) mais nécessite pagination+dédup.

## Format de réponse (hosts/dns/vhosts)

Enveloppe : `{"data":[...], "total":N, "relation":"eq", "took":ms, "profundis_quotas":{...}}`.
- `total` = nombre de **records** (≠ hosts uniques ; beaucoup de doublons host×port×timestamp → **dédupe sur `host`**).
- `HostData` : `host, port, protocol, resolution, resolved_ips[], ip_country_code/ip_city/ip_state, as_name/as_number, status_code/status_code_message/status_code_range, title, technologies[], cpes[], headers[], header_server_name, content_length, favicon_hash, cert_subj/cert_issuer_cn/cert_subj_org/cert_trusted/cert_expired, is_waf_or_cdn/waf_or_cdn_type[], analytics_tags[], timestamp/date_checked, transport_proto`.
- `DNSData` : `host, type` (A/AAAA/CNAME/MX/TXT/NS…), `value`, `as_levels[]`, `timestamp`.

## Limites & pagination (quota retourné dans `profundis_quotas`)
- `results_per_page` ≤ **50** (`MaxResultsPerQuery`) sinon `E1013`.
- `page` ≤ 100 (max API) **mais** plafonné par le **quota du compte** `MaxPagination` (ex. **10** ici → 500 records max accessibles par query).
- Quotas compte (exemple tier 2) : `MaxQueryPerDay/Month:2700`, `MaxResultsPerDay/Month:5000`, `MaxSubdomainsEnumPerMonth:50000`, `MaxFiltersPerQuery:5`, `MaxTimeoutPerQuery:25`.
- **Rate limit court** : header `x-ratelimit-limit:1` / `x-ratelimit-remaining` / `x-ratelimit-reset` → **~1 req par fenêtre** ⇒ espacer (~20-25s) ou boucle de retry sur `429`.
- Params hosts/dns/vhosts complets : `raw_query, include, aggregate, results_per_page, page, order_by, direction, time_frame, max_favicons`. (⚠️ `aggregate:true` observé renvoyant `data:[]` → ne pas compter dessus pour dédupe ; dédupe côté client sur `host`.)
- ⚠️ L'endpoint **stream via le proxy Burp ne passe pas** (SSE bufferisé → 000). Utiliser le mode JSON normal (sans `Accept: text/event-stream`).

---

## 1) Subdomain enumeration (`/subdomains`) — agrégation d'outils

Body : `domain` (requis), `estimate` (bool), `limit` (int).

### 💰 Coût & ESTIMATE-FIRST (obligatoire ici)
- Facturation = **`ceil(returned_subdomains / 100)`** crédits. estimate ≈ **1 crédit**. Cap gratuit 300.
- **TOUJOURS** prévisualiser le compte avant de payer :
```bash
# Étape 1 — ESTIMATE (~1 crédit) : combien ?
curl --proxy http://127.0.0.1:8080 -s -X POST \
  "https://api.profundis.io/api/v2/common/data/subdomains" \
  -H "X-API-KEY: $PROFUNDIS_API_KEY" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","estimate":true,"limit":200}'
# → coût réel = ceil(compte/100). Décider AVANT.

# Étape 2 — ÉNUMÉRATION RÉELLE, BORNÉE par limit (sans estimate = facturé)
curl --proxy http://127.0.0.1:8080 -s -X POST \
  "https://api.profundis.io/api/v2/common/data/subdomains" \
  -H "X-API-KEY: $PROFUNDIS_API_KEY" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","limit":100}'    # limit=100 → 1 crédit max
```
> ⚠️ Jamais sans `limit` sur un domaine inconnu (risque `limit:"max"` = vider le wallet). `{"domain","estimate":true}` seul a renvoyé `E9999 missing fields` en live → garder un `limit` entier. Streaming : `-H "Accept: text/event-stream" -N`.

---

## 2) Host search (`/hosts`) — certstream/CT + scan, filtrage puissant

Body : `raw_query` (requis), `include` (`"all"` ou `"host,resolution,port,..."`), `aggregate` (bool), `results_per_page` (int), `page` (int). **1 crédit / appel (page).**

```bash
curl --proxy http://127.0.0.1:8080 -s -X POST \
  "https://api.profundis.io/api/v2/common/data/hosts" \
  -H "X-API-KEY: $PROFUNDIS_API_KEY" -H "content-type: application/json" \
  -d '{"raw_query":"host:*.example.com","include":"all","aggregate":false,"results_per_page":50,"page":1}'
```

### Langage de requête `raw_query` (Host search)
Opérateurs : `AND` `OR` `NOT`, parenthèses `()`, wildcard `*`, guillemets `"..."` (valeurs avec espaces), comparateurs `<` `>` (champs numériques).

| Champ | Usage / exemple |
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

Exemple complexe : `host:*.example.com AND (protocol:"https" OR status_code:"400") AND NOT technologies:cloudflare`

**Cas d'usage recon** : trouver les hosts d'une orga par certificat (`cert_subj_org:*orange*`), par favicon, par techno (repérer un CMS/version), par ASN/IP range, par header serveur — bien plus ciblé que la simple énum.

---

## 3) DNS search (`/dns`) — enregistrements DNS uniquement

Body identique (`raw_query`, `include`, `aggregate`, `results_per_page`, `page`). **1 crédit / appel (page).** Champs : `host`, `type` (A/AAAA/CNAME/MX/TXT/NS…), `resolution`.

```bash
curl --proxy http://127.0.0.1:8080 -s -X POST \
  "https://api.profundis.io/api/v2/common/data/dns" \
  -H "X-API-KEY: $PROFUNDIS_API_KEY" -H "content-type: application/json" \
  -d '{"raw_query":"host:*.example.com AND type:CNAME","include":"all","aggregate":false,"results_per_page":50,"page":1}'
```
**Cas d'usage** : pivots DNS (CNAME → subdomain takeover candidates), MX/TXT (mail/SPF), résolutions IP, mapping infra.

---

## Maîtrise du coût (hosts/dns)
- Chaque appel = **1 crédit**, **par page**. Donc : `raw_query` le plus **étroit** possible + `results_per_page` raisonnable + **ne paginer que si nécessaire**.
- `aggregate:true` regroupe (utile pour compter/voir la diversité avant de paginer en détail).
- Pas de boucle de pagination non bornée : chaque `page` supplémentaire = +1 crédit.

## Codes d'erreur (tous endpoints)
| HTTP | code | sens | action |
|---|---|---|---|
| 400 | `E9999` | body invalide / champ manquant | vérifier `raw_query`/`domain`(+`limit`) |
| 402 | `Q2014` | plus de crédits (rien facturé) | recharger / stop |
| 429 | — | `Limit exceeded` (rate limit) | espacer les appels |

## Intégration recon
- Complément d'OathNet (`oathnet_search_subdomains`) et de la recon manuelle ; ajouter les actifs trouvés au **scope Burp**.
- Pipeline conseillé : `dns`/`hosts` (ciblé, 1 crédit) pour explorer/filtrer → `subdomains` (estimate d'abord) seulement si on veut la liste exhaustive.

## ⚠️ Garde-fous wallet (résumé)
1. **subdomains** : `estimate:true` AVANT, puis `limit` ; jamais `"max"` à l'aveugle.
2. **hosts/dns** : 1 crédit/page → `raw_query` étroit, `results_per_page` borné, paginer avec parcimonie.
3. `402` → stop. `429` → espacer.
4. Un domaine/une requête par appel ; pas de boucle non bornée.
