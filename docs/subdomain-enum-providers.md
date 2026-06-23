# Paid subdomain-enumeration providers (research, 2026-06)

Research for offloading subdomain discovery in autohunt's recon step. **Key insight:** autohunt's
recon runs ProjectDiscovery **subfinder**, which natively aggregates almost all of these as
"providers." So you don't need a separate platform — drop an API key into
`~/.config/subfinder/provider-config.yaml` and subfinder pulls that platform's dataset. Stack several
keys for far better coverage than any single source.

> Pricing verified against official pages where reachable (June 2026). Some pages are bot/JS-gated —
> flagged as estimate / contact-sales rather than invented. Confirm in-dashboard before buying.

## Paid sources that plug into subfinder (the right category)

| Platform | Price (2026) | What you get | subfinder key | Verdict |
|---|---|---|---|---|
| **SecurityTrails** | Free 50 lookups/mo · paid = **contact-sales** (opaque) | Deepest **historical/passive-DNS** index, **any domain**; best for forgotten/takeover-prone subs | `securitytrails` | **Best coverage**, but pricing friction since the Recorded Future acquisition |
| **Shodan** | **One-time ~$49 lifetime** (often ~$5 on sale); $69/mo for volume | DNS/subdomain API + bonus per-host data (ports/CVEs/certs) on the same key | `shodan` | **Best value** — buy once, keep forever |
| **C99.nl** | **$5/mo or $25/yr** (150k req/mo) | Single subdomain endpoint + ~50 other recon APIs | `c99` | **Cheapest**; coverage noisier/weaker |
| **Netlas** | Free 50/day · **$49/mo** (1k/day, 1M results/mo) · $249/mo | Internet-wide DNS+cert+WHOIS dataset, any domain | `netlas` (non-default) | Best free daily quota; solid mid-tier |
| **FullHunt** | Free 10/mo · **$149/mo** (500 cr) · $1,499/mo (10k) | Subs **+ ports + tech + CVEs** per host in one call | `fullhunt` | Best if you want enriched results, not just names |
| **Censys** | Free 100 cr/mo · pay-as-you-go **from $100** (12-mo credits) | Subs from cert/SAN + internet scans | `censys` (needs `PAT:ORG_ID`; paid for an org id) | Good cert-fronted assets; credits burn fast |
| **WhoisXML** | Free ~50 lookups · **$19/mo** (100) … $149/mo (1k) | Passive historical subdomains (10 DRS credits/lookup) | `whoisxmlapi` | Transparent pricing but pricey per lookup |
| **FOFA** | Free 300 q/mo · **$49/mo** ($25/mo annual) | Scan engine, `domain=`/`cert=` pivots | `fofa` (`email:key`) | Best of the China engines for a Western hunter (EN site, USD) |
| **BeVigil** (CloudSEK) | Free to start (~25–200 cr) | Subs/endpoints mined from **decompiled Android APKs** — internal/staging hosts not in DNS/CT | `bevigil` | Unique additive data when the target has a mobile app |
| **Chaos** (free, list it) | **Free** | PD's dataset — **only domains in public bug-bounty programs** | `chaos` | Always enable; complements the rest |
| ~~BinaryEdge~~ | **shut down Mar 2025** | — | removed from subfinder | Do not use |

### Free baseline already in subfinder (keep on)
`crtsh` (CT search, no account) and `certspotter` (SSLMate CT API; free 100 single-host + 10
full-domain/hr). Plus `Subdomain Center` (free, ML-boosted, often finds more than crt.sh) usable
directly though it's not a default subfinder source.

## Full EASM platforms — more than enumeration, likely overkill
Dashboards / continuous-monitoring products, enterprise-priced, **not** subfinder sources. Good for
monitoring *your own* assets; wrong tool/price for offensive bug-bounty recon:
- **Detectify** Surface Monitoring — from **€302/mo**, **€1,500/yr minimum**.
- **Censys ASM** — contact-sales (no self-serve).
- **ProjectDiscovery Cloud (PDCP)** — pay-as-you-go from **$250**; full discovery→nuclei pipeline.
- **DomainTools / Farsight DNSDB** — enterprise, ~$40k–$118k/yr; the useful piece (DNSDB passive DNS)
  is reachable far cheaper via subfinder's `dnsdb` source.

## Recommendation (tailored to autohunt)
- **Best bang-for-buck:** **Shodan lifetime (~$49)** + **C99 ($25/yr)** + free **Chaos** + the free CT
  sources (`crtsh`, `certspotter`). ~$74 of mostly one-time spend, big coverage jump, plugs straight in.
- **Single strongest paid source (if you'll email sales):** **SecurityTrails** — coverage king for any
  domain, the community's #1 subfinder key. (A circulating "~$500/mo for ~20k queries" is unverified.)
- **One clean monthly managed feed:** **FullHunt Builder ($149/mo)** (subs+ports+CVEs) or **Netlas
  Freelancer ($49/mo)** (broad dataset, generous limits).

## How to wire it into autohunt
1. Get the API key(s).
2. Put them in `~/.config/subfinder/provider-config.yaml`, e.g.:
   ```yaml
   securitytrails: ["KEY"]
   shodan: ["KEY"]
   c99: ["KEY"]
   netlas: ["KEY"]          # non-default → needs -all or -s netlas
   fofa: ["email@x.com:KEY"]
   censys: ["PAT:ORG_ID"]   # Platform API format (not the old api-id:secret)
   ```
3. Run subfinder with `-all` to include non-default sources (e.g. Netlas). The recon subagent
   (`autohunt/agents/subagents/recon.md`) calls `subfinder -silent -d <domain>`; add `-all` there to use
   every configured provider.

## Sources
SecurityTrails (docs.securitytrails.com, corp/api) · Shodan (account.shodan.io/billing,
developer.shodan.io) · Censys (censys.com/resources/pricing, docs.censys.com) ·
ProjectDiscovery/Chaos (projectdiscovery.io/pricing, chaos.projectdiscovery.io) ·
FullHunt (fullhunt.io/pricing/console) · Netlas (netlas.io/pricing) · C99 (api.c99.nl/shop) ·
WhoisXML (subdomains.whoisxmlapi.com/api/pricing) · Detectify (detectify.com/pricing) ·
FOFA (en.fofa.info/vip) · subfinder providers (docs.projectdiscovery.io/tools/subfinder).
