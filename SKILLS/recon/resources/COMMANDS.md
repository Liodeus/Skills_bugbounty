# Recon — full-pass command cheat sheet

Copy/paste reference for the whole A→J recon flow. The per-step *reasoning* (what each output
means, when to branch, how a WAF tunes things) lives in `SKILL.md`; this file is just the commands.
Shipped raw lists live alongside the skill: `secret-patterns.txt`, `dom-sinks.txt`,
`postmessage-handlers.txt`. The unauth-exposure lists (`juicy-paths.txt`, `backup-exts.txt`) moved
to `/exposure` — B.3–B.4 dispatch there.

```bash
# A. (wildcard only) subdomains → invoke /profundis (no local tools). Add returned hosts to scope.

# B. map + fingerprint frameworks
curl -sk "https://app.target.tld/" -o index.html
ugrep -aoErhE 'webpackChunk\w*|__NEXT_DATA__|/_next/|/_nuxt/|__NUXT__|data-reactroot|ng-version|__VUE__|/@vite/client' index.html | sort -u
#    + headless walk (Lightpanda default, CLAUDE.md Mode 3) to capture JS-rendered routes & XHR endpoints

# B.1 detect WAF (passive headers/cookies, then one noisy probe) — gates F ffuf; evasion → /waf-bypass
curl -sI "https://app.target.tld/" | ugrep -iE 'cf-ray|cloudflare|x-amzn|x-iinfo|incap_ses|AkamaiGHost|Sucuri|X-Azure-Ref'
curl -sk -o /dev/null -w '%{http_code}' "https://app.target.tld/?id='%20OR%201=1--"   # 403/406/451 = WAF

# B.2 force errors to fingerprint (read framework/stack from error pages; version-only = noise)
for p in "/%00" "/__nope__" "/?id='" ; do curl -sk -D - "https://app.target.tld$p" | head -n 20; done

# B.3–B.4 unauthenticated exposure → invoke /exposure (curated juicy paths + backup matrix +
#    autoindex + VCS/actuator/API-docs; baseline-first triage; git/svn reconstruction). Hand it
#    paths.txt + the host folder. Gated path → /403-401; predictable-ID leak → /idor; default-cred → /ato.

# B.5 401/403 gate → invoke /403-401 (identity/path/URL-override/method set, WAF-vs-ACL triage); confirmed flip → /rbac or /idor

# C. discover all JS — gau + headless-captured URLs
gau --subs target.tld | ugrep -Ei '\.js(\?|$)' | sort -u > js_urls.txt
mkdir -p js && while read -r u; do curl -sk "$u" -o "js/$(echo "$u"|sed 's#[^a-zA-Z0-9]#_#g').js"; done < js_urls.txt

# D. webpack chunks — reconstruct lazy chunks from the manifest
ugrep -aoErhE '[0-9]+:"[0-9a-f]{6,}"' js/ | sort -u > chunk_map.txt   # then build <base>/<id>.<hash>.chunk.js and curl

# E. source maps
ugrep -aoErh 'sourceMappingURL=[^ *]+' js/ | sort -u
jq -r '.sourcesContent[]' main.js.map > src_dump.js 2>/dev/null

# F. endpoints + params
ugrep -aErhoE '"(/[a-zA-Z0-9_./-]+)"' js/ | tr -d '"' | sort -u > paths.txt
xnLinkFinder -i js/ -sp target.tld -spo -sf target.tld -o endpoints.txt -op params.txt
# F. (MANDATORY) active fuzz — /ffuf-skill always runs in recon; a WAF only tunes rate/payloads, never skips it
#    if B.1 found a WAF: lower -rate/-t + small wordlist + payload obfuscation — adapt, don't abort
ffuf -w ~/wordlists/common.txt -u "https://app.target.tld/FUZZ" -ac -o ffuf_dirs.json

# G. secrets
ugrep -aErni -f .claude/skills/recon/secret-patterns.txt js/ > grep_hits.txt

# H. postMessage handlers + sender wildcard leaks + origin-check triage  → if sink reached, /xss
ugrep -anE -f .claude/skills/recon/postmessage-handlers.txt js/
ugrep -aonE "\.postMessage\s*\([^)]*,\s*[\"'\`]\*[\"'\`]|targetOrigin\s*:\s*[\"'\`]\*" js/
ugrep -aohE ".{0,60}(addEventListener\(\s*[\"'\`]message|\bonmessage).{0,400}" js/ \
  | head -c 8388608 \
  | ugrep -E '\.data|innerHTML|eval|location\s*=|document\.write|srcdoc|setTimeout' | ugrep -vE '\.(origin|source)|isTrusted'

# I. DOM sinks  → if source→sink flow, invoke /xss
ugrep -aErni -f .claude/skills/recon/dom-sinks.txt js/ > dom_hits.txt

# J. hidden params → reflected-XSS probe  → if it reflects, invoke /xss
curl -sk "https://app.target.tld/page?<hiddenparam>=xss7331probe" | ugrep -o 'xss7331probe'

# ✓ recon completion checklist (SKILL.md) — don't start vuln hunting with an unchecked box that matters
# → hand hosts/endpoints/secrets to the vuln skills; sinks/postMessage/hidden-params → /xss
```
