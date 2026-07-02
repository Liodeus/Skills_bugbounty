---
name: exposure
description: "Use when hunting resources or functionality reachable with ZERO credentials — forced browsing / hidden paths (via /ffuf-skill), backup & source-leftover files (.bak .old ~ .swp .zip .tar.gz .sql), exposed .git/.svn (reconstruct source), .env / config / secrets files (wp-config, appsettings, web.config, .htpasswd, cloud creds), open directory listing (autoindex), unauthenticated admin/debug panels, and unauth Swagger/OpenAPI, GraphQL introspection, Spring /actuator/*, debug consoles. The no-creds sibling of /rbac and /idor. Absorbs recon's info-disclosure + backup-file discovery. Hands gated paths to /403-401, predictable-ID leaks to /idor, default-cred panels to /ato."
---

# /exposure — Unauthenticated Broken Access Control

Find the sensitive resource or function that is **just sitting there, reachable with zero
credentials** — no session, no token, no login. The whole class is one failure: a file, endpoint,
panel, or action that *should* be gated is served (or fires) to an anonymous request. You don't
bypass a check here; **there is no check.** Forced browsing, backup/source leftovers, exposed VCS,
config/secrets files, open directory listings, unauthenticated admin panels, and unauth API
docs/actuators are all the same bug wearing different clothes.

This is the **no-credentials sibling** of `/rbac` (vertical) and `/idor` (object). Those need a
second identity to prove cross-user access. `/exposure` needs **nothing** — the impact is direct:
the data or function is anonymously accessible.

**Headless, low-rate, in-scope.** `curl` for every probe, sequential, under ~10 req/s, only against
in-scope hosts. Directory/file **brute force is delegated to `/ffuf-skill`** — this skill drives the
*curated known-path/known-extension* checks and the exposure-specific triage, then hands leads off.

---

## Core Philosophy

* **Zero credentials is the whole point.** Send every probe with **no** `Cookie`/`Authorization`
  header. If it needs a session to reach, it's not this skill — it's `/rbac` / `/idor`.
* **Baseline first — a `200` is not a finding.** The most common false positive is a `200` that is
  the site's SPA shell, a redirect-to-login, or a generic "not found" page rendered at `200`.
  Capture a baseline (status + size + body) for a *known-absent* path, and judge every hit against
  it. **New status + new sensitive content/function = exposure; `200` + same landing page =
  nothing.** (Same discipline as `/403-401`.)
* **Targeted, not brute.** Known juicy paths and backup-extension matrices are *curated* lists
  (one request each) — that's this skill. Blind directory/param brute force is the fuzzing *engine*,
  `/ffuf-skill`. Point at it; don't re-implement it.
* **Reach ≠ report — impact does.** A readable `.git/config` is reach; the report is the
  reconstructed source or the secret inside. A rendered admin panel is reach; the report is the
  action it lets an anonymous user perform, or the data it shows. Always pull the proof.

---

## Boundary — where /exposure ends and its siblings begin

| Skill | It owns | Hand-off trigger |
|---|---|---|
| **/exposure** | **Zero-cred.** File / endpoint / panel / function directly readable or callable with no session — it's just *there*. | — |
| **/403-401** | You *hit* a `401`/`403` on a known path and need to flip it to `200`. | A juicy path returns `401`/`403` → dispatch to `/403-401`; a confirmed flip comes back here for impact triage. |
| **/ffuf-skill** | The brute-force *engine* (directory/file/param discovery). | Need to *discover* unknown paths → run `/ffuf-skill`, feed its hits back into this skill's triage. |
| **/rbac** / **/idor** | *Authenticated* cross-user access (role gate / object ID). | An exposed resource leaks another user's data via a predictable ID → `/idor`; a role-gated function → `/rbac`. |
| **/ato** | Account takeover. | An exposed admin/login panel accepts **default creds** → `/ato`. |

---

## Baseline — capture before any probe

Every triage below compares against this. Set once per host:

```bash
BASE="https://app.target.tld"
# baseline for a definitely-absent path: status + size + a body sample
rand="/__nope_$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' ')__"
read -r nf sz < <(curl -sk -o baseline_404.html -w '%{http_code} %{size_download}' "$BASE$rand")
echo "absent-path baseline: $nf  size=$sz"   # often 404; SPAs frequently 200 with a fixed shell
```

If the app returns `200` for absent paths (SPA shell), **size + body** are what separate a real hit
from the shell — not the status code. Keep `baseline_404.html` to `diff` against candidates.

---

## 1. Forced browsing & backup / source leftovers

**Discovery is `/ffuf-skill`'s job.** Run it for hidden directories/files (its `resources/WORDLISTS.md`
names the lists; `-e .php,.bak,.zip,.sql,.old,.txt,.json,.config` layers extensions onto each word).
This skill then takes the *paths you already know* (from recon, ffuf hits, JS-extracted endpoints in
`paths.txt`) and runs the **curated backup-extension matrix** + the **autoindex** check over them.

```bash
# Backup / leftover matrix over known bases — one request each, flag non-empty 2xx.
mapfile -t exts  < <(grep -vE '^\s*#|^\s*$' .claude/skills/exposure/resources/backup-exts.txt)
mapfile -t bases < <(printf '%s\n' /index.php /api /config.php /backup /db /dump /admin /main.js \
                              "$(sed 's#\(.*\)/.*#\1#' paths.txt 2>/dev/null | sort -u)")
for b in "${bases[@]}"; do
  for e in "${exts[@]}"; do
    read -r code bsz < <(curl -sk -o /dev/null -w '%{http_code} %{size_download}' "$BASE$b$e")
    [[ "$code" =~ ^2 ]] && (( ${bsz:-0} > 0 )) && printf 'HIT %s %s  %s%s\n' "$code" "$bsz" "$b" "$e"
  done
done

# Open directory listing (nginx autoindex on / Apache Options +Indexes) — hands you filenames.
for d in /backup/ /backups/ /old/ /archive/ /tmp/ /dist/ /build/ /static/ /uploads/ /files/ /.git/; do
  curl -sk "$BASE$d" | ugrep -iqE 'Index of|Directory listing|<title>Index of' && echo "AUTOINDEX: $d"
done
```

**Reportable:** a `.sql` / `.zip` / `.tar.gz` / `.7z` / `.war` of the app source or a DB dump = source
or PII. `.swp` / `.swo` / `~` / `.orig` editor leftovers may carry partial source or secrets — pull and
`ugrep` them for keys. An open autoindex on a sensitive dir hands you the exact filenames to grab.
Download the hit, confirm it's *real* content (not a `200` error page), and treat any secret inside as
a chain starter (CLAUDE.md Phase 5).

---

## 2. Admin panels & unauthenticated functions

Locate panel/console candidates (recon fingerprint + ffuf + the `admin`/`panels` group in
`juicy-paths.txt`), then **test each for direct anonymous access** — the panel is the lead, the
*access* is the bug.

```bash
# Probe the admin/console/debug group — no auth header. Print status + size vs baseline.
ugrep -A99 '# admin / panels' .claude/skills/exposure/resources/juicy-paths.txt \
  | ugrep -m1 -B99 '# debug / runtime' | ugrep '^/' \
  | while read -r p; do
      read -r code psz < <(curl -sk -o /dev/null -w '%{http_code} %{size_download}' "$BASE$p")
      printf '%s\t%s\t%s\n' "$code" "$psz" "$p"
    done
```

Triage each candidate:
* **`200` + real panel UI** (dashboard markup, action forms, user tables) that is **not** a
  redirect-to-login and **not** the SPA shell → unauthenticated admin exposure. Confirm a
  **state-changing action actually fires anonymously** (submit a benign one, or observe the API it
  calls returns data) — that's the impact, not the rendered HTML alone.
* **`200` login form** → not exposure by itself. Try a small set of **default creds**
  (`admin:admin`, product defaults); a working login → `/ato`. Do **not** brute-force (guardrails).
* **`401` / `403`** → it's gated → **`/403-401`** for the bypass set; a confirmed flip returns here.
* **`302` → /login** → gated, move on (unless the redirect still leaks data in its body).

**Baseline discipline:** most `/admin` hits are the login page at `200`. `diff` the body against
`baseline_404.html` and against the app's own login page before calling anything exposed.

---

## 3. VCS, config & secrets files

Drive the curated list — source-control, `.env`, `config.*`, `appsettings.json`, `web.config`,
`.htpasswd`/`.netrc`/`.pgpass`, cloud creds, keys, logs. One request each; classify.

```bash
while read -r p; do
  [[ -z "$p" || "$p" =~ ^[[:space:]]*# ]] && continue
  read -r code fsz < <(curl -sk -o /dev/null -w '%{http_code} %{size_download}' "$BASE$p")
  [[ "$code" =~ ^2 ]] && (( ${fsz:-0} > 0 )) && printf 'HIT %s %s  %s\n' "$code" "$fsz" "$p"
done < .claude/skills/exposure/resources/juicy-paths.txt
```

**`2xx` on a secrets/source path** — `/.env`, `/.git/config`, `/config.php`, `/wp-config.php`,
`/web.config` (with keys), `/appsettings.json` / `/application.yml` (with secrets),
`/.aws/credentials`, `/.ssh/id_rsa`, `/.htpasswd` — is **reportable information disclosure**. Capture
the response; chain any live key/token/cred per CLAUDE.md Phase 5 (a leaked cloud token → S3/GCS →
mass PII; an API key → authenticated backend read).

**Exposed VCS → reconstruct the source.** If `/.git/HEAD` **and** `/.git/config` are readable, the repo
is dumpable — the full source (and its history, often with committed secrets) is recoverable:

```bash
# Confirm the .git dir is served, then pull it. Prefer a git-dumper-style tool if present.
curl -sk "$BASE/.git/HEAD" | head -1        # -> "ref: refs/heads/main" confirms it
command -v git-dumper >/dev/null && git-dumper "$BASE/.git/" ./dump_git \
  || echo "no git-dumper — grab /.git/config,/HEAD,/index,/logs/HEAD,/packed-refs + loose objects under /.git/objects/"
# .svn equivalent: /.svn/wc.db (SQLite) lists every file + pristine text-base to reconstruct.
```

Reconstruct, then `ugrep` the dumped tree for hardcoded secrets (reuse recon's `secret-patterns.txt`).
A `.DS_Store` similarly leaks directory contents — parse it for hidden filenames to probe.

---

## 4. Unauthenticated APIs, actuators & docs

API specs, GraphQL introspection, and framework management endpoints reachable **without auth** are
both a finding and a map to more. Probe the `API docs` and `debug / runtime` groups; test for `200`
with no auth header.

```bash
for p in /swagger.json /openapi.json /v3/api-docs /swagger-ui.html /api-docs /application.wadl \
         /actuator /actuator/env /actuator/health /actuator/heapdump /actuator/mappings \
         /jolokia/list /metrics /prometheus /debug/pprof/ /telescope /_profiler /trace.axd; do
  read -r code asz < <(curl -sk -o /dev/null -w '%{http_code} %{size_download}' "$BASE$p")
  [[ "$code" =~ ^2 ]] && printf 'UNAUTH %s %s  %s\n' "$code" "$asz" "$p"
done
# GraphQL introspection (schema dump = full API map)
curl -sk "$BASE/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' | head -c 400
```

Triage:
* **Swagger / OpenAPI / WADL / GraphQL schema `200`** → dump the endpoint list; feed it to
  `/ffuf-skill` (fuzz the newly-revealed routes) and to `/idor` / `/rbac` for the auth'd ones. The
  spec itself is not the bounty — the endpoints it unlocks are.
* **`/actuator/env` / `/actuator/heapdump` / `/jolokia` unauth `200`** → **reportable directly** —
  `env` leaks config/secrets, `heapdump` leaks live memory (tokens, sessions, PII). High-value.
* **`/actuator/gateway/routes`, `/debug/pprof`, `/metrics`, `/_profiler`** → internal-surface
  disclosure; report if it leaks routes/secrets/PII, else log as a chain lead.
* Any of these behind `401`/`403` → `/403-401`.

---

## Triage — real exposure vs noise

A `HIT`/`UNAUTH` line is a lead, not a finding. Re-fetch with `-D -`, save the body, and judge:

| Signal | Verdict |
|---|---|
| `2xx`, **new** sensitive body (source, secrets, real panel, dump, schema) vs baseline | **exposure** — pull proof, report |
| `200`, but body ≈ `baseline_404.html` / SPA shell / generic landing | **not** exposure — drop |
| `200` login form on `/admin` | not exposure alone — default-creds → `/ato`, else drop |
| `302` → `/login` (no data in body) | gated — move on |
| `401` / `403` on a juicy path | gated — dispatch to **`/403-401`** |
| uniform `403` across **every** path | edge/WAF block, not per-path ACL — classify before reading anything in |

**Confirm before reporting:** re-run the hit, save request+response, and verify the content is *real*
(renders, parses, contains the secret/data/function) — not a themed error page. Reach with no proof is
not reportable.

---

## WAF note

A WAF only **tunes** this pass (lower rate, obfuscate, smaller list) — it never cancels it (CLAUDE.md).
Watch for the tell that flips the whole triage: **a uniform `403`/`406`/`451` on _every_ path** is an
edge/WAF block, not hundreds of per-path ACLs — don't read individual "gated" verdicts into it.
Detect passively (recon B.1), throttle, and if an adapted pass keeps getting blocked, the evasion
*technique* lives in `/waf-bypass`. Never skip the pass because a WAF exists.

---

## Impact & hand-off

`/exposure` proves anonymous reach and pulls the proof, then routes:

* **Source / secrets / dumps read anonymously** (`.git` reconstruction, `.env`, DB dump, `heapdump`,
  cloud creds) → **`/report-yeswehack`** (info disclosure), and **chain** any live secret per
  CLAUDE.md Phase 5 before reporting for max impact.
* **Unauth admin panel / function that acts** → `/report-yeswehack`; if it only shows *another user's*
  data via an ID → `/idor`, if it's a role-gated action → `/rbac` to frame the class.
* **Gated juicy path** (`401`/`403`) → **`/403-401`**; a confirmed `403→200` with new content comes
  back here (or to `/rbac`/`/idor` if cross-user).
* **Default-cred login** → **`/ato`**.
* **Unknown paths to discover** → **`/ffuf-skill`**, then back into this triage.

**Never report bare reach.** The bounty is the data exposed, the source reconstructed, or the function
an anonymous user can invoke.

---

## Completion checklist

- [ ] **Absent-path baseline captured** (status + size + body) — SPA-shell `200` accounted for.
- [ ] **`/ffuf-skill` discovery** run for hidden dirs/files (unknown-path brute force delegated).
- [ ] **Backup/leftover matrix** run over known bases (§1); **autoindex** dirs checked.
- [ ] **Admin/console group** tested for anonymous access (§2); panels `diff`'d vs login/baseline.
- [ ] **VCS/config/secrets list** run (§3); readable `.git`/`.svn` **reconstructed** and grepped.
- [ ] **API docs / actuators** tested unauth (§4); GraphQL introspection attempted.
- [ ] Every hit **re-verified for real new content** (not baseline/error/login page).
- [ ] Gated paths **handed to `/403-401`**; cross-user leaks to `/idor`/`/rbac`; default-cred → `/ato`.
- [ ] Live secrets **chained** (Phase 5) before reporting.

---

## Quick reference

```bash
BASE="https://app.target.tld"
rand="/__nope_$(head -c4 /dev/urandom|od -An -tx1|tr -d ' ')__"
read -r nf sz < <(curl -sk -o baseline_404.html -w '%{http_code} %{size_download}' "$BASE$rand")  # baseline
# 1 forced-browse: /ffuf-skill (discover) -> backup matrix (backup-exts.txt) over paths.txt bases + autoindex dirs
# 2 admin:  admin/console group @ 200-no-auth = real panel (not login/shell)? action fires? -> report | default-creds -> /ato | 401/403 -> /403-401
# 3 vcs/cfg: juicy-paths.txt -> 2xx on .env/.git/config/wp-config/appsettings/.aws = report; /.git/HEAD+config readable -> git-dumper -> ugrep secrets
# 4 api:    /swagger.json /openapi.json /v3/api-docs /actuator/env /actuator/heapdump /jolokia/list ; graphql __schema introspection
# triage: 2xx NEW sensitive body = exposure; 2xx same shell/login = drop; 401/403 -> /403-401; uniform 403 everywhere = WAF
# resources: .claude/skills/exposure/resources/{juicy-paths.txt,backup-exts.txt}
```
