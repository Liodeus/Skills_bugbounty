---
name: ffuf-skill
description: Use when the user needs ffuf web fuzzing — directory/file/parameter/subdomain discovery, authenticated fuzzing with raw requests, auto-calibration, or fuzzing result analysis.
---

# /ffuf-skill - FFUF (Fuzz Faster U Fool) Web Fuzzing

## Overview
FFUF is a fast web fuzzer written in Go, designed for discovering hidden content, directories, files, subdomains, and testing for vulnerabilities. It's significantly faster than traditional tools like dirb or dirbuster.

## Environment (autonomous headless harness)

You run `ffuf` from a **firewalled Bash CLI** alongside `curl`, `httpx`, `katana`, `dnsx`, etc., plus Read/Grep/Glob/Write. Two rules dominate every command:

* **Rate caps are firewall-ENFORCED.** Every `ffuf` invocation MUST carry rate flags or it will be throttled/blocked. The exact numbers live in **TARGET.md — use the caps in TARGET.md**. Throughout this skill the examples show the shape `-rate 8 -t 10`; substitute the real numbers from TARGET.md.
* **`-ac` is mandatory** for clean, analyzable results (see Auto-Calibration below).

You craft raw-request files yourself from captured `curl`/`httpx` traffic — there is no proxy GUI to export from. You do not submit anything; the orchestrator handles delivery.

## Core Concepts

### The FUZZ Keyword
The `FUZZ` keyword is used as a placeholder that gets replaced with entries from your wordlist. You can place it anywhere:
- URLs: `https://target.com/FUZZ`
- Headers: `-H "Host: FUZZ"`
- POST data: `-d "username=admin&password=FUZZ"`
- Multiple locations with custom keywords: `-w wordlist.txt:CUSTOM` then use `CUSTOM` instead of `FUZZ`

### Multi-wordlist Modes
- **clusterbomb**: Tests all combinations (default) - cartesian product
- **pitchfork**: Iterates through wordlists in parallel (1-to-1 matching)
- **sniper**: Tests one position at a time (for multiple FUZZ positions)

## Common Use Cases

### 1. Directory and File Discovery
Every example carries the rate-cap shape `-rate 8 -t 10` and `-ac` — **use the actual caps from TARGET.md**.
```bash
# Basic directory fuzzing
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ac -rate 8 -t 10

# With file extensions
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -e .php,.html,.txt,.pdf -ac -rate 8 -t 10

# Colored and verbose output
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -c -v -ac -rate 8 -t 10

# With recursion (finds nested directories) — avoid recursion behind a WAF
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2 -ac -rate 8 -t 10
```

### 2. Subdomain Enumeration
```bash
# Virtual host discovery
ffuf -w /path/to/subdomains.txt -u https://target.com -H "Host: FUZZ.target.com" -fs 4242 -ac -rate 8 -t 10

# Note: -fs 4242 filters out responses of size 4242 (adjust based on default response size)
```

### 3. Parameter Fuzzing
```bash
# GET parameter names
ffuf -w /path/to/params.txt -u https://target.com/script.php?FUZZ=test_value -fs 4242 -ac -rate 8 -t 10

# GET parameter values
ffuf -w /path/to/values.txt -u https://target.com/script.php?id=FUZZ -fc 401 -ac -rate 8 -t 10

# Multiple parameters
ffuf -w params.txt:PARAM -w values.txt:VAL -u https://target.com/?PARAM=VAL -mode clusterbomb -ac -rate 8 -t 10
```

### 4. POST Data Fuzzing
```bash
# Basic POST fuzzing
ffuf -w /path/to/passwords.txt -X POST -d "username=admin&password=FUZZ" -u https://target.com/login.php -fc 401 -ac -rate 8 -t 10

# JSON POST data
ffuf -w entries.txt -u https://target.com/api -X POST -H "Content-Type: application/json" -d '{"name": "FUZZ", "key": "value"}' -fr "error" -ac -rate 8 -t 10

# Fuzzing multiple POST fields
ffuf -w users.txt:USER -w passes.txt:PASS -X POST -d "username=USER&password=PASS" -u https://target.com/login -mode pitchfork -ac -rate 8 -t 10
```

### 5. Header Fuzzing
```bash
# Custom headers
ffuf -w /path/to/wordlist.txt -u https://target.com -H "X-Custom-Header: FUZZ" -ac -rate 8 -t 10

# Multiple headers
ffuf -w /path/to/wordlist.txt -u https://target.com -H "User-Agent: FUZZ" -H "X-Forwarded-For: 127.0.0.1" -ac -rate 8 -t 10
```

## Filtering and Matching

### Matchers (Include Results)
- `-mc`: Match status codes (default: 200-299,301,302,307,401,403,405,500)
- `-ml`: Match line count
- `-mr`: Match regex
- `-ms`: Match response size
- `-mt`: Match response time (e.g., `>100` or `<100` milliseconds)
- `-mw`: Match word count

### Filters (Exclude Results)
- `-fc`: Filter status codes (e.g., `-fc 404,403,401`)
- `-fl`: Filter line count
- `-fr`: Filter regex (e.g., `-fr "error"`)
- `-fs`: Filter response size (e.g., `-fs 42,4242`)
- `-ft`: Filter response time
- `-fw`: Filter word count

### Auto-Calibration (USE BY DEFAULT!)
**CRITICAL:** Always use `-ac` unless you have a specific reason not to. It dramatically reduces noise and false positives — essential when you're parsing the output yourself.

```bash
# Auto-calibration - ALWAYS USE THIS (with TARGET.md rate caps)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ac -rate 8 -t 10

# Per-host auto-calibration (useful for multiple hosts)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ach -rate 8 -t 10

# Custom auto-calibration string (for specific patterns)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -acc "404NotFound" -rate 8 -t 10
```

**Why `-ac` is essential:**
- Automatically detects and filters repetitive false positive responses
- Removes noise from dynamic websites with random content
- Makes results analysis tractable
- Prevents thousands of identical 404/403 responses from cluttering output
- Adapts to the target's specific behavior

**`-ac` is MANDATORY** — without it you'll waste cycles sifting through thousands of false positives instead of finding the interesting anomalies.

## Rate Limiting and Timing

### Rate Control — FIREWALL-ENFORCED, NOT OPTIONAL
The harness enforces rate caps at the firewall. **Every** scan must carry the rate/thread flags
set to the values in **TARGET.md**. The numbers below are example shapes only.
```bash
# Limit requests/sec — use the rate from TARGET.md
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -rate 8

# Add delay between requests (0.1 to 2 seconds random)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -p 0.1-2.0

# Cap concurrent threads — use the thread cap from TARGET.md (default ffuf is 40, too high)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -t 10

# Typical combined shape
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ac -rate 8 -t 10
```

### Time Limits
```bash
# Maximum total execution time (60 seconds)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -maxtime 60

# Maximum time per job (useful with recursion)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -maxtime-job 60 -recursion
```

## Output Options

### Output Formats
```bash
# JSON output
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -o results.json

# HTML output
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -of html -o results.html

# CSV output
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -of csv -o results.csv

# All formats
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -of all -o results

# Silent mode (no progress, only results)
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -s

# Pipe to file with tee
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -s | tee results.txt
```

## Advanced Techniques

### Using Raw HTTP Requests (Critical for Authenticated Fuzzing)
This is one of the most powerful features of ffuf, especially for authenticated requests with complex headers, cookies, or tokens.

**Workflow (headless):**
1. Hand-write a raw HTTP request file from a known-good request — e.g. reconstruct it from the `curl -v` / `httpx` output of a working authenticated call, or build it from the auth token/cookie you already hold.
2. Save it to a file (e.g., `req.txt`).
3. Replace the value you want to fuzz with the `FUZZ` keyword.
4. Use the `--request` flag (always with `-ac` and TARGET.md rate caps).

```bash
# From a file containing raw HTTP request
ffuf --request req.txt -w /path/to/wordlist.txt -ac -rate 8 -t 10
```

**Example req.txt file:**
```http
POST /api/v1/users/FUZZ HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Cookie: session=abc123xyz; csrftoken=def456
Content-Type: application/json
Content-Length: 27

{"action":"view","id":"1"}
```

**Use Cases:**
- Fuzzing authenticated endpoints with complex auth headers
- Testing API endpoints with JWT tokens
- Fuzzing with CSRF tokens, session cookies, and custom headers
- Testing endpoints that require specific User-Agents or Accept headers
- POST/PUT/DELETE requests with authentication

**Pro Tips:**
- You can place FUZZ in multiple locations: URL path, headers, body
- Use `-request-proto https` if needed (default is https)
- Always use `-ac` to filter out authenticated "not found" or error responses
- Great for IDOR testing: fuzz user IDs, document IDs, etc. in authenticated contexts

```bash
# Common authenticated fuzzing patterns
ffuf --request req.txt -w user_ids.txt -ac -mc 200 -o results.json -rate 8 -t 10

# With multiple FUZZ positions using custom keywords
ffuf --request req.txt -w endpoints.txt:ENDPOINT -w ids.txt:ID -mode pitchfork -ac -rate 8 -t 10
```

### Cookie and Authentication
Pass the session/token you already hold directly on the command line — there is no proxy to route through in the headless harness.
```bash
# Using cookies
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -b "sessionid=abc123; token=xyz789" -ac -rate 8 -t 10

# Client certificate authentication
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -cc client.crt -ck client.key -ac -rate 8 -t 10
```

### Encoding
```bash
# URL encoding
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -enc 'FUZZ:urlencode' -ac -rate 8 -t 10

# Multiple encodings
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -enc 'FUZZ:urlencode b64encode' -ac -rate 8 -t 10
```

### Testing for Vulnerabilities
ffuf finds *candidates* (interesting status/size/regex hits); it never *confirms* execution.
Confirm the underlying vuln with its real oracle — server-side signal for SQLi/cmdi, and the
**xss-confirm.js oracle** (`node "$AUTOHUNT_XSS_CONFIRM" "<url>" --nonce <NONCE>`) for XSS, since
a reflected `<script>` in the body is not proof it runs.
```bash
# SQL injection candidate sweep (then confirm errors/timing with curl, or sqlmap if present)
ffuf -w sqli_payloads.txt -u https://target.com/page.php?id=FUZZ -fs 1234 -ac -rate 8 -t 10

# XSS reflection sweep (then confirm EXECUTION with the xss-confirm.js oracle, not -mr)
ffuf -w xss_payloads.txt -u https://target.com/search?q=FUZZ -mr "<script>" -ac -rate 8 -t 10

# Command injection candidate sweep
ffuf -w cmdi_payloads.txt -u https://target.com/execute?cmd=FUZZ -fr "error" -ac -rate 8 -t 10
```

### Batch Processing Multiple Targets
```bash
# Process multiple URLs (caps apply per-invocation; keep them on)
cat targets.txt | xargs -I@ sh -c 'ffuf -w wordlist.txt -u @/FUZZ -ac -rate 8 -t 10'

# Loop through multiple targets with results
for url in $(cat targets.txt); do
    ffuf -w wordlist.txt -u "$url/FUZZ" -ac -rate 8 -t 10 -o "results_$(echo "$url" | md5sum | cut -d' ' -f1).json"
done
```

## Best Practices

### 1. ALWAYS Use Auto-Calibration AND Rate Caps
`-ac` plus the TARGET.md rate caps on every scan — both are non-negotiable:
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -rate 8 -t 10
```

### 2. Use Raw Requests for Authentication
Don't struggle with command-line flags for complex auth. Build the full request file and use `--request`:
```bash
# 1. Reconstruct an authenticated request file from your working curl/httpx call (or known token)
# 2. Save to req.txt with FUZZ keyword in place
# 3. Run with -ac and TARGET.md caps
ffuf --request req.txt -w wordlist.txt -ac -o results.json -rate 8 -t 10
```

### 3. Use Appropriate Wordlists
- **Directory discovery**: SecLists Discovery/Web-Content (raft-large-directories.txt, directory-list-2.3-medium.txt)
- **Subdomains**: SecLists Discovery/DNS (subdomains-top1million-5000.txt)
- **Parameters**: SecLists Discovery/Web-Content (burp-parameter-names.txt)
- **Usernames**: SecLists Usernames
- **Passwords**: SecLists Passwords
- Source: https://github.com/danielmiessler/SecLists

### 3. Rate Limiting is ENFORCED
`-rate` / `-t` are firewall-enforced caps, not stealth niceties — set them to the TARGET.md
values on every run, especially behind a WAF (low rate, low threads, no recursion):
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -rate 8 -t 10
```

### 4. Filter Strategically
- Check the default response first to identify common response sizes, status codes, or patterns
- Use `-fs` to filter by size or `-fc` to filter by status code
- Combine filters: `-fc 403,404 -fs 1234`

### 5. Save Results Appropriately
Always save results to a file for later analysis:
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -o results.json -of json
```

### 6. Bound Every Run with -maxtime
Interactive mode isn't available in a non-TTY harness shell — instead bound runs with
`-maxtime` / `-maxtime-job` and `-o results.json`, then read the JSON to adjust filters and
re-run. Plan your filters up front rather than tuning live.

### 7. Recursion Depth
Be careful with recursion depth to avoid getting stuck in loops or overwhelming the server; do
NOT use recursion behind a WAF:
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2 -maxtime-job 120 -ac -rate 8 -t 10
```

## Common Patterns and One-Liners

All one-liners carry the rate-cap shape; **use the actual TARGET.md caps**.

### Quick Directory Scan
```bash
ffuf -w ~/wordlists/common.txt -u https://target.com/FUZZ -mc 200,301,302,403 -ac -c -v -rate 8 -t 10
```

### Comprehensive Scan with Extensions
```bash
ffuf -w ~/wordlists/raft-large-directories.txt -u https://target.com/FUZZ -e .php,.html,.txt,.bak,.old -ac -c -v -o results.json -rate 8 -t 10
```

### Authenticated Fuzzing (Raw Request)
```bash
# 1. Build req.txt from your working authenticated call, with FUZZ keyword in place
# 2. Run:
ffuf --request req.txt -w ~/wordlists/api-endpoints.txt -ac -o results.json -of json -rate 8 -t 10
```

### API Endpoint Discovery
```bash
ffuf -w ~/wordlists/api-endpoints.txt -u https://api.target.com/v1/FUZZ -H "Authorization: Bearer TOKEN" -mc 200,201 -ac -c -rate 8 -t 10
```

### Subdomain Discovery with Auto-Calibration
```bash
ffuf -w ~/wordlists/subdomains-top5000.txt -u https://FUZZ.target.com -ac -c -v -rate 8 -t 10
```

### POST Login Brute Force
```bash
ffuf -w ~/wordlists/passwords.txt -X POST -d "username=admin&password=FUZZ" -u https://target.com/login -fc 401 -ac -rate 8 -t 10
```

### IDOR Testing with Auth
```bash
# Use req.txt with authenticated headers and FUZZ in the ID parameter — keep enumeration small (5-10 IDs is proof)
ffuf --request req.txt -w numbers.txt -ac -mc 200 -fw 100-200 -rate 8 -t 10
```

## Configuration File
Create `~/.config/ffuf/ffufrc` for default settings (still pass `-rate`/`-t` explicitly per run to match TARGET.md):
```
[http]
headers = ["User-Agent: Mozilla/5.0"]
timeout = 10

[general]
colors = true
threads = 10

[matcher]
status = "200-299,301,302,307,401,403,405,500"
```

## Troubleshooting

### Too Many False Positives
- Use `-ac` for auto-calibration
- Check default response and filter by size with `-fs`
- Use regex filtering with `-fr`

### Too Slow
- You CANNOT raise threads above the TARGET.md cap — the firewall enforces it. Instead:
- Reduce wordlist size (use a targeted list)
- Use `-ignore-body` if you don't need response content

### Getting Blocked
- Drop to / below the TARGET.md `-rate` and `-t` caps
- Add delays: `-p 0.5-1.5`
- Randomize User-Agent
- If a WAF is detected, STOP fuzzing recursively — switch to a small targeted wordlist or pivot (see `/waf-bypass`)

### Missing Results
- Check if you're filtering too aggressively
- Use `-mc all` to see all responses
- Disable auto-calibration temporarily
- Use verbose mode `-v` to see what's happening

## Resources
- Official GitHub: https://github.com/ffuf/ffuf
- Wiki: https://github.com/ffuf/ffuf/wiki
- Codingo's Guide: https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html
- Practice Lab: http://ffuf.me
- SecLists Wordlists: https://github.com/danielmiessler/SecLists

## Quick Reference Card

Every command below already implies `-ac -rate 8 -t 10` (use TARGET.md caps).

| Task | Command Template |
|------|------------------|
| Directory Discovery | `ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -rate 8 -t 10` |
| Subdomain Discovery | `ffuf -w subdomains.txt -u https://FUZZ.target.com -ac -rate 8 -t 10` |
| Parameter Fuzzing | `ffuf -w params.txt -u https://target.com/page?FUZZ=value -ac -rate 8 -t 10` |
| POST Data Fuzzing | `ffuf -w wordlist.txt -X POST -d "param=FUZZ" -u https://target.com/endpoint -ac -rate 8 -t 10` |
| With Extensions | Add `-e .php,.html,.txt` |
| Filter Status | Add `-fc 404,403` |
| Filter Size | Add `-fs 1234` |
| Rate Limit (ENFORCED) | Add `-rate 8 -t 10` (use TARGET.md caps) |
| Save Output | Add `-o results.json` |
| Verbose | Add `-c -v` |
| Recursion (not behind WAF) | Add `-recursion -recursion-depth 2` |

## Additional Resources

This skill includes supplementary materials in the `resources/` directory:

### Resource Files
- **WORDLISTS.md**: Comprehensive guide to SecLists wordlists, recommended lists for different scenarios, file extensions, and quick reference patterns
- **REQUEST_TEMPLATES.md**: Pre-built req.txt templates for common authentication scenarios (JWT, OAuth, session cookies, API keys, etc.) with usage examples

### Helper Script
- **ffuf_helper.py**: Python script to assist with:
  - Analyzing ffuf JSON results for anomalies and interesting findings
  - Creating req.txt template files from command-line arguments
  - Generating number-based wordlists for IDOR testing

**Helper Script Usage:**
```bash
# Analyze results to find interesting anomalies
python3 ffuf_helper.py analyze results.json

# Create authenticated request template
python3 ffuf_helper.py create-req -o req.txt -m POST -u "https://api.target.com/users" \
    -H "Authorization: Bearer TOKEN" -d '{"action":"FUZZ"}'

# Generate IDOR testing wordlist
python3 ffuf_helper.py wordlist -o ids.txt -t numbers -s 1 -e 10000
```

**When to use resources:**
- Need wordlist recommendations → Reference WORDLISTS.md
- Building an authenticated request file → Reference REQUEST_TEMPLATES.md
- Analyzing results → Use ffuf_helper.py analyze
- Generating a req.txt → Use ffuf_helper.py create-req
- Need number ranges for IDOR → Use ffuf_helper.py wordlist

## Operating checklist
1. **ALWAYS include `-ac` AND the TARGET.md rate caps (`-rate`/`-t`) in every command** — both mandatory; caps are firewall-enforced.
2. For authenticated fuzzing, build a `req.txt` from your working call, insert FUZZ, run `ffuf --request req.txt -w wordlist.txt -ac -rate 8 -t 10`.
3. Pick appropriate SecLists wordlists for the task; prefer targeted lists behind a WAF.
4. Save output to JSON (`-o results.json -of json`) and read it back to analyze.
5. Always use the FUZZ keyword (case-sensitive).
6. When analyzing results: assume `-ac` was on; focus on anomalies (status, size, timing); flag interesting endpoints (admin, api, backup, config, .git) and signals (errors, stack traces, version info); queue follow-up fuzzing on the interesting hits.
7. ffuf only finds candidates — confirm the actual vuln with its oracle (server-side signal, `$AUTOHUNT_OOB` for blind, the xss-confirm.js oracle for XSS). Do not submit anything; the orchestrator handles delivery.
