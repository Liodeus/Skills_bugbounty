---
description: "RCE and remote code execution hunting methodology. TRIGGER: user is testing for RCE, command injection, code execution, or mentions headless browser exploitation, file write primitives, or protocol-level attacks."
---

# /hunt-rce - Remote Code Execution Hunting

You are assisting **Liodeus (YesWeHack)**, whose RCE reports include headless Chrome exploitation chains, Perforce protocol abuse for arbitrary file write, and vulnerable component exploitation. His RCE findings are typically chains: **SSRF → LFI → RCE**, or **file write → DLL hijack → RCE**.

## Core Philosophy

RCE is the holy grail. In bug bounty, you rarely get direct `eval(user_input)`. Instead, RCE comes from **"chaining primitives"**: a file write becomes RCE via DLL hijack, an SSRF becomes RCE via cloud metadata → instance credentials → deploy pipeline. **Think in chains.**

## RCE Chains (from real reports)

### Chain 1: Headless Chrome → Debug Protocol → File Read → K8s Secrets
When you find HTML-to-PDF or screenshot rendering:
1. Confirm JavaScript execution in the renderer
2. Port scan localhost for Chrome DevTools port (30000-50000 range)
3. Access `/json` endpoint on debug port to get WebSocket URL
4. Use Chrome DevTools Protocol over WebSocket to read local files
5. Read `/var/run/secrets/kubernetes.io/serviceaccount/token`
6. Use K8s service account token to access cluster API

### Chain 2: Perforce Client → Arbitrary File Write → DLL Hijack
When target uses Perforce for version control:
1. Set up malicious Perforce server
2. Coerce connection via mDNS poisoning or social engineering
3. Use `client-WriteFile` to write malicious DLL to application directory
4. Application loads DLL on next startup → RCE

**Key:** Check if `P4CLIENTPATH` is set. If not, the Perforce server can write ANYWHERE.

### Chain 3: Vulnerable Component → Known CVE
Identify component versions and check for known RCE CVEs:
* HeadlessChrome/77.0.3844.0 → multiple RCE CVEs
* pdf.js 1.10.97 → CVE-2018-5158 (XSS that enables further chains)
* Old libcurl → protocol smuggling
* OpenSearch with vulnerable Chrome → RCE via reporting plugin

### Chain 4: SSRF → Cloud Metadata → Deploy Key → Code Push
1. SSRF to `169.254.169.254/latest/meta-data/iam/security-credentials/`
2. Extract AWS credentials
3. List accessible services (S3, CodeCommit, ECR)
4. Push malicious code or container → RCE in deployment

## Discovery Methodology

### Step 1: Identify Code Execution Surfaces
* PDF generators (wkhtmltopdf, headless Chrome, Puppeteer)
* Image processors (ImageMagick, GraphicsMagick)
* Document converters (LibreOffice, Pandoc)
* Template engines (Jinja2, ERB, Handlebars)
* Import/export features using external tools
* Version control integrations (Git, SVN, Perforce)
* CI/CD pipelines accessible via API

### Step 2: Version Fingerprinting
For every component you identify:
* Extract exact version from headers, error messages, or behavior
* Check CVE databases for that version
* Look at the User-Agent of server-side HTTP clients
* Check `navigator.userAgent` in headless browsers via injected JS

### Step 3: Primitive Hunting
Look for these primitives that chain to RCE:
* **File write**: upload features, Perforce, import tools
* **File read**: SSRF, LFI, directory traversal
* **JS execution**: XSS in headless browser context, template injection
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

## Impact Demonstration

For RCE, demonstrate:
1. **Command execution proof**: `id`, `whoami`, `hostname` output
2. **Or file read proof**: sensitive file contents (tokens, configs)
3. **Environment context**: are you in a container? What services are accessible?
4. **Blast radius**: one pod? The whole cluster? All customer data?

For file-write-to-RCE chains, you may need to explain the chain rather than actually execute malicious code. Show the write primitive works, explain the RCE path.

## Key Considerations
* Always check if you're in a container (Docker/K8s) – K8s secrets are at known paths
* Check for service mesh/sidecar proxies that might give access to other services
* Look for IAM roles/service accounts attached to the compute instance
* Document the full chain clearly – reviewers need to understand each step