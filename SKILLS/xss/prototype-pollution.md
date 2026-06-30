# Client-Side Prototype Pollution (CSPP) — Poison `Object.prototype`, Trigger a Latent Sink

Read this when the page **parses attacker-controlled structured data** (URL querystring, JSON
body, fragment) into objects with an insecure recursive merge, letting you write properties
onto `Object.prototype`. You rarely get execution from the pollution alone — you get a
**latent sink**: app code that reads a property that *normally doesn't exist*, so it inherits
your poisoned value.

Companion to `/xss` Chain 10. Reuses [`playwright-dom-debugging.md`](playwright-dom-debugging.md)
for proofs.

## Mechanics — pollute the prototype, inherit the payload

Every plain object inherits missing properties from `Object.prototype`. If an insecure parser
lets you assign to `__proto__` (or `constructor.prototype`), you inject a property that *every*
subsequent object lookup will resolve to your value:

```js
// insecure recursive querystring parser (deparam-style)
function deparam(qs) {
  let obj = {};
  qs.split('&').forEach(pair => {
    let [key, val] = pair.split('=');
    let parts = key.split('.');           // supports a.b.c -> nested objects
    // ...recursive assign with NO __proto__ guard...
    obj[parts[0]][parts[1]] = val;
  });
  return obj;
}
```

Send `?__proto__.polluted=yes` and `({}).polluted === "yes"` becomes true globally on the page.

The two pollution keys (try both — engines/configs differ):
- `__proto__` — blocked on objects created with `Object.create(null)` or in hardened runtimes.
- `constructor.prototype` (a.k.a. `constructor[prototype]`) — the **same** hole, reached
  without writing the literal `__proto__`; slips filters that only block that token.

## Vectors & known-vulnerable parsers

| Vector | Shape | Notes |
|---|---|---|
| URL querystring | `?__proto__[x]=y`, `?__proto__.x=y`, `?constructor[prototype][x]=y` | most common; deparam/`qs` parsers |
| JSON body merge | `{"__proto__":{"x":"y"}}` into `$.extend(true, {}, userJson)` | classic jQuery deep-extend |
| `window.name` / hash | client routers that parse `name`/`hash` into options | survives cross-origin nav |
| IndexedDB / storage deserialization | app reads stored JSON then deep-merges | rarer, high-value |

Parsers/merge APIs historically vulnerable to CSPP (confirm against the app's bundled
version — many are patched in current releases):

- **jQuery** — `$.extend(true, {}, attackerObj)` (pre-3.4.0; the canonical one).
- **Lodash** — `_.merge`, `_.set`, `_.setWith`, `_.defaultsDeep`, `_.mergeWith` (pre-fixed
  versions).
- **`qs` / `query-string` / `jQuery.deparam` / custom deparam** — anything recursively
  building nested objects from dotted/bracketed keys without filtering magic keys.
- **framework option-merging** — Vue/Vue-router/Angular option merges that deep-merge
  attacker-influenced config.

## Gadgets — turn pollution into a sink firing

Pollution is inert until some code reads the polluted property through inheritance. Hunt the
gadget by finding reads of properties that *wouldn't* normally be set on the local object:

- **`sourceURL` / `//# sourceURL=` eval gadget** — the classic: some bundlers/devtools honor a
  `sourceURL`/`sourceMappingURL` inherited from the prototype and feed it to `eval`/`Function`.
  Payload: `?__proto__.sourceURL=javascript:alert(1)//` (or a value a `Function()`-style sink
  consumes). If the app does `cfg.sourceURL || "/js/default.js"` and `cfg` lacks the key, it
  inherits yours.
- **DOM/script gadgets** — `Object.prototype.src`, `.innerHTML`, `.href`, `.text` inherited by
  a code path that builds a `<script>`/element from a config object missing those keys.
- **Framework option-injection** — pollute `Object.prototype.<option>` to flip a framework
  flag (e.g. a sanitizer bypass, a render-as-html toggle, a redirect target).

Automated gadget discovery (when the bundle is large): CSPP gadget scanners — **`ppmap`**,
**`pp-finder`**, **`PPScan`** — instrument the page and report which prototype properties get
read. They're the CSPP analog of the `dom-sinks.txt` `ugrep` pass; run them after you've
confirmed the parser is reachable.

## Detection

```bash
# insecure parsers / deep-merges in the bundle (extended list now in dom-sinks.txt)
ugrep -aonE "\b(merge|extend|defaultsDeep|set|setWith|deepExtend|deparam|defaults)\s*\(" js/ | sort -u
# literal magic-key handling (absent = smell)
ugrep -aonE "__proto__|constructor\s*\[\s*['\"\`]?prototype" js/
```

A merge/parser hit is a **lead**. The bug is real only if (a) attacker data reaches the parser
and (b) a gadget reads the polluted key. Confirm both in the headless browser.

Quick reachability probe — run in the page console (or `browser_evaluate`) *before* sending the
payload, to see if the parser runs on load:

```js
() => { Object.prototype.__pp_probe__ = 'sentinel'; return ({}).__pp_probe__; }
// then send ?__proto__[__pp_probe__]=SENT-via-url and check whether ({}).__pp_probe__ flips
```

## Proof (headless Playwright)

1. Navigate to the target with the pollution payload in the chosen vector:
   ```
   browser_navigate: https://app.target.tld/page?__proto__[x]=CSPPMARK
   ```
2. Read back inheritance to confirm the parser accepted it:
   ```js
   () => ({ polluted: ({}).x })   // expect "CSPPMARK"
   ```
3. Then drive the **gadget** — seed the property the gadget reads (e.g.
   `?__proto__[sourceURL]=…`), install the sink hook from
   [`playwright-dom-debugging.md`](playwright-dom-debugging.md) §1, trigger the code path, and
   read `window.__xss.taint` / `.sinks` for your marker reaching the sink. A confirmed
   source→(prototype)→sink flow with a stack into the app bundle is the PoC.

> Prototype pollution **persists for the page lifetime** and affects *every* object — so a
> pollution that reaches a one-time loader may only fire on a fresh navigation. Re-trigger from
> a clean `browser_navigate` each test, and capture the effect with a visible DOM change /
   beacon, not `alert()` (headless auto-dismisses it — see `playwright-dom-debugging.md` §"Workflow").

## Cross-links

- `/ssti` — server-side prototype-pollution gadget for Handlebars; the client-side analog lives
  here.
- `/xss` Step 4 (DOM XSS) — CSPP is a source→sink variant where the "source" is the prototype.
- Live instrumentation: [`playwright-dom-debugging.md`](playwright-dom-debugging.md) §1 (sink
  hook) for proving the gadget fires.
