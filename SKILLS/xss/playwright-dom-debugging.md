# Playwright DOM-XSS Debugging — Live Sink & postMessage Hunting

Read this when `/xss` Step 4 (DOM XSS) needs more than grep — when you want the
**live browser** to tell you which sink fires, with what data, from which code, and
whether a `postMessage` handler is exploitable. This is the practical companion to
**CLAUDE.md → Playwright Mode 3 (DOM Hunter)** and **Mode 2 (XSS Validator)**.

All browser traffic proxies through Caido automatically. These techniques are for
*finding and confirming* the client-side flow; the moment you have a PoC URL/request,
hand it back to Caido.

## The one rule about timing

DOM-XSS instrumentation must be installed **before the code that uses the sink runs.**
Two injection vectors, by when the sink fires:

| Sink/handler fires… | Use | Why |
|---|---|---|
| On a **later event** — `postMessage`, `hashchange`, click, route change (the common bug-bounty case) | `browser_evaluate` snippet (below) | You install the hook, *then* trigger the source. Hook is in place in time. |
| During **initial page load** | opt-in init script | `browser_evaluate` runs after load — too late. Only a Playwright `initScript` beats page scripts. |

**Default to the snippets.** Reach for the init script only when you suspect a
load-time sink (e.g. the page reads `location.hash` and writes `innerHTML` immediately on first paint).

### Enabling the load-time init script
1. Add `playwright-chrome/init/xss-instrument.js` to the `initScript` array in
   `playwright-chrome/configs/userN.json` (see the commented example in `setup.sh`).
2. Restart the Playwright MCP so it picks up the new config.
3. Browse the target. Captures land in `window.__xss` + console (`[XSSHOOK]` prefix).
4. **Disable it again when done** — it adds console noise to every page.

## Shared data model

Every technique writes to one global so retrieval is uniform:

```js
window.__xss = { sinks: [], messages: [], listeners: [], taint: [], csp: [] }
```

Read it back any time with a single tool call:

```
browser_evaluate:  () => JSON.stringify(window.__xss, null, 2)
```

…or read `browser_console_messages` and filter for the `[XSSHOOK]` prefix. Clear between
tests with `browser_evaluate: () => { for (const k in window.__xss) window.__xss[k]=[]; }`.

---

## 1. Sink hooking — what reaches a sink, and from where

**When:** you have a JS-rendered page and want to know which dangerous sink executes
and what app code drives it. Install the hook, then exercise the page (navigate, click,
change the hash, send a message). Each capture includes a **stack trace** → that is your
source→sink path.

**Snippet** (paste via `browser_evaluate`; safe to run once per page load):

```js
() => {
  if (window.__xss) return 'already-installed';
  const MAX = 500, store = { sinks: [], messages: [], listeners: [], taint: [], csp: [] };
  window.__xss = store; window.__xssMarkers = window.__xssMarkers || [];
  const push = (c, r) => { const a = store[c]; if (a.length >= MAX) a.shift(); a.push(r); };
  const stack = () => { try { return new Error().stack.split('\n').slice(2,7).join('\n'); } catch(e){ return ''; } };
  const str = v => { try { return typeof v==='string'?v:String(v); } catch(e){ return '[?]'; } };
  const rec = (sink, val, extra) => {
    const v = str(val), hits = window.__xssMarkers.filter(m => m && v.indexOf(m) !== -1);
    const r = { sink, value: v.length>2000?v.slice(0,2000)+'…':v, url: location.href, stack: stack() };
    if (extra) Object.assign(r, extra);
    push('sinks', r);
    if (hits.length) push('taint', { sink, markers: hits, value: r.value, stack: r.stack });
  };
  const hookSet = (proto, prop, label) => { try {
    const d = Object.getOwnPropertyDescriptor(proto, prop); if (!d || !d.set) return;
    Object.defineProperty(proto, prop, { configurable:true, get:d.get,
      set(val){ rec(label, val); return d.set.call(this, val); } });
  } catch(e){} };
  hookSet(Element.prototype, 'innerHTML', 'innerHTML');
  hookSet(Element.prototype, 'outerHTML', 'outerHTML');
  if (window.HTMLIFrameElement) hookSet(HTMLIFrameElement.prototype, 'srcdoc', 'iframe.srcdoc');
  const hookFn = (o, n, label, guard) => { try {
    const orig = o[n]; if (typeof orig !== 'function') return;
    o[n] = function(...a){ if (!guard || guard(a)) rec(label, a[0], { args: a.slice(0,3).map(str) }); return orig.apply(this, a); };
  } catch(e){} };
  hookFn(window, 'eval', 'eval'); hookFn(window, 'Function', 'Function');
  hookFn(document, 'write', 'document.write'); hookFn(document, 'writeln', 'document.writeln');
  hookFn(window, 'setTimeout', 'setTimeout(str)', a => typeof a[0]==='string');
  hookFn(window, 'setInterval', 'setInterval(str)', a => typeof a[0]==='string');
  hookFn(Element.prototype, 'insertAdjacentHTML', 'insertAdjacentHTML');
  if (window.Range) hookFn(Range.prototype, 'createContextualFragment', 'createContextualFragment');
  const sa = Element.prototype.setAttribute, D = /^(on|src$|href$|srcdoc$|formaction$|xlink:href$)/i;
  Element.prototype.setAttribute = function(n, v){ try { if (typeof n==='string' && D.test(n)) rec('setAttribute('+n+')', v, {attr:n}); } catch(e){} return sa.apply(this, arguments); };
  return 'installed';
}
```

**Read results:** `() => JSON.stringify(window.__xss.sinks, null, 2)`

**Interpret:**
- A capture whose `value` contains *your* input and whose `stack` points into the app's
  bundle = a real flow worth a payload.
- Framework-internal writes (React/Angular/Vue rendering) are noise — their stacks point
  into the framework, and `value` is the app's own templated HTML, not your input. Filter
  by whether `value` carries your marker.
- `eval`/`Function`/`setTimeout(string)` firing with your data = near-certain XSS.

---

## 2. postMessage wiretap — enumerate handlers, then attack them

**When:** JS contains `addEventListener('message', …)`, or the app is composed of iframes /
talks to an SDK / SSO popup. This is the highest-value DOM-XSS class because origin checks
are so often missing or wrong.

### 2a. Enumerate existing handlers (post-load, best-effort)
Handlers registered *before* you inject can't be wrapped retroactively, but you can still
read them if the app exposed them, and you can always inspect the source. For full handler
capture, use the **init script** (it wraps `addEventListener` pre-load and records every
handler's source + whether it checks `e.origin`). Read with:

```
() => JSON.stringify(window.__xss.listeners, null, 2)
```

Each record flags `checksOrigin`, `checksSource`, and `weakOriginCheck` (origin compared with
`indexOf`/`includes`/`startsWith`/regex — the classic `target.com.evil.com` bypass).

### 2b. Fuzz/replay messages from a controlled origin
Install the sink hook (technique 1) first so you see what fires. Then post a battery of
message shapes and watch `window.__xss.sinks` / `.taint`:

```js
() => {
  const MARK = 'pmXSS9134';
  window.__xssMarkers = (window.__xssMarkers||[]).concat(MARK);
  const payloads = [
    MARK,                                                   // bare string
    '<img src=x onerror="/*'+MARK+'*/">',                   // HTML string
    { type: 'message', data: MARK }, { type: MARK, url: 'javascript:0//'+MARK },
    { action: 'navigate', url: 'javascript:void(0)//'+MARK },
    { html: '<img src=x onerror=1>'+MARK }, { content: MARK }, { message: MARK },
    JSON.stringify({ type: MARK, payload: MARK }),          // some handlers JSON.parse(e.data)
  ];
  // post to self and to every child frame
  const targets = [window]; for (let i=0;i<window.frames.length;i++) targets.push(window.frames[i]);
  payloads.forEach(p => targets.forEach(t => { try { t.postMessage(p, '*'); } catch(e){} }));
  return 'posted ' + payloads.length + ' payloads to ' + targets.length + ' frame(s)';
}
```

Then read `window.__xss.taint` — any hit means a posted payload reached a sink with **no
effective origin check**. That is a DOM-XSS via postMessage.

**Real-target note:** to attack a handler that *does* check `e.origin` against your origin,
you must post from an allowed origin. Confirm the bug here, then build the real PoC as an
attacker-hosted page that iframes the target and posts the payload — that page is the report
artifact (host it, or hand the HTML to Caido/the report).

**Interpret:**
- Hit on a structured shape (`{type,url,...}`) → the handler trusts `e.data.url`/`.html`.
  Note the exact key; that's your payload structure.
- No hit but a handler exists → re-read its source from `.listeners`; the origin check may be
  strict (good — note it and move on) or the dangerous path needs a specific `e.data` shape
  you haven't tried.

---

## 3. Source→sink tracing — confirm the flow end to end

**When:** you want proof that a *specific source* (`location.hash`, `?param`, `window.name`,
`document.referrer`) flows into a sink — not just that a sink exists.

1. Install the sink hook (technique 1).
2. Seed a unique marker into the source and trigger re-processing:

```js
() => {
  const MARK = 'srcXSS7782';
  window.__xssMarkers = (window.__xssMarkers||[]).concat(MARK);
  // pick the source under test:
  location.hash = MARK;                          // hash source
  // window.name = MARK;                          // window.name source
  window.dispatchEvent(new HashChangeEvent('hashchange'));
  return 'seeded ' + MARK;
}
```

For `?query` / path sources, instead `browser_navigate` to the URL with the marker in the
parameter (the hook from technique 1 survives the load only if installed via the init
script; for query sources prefer the init script, or re-install the hook then trigger any
client-side re-render).

3. Read `window.__xss.taint`. A record there = confirmed source→sink, and its `stack` shows
   the exact code path. That's your DOM-XSS, ready to weaponize with a context-appropriate
   payload from `/xss` Step 2.

---

## 4. Console / error / CSP capture — see the blocked-but-present sinks

**When:** always, during a DOM Hunter walk. Errors leak data and reveal sink locations; CSP
violations tell you a sink *fired* but was blocked (still reportable, often bypassable).

- **Console + errors:** read `browser_console_messages`. JS errors with file:line point you
  straight at vulnerable code; debug logs sometimes dump tokens/PII (note for separate report).
- **CSP violations:** the instrument registers a `securitypolicyviolation` listener →
  `window.__xss.csp` holds `{blockedURI, violatedDirective, sourceFile, sample}`. A violation
  on `script-src` from your injected payload means **the injection works; only CSP stopped
  execution.** Pivot to `/xss` Step "CSP bypass" (JSONP on self, nonce reuse, `base-uri`,
  `strict-dynamic` dangling markup). Headers lie — execution (or a violation report) is truth.

```
() => JSON.stringify(window.__xss.csp, null, 2)
```

---

## Workflow — putting it together

1. **Walk** the SPA (Mode 3) so routes/frames load; capture console throughout.
2. On any route with message handlers or hash/query-driven rendering: **install the sink
   hook** (technique 1).
3. **Trace** the suspected source (technique 3) and/or **fuzz postMessage** (technique 2b).
4. Read `window.__xss.taint` → confirmed flows. Read `.sinks` for near-misses.
5. If CSP blocked execution, check `.csp` and pivot to a CSP bypass.
6. **Confirm execution** (Mode 2 / XSS Validator): craft the context-fitting payload, fire it,
   screenshot the `alert`/callback. For postMessage, the PoC is an attacker page that frames
   the target and posts the payload.
7. **Back to Caido** to assemble the PoC request/URL chain for the report. Disable the init
   script if you enabled it.

## Gotchas

- **Frozen prototypes / non-configurable descriptors:** some hardened apps freeze
  `Element.prototype`. The hooks `try/catch` and skip silently — you'll just get fewer
  captures, not an error. Fall back to reading source + DevTools breakpoints.
- **Trusted Types:** if the app enforces Trusted Types, `innerHTML` assignment of a raw string
  throws before your hook's downstream call — you'll see the throw in console. That itself is a
  strong signal the app *was* funneling data to `innerHTML`.
- **Iframes / cross-origin frames:** you can only instrument same-origin frames from the
  parent. Cross-origin child frames need their own page context (navigate to them directly).
- **Don't trust a single run.** Re-trigger the source; some sinks only fire on the 2nd
  navigation or after a debounce. Re-read `window.__xss` after each trigger.
