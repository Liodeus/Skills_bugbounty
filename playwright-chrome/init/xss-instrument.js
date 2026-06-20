// DOM-XSS instrument — OPT-IN pre-load hook for DOM-XSS hunting.
//
// NOT wired into the default configs. Enable it only while hunting DOM XSS by
// adding this file to the "initScript" array in playwright-chrome/configs/userN.json
// (or via setup.sh — see the commented line there), then restart the Playwright MCP.
//
// Because it runs as a Playwright initScript, it installs BEFORE the page's own
// JavaScript. That is the only way to:
//   * hook sinks that fire during initial page load
//   * wiretap addEventListener('message', ...) before handlers register
//
// For sinks/handlers that fire on LATER events (postMessage, hashchange, clicks)
// you do NOT need this file — paste the equivalent snippet from
// SKILLS/xss/playwright-dom-debugging.md via browser_evaluate instead.
//
// All captures land in window.__xss (same schema the on-demand snippets use) and
// are mirrored to console with a [XSSHOOK] prefix so browser_console_messages
// picks them up. Read them with:  browser_evaluate -> JSON.stringify(window.__xss)
(() => {
  if (window.__xss) return; // idempotent across frames/reloads in the same context
  const MAX = 500; // ring-buffer cap per channel — avoid unbounded memory on noisy pages
  const store = { sinks: [], messages: [], listeners: [], taint: [], csp: [] };
  window.__xss = store;

  // Markers seeded by the source→sink tracer (set via browser_evaluate before navigating).
  // Any sink value containing one of these is flagged as a confirmed source→sink flow.
  window.__xssMarkers = window.__xssMarkers || [];

  const push = (chan, rec) => {
    const arr = store[chan];
    if (arr.length >= MAX) arr.shift();
    arr.push(rec);
    try { console.log('[XSSHOOK]', chan, JSON.stringify(rec)); } catch (e) { /* circular */ }
  };

  const stack = () => {
    try { return new Error().stack.split('\n').slice(2, 7).join('\n'); }
    catch (e) { return ''; }
  };

  const toStr = (v) => {
    try { return typeof v === 'string' ? v : String(v); } catch (e) { return '[unstringifiable]'; }
  };

  const taintHit = (value) => {
    const s = toStr(value);
    return window.__xssMarkers.filter((m) => m && s.indexOf(m) !== -1);
  };

  const record = (sink, value, extra) => {
    const v = toStr(value);
    const hits = taintHit(v);
    const rec = {
      sink,
      value: v.length > 2000 ? v.slice(0, 2000) + '…' : v,
      url: location.href,
      stack: stack(),
    };
    if (extra) Object.assign(rec, extra);
    push('sinks', rec);
    if (hits.length) push('taint', { sink, markers: hits, value: rec.value, stack: rec.stack });
  };

  // ---- Property-setter sinks -------------------------------------------------
  const hookSetter = (proto, prop, label) => {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set || d.__xssHooked) return;
      const orig = d.set;
      const ng = function (val) { record(label, val); return orig.call(this, val); };
      ng.__xssHooked = true;
      Object.defineProperty(proto, prop, { set: ng, get: d.get, configurable: true, enumerable: d.enumerable });
    } catch (e) { /* non-configurable in this engine */ }
  };

  hookSetter(Element.prototype, 'innerHTML', 'Element.innerHTML');
  hookSetter(Element.prototype, 'outerHTML', 'Element.outerHTML');
  if (window.HTMLIFrameElement) hookSetter(HTMLIFrameElement.prototype, 'srcdoc', 'iframe.srcdoc');
  if (window.HTMLScriptElement) hookSetter(HTMLScriptElement.prototype, 'src', 'script.src');
  if (window.HTMLScriptElement) hookSetter(HTMLScriptElement.prototype, 'text', 'script.text');

  // ---- Function sinks --------------------------------------------------------
  const hookFn = (obj, name, label, guard) => {
    try {
      const orig = obj[name];
      if (typeof orig !== 'function' || orig.__xssHooked) return;
      const ng = function (...args) {
        if (!guard || guard(args)) record(label, args[0], { args: args.slice(0, 3).map(toStr) });
        return orig.apply(this, args);
      };
      ng.__xssHooked = true;
      try { ng.toString = () => orig.toString(); } catch (e) {}
      obj[name] = ng;
    } catch (e) { /* frozen */ }
  };

  hookFn(window, 'eval', 'eval');
  hookFn(window, 'Function', 'Function');
  hookFn(document, 'write', 'document.write');
  hookFn(document, 'writeln', 'document.writeln');
  // setTimeout/setInterval only dangerous when first arg is a string (implicit eval)
  hookFn(window, 'setTimeout', 'setTimeout(string)', (a) => typeof a[0] === 'string');
  hookFn(window, 'setInterval', 'setInterval(string)', (a) => typeof a[0] === 'string');
  hookFn(Element.prototype, 'insertAdjacentHTML', 'insertAdjacentHTML', (a) => true);
  if (window.Range) hookFn(Range.prototype, 'createContextualFragment', 'createContextualFragment');

  // setAttribute — flag only dangerous attributes (event handlers, src, href, srcdoc, data)
  (() => {
    const orig = Element.prototype.setAttribute;
    if (orig.__xssHooked) return;
    const DANGER = /^(on|src$|href$|srcdoc$|data$|formaction$|xlink:href$)/i;
    const ng = function (name, value) {
      try { if (typeof name === 'string' && DANGER.test(name)) record('setAttribute(' + name + ')', value, { attr: name }); } catch (e) {}
      return orig.apply(this, arguments);
    };
    ng.__xssHooked = true;
    Element.prototype.setAttribute = ng;
  })();

  // jQuery (if/when it loads) — html()/append()/before()/after() route to innerHTML
  const hookJQuery = () => {
    const $ = window.jQuery || window.$;
    if (!$ || !$.fn || $.fn.__xssHooked) return;
    ['html', 'append', 'prepend', 'before', 'after', 'replaceWith'].forEach((m) => {
      if (typeof $.fn[m] !== 'function') return;
      const orig = $.fn[m];
      $.fn[m] = function (...args) {
        if (typeof args[0] === 'string' && /</.test(args[0])) record('jQuery.' + m, args[0]);
        return orig.apply(this, args);
      };
    });
    $.fn.__xssHooked = true;
  };
  hookJQuery();
  // jQuery often loads after us — retry briefly
  let jqTries = 0;
  const jqTimer = setInterval(() => { hookJQuery(); if (++jqTries > 40 || (window.jQuery && window.jQuery.fn.__xssHooked)) clearInterval(jqTimer); }, 250);

  // ---- postMessage wiretap ---------------------------------------------------
  // Record every message handler's source + whether it inspects e.origin/e.source.
  // Keep the raw addEventListener so the instrument's own listeners (below) don't
  // self-register into window.__xss.listeners.
  const rawAdd = EventTarget.prototype.addEventListener;
  (() => {
    if (rawAdd.__xssHooked) return;
    const ng = function (type, listener, opts) {
      if (type === 'message' && typeof listener === 'function') {
        let src = '';
        try { src = listener.toString(); } catch (e) {}
        push('listeners', {
          url: location.href,
          checksOrigin: /\.origin/.test(src),
          checksSource: /\.source/.test(src),
          // naive but useful: flag substring/indexOf origin checks (bypassable)
          weakOriginCheck: /origin[^;]*(indexOf|includes|startsWith|endsWith|search|match|RegExp)/i.test(src),
          handler: src.length > 1500 ? src.slice(0, 1500) + '…' : src,
        });
      }
      return rawAdd.call(this, type, listener, opts);
    };
    ng.__xssHooked = true;
    EventTarget.prototype.addEventListener = ng;
  })();

  // Also passively log received messages (origin + data shape) for triage.
  // Use rawAdd so this listener isn't itself recorded as an app handler.
  rawAdd.call(window, 'message', (e) => {
    let data;
    try { data = typeof e.data === 'string' ? e.data : JSON.stringify(e.data); } catch (x) { data = '[unserializable]'; }
    push('messages', { origin: e.origin, data: (data || '').slice(0, 1000) });
  }, true);

  // ---- CSP violation capture -------------------------------------------------
  document.addEventListener('securitypolicyviolation', (e) => {
    push('csp', {
      blockedURI: e.blockedURI,
      violatedDirective: e.violatedDirective,
      sourceFile: e.sourceFile,
      sample: (e.sample || '').slice(0, 200),
      line: e.lineNumber,
    });
  });

  console.log('[XSSHOOK] instrument active on', location.href);
})();
