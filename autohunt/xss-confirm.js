#!/usr/bin/env node
/*
 * xss-confirm.js — deterministic headless-browser XSS *execution* oracle.
 *
 * Loads a URL (which should already carry the XSS payload) in headless Chromium and
 * reports whether JavaScript actually EXECUTED — the proof needed before a finding is
 * reported. Strongest signal: an alert/confirm/prompt dialog firing with a unique nonce.
 * Also injects playwright-chrome/init/xss-instrument.js (a DOM source→sink tracer) BEFORE page JS
 * and seeds the nonce as a taint marker, so a nonce reaching an EXECUTING sink (eval/Function/
 * setTimeout(string)/script/document.write) also counts as confirmed execution — not just dialogs.
 * Reports console output, page errors, and the instrument's sink/taint hits (window.__xss).
 *
 * Usage:
 *   node xss-confirm.js "<url>" [--nonce <NONCE>] [--wait <ms>] [--shot <path>]
 *
 * Recommended payload pattern (so the nonce ties the alert to YOUR injection):
 *   alert(document.domain + '::' + 'NONCE')      ->  --nonce NONCE
 *
 * Output: a single JSON line on stdout:
 *   {"url","xss":bool,"oracle","dialog":{...}|null,"nonce_matched":bool,
 *    "console":[...],"pageerrors":[...],"xsshook":[...],"screenshot":"<path>|null","error":null}
 * Exit 0 if xss confirmed, 1 if not confirmed, 2 on harness error (e.g. playwright missing).
 */
'use strict';

const path = require('path');
const INSTRUMENT = path.join(__dirname, '..', 'playwright-chrome', 'init', 'xss-instrument.js');

function parseArgs(argv) {
  const a = { url: null, nonce: null, wait: 3500, shot: null };
  const rest = argv.slice(2);
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i];
    if (t === '--nonce') a.nonce = rest[++i];
    else if (t === '--wait') a.wait = parseInt(rest[++i], 10) || 3500;
    else if (t === '--shot') a.shot = rest[++i];
    else if (!a.url) a.url = t;
  }
  return a;
}

async function main() {
  const args = parseArgs(process.argv);
  const out = {
    url: args.url, xss: false, oracle: null, dialog: null, nonce_matched: false,
    console: [], pageerrors: [], xsshook: [], screenshot: null, error: null,
  };

  if (!args.url) {
    out.error = 'no url provided';
    console.log(JSON.stringify(out));
    process.exit(2);
  }

  let chromium;
  try {
    ({ chromium } = require('playwright'));
  } catch (e) {
    out.error = "playwright not installed (run: npm i -g playwright && npx playwright install --with-deps chromium)";
    console.log(JSON.stringify(out));
    process.exit(2);
  }

  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    // Seed the nonce as a taint marker, then install the DOM source→sink instrument BEFORE page JS.
    try {
      if (args.nonce) await ctx.addInitScript({ content: `window.__xssMarkers=[${JSON.stringify(args.nonce)}];` });
      await ctx.addInitScript({ path: INSTRUMENT });
    } catch (_) { /* instrument is optional — the dialog oracle still works without it */ }
    const page = await ctx.newPage();

    page.on('dialog', async (d) => {
      const msg = d.message();
      out.dialog = { type: d.type(), message: msg };
      out.xss = true;
      out.oracle = `dialog(${d.type()}) fired: ${JSON.stringify(msg)}`;
      if (args.nonce && msg && msg.includes(args.nonce)) out.nonce_matched = true;
      try { await d.dismiss(); } catch (_) {}
    });
    page.on('console', (m) => { if (out.console.length < 50) out.console.push(`${m.type()}: ${m.text()}`); });
    page.on('pageerror', (e) => { if (out.pageerrors.length < 20) out.pageerrors.push(String(e)); });

    try {
      await page.goto(args.url, { waitUntil: 'domcontentloaded', timeout: 20000 });
    } catch (e) {
      out.error = `navigation: ${String(e).slice(0, 200)}`;
    }
    await page.waitForTimeout(args.wait);

    // Pull the instrument's source→sink results (window.__xss).
    try {
      const hooked = await page.evaluate(() => {
        const x = window.__xss;
        if (!x) return null;
        return {
          sinks: (x.sinks || []).slice(0, 50), taint: (x.taint || []).slice(0, 50),
          listeners: (x.listeners || []).slice(0, 20), csp: (x.csp || []).slice(0, 20),
        };
      });
      if (hooked) {
        out.xsshook = hooked;
        // A seeded nonce reaching an EXECUTING sink is proof of execution (no dialog needed).
        const execHit = (hooked.taint || []).find(
          (t) => /^(eval|Function|setTimeout|setInterval|script\.(text|src)|document\.write)/.test(t.sink || ''));
        if (!out.xss && execHit) {
          out.xss = true;
          out.nonce_matched = true;
          out.oracle = `nonce reached executing sink ${execHit.sink} (DOM source→sink execution)`;
        } else if (!out.xss && (hooked.taint || []).length) {
          out.oracle = out.oracle ||
            `source→sink flow: nonce reached ${hooked.taint.length} markup sink(s) — craft an executing payload to confirm`;
        } else if (!out.xss && (hooked.sinks || []).length) {
          out.oracle = out.oracle || `${hooked.sinks.length} dangerous sink write(s) observed (no nonce taint match)`;
        }
      }
    } catch (_) {}

    if (args.shot) {
      try { await page.screenshot({ path: args.shot, fullPage: false }); out.screenshot = args.shot; } catch (_) {}
    }

    if (!out.oracle && out.pageerrors.some((e) => /SyntaxError|Unexpected/.test(e))) {
      out.oracle = 'pageerror suggests injected input reached a JS context (not proof of execution)';
    }
  } catch (e) {
    out.error = out.error || String(e).slice(0, 300);
  } finally {
    if (browser) { try { await browser.close(); } catch (_) {} }
  }

  console.log(JSON.stringify(out));
  process.exit(out.xss ? 0 : 1);
}

main();
