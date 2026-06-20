#!/usr/bin/env node
/*
 * xss-confirm.js — deterministic headless-browser XSS *execution* oracle.
 *
 * Loads a URL (which should already carry the XSS payload) in headless Chromium and
 * reports whether JavaScript actually EXECUTED — the proof needed before a finding is
 * reported. Strongest signal: an alert/confirm/prompt dialog firing with a unique nonce.
 * Also captures console output, page errors, and any [XSSHOOK] sink hits if the page's
 * payload set window.__xss (mirrors playwright-chrome/init/xss-instrument.js).
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

    // Pull sink-hook results if the page populated them (xss-instrument.js).
    try {
      const hooked = await page.evaluate(() => (window.__xss && window.__xss.events) ? window.__xss.events.slice(0, 50) : []);
      if (Array.isArray(hooked) && hooked.length) {
        out.xsshook = hooked;
        if (!out.xss) { out.oracle = out.oracle || `sink hit: ${hooked.length} dangerous sink write(s) recorded`; }
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
