// Fixtures for the browser suite: a static server for the test page (bundled from the package by esbuild, exactly the way an
// embedder's bundler would), and a `page` that has loaded it and fails the test on any uncaught error in the page.
import { test as base, expect } from '@playwright/test';
import { build } from 'esbuild';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));

let bundled = null;
/** The page bundle, built once per worker. */
async function pageBundle() {
  bundled ??= build({
    entryPoints: [path.join(here, 'page-entry.mjs')],
    bundle: true, write: false, platform: 'browser', format: 'esm', target: 'es2022', sourcemap: 'inline', logLevel: 'silent',
  }).then((r) => r.outputFiles[0].text);
  return bundled;
}

export async function startPageServer() {
  const js = await pageBundle();
  const server = http.createServer((req, res) => {
    if (req.url === '/bundle.js') { res.writeHead(200, { 'content-type': 'text/javascript' }); res.end(js); return; }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!doctype html><meta charset="utf-8"><title>wsh test page</title><script type="module" src="/bundle.js"></script>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}/`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

export const test = base.extend({
  /** A Chromium page with `window.wsh` loaded from the package's browser entry points. */
  page: async ({ page }, use) => {
    const app = await startPageServer();
    const errors = [];
    /** Console errors a test expects (the library logs one when a transport is dropped on purpose). */
    page.allowConsoleErrors = [];
    page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
    page.on('console', (m) => { if (m.type() === 'error' && !page.allowConsoleErrors.some((re) => re.test(m.text()))) errors.push(`console.error: ${m.text()}`); });
    await page.goto(app.url);
    await page.waitForFunction(() => window.wshReady === true);
    await use(page);
    await app.close();
    expect(errors, 'the page reported errors').toEqual([]);
  },
});
export { expect };
