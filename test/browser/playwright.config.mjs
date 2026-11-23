// Playwright config for `npm run test:browser` (a separate CI job; `npm test` stays JS-only and does not need a browser).
// One real Chromium; each spec starts its own Node-side servers (a wsh server, a byte pipe) and a static server for the page.
import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export default defineConfig({
  testDir: path.dirname(fileURLToPath(import.meta.url)),
  testMatch: '*.spec.mjs',
  // Traces and failure context land where CI uploads them from.
  outputDir: path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'test-results'),
  fullyParallel: false,
  workers: 1,
  // A flake here would hide a real race in the handshake or the pipe: no retries.
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['github']] : [['list']],
  use: { ...devices['Desktop Chrome'], headless: true },
  projects: [{ name: 'chromium' }],
});
