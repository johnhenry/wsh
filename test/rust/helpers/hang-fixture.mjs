// Run by guard.test.mjs, never by `npm run test:rust`: a test that spawns a child and then hangs.
import { it } from 'node:test';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import './guard.mjs';

it('this test hangs on purpose', async () => {
  const child = spawn('sleep', ['300'], { stdio: 'ignore' });
  writeFileSync(process.env.PID_FILE, String(child.pid));
  await new Promise(() => {});
});
