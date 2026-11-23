// test/browser-bundle.test.mjs -- every browser entry point bundles for the browser (#115, #128): nothing reachable
// from it imports a Node built-in or touches `Buffer`, and its size stays within the checked-in budget
// (`scripts/bundle-budget.json`; `npm run size` prints the table, `npm run size -- --update` rewrites the budget).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { ENTRY_POINTS, ROOT, bundle } from '../scripts/browser-bundles.mjs';
import { measure, readBudget, overBudget } from '../scripts/bundle-size.mjs';

describe('browser entry points (#115, #128)', () => {
  it('every exports entry except ./server is bundled', async () => {
    const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8'));
    const bundled = new Set(ENTRY_POINTS.filter((p) => p.entry).map((p) => p.name));
    const expected = Object.keys(pkg.exports).filter((k) => k !== './server').map((k) => (k === '.' ? '.' : k));
    assert.deepEqual([...bundled].sort(), expected.sort());
    assert.equal(pkg.sideEffects, false);
  });

  for (const point of ENTRY_POINTS) {
    it(`${point.name} bundles for the browser with no Node built-in, require() or Buffer`, async () => {
      const { problems, inputs } = await bundle(point);
      assert.deepEqual(problems, []);
      const nodeOnly = inputs.filter((f) => /^src\/server\/(index|fs|exec|gateway|host-key|self-signed|sessions|webtransport|backends|reverse-host|rpc)\.mjs$/.test(f));
      assert.deepEqual(nodeOnly, [], 'a Node-only module is reachable');
    });
  }

  it('the check fails on a Node built-in: ./server does not bundle for the browser', async () => {
    await assert.rejects(
      bundle({ name: './server', entry: 'src/server/index.mjs' }),
      (e) => /node:|Could not resolve/.test(e.message),
    );
    await assert.rejects(
      bundle({ name: 'fs', contents: "import { readFile } from 'node:fs/promises'; globalThis.x = readFile;" }),
      /node:fs\/promises/,
    );
  });

  it('the check fails on a Buffer reference', async () => {
    const { problems } = await bundle({ name: 'buf', contents: 'globalThis.x = Buffer.from([1]);' });
    assert.deepEqual(problems, ['references the Node `Buffer` global']);
  });

  it('stays within the size budget (gzip, +10%)', async () => {
    const sizes = await measure();
    assert.deepEqual(overBudget(sizes, await readBudget()), []);
  });

  it('./host does not import the client', async () => {
    const { inputs } = await bundle(ENTRY_POINTS.find((p) => p.name === './host'));
    assert.ok(!inputs.includes('src/client.mjs'));
  });

  it('a single import is tree-shaken: generateKeyPair does not pull in the client', async () => {
    const { raw, inputs } = await bundle(ENTRY_POINTS.find((p) => p.name === '. (generateKeyPair only)'));
    assert.ok(raw < 4096, `${raw} B`);
    assert.ok(!inputs.includes('src/client.mjs'));
  });
});
