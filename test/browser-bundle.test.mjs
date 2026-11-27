// test/browser-bundle.test.mjs -- every browser entry point bundles for the browser (#115, #128): nothing reachable
// from it imports a Node built-in or touches `Buffer`, and its size stays within the checked-in budget
// (`scripts/bundle-budget.json`; `npm run size` prints the table, `npm run size -- --update` rewrites the budget).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { ENTRY_POINTS, ROOT, bundle } from '../scripts/browser-bundles.mjs';
import {
  measure, readBudget, overBudget, README_FILE, README_START, README_END, readmeBlock, renderReadmeTable, replaceReadmeBlock,
} from '../scripts/bundle-size.mjs';

describe('browser entry points (#115, #128)', () => {
  it('every exports entry except the Node-only ones is bundled', async () => {
    const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8'));
    const bundled = new Set(ENTRY_POINTS.filter((p) => p.entry).map((p) => p.name));
    // ./server needs Node. ./pipe-relay IS bundled: its `listen()` (`ws`, `node:http`) is a separate module loaded by name
    // at call time, so a page can import `pipeUrl`, `newRendezvousId`, `watchPairing` or run `accept()` over sockets it holds.
    // ./mcp-stdio (#127) is the `wsh-mcp` bridge: it reads a key file and speaks stdio, so it is Node-only.
    // ./spec/* are data files (the notation, its vectors, the wire spec), not code.
    const expected = Object.keys(pkg.exports).filter((k) => k !== './server' && k !== './mcp-stdio' && !k.startsWith('./spec/'));
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

  it('#299: the gateway session is a chunk of its own behind a dynamic import: a host entry that is given no gateway does not ship it, and the explicit entry does', async () => {
    for (const name of ['./memory', './reverse', './testing', './page']) {
      const { code, chunkFiles, lazy, inputs } = await bundle(ENTRY_POINTS.find((p) => p.name === name));
      assert.ok(lazy.chunks >= 1 && chunkFiles.some((f) => /^(gateway-session|reverse-gateway)-/.test(f)), `${name}: the gateway session is split into a chunk (${chunkFiles.join(', ')})`);
      assert.ok(!code.includes('this network cannot open TCP connections'), `${name}: the entry chunk has no gateway session in it`);
      assert.ok(inputs.includes('src/server/gateway-session.mjs'), `${name}: and it is still bundled (the lazy chunk)`);
    }
    const gateway = await bundle(ENTRY_POINTS.find((p) => p.name === './gateway'));
    assert.ok(gateway.code.includes('this network cannot open TCP connections'), './gateway is the session itself, in its entry');
    assert.equal(gateway.lazy.chunks, 0);
  });

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

  it('#128: the README states the gzipped size of each browser entry point, as the budget file has it (`npm run size -- --update` rewrites both)', async () => {
    const budget = await readBudget();
    const readme = await readFile(README_FILE, 'utf8');
    assert.equal(readmeBlock(readme), renderReadmeTable(budget), 'the README size table is stale: run `npm run size -- --update`');
    for (const p of ENTRY_POINTS.filter((x) => x.entry)) assert.ok(readmeBlock(readme).includes(`\`@johnhenry/wsh${p.name === '.' ? '' : p.name.slice(1)}\``), `${p.name} is in the README table`);
  });

  it('the README table is regenerated from the budget, and a stale one is detected', async () => {
    const budget = await readBudget();
    const table = renderReadmeTable(budget);
    const doc = `before\n${README_START}\n${table}\n${README_END}\nafter\n`;
    assert.equal(readmeBlock(doc), table);
    const changed = { ...budget, entries: { ...budget.entries, '.': { ...budget.entries['.'], gzip: budget.entries['.'].gzip + 4096 } } };
    assert.notEqual(readmeBlock(doc), renderReadmeTable(changed));
    assert.equal(replaceReadmeBlock(doc, renderReadmeTable(changed)).startsWith('before\n'), true);
    assert.equal(readmeBlock(replaceReadmeBlock(doc, renderReadmeTable(changed))), renderReadmeTable(changed));
    assert.throws(() => replaceReadmeBlock('no markers', table), /markers/);
  });

  it('./pipe-relay bundles for the browser without `ws` or a Node built-in, and so does a page that statically imports it with ./memory', async () => {
    const own = await bundle(ENTRY_POINTS.find((p) => p.name === './pipe-relay'));
    assert.deepEqual(own.problems, []);
    assert.deepEqual(own.inputs, ['src/pipe-relay.mjs'], 'only the relay module itself contributes bytes');
    assert.ok(!/from\s*["']ws["']|require\(["']ws/.test(own.code));
    // The shape the downstream hit: one bundle with a static import of the pipe relay next to the memory host.
    const page = await bundle({
      name: 'memory + pipe-relay',
      contents: "import { createMemoryHost } from './src/memory-host.mjs'; import { pipeUrl, newRendezvousId, watchPairing, createPipeRelay } from './src/pipe-relay.mjs'; globalThis.x = [createMemoryHost, pipeUrl, newRendezvousId, watchPairing, createPipeRelay];",
    });
    assert.deepEqual(page.problems, []);
  });

  it('the check this guards is real: a relay whose listen() named ws and node:http literally would not bundle', async () => {
    await assert.rejects(
      bundle({ name: 'literal', contents: "export async function listen() { const http = await import('node:http'); return http; } globalThis.x = listen;" }),
      /node:http/,
    );
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
