// scripts/browser-bundles.mjs -- bundle every browser entry point of the package for the browser and measure it.
//
// Why esbuild: it is one small native binary with no dependency tree (about 10 MB installed; Playwright is the heavy
// devDependency, esbuild is not), bundles ESM with real tree-shaking, and fails the build when a module imports a Node
// built-in under `platform: 'browser'` -- which is exactly the check this exists for (#115, #128). It is a devDependency
// only; nothing in `src/` imports it and the published package is unchanged.
//
// Used by `test/browser-bundle.test.mjs` (fails on a Node built-in, a `Buffer`, or a size regression against
// `scripts/bundle-budget.json`) and `npm run size` (prints the table; `-- --update` rewrites the budget).

import { build } from 'esbuild';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * What a bundler of an embedder's page would be handed: each `exports` entry that is meant for a browser, whole
 * (`entry`), and the tree-shaken size of one import from it (`contents`). `./server` is Node-only and not here.
 * `@noble/post-quantum` (the optional ML-KEM backend, loaded on demand) is left external so the numbers are this
 * package's own code and do not change with what is installed next to it.
 */
export const ENTRY_POINTS = [
  { name: '.', entry: 'src/index.mjs' },
  { name: './memory', entry: 'src/memory-host.mjs' },
  { name: './host', entry: 'src/host.mjs' },
  { name: './reverse', entry: 'src/reverse-host.mjs' },
  { name: './pipe-relay', entry: 'src/pipe-relay.mjs' },
  { name: './testing', entry: 'src/testing.mjs' },
  { name: './page', entry: 'src/page-host.mjs' },
  { name: './objects', entry: 'src/objects.mjs' },
  { name: './objects-types', entry: 'src/objects-types.mjs' },
  { name: './capabilities', entry: 'src/capabilities.mjs' },
  { name: './identity', entry: 'src/identity.mjs' },
  { name: './duplex', entry: 'src/duplex.mjs' },
  { name: './address-guard', entry: 'src/address-guard.mjs' },
  { name: './gateway', entry: 'src/gateway.mjs' },
  { name: './testing (encodeRecord only)', contents: "import { encodeRecord } from './src/testing.mjs'; globalThis.x = encodeRecord;" },
  { name: '. (generateKeyPair only)', contents: "import { generateKeyPair } from './src/index.mjs'; globalThis.x = generateKeyPair;" },
  { name: '. (WshClient only)', contents: "import { WshClient } from './src/index.mjs'; globalThis.x = WshClient;" },
  { name: './address-guard (isPublicAddress only)', contents: "import { isPublicAddress } from './src/address-guard.mjs'; globalThis.x = isPublicAddress;" },
  { name: './host (createConnectionFactory only)', contents: "import { createConnectionFactory } from './src/host.mjs'; globalThis.x = createConnectionFactory;" },
];

/** Replaced by a marker so any reference to the Node global survives into the output, where we can see it. */
const BUFFER_MARKER = '__WSH_NODE_BUFFER__';

/**
 * Bundle one entry for the browser. Rejects (with esbuild's message naming the import) when anything reachable imports
 * a Node built-in; resolves with `{ code, raw, gzip, lazy, chunkFiles, inputs }` (`code`, `raw`, `gzip`: the entry chunk; `lazy`: the chunks behind a dynamic import). `code` is the bundle; `problems` lists a reference to the
 * Node `Buffer` global or a `require(`.
 */
export async function bundle(point, { minify = true } = {}) {
  const result = await build({
    ...(point.entry ? { entryPoints: [path.join(ROOT, point.entry)] } : { stdin: { contents: point.contents, resolveDir: ROOT, loader: 'js' } }),
    bundle: true,
    write: false,
    // Code behind a dynamic `import()` (the gateway session of a host that was given a `gateway`, #299) is a chunk of its own, as it is in an
    // embedder's bundler: the entry's size is what a page that never uses it ships, and the chunks are reported apart as `lazy`.
    splitting: true,
    outdir: path.join(ROOT, '.bundle-out'),
    platform: 'browser',
    format: 'esm',
    target: 'es2022',
    minify,
    treeShaking: true,
    external: ['@noble/*'],
    define: { Buffer: BUFFER_MARKER },
    metafile: true,
    logLevel: 'silent',
  });
  // What a page loads at once is the entry chunk and every chunk it reaches by a STATIC import (code shared between the entry and a lazy chunk is split
  // into a `chunk-*.js` the entry imports); what only a dynamic `import()` reaches is `lazy`. Every chunk is checked for Node built-ins, only the eager
  // ones are the entry's size.
  const files = result.outputFiles;
  const key = (f) => path.relative(ROOT, f.path).split(path.sep).join('/');
  const byKey = new Map(files.map((f) => [key(f), f]));
  const entryKey = Object.keys(result.metafile.outputs).find((k) => result.metafile.outputs[k].entryPoint) ?? key(files[0]);
  const eagerKeys = new Set();
  const visit = (k) => {
    if (eagerKeys.has(k) || !byKey.has(k)) return;
    eagerKeys.add(k);
    for (const i of result.metafile.outputs[k]?.imports ?? []) if (i.kind === 'import-statement') visit(i.path);
  };
  visit(entryKey);
  const eagerFiles = files.filter((f) => eagerKeys.has(key(f)));
  const lazyFiles = files.filter((f) => !eagerKeys.has(key(f)));
  const code = eagerFiles.map((f) => f.text).join('\n');
  const bytes = Buffer.from(code);
  const lazyBytes = Buffer.concat(lazyFiles.map((f) => Buffer.from(f.text)));
  const lazy = { chunks: lazyFiles.length, raw: lazyBytes.length, gzip: lazyFiles.length ? gzipSync(lazyBytes, { level: 9 }).length : 0 };
  const problems = [];
  const all = files.map((f) => f.text).join('\n');
  if (all.includes(BUFFER_MARKER)) problems.push('references the Node `Buffer` global');
  if (/\brequire\(/.test(all)) problems.push('calls require()');
  // The source files that contribute bytes to the bundle (what tree-shaking left), not every file that was parsed.
  const inputs = Object.values(result.metafile.outputs).flatMap((o) => Object.entries(o.inputs))
    .filter(([f, i]) => i.bytesInOutput > 0 && !f.startsWith('node_modules/')).map(([f]) => f);
  return { code, raw: bytes.length, gzip: gzipSync(bytes, { level: 9 }).length, lazy, chunkFiles: files.map((f) => path.basename(f.path)), inputs, problems };
}
