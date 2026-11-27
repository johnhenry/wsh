// Child of test/gateway-network.test.mjs: which modules does a memory host load? Prints one JSON line: { before, afterConnect, afterGateway }, each whether
// `server/gateway-session.mjs` had been resolved at that point. Mode "none": a host without `gateway`; mode "gateway": a host with one.
import { registerHooks } from 'node:module';

const seen = [];
registerHooks({ resolve(specifier, context, nextResolve) { const r = nextResolve(specifier, context); seen.push(r.url); return r; } });
const loaded = () => seen.some((u) => u.endsWith('/src/server/gateway-session.mjs'));

const mode = process.argv[2];
const { createMemoryHost } = await import('../../src/memory-host.mjs');
const { generateKeyPair, exportPublicKeyRaw } = await import('../../src/index.mjs');
const keyPair = await generateKeyPair(true);
const raw = await exportPublicKeyRaw(keyPair.publicKey);
const network = { async connectTcp() { const t = new TransformStream(); return { readable: t.readable, writable: t.writable }; } };
const host = createMemoryHost({
  auth: { authorizedKeys: [raw] },
  endpoints: { e: () => {} },
  ...(mode === 'gateway' ? { gateway: { network, allow: ['93.184.216.7'] } } : {}),
});
const before = loaded();
const client = await host.connect({ username: 'alice', keyPair });
const afterConnect = loaded();
let afterGateway = null;
if (mode === 'gateway') { (await client.openTcp('93.184.216.7', 7)).destroy(); afterGateway = loaded(); }
await client.disconnect();
await host.close();
console.log(JSON.stringify({ before, afterConnect, afterGateway }));
