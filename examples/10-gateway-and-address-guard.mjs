/**
 * The gateway resolves once, classifies every answer, and dials only what passed (wsh #98, address guard since 0.55.0).
 *
 * `@johnhenry/wsh/address-guard` is the check behind the Node gateway: a name is looked up ONCE, every address in the
 * answer is classified (`public`, or the reason it is not: loopback, private, link-local, metadata, ...) and the socket
 * is opened to the address that passed, never to the name, so a second lookup cannot redirect it. This example uses
 * (1) the classifier, (2) `resolveChecked` with a stand-in resolver, so no DNS is queried, and (3) a real wsh server
 * with a gateway, where the only destination is a local echo service on 127.0.0.1: it contacts no third-party host.
 */

import assert from 'node:assert/strict';
import net from 'node:net';
import { WshClient, GatewayError, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { createWshServer } from '@johnhenry/wsh/server';
import { classifyAddress, isPublicAddress, checkAddress, resolveChecked, dialChecked, AddressGuardError } from '@johnhenry/wsh/address-guard';

// ── 1. Classify: the reason, not just yes/no ──────────────────────────

console.log('1. classifyAddress');
const samples = { '8.8.8.8': 'public', '127.0.0.1': 'loopback', '10.1.2.3': 'private', '169.254.169.254': 'metadata', '100.64.0.1': 'carrier-nat',
  'fd00::1': 'unique-local', '::ffff:10.0.0.1': 'private', '64:ff9b::808:808': 'public', '2001::1': 'teredo' };
for (const [ip, want] of Object.entries(samples)) {
  assert.equal(classifyAddress(ip), want, ip);
  console.log(`   ${ip.padEnd(18)} ${classifyAddress(ip).padEnd(13)} ${isPublicAddress(ip) ? 'ALLOWED' : 'REFUSED'}`);
}
assert.equal(checkAddress('10.0.0.1', { allowPrivate: true }).permitted, true);
assert.equal(checkAddress('169.254.169.254', { allowPrivate: true }).permitted, false, 'allowPrivate never opens the metadata address');
assert.equal(checkAddress('8.8.8.8', { deny: ['8.8.8.0/24'] }).reason, 'deny', 'deny wins, public or not');

// ── 2. Resolve once, check every answer ───────────────────────────────

console.log('2. resolveChecked with a stand-in resolver');
const calls = [];
const table = { 'api.test': ['93.184.216.34'], 'meta.test': ['169.254.169.254'], 'rebind.test': ['10.0.0.5', '93.184.216.34'] };
const lookup = async (name) => { calls.push(name); return table[name]; };
const ok = await resolveChecked('api.test', { lookup });
console.log(`   ALLOWED: api.test -> ${ok[0].address} (${ok[0].class})`);
assert.deepEqual(ok.map((a) => a.address), ['93.184.216.34']);
const refusal = await resolveChecked('meta.test', { lookup }).catch((e) => e);
assert.ok(refusal instanceof AddressGuardError && refusal.code === 'ADDRESS_REFUSED');
console.log(`   REFUSED: meta.test -> ${refusal.code} ${refusal.refused.map((r) => `${r.address} (${r.class})`)}`);
const mixed = await resolveChecked('rebind.test', { lookup });
console.log(`   MIXED:   rebind.test keeps ${mixed.map((a) => a.address)} and drops the private answer`);
assert.deepEqual(mixed.map((a) => a.address), ['93.184.216.34']);
await assert.rejects(resolveChecked('rebind.test', { lookup, refuseMixed: true }), (e) => e.code === 'ADDRESS_REFUSED');
console.log('   REFUSED: the same name with refuseMixed: true');
assert.equal(calls.length, 4, 'one lookup per call, never a second one to dial');

// ── 3. The gateway: a local echo service is the destination ───────────

const echo = net.createServer((c) => { c.on('data', (d) => c.write(`echo:${d}`)); c.on('error', () => {}); });
await new Promise((r) => echo.listen(0, '127.0.0.1', r));
const { port } = echo.address();

const keyPair = await generateKeyPair(true);
async function gatewayTo(gateway) {
  const server = createWshServer({ auth: { authorizedKeys: `${await exportPublicKeySSH(keyPair.publicKey)} alice` }, gateway });
  const { port: p } = await server.listen();
  const client = new WshClient();
  await client.connect(`ws://127.0.0.1:${p}`, { username: 'alice', keyPair });
  return { client, close: async () => { await client.disconnect(); await server.close(); } };
}

console.log('3. a wsh gateway in front of a local echo service');
const strict = await gatewayTo({ allow: ['*'] });    // any name and port, but only public addresses
const denied = await strict.client.openTcp('127.0.0.1', port).catch((e) => e);
assert.ok(denied instanceof GatewayError, 'loopback is refused although the name is on the allow list');
console.log(`   REFUSED: openTcp(127.0.0.1:${port}) -> ${denied.message}`);
await strict.close();

const open = await gatewayTo({ allow: ['*'], allowPrivate: ['127.0.0.1/32'] });   // an explicit rule names the stand-in
const conn = await open.client.openTcp('127.0.0.1', port);
const reader = conn.readable.getReader();
const writer = conn.writable.getWriter();
await writer.write(new TextEncoder().encode('ping'));
const { value } = await reader.read();
console.log(`   ALLOWED: with allowPrivate ['127.0.0.1/32'] -> "${new TextDecoder().decode(value)}"`);
assert.equal(new TextDecoder().decode(value), 'echo:ping');
await writer.close().catch(() => {});
await open.close();

// The same guard, used directly by anything else that dials where someone else asks.
await assert.rejects(dialChecked('127.0.0.1', port), (e) => e.code === 'ADDRESS_REFUSED');
const direct = await dialChecked('127.0.0.1', port, { allow: ['127.0.0.1'] });
console.log(`   dialChecked: REFUSED by default, ALLOWED with allow: ['127.0.0.1'] (dialled ${direct.address}, class ${direct.class})`);
direct.socket.destroy();

echo.close();
console.log('ok: every answer was classified; only what passed was dialled');
