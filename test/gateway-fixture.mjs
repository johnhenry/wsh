// Shared by the gateway tests: a Node wsh server with a gateway, and a client that either drives the raw gateway
// messages (like netway does) or uses the high-level client API.
import net from 'node:net';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export async function until(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
export const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));

export function fixture() {
  const servers = []; const clients = []; const nets = []; const cleanups = [];
  async function teardown() {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
    for (const n of nets.splice(0)) n.close();
    for (const f of cleanups.splice(0)) await f();
  }
  /**
   * @param {object|undefined} gateway  `createWshServer({ gateway })`
   * @param {{ onLog?: Function, clientFeatures?: boolean }} [opts]
   */
  async function setup(gateway, { onLog = () => {} } = {}) {
    const keyPair = await generateKeyPair(true);
    const line = `${await exportPublicKeySSH(keyPair.publicKey)} alice`;
    const server = createWshServer({ auth: { authorizedKeys: line }, gateway, onLog });
    const { port } = await server.listen(); servers.push(server);
    const client = new WshClient();
    await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
    clients.push(client);
    const inbox = [];
    client.onGatewayMessage = (m) => inbox.push(m);
    return { client, server, port, keyPair, inbox };
  }
  const echoServer = async () => {
    const echo = net.createServer((c) => { c.on('data', (d) => c.write(Buffer.concat([Buffer.from('echo:'), d]))); c.on('error', () => {}); });
    const port = await listen(echo); nets.push(echo);
    return port;
  };
  return { setup, teardown, servers, clients, nets, cleanups, echoServer };
}
