// test/free-port.test.mjs -- test/helpers/free-port.mjs: the port a test hands to `wsh-server` must be free for TCP (the WebSocket listener)
// AND for UDP (the WebTransport listener binds the same number); a helper that only looked at TCP sometimes returned a port the server
// then could not bind ("WebTransport bind failed: Address already in use"), which failed whichever test happened to start a server then (#248).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { freePort, portIsFree } from './helpers/free-port.mjs';

const bindUdp = () => new Promise((resolve) => { const s = dgram.createSocket('udp4'); s.bind(0, '0.0.0.0', () => resolve(s)); });
const bindTcp = () => new Promise((resolve) => { const s = net.createServer().listen(0, '0.0.0.0', () => resolve(s)); });
const closeUdp = (s) => new Promise((r) => s.close(r));
const closeTcp = (s) => new Promise((r) => s.close(r));

describe('free-port helper', () => {
  it('a port that only UDP holds is not free (the case a TCP-only check misses)', async () => {
    const udp = await bindUdp();
    try {
      assert.equal(await portIsFree(udp.address().port), false);
    } finally { await closeUdp(udp); }
  });

  it('a port that only TCP holds is not free', async () => {
    const tcp = await bindTcp();
    try {
      assert.equal(await portIsFree(tcp.address().port), false);
    } finally { await closeTcp(tcp); }
  });

  it('a port nothing holds is free, and freePort() returns one that is', async () => {
    const udp = await bindUdp();
    const port = udp.address().port;
    await closeUdp(udp);
    assert.equal(await portIsFree(port), true);
    const chosen = await freePort();
    assert.ok(Number.isInteger(chosen) && chosen > 0 && chosen < 65536);
    assert.equal(await portIsFree(chosen), true);
  });
});
