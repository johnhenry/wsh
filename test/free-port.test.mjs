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
const bindTcp0 = (port) => new Promise((resolve) => { const s = net.createServer(); s.once('error', () => resolve(null)); s.listen(port, '0.0.0.0', () => resolve(s)); });
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
    // The OS hands out an ephemeral UDP port by looking at UDP alone. Whether the SAME number is free for TCP depends on every other
    // socket on the machine: an outgoing connection's local port is in the same range, and on a busy machine (parallel test files, CI)
    // a tenth or more of the numbers can be taken. Asserting that the one port the OS gave is free for both was therefore a coin the
    // machine tossed (7 failures in 40 runs with 9000 connections open, #291). The property is that a port nothing holds IS reported
    // free: find one the independent way (bind both ourselves), and only then ask the helper about it.
    let reported = null;
    for (let attempt = 0; attempt < 50 && reported === null; attempt += 1) {
      const udp = await bindUdp();
      const port = udp.address().port;
      await closeUdp(udp);
      const tcp = await bindTcp0(port);
      if (!tcp) continue;                       // TCP holds this number: not a port nothing holds, try another
      await closeTcp(tcp);
      if (await portIsFree(port)) reported = true;
    }
    assert.equal(reported, true, 'a port that nothing held was reported free');
    // freePort() must hand out a port that is free for both. Another process may take it in the moment after (the helper's own comment),
    // so a port that is no longer free is looked at again, a few times, instead of failing on one lost race.
    let ok = false; let chosen;
    for (let attempt = 0; attempt < 10 && !ok; attempt += 1) {
      chosen = await freePort();
      assert.ok(Number.isInteger(chosen) && chosen > 0 && chosen < 65536);
      ok = await portIsFree(chosen);
    }
    assert.equal(ok, true);
  });
});
