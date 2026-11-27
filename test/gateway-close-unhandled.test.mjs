// test/gateway-close-unhandled.test.mjs -- a gateway connection that closes while a call is still being sent leaves no unhandled rejection.
//
// `openEndpoint`, `openTcp`, `openUnix`, `openUdp`, `listenTcp` and `listenUnix` register the promise that settles when the host answers
// BEFORE they await the send of the request. The transport closing (`abandonAll`), the signal firing or the timeout running while that
// send is still in flight rejected the answer promise before anything was waiting on it: a rejection nobody saw, which Node ends the
// process for. The caller's own promise must still reject (with the error that applies), and nothing else may.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { GatewayConnections, GatewayError } from '../src/gateway-client.mjs';

/** Run `fn` with a process-wide hook on `unhandledRejection`/`uncaughtException`; resolve with what was raised after a few macrotasks. */
async function raised(fn) {
  const seen = [];
  const hook = (e) => seen.push(e);
  process.on('unhandledRejection', hook);
  process.on('uncaughtException', hook);
  try {
    await fn();
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 30));
  } finally {
    process.off('unhandledRejection', hook);
    process.off('uncaughtException', hook);
  }
  return seen;
}

/** A GatewayConnections whose sends are held until the test settles them, one at a time. */
function held() {
  const sends = [];
  const gw = new GatewayConnections({
    send: (msg) => new Promise((resolve, reject) => { sends.push({ msg, resolve, reject }); }),
    hasFeature: () => true,
  });
  return { gw, sends };
}
const tick = () => new Promise((r) => setImmediate(r));

const calls = {
  openEndpoint: (gw, opts) => gw.openEndpoint('mesh', opts),
  openTcp: (gw, opts) => gw.openTcp('example.test', 80, opts),
  openUnix: (gw, opts) => gw.openUnix('/run/x.sock', opts),
  openUdp: (gw, opts) => gw.openUdp('example.test', 53, opts),
  listenTcp: (gw, opts) => gw.listenTcp(0, { onConnection() {}, ...opts }),
  listenUnix: (gw, opts) => gw.listenUnix('/run/y.sock', { onConnection() {}, ...opts }),
};

for (const [name, call] of Object.entries(calls)) {
  describe(`${name}: the connection closes while the request is being sent`, () => {
    it('the transport closes, then the send completes: the caller gets the GatewayError, nothing else is raised', async () => {
      const { gw, sends } = held();
      let outcome;
      const seen = await raised(async () => {
        const p = call(gw).then((v) => ({ v }), (e) => ({ e }));
        await tick();
        assert.equal(sends.length, 1);
        gw.abandonAll('transport closed');
        await tick();
        sends[0].resolve();
        outcome = await p;
      });
      assert.deepEqual(seen, []);
      assert.ok(outcome.e instanceof GatewayError, 'the caller still sees the rejection');
      assert.equal(outcome.e.code, 6);
      assert.equal(outcome.e.message, 'transport closed');
    });

    it('the transport closes, then the send fails: the caller gets the send error, nothing else is raised', async () => {
      const { gw, sends } = held();
      const failure = new Error('write after close');
      let outcome;
      const seen = await raised(async () => {
        const p = call(gw).then((v) => ({ v }), (e) => ({ e }));
        await tick();
        gw.abandonAll('transport closed');
        await tick();
        sends[0].reject(failure);
        outcome = await p;
      });
      assert.deepEqual(seen, []);
      assert.equal(outcome.e, failure);
    });

    it('the timeout runs while the send is held, then the send completes: the caller gets the timeout, nothing else is raised', async () => {
      const { gw, sends } = held();
      let outcome;
      const seen = await raised(async () => {
        const p = call(gw, { timeoutMs: 5 }).then((v) => ({ v }), (e) => ({ e }));
        await tick();
        await new Promise((r) => setTimeout(r, 25)); // the 5 ms timer has run while the send is held
        sends[0].resolve();
        outcome = await p;
      });
      assert.deepEqual(seen, []);
      assert.ok(outcome.e instanceof GatewayError, 'the caller still sees the rejection');
      assert.equal(outcome.e.code, 5);
    });
  });
}

for (const name of ['openEndpoint', 'openTcp', 'openUnix', 'openUdp']) {
  describe(`${name}: the signal fires while the request is being sent`, () => {
    it('the caller gets the abort, nothing else is raised, whether the send then completes or fails', async () => {
      for (const settle of ['resolve', 'reject']) {
        const { gw, sends } = held();
        const ac = new AbortController();
        let outcome;
        const seen = await raised(async () => {
          const p = calls[name](gw, { signal: ac.signal }).then((v) => ({ v }), (e) => ({ e }));
          await tick();
          ac.abort(new Error('stop'));
          await tick();
          sends[0][settle](settle === 'reject' ? new Error('late send failure') : undefined);
          outcome = await p;
        });
        assert.deepEqual(seen, [], settle);
        assert.ok(outcome.e instanceof Error, settle);
      }
    });
  });
}
