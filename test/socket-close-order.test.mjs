// test/socket-close-order.test.mjs -- `bindSocket` (what `server.accept(socket)` and `host.accept(socket)` run): what the peer sent before its
// socket closed is given to the connection before the close is, even though each message is handled asynchronously.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { bindSocket } from '@johnhenry/wsh/host';

/** A socket whose events the test fires by hand (the `on(event, fn)` shape of the `ws` package). */
function fakeSocket() {
  const handlers = new Map();
  return {
    readyState: 1,
    send() {},
    close() {},
    on(event, fn) { handlers.set(event, fn); },
    fire(event, ...args) { handlers.get(event)?.(...args); },
  };
}

describe('bindSocket: the close does not overtake what the peer sent before it', () => {
  it('messages already received reach the connection, in order, before it is told the socket closed', async () => {
    const socket = fakeSocket();
    const seen = [];
    const attach = () => ({ receive: (b) => seen.push(`rx ${b[0]}`), close: () => seen.push('close') });
    const bound = bindSocket(socket, Promise.resolve(attach));
    await bound;
    socket.fire('message', Buffer.from([1]));
    socket.fire('message', Buffer.from([2]));
    socket.fire('close');
    // Anything after the close is not heard.
    socket.fire('message', Buffer.from([3]));
    await (await bound).close();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(seen, ['rx 1', 'rx 2', 'close']);
  });

  it('a close with nothing before it closes the connection once', async () => {
    const socket = fakeSocket();
    const seen = [];
    const bound = await bindSocket(socket, Promise.resolve(() => ({ receive: () => seen.push('rx'), close: () => seen.push('close') })));
    socket.fire('close');
    bound.close();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(seen, ['close']);
  });
});
