import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { dispatchSerially, SerialQueue } from '../src/transport.mjs';

// These tests deliberately reproduce the *shape* of the bug that
// motivated dispatchSerially/SerialQueue (CHANGELOG 0.3.0): a handler
// for item N does async work whose continuation (the code after an
// `await`) must run — e.g. to register a waiter — before item N+1 is
// dispatched, or N+1 arrives with state N's handling hasn't finished
// setting up. Real transports only exercise this by accident, when a
// server happens to batch messages in a way that reproduces the race;
// these tests reproduce it directly and deterministically, so a future
// change that reintroduces a fire-and-forget dispatch loop fails fast
// here instead of surfacing as an intermittent hang somewhere else.

describe('dispatchSerially', () => {
  it('adversarial: a later item never observes state an earlier item has not finished registering', async () => {
    // Simulates: item 1 is "SERVER_HELLO", whose handler resolves a
    // pending promise and then (in its continuation, after an await)
    // registers a new "waiter" for item 2. If dispatch doesn't wait for
    // that continuation before calling item 2's handler, item 2 would
    // find no waiter registered -- exactly the original bug.
    let waiterRegistered = false;
    let sawWaiterRegisteredInTime = null;

    async function handler(item) {
      if (item === 'SERVER_HELLO') {
        await Promise.resolve(); // the resolved-elsewhere microtask hop
        waiterRegistered = true; // the "register the next waiter" continuation
      } else if (item === 'CHALLENGE') {
        sawWaiterRegisteredInTime = waiterRegistered;
      }
    }

    await dispatchSerially(['SERVER_HELLO', 'CHALLENGE'], handler);

    assert.equal(sawWaiterRegisteredInTime, true);
  });

  it('processes items in order even when a handler yields multiple times', async () => {
    const order = [];
    async function handler(item) {
      await Promise.resolve();
      await Promise.resolve();
      order.push(item);
    }

    await dispatchSerially([1, 2, 3], handler);

    assert.deepEqual(order, [1, 2, 3]);
  });

  it('works with plain synchronous handlers (no artificial await needed by the caller)', async () => {
    const seen = [];
    await dispatchSerially(['a', 'b', 'c'], (item) => seen.push(item));
    assert.deepEqual(seen, ['a', 'b', 'c']);
  });

  it('propagates a handler error and stops processing remaining items', async () => {
    const seen = [];
    await assert.rejects(
      () => dispatchSerially([1, 2, 3], (item) => {
        if (item === 2) throw new Error('boom');
        seen.push(item);
      }),
      /boom/
    );
    assert.deepEqual(seen, [1]);
  });
});

describe('SerialQueue', () => {
  it('adversarial: items pushed synchronously (simulating a burst of events in one task) are still dispatched serially', async () => {
    // Simulates multiple WebSocket `message` events firing synchronously
    // from one underlying read, which is exactly what real WebSocket
    // implementations (e.g. Node's `ws` package parsing several frames
    // out of one TCP chunk) can do.
    let waiterRegistered = false;
    let sawWaiterRegisteredInTime = null;
    let done;
    const donePromise = new Promise((resolve) => { done = resolve; });

    const queue = new SerialQueue(async (item) => {
      if (item === 'SERVER_HELLO') {
        await Promise.resolve();
        waiterRegistered = true;
      } else if (item === 'CHALLENGE') {
        sawWaiterRegisteredInTime = waiterRegistered;
        done();
      }
    });

    // Both pushed synchronously, in the same tick -- no await between
    // them, reproducing "arrived batched" rather than "arrived separately".
    queue.push('SERVER_HELLO');
    queue.push('CHALLENGE');

    await donePromise;
    assert.equal(sawWaiterRegisteredInTime, true);
  });

  it('a push() during an in-progress drain is picked up by the same drain loop', async () => {
    const seen = [];
    const queue = new SerialQueue(async (item) => {
      seen.push(item);
      if (item === 1) {
        // Push a new item mid-drain, before the loop would otherwise exit.
        queue.push(2);
      }
      await Promise.resolve();
    });

    queue.push(1);
    // Let the drain loop run to completion.
    await new Promise((resolve) => setTimeout(resolve, 10));

    assert.deepEqual(seen, [1, 2]);
  });

  it('clear() discards queued-but-undispatched items', async () => {
    // Models the real use case (e.g. WebSocketTransport's _doConnect on
    // reconnect): the drain loop is mid-flight, paused inside the
    // current item's handler, and clear() is called from *outside* the
    // queue entirely to drop anything still queued behind it.
    const seen = [];
    let releaseFirst;
    const firstGate = new Promise((resolve) => { releaseFirst = resolve; });

    const queue = new SerialQueue(async (item) => {
      seen.push(item);
      if (item === 'keep-1') await firstGate;
    });

    // push() starts draining synchronously and runs the handler up to
    // its first await, so by the time push() returns here, the drain
    // loop is already parked on firstGate -- these two pushes land in
    // the queue behind it, not yet dispatched.
    queue.push('keep-1');
    queue.push('drop-1');
    queue.push('drop-2');

    queue.clear();
    releaseFirst();

    await new Promise((resolve) => setTimeout(resolve, 10));

    assert.deepEqual(seen, ['keep-1']);
  });

  it('concurrent push() calls do not start two overlapping drain loops', async () => {
    let concurrentDrains = 0;
    let maxConcurrentDrains = 0;
    const queue = new SerialQueue(async () => {
      concurrentDrains++;
      maxConcurrentDrains = Math.max(maxConcurrentDrains, concurrentDrains);
      await Promise.resolve();
      await Promise.resolve();
      concurrentDrains--;
    });

    queue.push(1);
    queue.push(2);
    queue.push(3);

    await new Promise((resolve) => setTimeout(resolve, 10));

    assert.equal(maxConcurrentDrains, 1);
  });
});
