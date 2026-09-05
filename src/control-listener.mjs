/**
 * Control-message subscription for the helper classes that compose their
 * own wire messages — `WshMcpBridge` and `WshFileTransfer`.
 *
 * Both accept "a WshClient, or any object exposing sendControl() plus a
 * way to observe inbound control messages", and both used to inline the
 * same three-way registration. The third branch of it — the fallback for
 * an object whose only hook is a settable `onControl` property, which is
 * what a bare `WshTransport` is — wrapped that property and **never
 * unwrapped it**:
 *
 * ```js
 * const prev = client.onControl;
 * client.onControl = (msg) => { prev?.(msg); listener(msg); };
 * ```
 *
 * The matching `cleanup()` handled `removeControlListener` and
 * `_controlListeners` and did nothing at all for this branch. So every
 * `discover()` / `call()` / `list()` left another wrapper permanently in
 * the chain. Measured against a real `WshTransport`, the number of frames
 * an inbound control message traverses to reach the connection's own
 * handler grew one-for-one with the number of operations — 1, 5, 20 and
 * 50 operations gave 5, 9, 24 and 54 frames — with no ceiling.
 *
 * Attaching once per subscriber and detaching on cleanup keeps that flat.
 */

/**
 * Subscribe `listener` to a client's inbound control messages.
 *
 * Supports, in order of preference:
 *  1. `addControlListener()` / `removeControlListener()` — what `WshClient`
 *     exposes, and the only shape that can deregister cleanly.
 *  2. A `_controlListeners` array.
 *  3. A settable `onControl` property (a bare `WshTransport`), wrapped
 *     once and restored on detach.
 *
 * @param {object} client
 * @param {function(object): void} listener
 * @returns {function(): void} detach — idempotent; safe to call twice.
 */
export function attachControlListener(client, listener) {
  if (typeof client.addControlListener === 'function') {
    client.addControlListener(listener);
    let detached = false;
    return () => {
      if (detached) return;
      detached = true;
      client.removeControlListener?.(listener);
    };
  }

  if (Array.isArray(client._controlListeners)) {
    client._controlListeners.push(listener);
    let detached = false;
    return () => {
      if (detached) return;
      detached = true;
      const idx = client._controlListeners.indexOf(listener);
      if (idx !== -1) client._controlListeners.splice(idx, 1);
    };
  }

  // Fallback: wrap `onControl`. Restoring `prev` is only correct while our
  // wrapper is still the installed handler — if something else has wrapped
  // it since, putting `prev` back would drop that handler. In that case the
  // wrapper stays but is made inert, so the chain stops growing per
  // operation even though this one link cannot be spliced out.
  const prev = client.onControl;
  let live = true;
  const wrapper = (msg) => {
    prev?.(msg);
    if (live) listener(msg);
  };
  client.onControl = wrapper;

  let detached = false;
  return () => {
    if (detached) return;
    detached = true;
    live = false;
    if (client.onControl === wrapper) client.onControl = prev;
  };
}

/**
 * Wait for the first inbound control message matching `predicate`.
 *
 * @param {object} client
 * @param {function(object): boolean} predicate
 * @param {number} timeoutMs
 * @param {string} label - Used in the timeout message.
 * @returns {Promise<object>}
 */
export function waitForControlMessage(client, predicate, timeoutMs, label) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let detach = () => {};
    let timer = null;

    const cleanup = () => {
      settled = true;
      if (timer !== null) clearTimeout(timer);
      detach();
    };

    // `detach` is assigned after attach() returns, but a client that
    // dispatches synchronously from inside attach() would fire the
    // listener first — hence the `settled` guard rather than relying on
    // detach() having been wired up.
    detach = attachControlListener(client, (msg) => {
      if (settled) return;
      let matches = false;
      try {
        matches = predicate(msg);
      } catch {
        matches = false;
      }
      if (!matches) return;
      cleanup();
      resolve(msg);
    });

    timer = setTimeout(() => {
      if (settled) return;
      cleanup();
      reject(new Error(`${label} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
}
