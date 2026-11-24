/**
 * `@johnhenry/wsh/duplex` -- a full wsh session over a duplex that someone else provides (#220): a mesh channel, a `MessagePort`, a data
 * channel, anything that can carry bytes in order. Browser-safe. The specification, with what the duplex must guarantee and what a hop on it can
 * and cannot do, is `spec/duplex-binding.md`; this file is the binding.
 *
 * ```js
 * // the host side (a page, a pod): a memory host with a host key, served over the link
 * const host = createMemoryHost({ auth: { authorizedKeys }, hostKey: true, dataStreams: false, exec });
 * const served = serveWshOverDuplex(host, { send: (bytes) => channel.send(bytes) });
 * channel.onmessage = (bytes) => served.receive(bytes);
 *
 * // the client side: pinned to the host key it expects (a mesh knows the peer's key), sealed
 * const link = connectWshOverDuplex({ send: (bytes) => channel.send(bytes) }, { username: 'alice', keyPair, expectHostKey });
 * channel.onmessage = (bytes) => link.receive(bytes);
 * const client = await link.connected;
 * ```
 *
 * Nothing new is on the wire: the duplex carries what a WebSocket would (QMux records), and `createDuplexSocket` is the WebSocket-shaped
 * object the existing transport and `host.accept` already take. A session over it is SEALED unless you say `allowUnsealed: true` out loud.
 */

import { WshClient } from './client.mjs';
import { WebSocketTransport } from './transport-ws.mjs';

const CONNECTING = 0;
const OPEN = 1;
const CLOSING = 2;
const CLOSED = 3;

/** Largest message handed to `send` unless the duplex says otherwise: what the pipe relay carries by default is 4 MiB; a mesh channel is far smaller. */
export const DUPLEX_DEFAULT_MAX_MESSAGE_BYTES = 64 * 1024;
/** Bytes held for a duplex whose `send` has not finished before the link is dropped (a peer that does not read). */
export const DUPLEX_DEFAULT_MAX_BUFFERED_BYTES = 4 * 1024 * 1024;

const toBytes = (data) => {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return null;
};

class DuplexEvent extends Event {
  constructor(type, init = {}) { super(type); Object.assign(this, init); }
}

/**
 * The WebSocket-shaped object over a duplex of messages.
 *
 * @param {object} options
 * @param {(bytes: Uint8Array) => void | Promise<void>} options.send writes ONE message to the far side. Messages must arrive reliably and in order. It may be
 *   asynchronous (it is waited for before the next is written, which is the backpressure) and a rejection or throw ends the link.
 * @param {(reason?: string) => void} [options.close] ends the underlying duplex
 * @param {number} [options.maxMessageBytes=65536] the largest message `send` is given (a bigger write is cut into messages of at most this size: the
 *   transport above reads a byte stream, so where the cuts fall does not matter) and the largest message `receive` accepts (a bigger one ends the link)
 * @param {number} [options.maxBufferedBytes=4194304] bytes waiting for `send`; over it the link is ended (a peer that does not read is not buffered for without bound)
 * @returns {{ socket: object, receive(data: Uint8Array | ArrayBuffer): void, end(reason?: string): void, readonly closed: boolean }}
 */
export function createDuplexSocket({ send, close, maxMessageBytes = DUPLEX_DEFAULT_MAX_MESSAGE_BYTES, maxBufferedBytes = DUPLEX_DEFAULT_MAX_BUFFERED_BYTES } = {}) {
  if (typeof send !== 'function') throw new TypeError('createDuplexSocket: send(bytes) is required');
  if (close !== undefined && typeof close !== 'function') throw new TypeError('createDuplexSocket: close must be a function');
  if (!Number.isSafeInteger(maxMessageBytes) || maxMessageBytes < 256) throw new TypeError('createDuplexSocket: maxMessageBytes must be a whole number of at least 256');
  if (!Number.isSafeInteger(maxBufferedBytes) || maxBufferedBytes < maxMessageBytes) throw new TypeError('createDuplexSocket: maxBufferedBytes must be a whole number of at least maxMessageBytes');

  const events = new EventTarget();
  let buffered = 0;
  let pending = Promise.resolve();
  let finished = false;

  const finish = (code, reason, { callClose = true } = {}) => {
    if (finished) return;
    finished = true;
    socket.readyState = CLOSED;
    if (callClose) { try { close?.(reason); } catch { /* the duplex is already gone */ } }
    events.dispatchEvent(new DuplexEvent('close', { code, reason, wasClean: code === 1000 }));
  };

  // A duplex is already up when the socket is made, but whoever uses the socket attaches its listeners a moment later (a client builds its
  // transport after some asynchronous steps). So `open` is told to a listener that arrives after it, and messages wait, in order, for the
  // first listener of `message`: nothing the far side said first (the host speaks first) is lost.
  let opened = false;
  let messageListeners = 0;
  const incoming = [];
  const flush = () => {
    if (!opened || messageListeners === 0) return;
    while (incoming.length && !finished) events.dispatchEvent(new DuplexEvent('message', { data: incoming.shift() }));
  };

  const socket = {
    CONNECTING, OPEN, CLOSING, CLOSED,
    readyState: CONNECTING,
    binaryType: 'arraybuffer',
    get bufferedAmount() { return buffered; },
    addEventListener: (type, fn, options) => {
      events.addEventListener(type, fn, options);
      if (type === 'open' && opened && !finished) queueMicrotask(() => { if (!finished) fn(new DuplexEvent('open')); });
      if (type === 'message') { messageListeners++; queueMicrotask(flush); }
    },
    removeEventListener: (type, fn) => events.removeEventListener(type, fn),
    send(data) {
      if (socket.readyState !== OPEN) throw new Error('WebSocket is not open');
      const bytes = toBytes(data);
      if (!bytes) return; // wsh frames are binary
      for (let at = 0; at < bytes.byteLength; at += maxMessageBytes) {
        const part = bytes.slice(at, at + maxMessageBytes);
        if (buffered + part.byteLength > maxBufferedBytes) { finish(1013, 'the duplex does not take what is written to it'); return; }
        buffered += part.byteLength;
        pending = pending.then(async () => {
          if (finished) return;
          try { await send(part); } catch { finish(1011, 'the duplex failed to send'); } finally { buffered -= part.byteLength; }
        });
      }
    },
    close(code = 1000, reason = '') { finish(code, reason); },
  };

  queueMicrotask(() => { if (finished) return; socket.readyState = OPEN; opened = true; events.dispatchEvent(new DuplexEvent('open')); flush(); });

  return {
    socket,
    /** One message from the far side. A message that is not bytes, or is larger than `maxMessageBytes`, ends the link. */
    receive(data) {
      if (finished) return;
      const bytes = toBytes(data);
      if (!bytes) { finish(1003, 'a message that is not bytes'); return; }
      if (bytes.byteLength > maxMessageBytes) { finish(1009, 'a message larger than maxMessageBytes'); return; }
      if (incoming.reduce((n, b) => n + b.byteLength, 0) + bytes.byteLength > maxBufferedBytes) { finish(1013, 'more arrived than the receiver takes'); return; }
      incoming.push(bytes.slice().buffer);
      queueMicrotask(flush); // in order, after `open`, once something listens
    },
    /** The duplex ended on its own (the peer left, the channel closed): the socket closes, `close` is not called back. */
    end(reason = 'the duplex ended') { finish(1006, reason, { callClose: false }); },
    get closed() { return finished; },
  };
}

/**
 * Serve a host's wsh session over a duplex: `host.accept(socket)` with `dataStreams: false` and the session SEALED, whatever the host's own
 * `sealSession` says (it can only be strengthened). The host needs a host key (`hostKey: ...`): with none it cannot seal, so it cannot serve a
 * duplex, and `ready` rejects. `host` is anything with `accept(socket, options)`: `createMemoryHost()`, `createWshServer()`.
 *
 * @param {{ accept(socket: object, options?: object): Promise<{ close(): void }> }} host
 * @param {object} options as `createDuplexSocket` (`send`, `close`, `maxMessageBytes`, `maxBufferedBytes`), and
 * @param {boolean} [options.allowUnsealed=false] serve a client that does not seal: nothing a hop does is then caught. Refused by default.
 * @param {object} [options.remote] what the host knows of the far side (`{ address }`, for its rate limiting of password failures)
 * @returns {{ receive(data: Uint8Array | ArrayBuffer): void, end(reason?: string): void, ready: Promise<{ close(): void }>, close(): void }}
 */
export function serveWshOverDuplex(host, { allowUnsealed = false, remote, ...duplexOptions } = {}) {
  if (typeof host?.accept !== 'function') throw new TypeError('serveWshOverDuplex: host must have accept(socket, options) (createMemoryHost(), createWshServer())');
  if (typeof allowUnsealed !== 'boolean') throw new TypeError('serveWshOverDuplex: allowUnsealed must be true or false');
  const link = createDuplexSocket(duplexOptions);
  const ready = Promise.resolve().then(() => host.accept(link.socket, {
    dataStreams: false,
    ...(allowUnsealed ? {} : { sealSession: 'require' }),
    ...(remote ? { remote } : {}),
  })).catch((e) => { link.socket.close(1011, 'this host cannot serve this duplex'); throw e; });
  ready.catch(() => {});
  return {
    receive: link.receive,
    end: link.end,
    ready,
    close() { link.socket.close(1000, 'closed'); },
  };
}

/**
 * Connect a wsh client over a duplex: the login is a key login, the session is SEALED, the login is bound to the host's key, and the host's key
 * must be named: a hop on the duplex that answers as a host of its own would otherwise be trusted on first use. Name it with `expectHostKey` (the
 * hex fingerprint; over a mesh it is the peer's pod id, `podIdToFingerprint(peer)`), or `knownHosts`, or say `trustOnFirstUse: true`.
 *
 * @param {object} duplex as `createDuplexSocket` (`send`, `close`, `maxMessageBytes`, `maxBufferedBytes`)
 * @param {object} credentials `{ username, keyPair | signer, expectHostKey | knownHosts | trustOnFirstUse, timeout, allowUnsealed }` and the other options of
 *   `WshClient.connect`; `allowUnsealed: true` (and `sealSession`, `requireChannelBinding`) set the guarantees down, out loud
 * @returns {{ receive(data: Uint8Array | ArrayBuffer): void, end(reason?: string): void, client: WshClient, connected: Promise<WshClient>, close(): Promise<void> }}
 */
export function connectWshOverDuplex(duplex, { allowUnsealed = false, ...credentials } = {}) {
  if (typeof allowUnsealed !== 'boolean') throw new TypeError('connectWshOverDuplex: allowUnsealed must be true or false');
  if (credentials.password !== undefined && !allowUnsealed) throw new TypeError('connectWshOverDuplex: a password login cannot be sealed (a hop would read it): use a key, or say allowUnsealed: true');
  if (credentials.expectHostKey === undefined && credentials.knownHosts === undefined && credentials.trustOnFirstUse !== true && credentials.onHostKey === undefined) {
    throw new TypeError('connectWshOverDuplex: name the host key you expect (expectHostKey: its hex fingerprint, over a mesh the peer\'s pod id converted with podIdToFingerprint), or knownHosts, or say trustOnFirstUse: true (a hop on the duplex could answer as the host)');
  }
  const link = createDuplexSocket(duplex);
  let used = false;
  // One duplex serves one connection: the constructor the transport calls hands back the socket made for it, once.
  function LinkSocket() {
    if (used) throw new Error('this duplex carries one connection and it is in use');
    used = true;
    return link.socket;
  }
  const client = new WshClient({
    transportFactories: {
      ws: () => new WebSocketTransport({ WebSocket: LinkSocket }),
      wt: () => { throw new Error('connectWshOverDuplex: a duplex is not WebTransport'); },
    },
  });
  const connected = client.connect('ws://duplex.invalid/', {
    transport: 'ws',
    ...(allowUnsealed ? {} : { sealSession: true, requireChannelBinding: ['host'] }),
    ...credentials,
  }).then(() => client);
  connected.catch(() => {});
  return {
    receive: link.receive,
    end: link.end,
    client,
    connected,
    close: () => client.disconnect(),
  };
}
