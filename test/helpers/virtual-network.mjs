// A virtual network for the gateway tests: a map of "address:port" to a handler, names that resolve to addresses, UDP echoes and
// listeners the test can connect to. Browser-safe (no `node:*`), so the same network backs the Node tests and the browser spec.
//
// It is the network a `createMemoryHost({ gateway: { network } })` embedder would write for its own world: it records every call
// it gets (what was resolved, what address was dialled, which signal it was given) so a test can say what wsh did NOT call.

/** A service handler gets `{ readable, writable, address, port, signal }`: the far end of the connection, as a server would. */
export function createVirtualNetwork({ services = {}, names = {}, udp = {}, methods = ['connectTcp', 'resolve', 'openUdp', 'listenTcp'] } = {}) {
  const calls = { connect: [], resolve: [], udp: [], listen: [] };
  /** One record per connection / flow the network handed out: what became of it. */
  const conns = [];
  const listeners = new Map();
  const table = new Map(Object.entries(services));
  const nameTable = new Map(Object.entries(names));
  const udpTable = new Map(Object.entries(udp));

  const fail = (code, message) => Object.assign(new Error(message), { code });

  /** Two byte pipes: what the caller writes the service reads, and the other way. Both observable. */
  function connection(signal, info) {
    const rec = { ...info, clientAborted: false, serviceCancelled: false, clientClosed: false, signalAborted: false, bytesToService: 0, bytesToCaller: 0 };
    conns.push(rec);
    const toService = new TransformStream();
    const toCaller = new TransformStream();
    signal?.addEventListener('abort', () => { rec.signalAborted = true; }, { once: true });
    const wsw = toService.writable.getWriter();
    const callerSide = {
      readable: new ReadableStream({
        start(c) { this.r = toCaller.readable.getReader(); void c; },
        async pull(c) { const { value, done } = await this.r.read(); if (done) c.close(); else c.enqueue(value); },
        cancel(reason) { rec.serviceCancelled = true; return this.r.cancel(reason); },
      }, { highWaterMark: 0 }),
      writable: new WritableStream({
        async write(chunk) { rec.bytesToService += chunk.byteLength; await wsw.write(chunk); },
        async close() { rec.clientClosed = true; await wsw.close(); },
        async abort(reason) { rec.clientAborted = true; await wsw.abort(reason); },
      }),
    };
    const serviceSide = { readable: toService.readable, writable: toCaller.writable };
    return { rec, callerSide, serviceSide };
  }

  const network = {};
  if (methods.includes('connectTcp')) {
    network.connectTcp = async ({ host, port, signal }) => {
      calls.connect.push({ host, port, signal });
      const handler = table.get(`${host}:${port}`);
      if (!handler) throw fail('ECONNREFUSED', `nothing listens on ${host}:${port}`);
      const { rec, callerSide, serviceSide } = connection(signal, { kind: 'tcp', host, port });
      void Promise.resolve(handler({ ...serviceSide, address: host, port, signal, rec })).catch(() => {});
      return callerSide;
    };
  }
  if (methods.includes('resolve')) {
    network.resolve = async ({ name, family, signal }) => {
      calls.resolve.push({ name, family, signal });
      const answer = nameTable.get(name);
      if (!answer) throw fail('ENOTFOUND', `no such name ${name}`);
      return typeof answer === 'function' ? answer({ name, family }) : answer;
    };
  }
  if (methods.includes('openUdp')) {
    network.openUdp = async ({ host, port, signal }) => {
      calls.udp.push({ host, port, signal });
      const handler = udpTable.get(`${host}:${port}`);
      if (!handler) throw fail('ECONNREFUSED', `no UDP service on ${host}:${port}`);
      const { rec, callerSide, serviceSide } = connection(signal, { kind: 'udp', host, port });
      void Promise.resolve(handler({ ...serviceSide, address: host, port, signal, rec })).catch(() => {});
      return callerSide;
    };
  }
  if (methods.includes('listenTcp')) {
    network.listenTcp = async ({ port, bindAddr, signal, onConnection }) => {
      const actual = port === 0 ? 40000 + listeners.size : port;
      calls.listen.push({ port, bindAddr, signal });
      const entry = { port: actual, bindAddr, closed: false, onConnection, signal };
      listeners.set(actual, entry);
      return { port: actual, close: async () => { entry.closed = true; listeners.delete(actual); } };
    };
  }

  return {
    network,
    calls,
    conns,
    listeners,
    services: table,
    names: nameTable,
    udpServices: udpTable,
    /** Someone on the virtual network connects to a listener wsh opened for the caller. Resolves with the far end. */
    connectTo(port, peer = { address: '10.0.0.9', port: 5555 }) {
      const entry = listeners.get(port);
      if (!entry || entry.closed) throw fail('ECONNREFUSED', `nothing listens on ${port}`);
      const ac = new AbortController();
      const { rec, callerSide, serviceSide } = connection(ac.signal, { kind: 'inbound', port });
      // The listener side gets the near end (what the host reads and writes); the connector keeps the far end.
      entry.onConnection(callerSide, { peerAddr: peer.address, peerPort: peer.port });
      return { ...serviceSide, rec };
    },
  };
}

export const echoService = async ({ readable, writable }) => { try { await readable.pipeTo(writable); } catch { /* the caller went away */ } };

/** Reads everything until the end of the stream. */
export async function readAll(readable) {
  const reader = readable.getReader();
  const parts = [];
  let n = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    parts.push(value);
    n += value.byteLength;
  }
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.byteLength; }
  return out;
}

export function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.byteLength, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.byteLength; }
  return out;
}
