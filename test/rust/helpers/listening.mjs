// The port a `wsh-server` started with `--port 0` really got (#320).
//
// A test used to pick a free port (test/helpers/free-port.mjs) and pass it with `--port N`; the number could be taken between the
// check and the server's own bind, so the server either failed to start or, worse, a connection reached something else on that port.
// With `--port 0` the server binds first and, once both listeners (TCP for WebSocket, UDP for WebTransport) are bound, prints
//
//   listening on 0.0.0.0:<port>
//
// on stdout. That line is the readiness signal: nothing connects before it, and the port comes from it.
/** The port in `listening on 0.0.0.0:<port>` somewhere in `text` (a string, or an array of chunks), or null if it has not been printed yet. */
export function listeningPort(text) {
  const m = /listening on \S+:(\d+)/.exec(Array.isArray(text) ? text.join('') : String(text));
  return m ? Number(m[1]) : null;
}
