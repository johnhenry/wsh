// A port for a `wsh-server` a test starts. The server binds the SAME number twice: TCP for the WebSocket listener and UDP for the WebTransport
// one, both on 0.0.0.0. A port that was free for TCP only (what `net.createServer().listen(0)` shows) could be held for UDP by any other
// socket on the machine, and the server then exited with "WebTransport bind failed: Address already in use" (#248). So a port is chosen only
// when it can be bound for both, the way the server will.
//
// There is still a window between this check and the server's own bind (another process could take the port in it); it is the time it takes
// to start a process, and a port that fails there is a different, much rarer, failure than the one this removes.
import dgram from 'node:dgram';
import net from 'node:net';

const HOST = '0.0.0.0';

/** Whether `port` can be bound for TCP and for UDP right now (both are released again before this resolves). */
export async function portIsFree(port) {
  const tcp = await new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, HOST, () => s.close(() => resolve(true)));
  });
  if (!tcp) return false;
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    s.once('error', () => { try { s.close(); } catch { /* not open */ } resolve(false); });
    s.bind(port, HOST, () => s.close(() => resolve(true)));
  });
}

/** A port that is free for TCP and UDP. Candidates are what the operating system hands out for TCP; one that UDP holds is skipped. */
export async function freePort() {
  for (;;) {
    const port = await new Promise((resolve) => {
      const s = net.createServer().listen(0, HOST, () => { const { port: p } = s.address(); s.close(() => resolve(p)); });
    });
    if (await portIsFree(port)) return port;
  }
}
