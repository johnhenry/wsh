// The local program of test/gateway-half-close-abort.test.mjs: connects to a unix socket path or a TCP port, sends a byte,
// half-closes, says "half-closed" on stdout and then only reads, until it is killed.
import net from 'node:net';

const [kind, target] = process.argv.slice(2);
const sock = kind === 'unix'
  ? net.connect({ path: target, allowHalfOpen: true })
  : net.connect({ host: '127.0.0.1', port: Number(target), allowHalfOpen: true });
sock.on('error', () => {});
sock.on('connect', () => { sock.end('x', () => { process.stdout.write('half-closed\n'); }); });
sock.resume();
setInterval(() => {}, 1 << 30);
