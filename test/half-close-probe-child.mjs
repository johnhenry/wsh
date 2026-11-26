// The local program of test/half-close-probe.test.mjs, started as a child process so the test can SIGKILL it by pid.
//
//   client unix|tcp TARGET [paused]   connects, sends one byte, half-closes (FIN, still reading) and says "half-closed";
//                                     then reads and says "got N" (N = bytes so far) per chunk and "end" at the far side's end.
//                                     "paused": it never reads, so what the far side sends sits unread in the kernel (a close
//                                     with unread data is a reset on TCP).
//   server unix|tcp [PATH] [paused]   listens (TCP on 127.0.0.1, port chosen; says "listening PORT" / "listening PATH"), and on
//                                     each connection half-closes at once (an origin that finished) and says "accepted";
//                                     it then only reads ("paused": not even that).
import net from 'node:net';

const [role, kind, target, flag] = process.argv.slice(2);
const say = (s) => process.stdout.write(`${s}\n`);
const paused = flag === 'paused' || target === 'paused';

if (role === 'client') {
  const sock = kind === 'unix'
    ? net.connect({ path: target, allowHalfOpen: true })
    : net.connect({ host: '127.0.0.1', port: Number(target), allowHalfOpen: true });
  sock.on('error', () => {});
  let got = 0;
  sock.on('data', (d) => { got += d.length; say(`got ${got}`); });
  sock.on('end', () => say('end'));
  sock.on('connect', () => { sock.end('x', () => say('half-closed')); });
  if (paused) sock.pause();
} else {
  const server = net.createServer({ allowHalfOpen: true }, (s) => {
    s.on('error', () => {});
    s.end(() => say('accepted'));
    if (paused) s.pause(); else s.resume();
  });
  if (kind === 'unix') server.listen(target, () => say(`listening ${target}`));
  else server.listen(0, '127.0.0.1', () => say(`listening ${server.address().port}`));
}
setInterval(() => {}, 1 << 30);
