// Helper for the unix socket cleanup tests: another process that listens on the unix socket named by argv[2], answers every
// connection with "other" and stays up until its stdin closes. It writes "ready" to stdout once it is listening.
import net from 'node:net';

const server = net.createServer((c) => { c.on('error', () => {}); c.end('other'); });
server.listen(process.argv[2], () => process.stdout.write('ready\n'));
process.stdin.resume();
process.stdin.on('end', () => process.exit(0));
