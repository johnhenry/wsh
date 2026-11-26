// Helper for test/forward-endpoint.test.mjs: listen on the unix socket named by argv[2] the way a forward does (a private
// directory next to it, the socket hard-linked to its name), then die without cleaning up: what a crashed forward leaves.
import net from 'node:net';
import { listenUnixSocket } from '../src/unix-listen.mjs';

await listenUnixSocket(net.createServer(), process.argv[2]);
process.kill(process.pid, 'SIGKILL');
