// Helper for test/forward-endpoint.test.mjs: listen on the unix socket named by argv[2], then die without cleaning up,
// which leaves a stale socket file behind (nothing listening on it).
import net from 'node:net';

net.createServer().listen(process.argv[2], () => process.kill(process.pid, 'SIGKILL'));
