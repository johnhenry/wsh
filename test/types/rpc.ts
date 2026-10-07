/** Type-only fixture for the typed RPC channel API (wsh #85), as documented in the README. */
import {
  WshClient, RpcChannel, RpcError, RPC_FEATURE, RPC_ERROR, rpcProtocolFeature, mcpClientTransport, parseRpcFeatures,
  type RpcContext, type RpcRequestPromise,
} from '@johnhenry/wsh';
import { createWshServer, mcpServerAdapter, type WshRpcHandler } from '@johnhenry/wsh/server';

async function client(wsh: WshClient) {
  const rpc: RpcChannel = await wsh.openRpc('mcp', { timeoutMs: 5000 });
  const call: RpcRequestPromise<{ tools: unknown[] }> = rpc.request('tools/list', {});
  const id: string | number = call.id;
  rpc.onProgress(id, (chunk) => void chunk);
  const result = await call;
  void result.tools;
  rpc.notify('notifications/initialized');
  rpc.onRequest('sampling/createMessage', async (params, ctx: RpcContext) => ({ params, id: ctx.id, aborted: ctx.signal.aborted }));
  const read = await rpc.request<{ size: number }>('read', { path: 'a' }, { onProgress: (c: Uint8Array) => void c.byteLength, timeoutMs: 1000 });
  void read.size;
  try { await rpc.request('x'); } catch (e) {
    if (e instanceof RpcError && e.code === RPC_ERROR.CANCELLED && e.reason === 'channel-closed') void e.data;
  }
  await rpc.close();
  const session = await wsh.openSession({ type: 'rpc', protocol: 'wsh-host' });
  void session.channelId;
  wsh.preferRpcFiles = false;
  void [RPC_FEATURE, rpcProtocolFeature('mcp'), parseRpcFeatures(wsh.features).protocols];
  void mcpClientTransport(rpc).onmessage;
}

const custom: WshRpcHandler = (channel, ctx) => {
  channel.onRequest('echo', (p, rctx) => { void rctx.progress('x'); return { p, user: ctx.user }; });
};
const server = createWshServer({
  rpc: { 'wsh-host': true, 'wsh-fs': { root: '/tmp', readOnly: true }, mcp: mcpServerAdapter({ connect: async () => {} }), custom },
  rpcMaxMessageBytes: 4096,
  rpcMaxInflight: 8,
});
void [client, server];
