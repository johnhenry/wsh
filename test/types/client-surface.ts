/**
 * Type-only fixture for the WshClient surface added in #240: `transportFactories` (and the keepalive options) on the constructor,
 * `close()`, `onClose(info)` and `closeInfo`.
 */
import { WshClient, WebSocketTransport, type WshCloseInfo, type WshClientOptions } from '@johnhenry/wsh';

const custom = new WshClient({
  transportFactories: { ws: () => new WebSocketTransport({ WebSocket: globalThis.WebSocket as never }), wt: () => new WebSocketTransport() },
  pingIntervalMs: 5000,
  pongTimeoutMs: 15000,
});
const opts: WshClientOptions = { transportFactories: { ws: () => new WebSocketTransport() } };
new WshClient(opts);
new WshClient();

// @ts-expect-error -- a factory builds a transport, not a number
new WshClient({ transportFactories: { ws: () => 1 } });
// @ts-expect-error -- only 'ws' and 'wt' are transport kinds
new WshClient({ transportFactories: { tcp: () => new WebSocketTransport() } });

async function lifecycle(client: WshClient): Promise<void> {
  client.onClose = (info) => {
    const code: number | null = info.code;
    const reason: string = info.reason;
    const clean: boolean = info.wasClean;
    const source: string = info.source;
    void code; void reason; void clean; void source;
  };
  client.onClose = () => {}; // a handler that ignores the argument still type-checks
  const why: WshCloseInfo | null = client.closeInfo;
  void why;
  await client.close();
  await client.disconnect();
  // @ts-expect-error -- closeInfo is read only
  client.closeInfo = null;
}
void custom; void lifecycle;
