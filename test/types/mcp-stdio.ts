/**
 * Type-only fixture for `@johnhenry/wsh/mcp-stdio` (wsh #127): the bridge behind `wsh-mcp`. Checked by `npm run typecheck`, not run.
 */
import { runMcpStdioBridge, loadIdentity, McpBridgeError, type McpStdioBridgeOptions } from '@johnhenry/wsh/mcp-stdio';

async function main(): Promise<void> {
  const signer = await loadIdentity('/keys/default.pem');
  const options: McpStdioBridgeOptions = { url: 'wss://host.example:4422', username: 'alice', signer, channel: 'mcp', reconnect: { attempts: 3 } };
  const status: number = await runMcpStdioBridge(options);
  const failed = new McpBridgeError('x', { exitCode: 2 });
  const exitCode: number = failed.exitCode;
  void [status, exitCode];
  // @ts-expect-error reconnect: true is not a policy (false or an object)
  await runMcpStdioBridge({ ...options, reconnect: true });
}
void main;
