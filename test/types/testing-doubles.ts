/** Type-only fixture for #220: the test doubles of `@johnhenry/wsh/testing`. Run by `npm run typecheck`. */
import { createInProcessPipeRelay, createMemoryPair, QMUX_TESTING_API } from '@johnhenry/wsh/testing';
import { pipeUrl } from '@johnhenry/wsh/pipe-relay';

export async function doubles(): Promise<void> {
  const env = await createInProcessPipeRelay({ tap: ({ to, id, bytes }) => (to === 'host' && id.length > 0 && bytes.byteLength > 1 ? null : undefined) });
  const socket = new env.WebSocket(pipeUrl('ws://relay.test', 'x'.repeat(22), 'host'));
  const counts: { waiting: number; pipes: number } = env.stats();
  env.dropAll();
  env.tap = null;
  await env.close();
  const pair = await createMemoryPair({ host: { exec: async () => 0 }, username: 'alice' });
  const state: string = pair.client.state;
  await pair.close();
  const stable: false = QMUX_TESTING_API.stable;
  void [socket, counts, state, stable, env.recorded[0]?.to];
}
