/**
 * Type-only fixture for the identity surface (#117, #118, #119, #125, #126): the host options, the operator's
 * `reverseConnect` options, channel binding and the pipe relay's entry point.
 */
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { WshClient, SealedBridge, computeChannelBinding, OPERATOR_PROOF_FEATURE, type WshChannelBindingKind } from '@johnhenry/wsh';

createWshServer({
  connectionTtlMs: 60_000,
  requireChannelBinding: ['host', 'tls-exporter'],
  exec: { clientEnv: ['TERM', 'LC_*'] },
  pty: { spawn: (() => { throw new Error('type fixture'); }) as never, clientEnv: (name) => name === 'TERM' },
});

createReverseHost({
  url: 'wss://relay', username: 'host', keyPair: {} as CryptoKeyPair,
  requireOperatorProof: true, proofTimeoutMs: 2000,
  accept: ({ fingerprint, username, proven, publicKey }) => proven && publicKey instanceof Uint8Array && fingerprint.length > 0 && username.length > 0,
});

async function operator(client: WshClient): Promise<void> {
  await client.connect('wss://host', { username: 'alice', requireChannelBinding: true });
  const kinds: WshChannelBindingKind[] = client.channelBinding;
  const ttl: number = client.authTtl;
  await client.reverseConnect('abcdef012345', 5000, { sealed: { hybrid: false }, requirePeerProof: true, proof: 'auto' });
  void kinds; void ttl;
}

const relay = createPipeRelay({ maxWaiting: 8, authorize: ({ role }) => role === 'host' });
const id: string = newRendezvousId();
const url: string = pipeUrl('wss://relay.example', id, 'host');
void relay.listen({ port: 0 }); void url; void operator; void SealedBridge; void computeChannelBinding; void OPERATOR_PROOF_FEATURE;

// The browser-safe hosts: the same identity options, with `clientEnv` typed as the list / predicate it is.
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createReverseHost as createBrowserReverseHost } from '@johnhenry/wsh/reverse';

createMemoryHost({
  hostKey: true, connectionTtlMs: 60_000, requireChannelBinding: ['host'],
  exec: { run: async () => 0, clientEnv: ['TERM', 'LC_*'] },
});
createMemoryHost({ exec: { run: async () => 0, clientEnv: (name: string, value: string) => name === 'TERM' && value.length < 32 } });
createBrowserReverseHost({
  url: 'wss://relay', username: 'host', keyPair: {} as CryptoKeyPair, requireOperatorProof: true,
  exec: { run: async () => 0, clientEnv: true },
  accept: ({ proven, publicKey }) => proven === true && publicKey instanceof Uint8Array,
});
