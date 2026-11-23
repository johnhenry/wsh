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
