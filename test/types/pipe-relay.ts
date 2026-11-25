/**
 * Type-only fixture for the pipe relay's single-use ids and close reasons (#240).
 */
import { createPipeRelay, PIPE_CLOSE_REASONS } from '@johnhenry/wsh/pipe-relay';

const relay = createPipeRelay({ retirePaired: true, maxRetired: 5000 });
const stats: { waiting: number; pipes: number; retired: number } = relay.stats();
void stats;

const reason: 'rendezvous id already used' = PIPE_CLOSE_REASONS.idRetired;
const peer: 'peer closed' = PIPE_CLOSE_REASONS.peerClosed;
void reason; void peer;

// @ts-expect-error -- retirePaired is a boolean
createPipeRelay({ retirePaired: 'yes' });
// @ts-expect-error -- the list is read only
PIPE_CLOSE_REASONS.idle = 'quiet';
