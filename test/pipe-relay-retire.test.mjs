// test/pipe-relay-retire.test.mjs -- #240: `retirePaired` makes a rendezvous id single-use. Off (the default), an id can be used again
// once its pipe paired, which a page host that redials relies on (README, createPageHost `reconnect`); on, the id is remembered in a
// bounded set and a later arrival is refused.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createPipeRelay, newRendezvousId } from '@johnhenry/wsh/pipe-relay';

/** A stand-in socket: records what it was sent and told. */
function fake() {
  const s = Object.assign(new EventEmitter(), {
    readyState: 1, bufferedAmount: 0, sent: [], closedWith: null,
    send(d) { s.sent.push(d); },
    close(code, reason) { s.closedWith = [code, reason]; s.readyState = 3; },
  });
  return s;
}

/** Pair a host and an operator on `id`. */
async function pairOn(relay, id) {
  const host = fake(); const op = fake();
  assert.equal(await relay.accept(host, { id, role: 'host' }), true);
  assert.equal(await relay.accept(op, { id, role: 'operator' }), true);
  return { host, op };
}

describe('pipe relay: retiring a paired id (#240)', () => {
  it('by default an id can be used again once it paired (what a redialling page host relies on)', async () => {
    const relay = createPipeRelay();
    const id = newRendezvousId();
    const first = await pairOn(relay, id);
    first.op.emit('close', 1000); // the operator leaves; the pipe ends
    const again = fake();
    assert.equal(await relay.accept(again, { id, role: 'host' }), true, 'the host dials the same id again and waits');
    assert.equal(again.closedWith, null);
    assert.equal(relay.stats().waiting, 1);
    const next = fake();
    assert.equal(await relay.accept(next, { id, role: 'operator' }), true, 'and a second operator pairs with it');
    assert.equal(relay.stats().pipes, 1);
    assert.equal(relay.stats().retired, 0, 'nothing is remembered');
    await relay.close();
  });

  it('retirePaired: a third arrival is refused while the pipe lives, and after it ended', async () => {
    const relay = createPipeRelay({ retirePaired: true });
    const id = newRendezvousId();
    const { host, op } = await pairOn(relay, id);
    const third = fake();
    assert.equal(await relay.accept(third, { id, role: 'host' }), false);
    assert.deepEqual(third.closedWith, [1008, 'rendezvous id already used']);
    assert.equal(relay.stats().waiting, 0, 'it did not wait as a new half');
    op.emit('close', 1000);
    assert.ok(host.closedWith, 'the pipe ended');
    for (const role of ['host', 'operator']) {
      const late = fake();
      assert.equal(await relay.accept(late, { id, role }), false);
      assert.deepEqual(late.closedWith, [1008, 'rendezvous id already used']);
    }
    assert.equal(relay.stats().waiting, 0);
    assert.equal(relay.stats().retired, 1);
    await relay.close();
  });

  it('retirePaired: an id that never paired is not retired (a half that timed out or left can dial again)', async () => {
    const relay = createPipeRelay({ retirePaired: true });
    const id = newRendezvousId();
    const a = fake();
    assert.equal(await relay.accept(a, { id, role: 'host' }), true);
    a.emit('close', 1001);
    const b = fake();
    assert.equal(await relay.accept(b, { id, role: 'host' }), true);
    assert.equal(relay.stats().retired, 0);
    await relay.close();
  });

  it('retirePaired: the set is bounded by maxRetired; the oldest id is forgotten first', async () => {
    const relay = createPipeRelay({ retirePaired: true, maxRetired: 3 });
    const ids = [1, 2, 3, 4].map(() => newRendezvousId());
    for (const id of ids) await pairOn(relay, id);
    assert.equal(relay.stats().retired, 3, 'never more than the bound');
    const oldest = fake();
    assert.equal(await relay.accept(oldest, { id: ids[0], role: 'host' }), true, 'the oldest was forgotten, so it is usable again (documented)');
    for (const id of ids.slice(1)) {
      const s = fake();
      assert.equal(await relay.accept(s, { id, role: 'host' }), false, 'the newer three are still retired');
      assert.equal(s.closedWith[1], 'rendezvous id already used');
    }
    await relay.close();
  });

  it('retirePaired: the check runs after authorize, so a refused half does not learn whether an id was used, and authorize still counts the attempt', async () => {
    let calls = 0; let allow = true;
    const relay = createPipeRelay({ retirePaired: true, authorize: () => { calls++; return allow; } });
    const id = newRendezvousId();
    await pairOn(relay, id);
    assert.equal(calls, 2);
    allow = false;
    const refused = fake();
    assert.equal(await relay.accept(refused, { id, role: 'host' }), false);
    assert.deepEqual(refused.closedWith, [1008, 'not permitted'], 'a caller authorize refuses is told only that');
    allow = true;
    const retired = fake();
    assert.equal(await relay.accept(retired, { id, role: 'host' }), false);
    assert.deepEqual(retired.closedWith, [1008, 'rendezvous id already used']);
    assert.equal(calls, 4, 'authorize saw both attempts');
    await relay.close();
  });

  it('refuses a retirePaired that is not a boolean and a maxRetired that is not a positive integer', () => {
    assert.throws(() => createPipeRelay({ retirePaired: 'yes' }), /retirePaired must be a boolean/);
    for (const bad of [0, -1, 1.5, Number.NaN, '5']) assert.throws(() => createPipeRelay({ retirePaired: true, maxRetired: bad }), /maxRetired must be a positive integer/);
  });

  it('maxRetired alone does nothing, and costs no memory when retirePaired is off', async () => {
    const relay = createPipeRelay({ maxRetired: 2 });
    for (let i = 0; i < 4; i++) await pairOn(relay, newRendezvousId());
    assert.equal(relay.stats().retired, 0);
    await relay.close();
  });
});
