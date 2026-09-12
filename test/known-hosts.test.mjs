// test/known-hosts.test.mjs — WshKnownHosts (wsh #59).
//
// Mirrors crates/wsh-client/src/known_hosts.rs's own test suite
// (unknown_host, add_and_verify_known, detect_changed_fingerprint,
// update_host, remove_host, list_hosts) so the two implementations are
// checked against the same behavioral contract, not just typechecked
// independently.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WshKnownHosts } from '../src/known-hosts.mjs';

/** In-memory Storage-shaped backend, isolated per test (no shared global state). */
class FakeStorage {
  #map = new Map();
  getItem(key) { return this.#map.has(key) ? this.#map.get(key) : null; }
  setItem(key, value) { this.#map.set(key, value); }
  removeItem(key) { this.#map.delete(key); }
}

function freshKnownHosts() {
  return new WshKnownHosts({ storage: new FakeStorage() });
}

describe('WshKnownHosts', () => {
  it('unknown host', () => {
    const kh = freshKnownHosts();
    assert.deepEqual(kh.verifyHost('example.com', 'abc123'), { status: 'unknown' });
  });

  it('add and verify known', () => {
    const kh = freshKnownHosts();
    kh.addHost('example.com', 'abc123');
    assert.deepEqual(kh.verifyHost('example.com', 'abc123'), { status: 'known' });
  });

  it('detects a changed fingerprint', () => {
    const kh = freshKnownHosts();
    kh.addHost('example.com', 'abc123');
    assert.deepEqual(kh.verifyHost('example.com', 'def456'), { status: 'changed', expected: 'abc123' });
  });

  it('update host', () => {
    const kh = freshKnownHosts();
    kh.addHost('example.com', 'abc123');
    kh.addHost('example.com', 'def456');
    assert.deepEqual(kh.verifyHost('example.com', 'def456'), { status: 'known' });
  });

  it('remove host', () => {
    const kh = freshKnownHosts();
    kh.addHost('example.com', 'abc123');
    assert.equal(kh.removeHost('example.com'), true);
    assert.deepEqual(kh.verifyHost('example.com', 'abc123'), { status: 'unknown' });
  });

  it('removing a host that was never added returns false', () => {
    const kh = freshKnownHosts();
    assert.equal(kh.removeHost('never-added.example.com'), false);
  });

  it('list hosts', () => {
    const kh = freshKnownHosts();
    kh.addHost('host1.com', 'fp1');
    kh.addHost('host2.com', 'fp2');
    const list = kh.list();
    assert.equal(list.length, 2);
    assert.deepEqual(
      list.sort((a, b) => a.host.localeCompare(b.host)),
      [{ host: 'host1.com', fingerprint: 'fp1' }, { host: 'host2.com', fingerprint: 'fp2' }],
    );
  });

  it('persists across instances sharing the same storage backend', () => {
    const storage = new FakeStorage();
    const first = new WshKnownHosts({ storage });
    first.addHost('example.com', 'abc123');

    const second = new WshKnownHosts({ storage });
    assert.deepEqual(second.verifyHost('example.com', 'abc123'), { status: 'known' });
  });

  it('defaults to an isolated in-memory store when no storage is injected and localStorage is unavailable', () => {
    // This Node test environment has no global `localStorage`, so the
    // default-storage fallback path is exercised here for free.
    const a = new WshKnownHosts();
    const b = new WshKnownHosts();
    a.addHost('example.com', 'abc123');
    // Distinct instances must not share state through the fallback.
    assert.deepEqual(b.verifyHost('example.com', 'abc123'), { status: 'unknown' });
  });

  it('a corrupted storage value is treated as empty rather than throwing', () => {
    const storage = new FakeStorage();
    storage.setItem('wsh:known-hosts:v1', 'not valid json{{{');
    const kh = new WshKnownHosts({ storage });
    assert.deepEqual(kh.verifyHost('example.com', 'abc123'), { status: 'unknown' });
    // And it should still be writable afterward.
    kh.addHost('example.com', 'abc123');
    assert.deepEqual(kh.verifyHost('example.com', 'abc123'), { status: 'known' });
  });
});
