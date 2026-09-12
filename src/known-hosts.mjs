/**
 * WshKnownHosts — trust-on-first-use (TOFU) host-identity store for the
 * browser SDK (wsh #59).
 *
 * ## Why this exists, and why it is not yet load-bearing
 *
 * wsh #59 asked for a decision on host identity: TOFU *policy* (when to
 * prompt, how long to trust) is legitimately per-implementation, but the
 * *host identity record* -- what a fingerprint covers, how it is computed,
 * what counts as "the same host" -- must not be invented twice. This class
 * mirrors Rust's `KnownHosts`/`HostStatus`
 * (`crates/wsh-client/src/known_hosts.rs`) in shape and semantics --
 * `verifyHost`/`addHost`/`removeHost`/`list`, keyed by a host label,
 * storing one fingerprint per host -- so the browser gets the same
 * mechanism rather than a second, differently-shaped answer arrived at
 * later under pressure.
 *
 * What it pins is `ServerHello.host_fingerprint` (spec/wsh-v1.yaml, added
 * by this same change): the server's own persistent Ed25519 host-identity
 * key, SHA-256-fingerprinted the same way `fingerprint()` in `auth.mjs`
 * already fingerprints user/peer keys. That field is new spec surface,
 * not new server behavior -- no `wsh-server` release populates it yet.
 * Minting and persisting a server host keypair is a separate,
 * security-sensitive feature this change does not implement (see the
 * wsh #59 PR description for the full reasoning). Until a server
 * populates it, `verifyHost()` has nothing authoritative to check for any
 * real deployment -- exactly the same degraded state Rust's own
 * `verify_host_key` is in today when it falls back to `fingerprints[0]`
 * (an authorized *client* key, not a host identity -- see that fallback's
 * comment in `client.rs`). This store does not paper over that; a caller
 * that gets `'unknown'` back from every real server today is seeing the
 * honest state of host verification in this protocol version, not a bug
 * in this class.
 *
 * The README's `serverCertificateHashes` pinning
 * (see "Pinning a Self-Signed Certificate") is a different mechanism: it
 * pins a certificate supplied *per connection*, decided by the caller in
 * advance -- it is not a persisted record of what a host presented last
 * time, so it does not already solve TOFU. `WshKnownHosts` is the
 * missing persisted-record half.
 *
 * ## Storage
 *
 * Pluggable (defaults to `localStorage` when available, else an
 * in-memory `Map` that does not survive a page reload) since "persist
 * trust across sessions" needs a browser storage API this package has
 * never assumed before. Pass `{ storage }` with a `getItem`/`setItem`/
 * `removeItem` interface (the `Storage` interface `localStorage`
 * already implements) to use IndexedDB-via-adapter, `sessionStorage`,
 * or anything else.
 */

const STORAGE_KEY = 'wsh:known-hosts:v1';

/** In-memory fallback storage, used when no persistent storage is available or injected. */
class MemoryStorage {
  #map = new Map();
  getItem(key) { return this.#map.has(key) ? this.#map.get(key) : null; }
  setItem(key, value) { this.#map.set(key, value); }
  removeItem(key) { this.#map.delete(key); }
}

function defaultStorage() {
  if (typeof localStorage !== 'undefined' && localStorage) return localStorage;
  return new MemoryStorage();
}

export class WshKnownHosts {
  #storage;
  #storageKey;

  /**
   * @param {object} [opts]
   * @param {{getItem: function, setItem: function, removeItem: function}} [opts.storage]
   *   Storage backend (defaults to `localStorage` if present, else an
   *   in-memory `Map` scoped to this instance).
   * @param {string} [opts.storageKey] - Override the storage key (useful
   *   for isolating multiple instances/tests under one storage backend).
   */
  constructor({ storage, storageKey = STORAGE_KEY } = {}) {
    this.#storage = storage || defaultStorage();
    this.#storageKey = storageKey;
  }

  /**
   * Verify a host's fingerprint against the stored record.
   *
   * @param {string} host - Host label (e.g. "example.com:4422")
   * @param {string} fingerprint - Hex SHA-256 fingerprint to check
   * @returns {{ status: 'known' | 'unknown' | 'changed', expected?: string }}
   */
  verifyHost(host, fingerprint) {
    const entries = this.#load();
    if (!(host in entries)) {
      return { status: 'unknown' };
    }
    if (entries[host] === fingerprint) {
      return { status: 'known' };
    }
    return { status: 'changed', expected: entries[host] };
  }

  /** Add or update a host's fingerprint. */
  addHost(host, fingerprint) {
    const entries = this.#load();
    entries[host] = fingerprint;
    this.#save(entries);
  }

  /** Remove a host entry. Returns true if an entry was removed. */
  removeHost(host) {
    const entries = this.#load();
    if (!(host in entries)) return false;
    delete entries[host];
    this.#save(entries);
    return true;
  }

  /** List all known hosts and their fingerprints. */
  list() {
    const entries = this.#load();
    return Object.entries(entries).map(([host, fingerprint]) => ({ host, fingerprint }));
  }

  #load() {
    const raw = this.#storage.getItem(this.#storageKey);
    if (!raw) return {};
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  #save(entries) {
    this.#storage.setItem(this.#storageKey, JSON.stringify(entries));
  }
}
