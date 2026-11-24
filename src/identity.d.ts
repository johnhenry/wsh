/**
 * `@johnhenry/wsh/identity`: a key's identity in its spellings (raw 32-byte key, OpenSSH `ssh-ed25519` line, hex fingerprint, base64url
 * pod id), and a builder of `authorized_keys` lines that refuses unsafe input. Browser-safe (no Node import); a stable entry point.
 */

/** Who a call is from, whatever carried it: a login name and a key (over wsh), or a pod id (over a mesh). The key's two names are one hash. */
export interface WshIdentity {
  username: string | null;
  /** 64 lower-case hex digits: the SHA-256 of the caller's raw public key. `null` for a caller with no key. */
  fingerprint: string | null;
  /** 43 base64url characters: the same hash. Derived from `fingerprint` when only that is known, and the other way round. */
  podId: string | null;
}

/** SHA-256 of a raw Ed25519 public key, as 64 lower-case hex digits. */
export function fingerprint(publicKeyRaw: Uint8Array): Promise<string>;
/** SHA-256 of a raw Ed25519 public key, as 43 base64url characters (BrowserMesh's pod id). */
export function podId(publicKeyRaw: Uint8Array): Promise<string>;
/** Convert a fingerprint (exactly 64 hex digits, either case) to a pod id. Throws a `TypeError` for anything else. */
export function fingerprintToPodId(hexFingerprint: string): string;
/** Convert a pod id (exactly 43 base64url characters, canonical spelling) to a fingerprint. Throws a `TypeError` for anything else. */
export function podIdToFingerprint(podIdStr: string): string;

/** The OpenSSH `ssh-ed25519` line of a raw 32-byte public key (`comment`: no control character or line break). */
export function rawKeyToOpenSsh(raw: Uint8Array, comment?: string): string;
/** The OpenSSH `ssh-ed25519` line of a public `CryptoKey`. */
export function publicKeyToOpenSsh(publicKey: CryptoKey, comment?: string): Promise<string>;
/** Read a plain `ssh-ed25519 <base64> [comment]` line. Refuses options in front, other key types, trailing bytes, more than one line. */
export function parseOpenSshKey(line: string): { raw: Uint8Array; comment: string };
/** The raw 32-byte public key of an OpenSSH `ssh-ed25519` line. */
export function openSshToRawKey(line: string): Uint8Array;

/** One key in every spelling. */
export function identityOf(key: Uint8Array | string | CryptoKey): Promise<{ raw: Uint8Array; fingerprint: string; podId: string; openssh: string }>;

/**
 * An identity as `{ username, fingerprint, podId }`: whichever of `fingerprint` and `podId` is given, the other is derived. Throws a
 * `TypeError` for an identity that names two keys or is malformed (`strict: false` keeps a `fingerprint` that is not a key hash).
 */
export function normalizeIdentity(
  who: { username?: string | null; fingerprint?: string | null; podId?: string | null } | null | undefined,
  options?: { strict?: boolean },
): WshIdentity;

export interface AuthorizedKeyLineOptions {
  /** The capabilities the key holds (`spec/capabilities.md`); `[]` for a key that may do nothing. Required unless `allowFullAccess`. */
  capabilities?: string[] | string;
  /** When the key stops working: an RFC 3339 string, a `Date` or epoch milliseconds. Written in UTC. */
  expires?: string | Date | number;
  /** Written after the key; no control character or line break. */
  comment?: string;
  /** Say it out loud: a line with no capability list is a key that may do everything. Contradicts `capabilities`. */
  allowFullAccess?: boolean;
}

/**
 * A line for an `authorized_keys` file, read back through the host's own parser before it is returned. Throws a `TypeError` for a
 * capability that is not in the notation, a malformed expiry, a comment that could start another line, a key that is not a plain
 * Ed25519 key, or an option it does not write.
 */
export function authorizedKeyLine(key: Uint8Array | string, options: AuthorizedKeyLineOptions): string;
