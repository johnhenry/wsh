/**
 * What a host serves, built from injected parts only: no shell to spawn and no directory to read, so nothing here
 * imports from `node:*` and a browser host (`@johnhenry/wsh/memory`, `/reverse`, `/host`) can use it. The Node
 * server wraps it (`server/backends.mjs`) with the two backends that need Node: `exec: true` and `fs: { root }`.
 */

import { normalizePty } from './server/pty.mjs';
import { createMcpHost } from './server/mcp.mjs';
import { DEFAULT_MAX_FILE_BYTES } from './server/constants.mjs';
import { generateKeyPair, resolveSigner, fingerprint, exportPublicKeySSH, importPublicKeyRaw } from './auth.mjs';

/** The operations a file backend must have (`openRange` is optional: only the `wsh-fs` rpc built-in, which needs Node, reads it). */
const FILE_OPERATIONS = ['operate', 'readWhole', 'writeWhole', 'writeAt'];

/**
 * Validate a file backend: an object of operations, as `createFileAccess` (`@johnhenry/wsh/server`, confined to a
 * root directory) returns one. Paths arrive exactly as the client sent them -- confining them is the backend's job.
 *
 *  - `operate(op, path, { offset, length, newPath, data })` -> `{ metadata?, entries? }`, for the FileOp requests
 *    `list`, `stat`, `read`, `write`, `rename`, `mkdir`, `remove`
 *  - `readWhole(path)` -> `Uint8Array`  (a `download:` channel)
 *  - `writeWhole(path, bytes)`          (an `upload:` channel)
 *  - `writeAt(path, bytes, offset?, { mkdirs? })`
 *  - `maxFileBytes`                     (default 64 MiB)
 *
 * Throw an `Error` with `wsh: true` to have its message sent to the client as is; any other error is reported by its message too.
 *
 * @param {object} fs
 * @param {string} [who] - the option's name in error messages
 */
export function normalizeFileBackend(fs, who = 'fs') {
  if (!fs || typeof fs !== 'object') throw new TypeError(`${who} must be an object of file operations`);
  if (typeof fs.root === 'string' && typeof fs.operate !== 'function') {
    throw new TypeError(`${who}.root names a directory, which needs Node: use @johnhenry/wsh/server, or give ${who} as an object of operations ({ operate, readWhole, writeWhole, writeAt })`);
  }
  for (const name of FILE_OPERATIONS) {
    if (typeof fs[name] !== 'function') throw new TypeError(`${who}.${name} must be a function`);
  }
  if (fs.openRange !== undefined && typeof fs.openRange !== 'function') throw new TypeError(`${who}.openRange must be a function`);
  const maxFileBytes = fs.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1) throw new TypeError(`${who}.maxFileBytes must be a positive integer`);
  // Call through `fs` so a backend written with `this` keeps working.
  const files = {
    maxFileBytes,
    operate: (...a) => fs.operate(...a),
    readWhole: (...a) => fs.readWhole(...a),
    writeWhole: (...a) => fs.writeWhole(...a),
    writeAt: (...a) => fs.writeAt(...a),
  };
  if (fs.openRange) files.openRange = (...a) => fs.openRange(...a);
  return files;
}

/**
 * @param {{ exec?: Function | { run: Function }, pty?: { spawn: Function }, fs?: object, mcp?: object }} options
 * @returns {{ execRunner: Function | null, execOptions: object, pty: object | null, files: object | null, mcp: object | null }}
 */
export function resolveBackends({ exec, pty, fs, mcp } = {}) {
  let execRunner = null;
  let execOptions = {};
  if (typeof exec === 'function') {
    execRunner = exec;
  } else if (exec !== undefined && exec !== null && exec !== false) {
    if (typeof exec !== 'object' || typeof exec.run !== 'function') {
      throw new TypeError('exec must be a function run(command, io) or { run }: there is no shell to run `true` with here (use @johnhenry/wsh/server for that)');
    }
    execOptions = exec;
    execRunner = exec.run;
  }
  return {
    execRunner,
    execOptions,
    pty: pty ? normalizePty(pty) : null,
    files: fs ? normalizeFileBackend(fs) : null,
    mcp: mcp ? createMcpHost(mcp) : null,
  };
}

/**
 * The host's own identity (`ServerHello.host_fingerprint` and the host-key proof; see `host-key.mjs`), from what a page
 * can hold: a `CryptoKeyPair` (generate it with `generateKeyPair(false)` and the private key never leaves the browser),
 * or a signer `{ publicKey, sign(data) }` (`WshSigner`) when the key lives elsewhere (a hardware key, a Worker, an
 * HSM). `true` makes a fresh non-extractable key for this host (TOFU clients see "changed" next time: demos and tests).
 * The Node server's `hostKey` also takes `{ file }`.
 *
 * @returns {Promise<{ publicKey: Uint8Array, fingerprint: string, openssh: string, sign(data: Uint8Array): Promise<Uint8Array> }>}
 */
export async function resolveHostKey(option, who = 'hostKey') {
  if (option === true) option = await generateKeyPair(false);
  const isPair = option && typeof option === 'object' && option.privateKey && option.publicKey;
  const isSigner = option && typeof option === 'object' && typeof option.sign === 'function' && option.publicKey;
  if (!isPair && !isSigner) throw new TypeError(`${who} must be true, a CryptoKeyPair, or a signer { publicKey, sign(data) }`);
  const resolved = await resolveSigner(isPair ? { keyPair: option } : { signer: option });
  return {
    publicKey: resolved.publicKeyRaw,
    fingerprint: await fingerprint(resolved.publicKeyRaw),
    openssh: await exportPublicKeySSH(await importPublicKeyRaw(resolved.publicKeyRaw)),
    sign: resolved.sign,
  };
}
