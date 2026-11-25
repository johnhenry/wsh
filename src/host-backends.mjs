/**
 * What a host serves, built from injected parts only: no shell to spawn and no directory to read, so nothing here
 * imports from `node:*` and a browser host (`@johnhenry/wsh/memory`, `/reverse`, `/host`) can use it. The Node
 * server wraps it (`server/backends.mjs`) with the two backends that need Node: `exec: true` and `fs: { root }`.
 */

import { normalizePty } from './server/pty.mjs';
import { createMcpHost } from './server/mcp.mjs';
import { normalizeEndpoints } from './server/gateway-core.mjs';
import { DEFAULT_MAX_FILE_BYTES } from './server/constants.mjs';
import { RPC_PROTOCOL_NAME_RE } from './rpc.mjs';
import { generateKeyPair, resolveSigner, fingerprint, exportPublicKeySSH, importPublicKeyRaw } from './auth.mjs';
import { assertEd25519HostKey } from './host-key.mjs';

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
 * Validate an `rpc` option into the table the connection handler reads: `{ protocols, maxMessageBytes, maxInflight }`
 * (`createRpcHost` in `server/rpc.mjs` is this plus the Node-only built-ins). Handlers only: `wsh-host` and `wsh-fs` need Node.
 * @param {Record<string, Function | false | null | undefined>} rpc
 * @param {number} maxMessageBytes
 * @param {number} maxInflight
 * @param {string} [who] - the host's name in error messages
 */
export function createRpcTable(rpc, maxMessageBytes, maxInflight, who = 'createMemoryHost') {
  if (!rpc || typeof rpc !== 'object' || Array.isArray(rpc)) throw new TypeError(`${who}: rpc must be an object of { [protocol]: handler }`);
  if (!(maxMessageBytes >= 256)) throw new TypeError(`${who}: rpcMaxMessageBytes must be at least 256`);
  if (!Number.isSafeInteger(maxInflight) || maxInflight < 1) throw new TypeError(`${who}: rpcMaxInflight must be a positive integer`);
  const protocols = new Map();
  for (const [name, handler] of Object.entries(rpc)) {
    if (handler === undefined || handler === false || handler === null) continue;
    if (!RPC_PROTOCOL_NAME_RE.test(name)) throw new TypeError(`${who}: rpc protocol name ${JSON.stringify(name)} is not allowed (letters, digits, ".", "_", "-")`);
    if (typeof handler !== 'function') throw new TypeError(`${who}: rpc[${JSON.stringify(name)}] needs a handler function (channel, ctx) => void (the wsh-host / wsh-fs built-ins need Node; use @johnhenry/wsh/server)`);
    protocols.set(name, handler);
  }
  return { protocols, maxMessageBytes, maxInflight };
}

/** A target's name: what a client puts in `Open.target`. */
export const TARGET_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TARGET_KEYS = ['description', 'authorize', 'exec', 'pty', 'fs', 'endpoints'];

/** A file backend that tells every call which target it serves (the last argument's `target`). */
function fileBackendForTarget(files, name) {
  return {
    maxFileBytes: files.maxFileBytes,
    operate: (op, path, opts = {}) => files.operate(op, path, { ...opts, target: name }),
    readWhole: (path, opts = {}) => files.readWhole(path, { ...opts, target: name }),
    writeWhole: (path, data, opts = {}) => files.writeWhole(path, data, { ...opts, target: name }),
    writeAt: (path, data, offset, opts = {}) => files.writeAt(path, data, offset, { ...opts, target: name }),
    ...(files.openRange ? { openRange: (path, opts = {}) => files.openRange(path, { ...opts, target: name }) } : {}),
  };
}

/**
 * Validate the `targets` option (#121) and build one entry per target: its own exec / pty / files / endpoints
 * (`buildOne({ exec, pty, fs })` makes the first three: `resolveBackends` in a browser, `buildBackends` in Node), the
 * `authorize(who, { target, kind })` that decides who may use it, and a description. Nothing here is on by default: no
 * `targets` option, no targets.
 *
 * @param {object | undefined} targets - `{ [name]: { description?, authorize?, exec?, pty?, fs?, endpoints? } }`
 * @param {boolean | undefined} requireTarget
 * @param {(spec: object) => { execRunner: Function | null, execOptions: object, pty: object | null, files: object | null }} buildOne
 * @param {string} [who] - the host's name in error messages
 * @returns {{ targets: Map<string, object> | null, requireTarget: boolean }}
 */
export function normalizeTargets(targets, requireTarget, buildOne, who = 'host') {
  if (requireTarget !== undefined && typeof requireTarget !== 'boolean') throw new TypeError(`${who}: requireTarget must be a boolean`);
  if (targets === undefined || targets === null) {
    if (requireTarget) throw new TypeError(`${who}: requireTarget needs targets`);
    return { targets: null, requireTarget: false };
  }
  if (typeof targets !== 'object' || Array.isArray(targets)) throw new TypeError(`${who}: targets must be an object of { name: { exec, pty, fs, endpoints, authorize, description } }`);
  const map = new Map();
  for (const [name, spec] of Object.entries(targets)) {
    if (!TARGET_NAME_RE.test(name)) throw new TypeError(`${who}: targets: ${JSON.stringify(name)} is not a valid target name (letters, digits, ".", "_", "-"; at most 64)`);
    if (spec === null || typeof spec !== 'object' || Array.isArray(spec)) throw new TypeError(`${who}: targets.${name} must be an object`);
    for (const key of Object.keys(spec)) {
      if (!TARGET_KEYS.includes(key)) throw new TypeError(`${who}: targets.${name}.${key} is not an option of a target (${TARGET_KEYS.join(', ')})`);
    }
    if (spec.authorize !== undefined && typeof spec.authorize !== 'function') throw new TypeError(`${who}: targets.${name}.authorize must be a function (who, { target, kind }) => boolean`);
    if (spec.description !== undefined && typeof spec.description !== 'string') throw new TypeError(`${who}: targets.${name}.description must be a string`);
    const built = buildOne({ exec: spec.exec, pty: spec.pty, fs: spec.fs });
    map.set(name, {
      name,
      description: spec.description,
      authorize: spec.authorize ?? null,
      execRunner: built.execRunner,
      execOptions: built.execOptions,
      pty: built.pty,
      files: built.files ? fileBackendForTarget(built.files, name) : null,
      endpoints: normalizeEndpoints(spec.endpoints),
    });
  }
  return { targets: map.size ? map : null, requireTarget: map.size ? !!requireTarget : false };
}

/**
 * @param {{ exec?: Function | { run: Function }, pty?: { spawn: Function }, fs?: object, mcp?: object, targets?: object, requireTarget?: boolean }} options
 * @returns {{ execRunner: Function | null, execOptions: object, pty: object | null, files: object | null, mcp: object | null, targets: Map<string, object> | null, requireTarget: boolean }}
 */
export function resolveBackends({ exec, pty, fs, mcp, targets, requireTarget } = {}) {
  const base = resolveOwnBackends({ exec, pty, fs, mcp });
  return { ...base, ...normalizeTargets(targets, requireTarget, (spec) => resolveOwnBackends(spec), 'host') };
}

function resolveOwnBackends({ exec, pty, fs, mcp } = {}) {
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
  else assertEd25519HostKey(option, who);
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
