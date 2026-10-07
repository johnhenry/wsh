/**
 * Typed RPC channels for `@johnhenry/wsh/server` -- wsh #85.
 *
 * `createWshServer({ rpc: { [protocol]: handler } })`. A handler is
 *   - `true` for a built-in (`wsh-host`; `wsh-fs`, confined by the server's `fs` option), or `{ root, ... }` for
 *     `wsh-fs` with its own root;
 *   - a function `(channel, ctx) => void | Promise<void>` for anything else (including `mcpServerAdapter(server)`),
 *     called once per opened channel with an `RpcChannel` to register methods on.
 *
 * Built-ins:
 *   wsh-host  host.info, host.ping
 *   wsh-fs    stat, list, read, write, upload, download, rename, mkdir, remove
 */

import { createRequire } from 'node:module';
import { RpcError, RPC_ERROR, RPC_PROTOCOL_NAME_RE, RPC_DEFAULT_MAX_MESSAGE } from '../rpc.mjs';
import { RpcMcpTransport } from '../rpc-mcp.mjs';
import { createFileAccess } from './fs.mjs';

const { version: PACKAGE_VERSION } = createRequire(import.meta.url)('../../package.json');

export const WSH_HOST = 'wsh-host';
export const WSH_FS = 'wsh-fs';
const BUILT_INS = new Set([WSH_HOST, WSH_FS, 'mcp']);

const needString = (params, key) => {
  const v = params?.[key];
  if (typeof v !== 'string') throw new RpcError(RPC_ERROR.INVALID_PARAMS, `"${key}" (string) is required`);
  return v;
};

const needBytes = (params, key) => {
  const v = params?.[key];
  if (!(v instanceof Uint8Array)) throw new RpcError(RPC_ERROR.INVALID_PARAMS, `"${key}" (byte string) is required`);
  return v;
};

/** Map a file-access failure onto an RpcError. */
function fsError(e) {
  if (e instanceof RpcError) return e;
  if (e?.denied) return new RpcError(RPC_ERROR.UNAUTHORIZED, e.message);
  if (e?.wsh) return new RpcError(RPC_ERROR.INVALID_PARAMS, e.message);
  if (e?.code === 'ENOENT') return new RpcError(RPC_ERROR.INTERNAL, 'no such file or directory', { code: 'ENOENT' });
  return new RpcError(RPC_ERROR.INTERNAL, 'file operation failed', e?.code ? { code: e.code } : undefined);
}

/** @param {ReturnType<typeof createFileAccess>} files */
function fsProtocol(files) {
  return (channel, ctx) => {
    const guarded = (fn) => async (params, rctx) => {
      try { return await fn(params ?? {}, rctx); } catch (e) {
        if (!(e instanceof RpcError)) ctx.log?.(`wsh-fs: ${e.wsh ? e.message : (e.stack ?? e)}`);
        throw fsError(e);
      }
    };
    channel.onRequest('stat', guarded(async (p) => (await files.operate('stat', needString(p, 'path'))).metadata));
    channel.onRequest('list', guarded(async (p) => {
      const r = await files.operate('list', typeof p.path === 'string' ? p.path : '/');
      return { path: r.metadata?.path ?? p.path ?? '/', entries: r.entries ?? [] };
    }));
    channel.onRequest('mkdir', guarded(async (p) => (await files.operate('mkdir', needString(p, 'path'))).metadata));
    channel.onRequest('remove', guarded(async (p) => (await files.operate('remove', needString(p, 'path'))).metadata));
    channel.onRequest('rename', guarded(async (p) => (await files.operate('rename', needString(p, 'path'), { newPath: needString(p, 'newPath') })).metadata));
    channel.onRequest('write', guarded(async (p) => (await files.operate('write', needString(p, 'path'), { offset: p.offset, data: needBytes(p, 'data') })).metadata));
    // upload: the chunk-friendly write. offset omitted/0 creates or truncates the file; offset > 0 continues it in place.
    channel.onRequest('upload', guarded(async (p) => {
      const data = needBytes(p, 'data');
      const offset = p.offset === undefined || p.offset === null ? 0 : Number(p.offset);
      if (!Number.isSafeInteger(offset) || offset < 0) throw new RpcError(RPC_ERROR.INVALID_PARAMS, 'illegal offset');
      if (offset === 0) await files.writeAt(needString(p, 'path'), data, undefined, { mkdirs: true });
      else await files.writeAt(needString(p, 'path'), data, offset);
      return { written: data.byteLength, offset };
    }));
    // read / download: chunks arrive as `$/progress`, the result is a summary.
    const stream = async (p, rctx) => {
      const range = await files.openRange(needString(p, 'path'), {
        offset: p.offset, length: p.length, chunkBytes: Math.max(64, Math.min(64 * 1024, rctx.channel.maxMessageBytes - 512)),
      });
      let sent = 0;
      for await (const chunk of range.chunks) {
        if (rctx.signal.aborted) break;
        await rctx.progress(chunk);
        sent += chunk.byteLength;
      }
      return { size: range.size, offset: range.offset, length: sent, eof: range.offset + sent >= range.size };
    };
    channel.onRequest('read', guarded(stream));
    channel.onRequest('download', guarded((p, rctx) => stream({ path: p.path }, rctx)));
  };
}

function hostProtocol(info) {
  return (channel, ctx) => {
    channel.onRequest('host.info', () => ({
      version: PACKAGE_VERSION,
      protocol: 'wsh-v1',
      features: [...ctx.features],
      hostFingerprint: ctx.hostFingerprint ?? null,
      user: ctx.user,
      rpc: { protocols: info.protocols(), maxMessageBytes: info.maxMessageBytes },
    }));
    channel.onRequest('host.ping', () => ({ time: Date.now() }));
  };
}

/**
 * Validate the `rpc` option and build the per-connection protocol table.
 * @param {Record<string, true | object | Function>} rpc
 * @param {{ files: object | null, maxMessageBytes?: number, maxInflight?: number }} deps
 * @returns {{ protocols: Map<string, Function>, maxMessageBytes: number, maxInflight: number }}
 */
export function createRpcHost(rpc, { files, maxMessageBytes = RPC_DEFAULT_MAX_MESSAGE, maxInflight = 64 } = {}) {
  if (!rpc || typeof rpc !== 'object' || Array.isArray(rpc)) throw new TypeError('createWshServer: rpc must be an object of { [protocol]: handler }');
  if (!(maxMessageBytes >= 256)) throw new TypeError('createWshServer: rpcMaxMessageBytes must be at least 256');
  const protocols = new Map();
  const info = { protocols: () => [...protocols.keys()], maxMessageBytes };
  for (const [name, spec] of Object.entries(rpc)) {
    if (spec === undefined || spec === false || spec === null) continue;
    if (!RPC_PROTOCOL_NAME_RE.test(name)) throw new TypeError(`createWshServer: rpc protocol name ${JSON.stringify(name)} is not allowed (letters, digits, ".", "_", "-")`);
    if (typeof spec === 'function') { protocols.set(name, spec); continue; }
    if (name === WSH_HOST && spec === true) { protocols.set(name, hostProtocol(info)); continue; }
    if (name === WSH_FS && (spec === true || (spec && typeof spec === 'object'))) {
      if (spec === true && !files) throw new TypeError('createWshServer: rpc["wsh-fs"]: true needs the fs option (or pass { root })');
      protocols.set(name, fsProtocol(spec === true ? files : createFileAccess(spec)));
      continue;
    }
    if (name === 'mcp') throw new TypeError('createWshServer: rpc.mcp needs a handler: mcpServerAdapter(server)');
    throw new TypeError(`createWshServer: rpc[${JSON.stringify(name)}] needs a handler function (channel, ctx) => void${BUILT_INS.has(name) ? ' or a valid built-in config' : ''}`);
  }
  return { protocols, maxMessageBytes, maxInflight };
}

/**
 * Expose an MCP `Server` (`@modelcontextprotocol/sdk`) over an `rpc` channel: `rpc: { mcp: mcpServerAdapter(server) }`.
 *
 * Pass a Server instance to serve one channel at a time (a second concurrent channel is closed with an error),
 * or a factory `(ctx) => Server` to give every channel its own. The SDK is not imported here; any object with
 * `connect(transport)` works.
 *
 * @param {{ connect(transport: object): Promise<void>, close?(): Promise<void> } | ((ctx: object) => any)} serverOrFactory
 * @returns {(channel: import('../rpc.mjs').RpcChannel, ctx: object) => Promise<void>}
 */
export function mcpServerAdapter(serverOrFactory) {
  const isFactory = typeof serverOrFactory === 'function' && typeof serverOrFactory.connect !== 'function';
  if (!isFactory && typeof serverOrFactory?.connect !== 'function') {
    throw new TypeError('mcpServerAdapter: expected an MCP Server (with connect(transport)) or a factory returning one');
  }
  let busy = false;
  return async (channel, ctx) => {
    if (!isFactory && busy) {
      // The SDK's Server speaks to one transport at a time; saying so beats silently stealing the first channel.
      throw new Error('mcp server instance is already serving another channel (pass a factory for concurrent channels)');
    }
    const server = isFactory ? await serverOrFactory(ctx) : serverOrFactory;
    if (typeof server?.connect !== 'function') throw new TypeError('mcpServerAdapter: the factory must return an MCP Server');
    const transport = new RpcMcpTransport(channel);
    if (!isFactory) busy = true;
    const prior = channel.onClose;
    channel.onClose = (reason) => {
      if (!isFactory) busy = false;
      try { prior?.(reason); } catch { /* ignore */ }
      if (isFactory) Promise.resolve(server.close?.()).catch(() => {});
    };
    try {
      await server.connect(transport);
    } catch (e) {
      if (!isFactory) busy = false;
      throw e;
    }
  };
}
