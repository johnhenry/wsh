/**
 * MCP tools for `@johnhenry/wsh/server`: what `createWshServer({ mcp })`
 * exposes through `McpDiscover` / `McpCall`.
 *
 * Two sources, which may be combined:
 *  - `mcp.tools` -- an array of `{ name, description, inputSchema, call }`, or
 *    a `{ name: { description, inputSchema, call } }` map.
 *  - `mcp.client` -- anything shaped like an `@modelcontextprotocol/sdk`
 *    `Client` (`listTools()` / `callTool({ name, arguments })`); its tools are
 *    proxied. Duck-typed, so the SDK is never imported by this package.
 *
 * Tools the operator did not list are never reachable: a call is looked up by
 * exact name in the set built here, after the optional `authorize` filter.
 */

import { assertSupportedSchema, validateSchema } from './json-schema.mjs';

const DEFAULT_SCHEMA = Object.freeze({ type: 'object' });
export const MCP_DEFAULTS = Object.freeze({ maxConcurrent: 8, timeoutMs: 30_000 });

function normalizeTool(name, spec, origin) {
  if (typeof name !== 'string' || !name) throw new TypeError('createWshServer: every mcp tool needs a name');
  if (!spec || typeof spec.call !== 'function') {
    throw new TypeError(`createWshServer: mcp tool "${name}" needs a call(args, ctx) function`);
  }
  const inputSchema = spec.inputSchema ?? spec.parameters ?? DEFAULT_SCHEMA;
  assertSupportedSchema(inputSchema, `#(${name})`);
  return { name, description: String(spec.description ?? ''), inputSchema, call: spec.call, origin };
}

/**
 * @param {object} mcp - the `createWshServer` `mcp` option
 * @returns {{ list(user: string, who: object): Promise<object[]>, find(name: string, user: string, who: object): Promise<object | null>, maxConcurrent: number, timeoutMs: number }}
 */
export function createMcpHost(mcp) {
  if (!mcp || typeof mcp !== 'object') throw new TypeError('createWshServer: mcp must be an object');
  const local = new Map();
  const entries = Array.isArray(mcp.tools)
    ? mcp.tools.map((t) => [t?.name, t])
    : Object.entries(mcp.tools ?? {});
  for (const [name, spec] of entries) {
    if (local.has(name)) throw new TypeError(`createWshServer: duplicate mcp tool "${name}"`);
    local.set(name, normalizeTool(name, spec, 'local'));
  }
  const client = mcp.client ?? null;
  if (client && (typeof client.listTools !== 'function' || typeof client.callTool !== 'function')) {
    throw new TypeError('createWshServer: mcp.client needs listTools() and callTool() (an @modelcontextprotocol/sdk Client)');
  }
  if (typeof mcp.authorize !== 'undefined' && typeof mcp.authorize !== 'function') {
    throw new TypeError('createWshServer: mcp.authorize must be a function');
  }

  /** Remote tools, refreshed on every discover; calls use the most recent listing. */
  let proxied = new Map();
  async function refreshProxied() {
    if (!client) return;
    const next = new Map();
    const { tools = [] } = await client.listTools();
    for (const t of tools) {
      if (!t || typeof t.name !== 'string' || local.has(t.name)) continue; // local tools win
      try {
        next.set(t.name, normalizeTool(t.name, {
          description: t.description,
          inputSchema: t.inputSchema,
          call: (args, ctx) => callProxied(t.name, args, ctx),
        }, 'proxy'));
      } catch { /* a schema we cannot enforce is not exposed */ }
    }
    proxied = next;
  }

  async function callProxied(name, args, { signal }) {
    const res = await client.callTool({ name, arguments: args }, undefined, { signal });
    if (res?.isError) {
      const text = Array.isArray(res.content) ? res.content.filter((c) => c?.type === 'text').map((c) => c.text).join('\n') : '';
      throw new Error(text || `tool ${name} failed`);
    }
    return res?.structuredContent ?? res?.content ?? null;
  }

  const allowed = async (tool, user, who) => {
    if (!mcp.authorize) return true;
    try { return (await mcp.authorize(user, { name: tool.name, description: tool.description, inputSchema: tool.inputSchema }, who)) === true; } catch { return false; }
  };

  return {
    maxConcurrent: mcp.maxConcurrent > 0 ? mcp.maxConcurrent : MCP_DEFAULTS.maxConcurrent,
    timeoutMs: mcp.timeoutMs >= 0 ? mcp.timeoutMs : MCP_DEFAULTS.timeoutMs,

    async list(user, who) {
      await refreshProxied();
      const out = [];
      for (const t of [...local.values(), ...proxied.values()]) {
        if (await allowed(t, user, who)) out.push({ name: t.name, description: t.description, parameters: t.inputSchema });
      }
      return out;
    },

    /** A tool this principal may call, or `null` -- indistinguishable for hidden and absent. */
    async find(name, user, who) {
      let tool = local.get(name) ?? proxied.get(name);
      if (!tool && client && !local.has(name)) {
        await refreshProxied();
        tool = proxied.get(name);
      }
      return tool && await allowed(tool, user, who) ? tool : null;
    },

    validate: (tool, args) => validateSchema(tool.inputSchema, args),
  };
}
