/**
 * An MCP face for allow-listed object paths (#219): the host names, in `mcp: { tools: [...] }`, which paths of which roots become MCP tools; each gets a host-authored name,
 * description and JSON Schema for its arguments. This module builds the tool definitions; `webmcpTools({ tools })` serves them on the `mcp` channel with the WebMCP bridge's own
 * approval, bounds and untrusted label (so a tool that is not marked read-only asks the person at the page, exactly as a WebMCP tool does).
 *
 * What a tool is: a CALL of one named method (`call: 'window.app.cart.add'`), or a read-only GET of one named value (`get: 'window.document.title'`). Nothing is a tool by being
 * allowed: a path is a tool only if it is written here, and only if the host's allow-list (the same one the objects client is held to) names it for that operation (checked when
 * the host is created; and again on every call, because a call goes through the same checks as an objects call: the allow-list, the names that need listing, the key's
 * `objects:ROOT:OP` capability and `authorize`). No handles, events or callbacks: an argument is plain data validated against the schema, a result is plain data or an error.
 */

import { compileSchema } from './objects-schema.mjs';

/** The key of the host-only part of a tool definition (see `INTERNAL_TOOL` in `webmcp.mjs`; the same registered symbol, so this file need not import it). */
const INTERNAL_TOOL = Symbol.for('wsh.webmcp.internal');

const TOOL_NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;
const TOOL_FIELDS = new Set(['name', 'title', 'description', 'call', 'get', 'inputSchema', 'args', 'readOnly']);
const NEVER = new Set(['__proto__', 'prototype', 'constructor', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__', 'eval', 'Function', 'import', 'execScript']);

export const MCP_TOOL_LIMITS = Object.freeze({
  /** Tools one host may name. */
  maxTools: 64,
  /** Characters of a description. */
  maxDescriptionChars: 2000,
  /** Arguments of a call tool (positional). */
  maxArgs: 16,
});

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * @param {object} options
 * @param {unknown} options.mcp - the host's `mcp` option
 * @param {string[]} options.rootNames
 * @param {(kind: 'get' | 'call', root: string, segs: string[]) => void} options.allows - throws (an `ObjectsError`) unless the allow-list names the path for the operation
 * @param {(request: { kind: 'get' | 'call', path: string[], args?: unknown[] }, ctx: object) => Promise<object>} options.invoke - one call through the server's checks
 * @returns {object[]} tool definitions for `webmcpTools({ tools })`
 */
export function buildMcpTools({ mcp, rootNames, allows, invoke }) {
  if (mcp === undefined) return [];
  if (!isObj(mcp)) throw new TypeError('exposeObjects: mcp must be { tools: [...] }');
  for (const k of Object.keys(mcp)) if (k !== 'tools') throw new TypeError(`exposeObjects: mcp.${k} is not an option (mcp is { tools: [...] }: name each path that becomes a tool; nothing is a tool by being allowed)`);
  if (!Array.isArray(mcp.tools)) throw new TypeError('exposeObjects: mcp.tools must be an array of { name, description, call | get, inputSchema, ... }');
  if (mcp.tools.length > MCP_TOOL_LIMITS.maxTools) throw new TypeError(`exposeObjects: mcp.tools lists at most ${MCP_TOOL_LIMITS.maxTools} tools`);
  const seen = new Set();
  return mcp.tools.map((spec, index) => {
    const label = isObj(spec) && typeof spec.name === 'string' ? `mcp tool "${spec.name.slice(0, 60)}"` : `mcp.tools[${index}]`;
    const fail = (message) => new TypeError(`exposeObjects: ${label}: ${message}`);
    if (!isObj(spec)) throw fail('must be an object');
    for (const k of Object.keys(spec)) if (!TOOL_FIELDS.has(k)) throw fail(`"${k}" is not a field of a tool (${[...TOOL_FIELDS].join(', ')}); events, handles and callbacks have no MCP tool`);
    if (typeof spec.name !== 'string' || !TOOL_NAME_RE.test(spec.name)) throw fail('name must be 1 to 128 characters of letters, digits, "_", "-" and "."');
    if (seen.has(spec.name)) throw fail('is listed twice');
    seen.add(spec.name);
    if (typeof spec.description !== 'string' || spec.description.trim() === '' || spec.description.length > MCP_TOOL_LIMITS.maxDescriptionChars) throw fail(`needs a description of 1 to ${MCP_TOOL_LIMITS.maxDescriptionChars} characters (the far side reads it to decide when to call the tool)`);
    if (spec.title !== undefined && (typeof spec.title !== 'string' || spec.title.length > 200)) throw fail('title must be a string of at most 200 characters');
    const named = [['call', spec.call], ['get', spec.get]].filter(([, v]) => v !== undefined);
    if (named.length !== 1) throw fail('names exactly one of call, get: the path it runs (a path is a tool only if it is written here)');
    const [kind, text] = named[0];
    if (typeof text !== 'string') throw fail(`${kind} must be the path as text`);
    const segs = text.split('.');
    for (const s of segs) {
      if (s === '') throw fail(`${kind} ${JSON.stringify(text.slice(0, 80))} has an empty segment`);
      if (/\*/.test(s)) throw fail(`${kind} must be a literal path, with no wildcard (${JSON.stringify(text.slice(0, 80))})`);
      if (s.includes('(') || s.includes(')')) throw fail(`${kind} must be a literal member path, not one through a call result (${JSON.stringify(text.slice(0, 80))})`);
      if (NEVER.has(s)) throw fail(`${kind} names "${s}", which is never reachable`);
    }
    if (!rootNames.includes(segs[0])) throw fail(`${kind} ${JSON.stringify(text.slice(0, 80))} starts at ${JSON.stringify(segs[0].slice(0, 40))}, which is not a root of this host`);
    if (segs.length < 2) throw fail(`${kind} must name a member of a root, not the root itself`);
    try { allows(kind, segs[0], segs); } catch (e) { throw fail(`${String(e?.message ?? e)} (a tool never widens the allow-list: list the path there, then name it here)`); }

    if (spec.readOnly !== undefined && typeof spec.readOnly !== 'boolean') throw fail('readOnly must be true or false');
    const readOnly = spec.readOnly ?? (kind === 'get');
    const schema = spec.inputSchema ?? { type: 'object', properties: {}, additionalProperties: false };
    if (!isObj(schema) || (schema.type !== undefined && schema.type !== 'object')) throw fail('inputSchema must describe an object');
    let compiled;
    try { compiled = compileSchema({ type: 'object', ...schema }, { what: `${label} inputSchema` }); } catch (e) { throw new TypeError(`exposeObjects: ${e.message}`); }
    const properties = isObj(schema.properties) ? Object.keys(schema.properties) : [];

    let mapping;
    if (kind === 'get') {
      if (spec.args !== undefined) throw fail('args is for a call: a get takes no arguments');
      mapping = null;
    } else if (spec.args === undefined) mapping = properties.length ? 'object' : [];
    else if (spec.args === 'object') mapping = 'object';
    else if (Array.isArray(spec.args) && spec.args.length <= MCP_TOOL_LIMITS.maxArgs && new Set(spec.args).size === spec.args.length && spec.args.every((a) => typeof a === 'string')) {
      for (const a of spec.args) if (!properties.includes(a)) throw fail(`args names "${a.slice(0, 40)}", which is not a property of inputSchema`);
      mapping = spec.args.slice();
    } else throw fail(`args must be 'object' (the input is the one argument) or a list of up to ${MCP_TOOL_LIMITS.maxArgs} property names (the arguments, in order)`);

    const root = segs[0];
    const op = kind;
    const argsOf = (input) => {
      if (mapping === 'object') return [input];
      const list = mapping.map((name) => (Object.hasOwn(input, name) ? input[name] : undefined));
      while (list.length && list[list.length - 1] === undefined) list.pop();
      return list.map((v) => (v === undefined ? null : v));
    };
    const definition = {
      name: spec.name,
      ...(spec.title ? { title: spec.title } : {}),
      description: spec.description,
      inputSchema: JSON.parse(JSON.stringify({ type: 'object', ...schema })),
      annotations: { readOnlyHint: readOnly },
      [INTERNAL_TOOL]: {
        caller: true,
        // Before the person is asked and before the page runs anything.
        validate: (input) => compiled.validate(input),
        // Listed only to a key that may do this on this root: `mcp:TOOL` and `objects:ROOT:OP` are both needed.
        available: ({ permits } = {}) => !permits || permits({ kind: 'objects', root, op }) === true,
      },
      async execute(input, { signal, who, permits } = {}) {
        const problem = compiled.validate(input);
        if (problem) throw new Error(`invalid arguments: ${problem}`);
        const permit = permits ? (r, o) => permits({ kind: 'objects', root: r, op: o }) === true : undefined;
        const out = await invoke({ kind, path: segs, args: kind === 'call' ? argsOf(input) : [] }, { who, permit, signal });
        if (out && 'u' in out) {
          if (out.u === 'undefined') return { content: [] };
          throw new Error(`the ${kind} of ${text} returned something that is not plain data (${out.u}${out.type ? ` ${out.type}` : ''}): only plain values are carried`);
        }
        const value = out?.v;
        const isPlainObject = value !== null && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Uint8Array);
        const rendered = typeof value === 'string' ? value : value instanceof Uint8Array ? `[${value.byteLength} bytes]` : JSON.stringify(value);
        return { content: [{ type: 'text', text: rendered ?? '' }], ...(isPlainObject ? { structuredContent: value } : {}) };
      },
    };
    return definition;
  });
}
