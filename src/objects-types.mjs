/**
 * `@johnhenry/wsh/objects-types` -- TypeScript declarations for a root of `wsh-objects`, so the far side's Proxy is typed.
 *
 * `describeRootTypes(description, { name })` is a PURE function: it takes what a host says one key may do on one root (the host's `types` answer, which
 * `rootDescription(page.window)` fetches, or the allow-lists a host holds) and returns the text of a `.d.ts` file. It reads nothing, writes nothing,
 * evaluates nothing, and throws on anything it does not understand. What it writes:
 *
 * - **Only what the key may do.** A path appears only if one of the key's allow-list entries (for an operation the key's `objects:ROOT:OP` capabilities
 *   grant) names it. A path in no entry, an operation not granted, and a member the host refuses are not in the file, not even as `never`.
 * - **Value types limited to what can be known.** A plain value is `RemoteValue<unknown>` unless the host supplied a type for the path; a call is
 *   `(...args: unknown[]) => PromiseLike<unknown>`; a wildcard (`*`, `**`) is `RemoteUntyped` (`any`): the file does not guess the members behind it.
 *   An event source carries typed `on` overloads from `allow.on` and `eventFields`; a path that may be set carries a typed `set`.
 * - **Host-supplied types are untrusted text.** They pass `checkTypeText` (a conservative subset, see `objects-type-text.mjs`), must belong to a path an
 *   entry allows, and are bounded; they are copied into the file and never evaluated.
 * - **Advisory.** A type is erased before anything runs. It does not widen what the host allows, and `authorize`, the always-refused names and the paths that
 *   must be named still refuse at call time whatever the file says.
 */

import { checkTypeText, TYPE_TEXT_LIMITS } from './objects-type-text.mjs';

export { checkTypeText, TYPE_TEXT_LIMITS };

export const OBJECTS_TYPES_LIMITS = Object.freeze({
  /** Entries in one allow list of a description. */
  maxEntries: 1000,
  /** Characters of one allow-list entry. */
  maxEntryChars: 512,
  /** Nodes of the tree the entries make. */
  maxNodes: 4000,
  /** Event types and fields in one description. */
  maxEvents: 256,
});

const OPS = ['get', 'call', 'set', 'on'];
const IDENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const ROOT_NAME = /^[A-Za-z_$][A-Za-z0-9_$-]{0,63}$/;
const EVENT_TYPE = /^[A-Za-z0-9_$:.-]{1,128}$/;
const FIELD_NAME = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/;
const SEGMENT = /^[\x21-\x7e][\x20-\x7e]{0,255}$/;
const RESERVED = new Set([
  'any', 'unknown', 'never', 'string', 'number', 'boolean', 'object', 'symbol', 'void', 'null', 'undefined', 'bigint', 'Promise', 'PromiseLike', 'Record', 'Array',
  'RemoteValue', 'RemoteCall', 'RemoteUntyped', 'RemoteHandle', 'NonValue', 'WithEvents', 'WithSet', 'RemoteEventData',
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default', 'delete', 'do', 'else', 'enum', 'export', 'extends', 'false', 'finally', 'for', 'function', 'if', 'import', 'in',
  'instanceof', 'new', 'return', 'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof', 'var', 'while', 'with', 'yield', 'let', 'static', 'implements', 'interface', 'package', 'private',
  'protected', 'public', 'await', 'async', 'of', 'type', 'declare', 'module', 'namespace', 'global', 'require',
]);

const bad = (message) => new TypeError(`describeRootTypes: ${message}`);

/** Does a literal path match a pattern (`*` one segment, `**` any number, also none)? */
function matches(pattern, path) {
  const rec = (i, j) => {
    if (i === pattern.length) return j === path.length;
    if (pattern[i] === '**') return rec(i + 1, j) || (j < path.length && rec(i, j + 1));
    return j < path.length && (pattern[i] === '*' || pattern[i] === path[j]) && rec(i + 1, j + 1);
  };
  return rec(0, 0);
}

function splitPath(text, what) {
  const segs = text.split('.');
  for (const s of segs) {
    if (!SEGMENT.test(s)) throw bad(`${what} ${JSON.stringify(text.slice(0, 80))} has a path segment that is empty or not printable ASCII`);
    if (/\*/.test(s) && s !== '*' && s !== '**') throw bad(`${what} ${JSON.stringify(text.slice(0, 80))}: a wildcard must be a whole segment`);
  }
  return segs;
}

/** One entry of an allow list: `{ segs, callbacks, type? }`. */
function parseEntry(raw, op) {
  if (typeof raw !== 'string' || raw === '' || raw.length > OBJECTS_TYPES_LIMITS.maxEntryChars) throw bad(`an allow.${op} entry must be a string of 1 to ${OBJECTS_TYPES_LIMITS.maxEntryChars} characters`);
  let text = raw;
  let type;
  let callbacks = false;
  if (op === 'on') {
    const at = text.indexOf('@');
    if (at < 0) throw bad(`allow.on entry ${JSON.stringify(raw.slice(0, 80))} must be "path@type"`);
    type = text.slice(at + 1);
    text = text.slice(0, at);
    if (!EVENT_TYPE.test(type)) throw bad(`allow.on entry ${JSON.stringify(raw.slice(0, 80))}: the event type is not a name`);
  }
  if (op === 'call' && text.endsWith('(callback)')) { callbacks = true; text = text.slice(0, -'(callback)'.length); }
  const segs = splitPath(text, `allow.${op} entry`);
  if (op === 'on' && segs.some((s) => s.includes('*'))) throw bad(`allow.on entry ${JSON.stringify(raw.slice(0, 80))}: an event source is named exactly`);
  return { segs, callbacks, type, text };
}

class Node {
  constructor() {
    this.kids = new Map();
    this.result = null; // the node of what a call of this one returns
    this.wild = false; // a `*` or `**` below: the members are not enumerated
    this.get = false; this.call = false; this.setKeys = new Set(); this.setWild = false; this.on = new Set();
  }
}

/** The entries of one operation that belong to a root (or start with a wildcard), parsed. */
function entriesFor(root, allow, op) {
  const list = allow[op] ?? [];
  if (!Array.isArray(list) || list.length > OBJECTS_TYPES_LIMITS.maxEntries) throw bad(`allow.${op} must be an array of at most ${OBJECTS_TYPES_LIMITS.maxEntries} entries`);
  const out = [];
  for (const raw of list) {
    const e = parseEntry(raw, op);
    if (e.segs[0] === root || e.segs[0] === '*' || e.segs[0] === '**') out.push(e);
  }
  return out;
}

/** Is one field of a type-map entry for a path that some entry allows? (`value`: a get or set entry; `args` and `result`: a call entry; `data`: the exact event entry.) */
function fieldAllowed(entries, field, segs, eventType) {
  if (field === 'data') return entries.on.some((e) => e.type === eventType && e.segs.length === segs.length && e.segs.every((s, i) => s === segs[i]));
  if (field === 'value') return entries.get.some((e) => matches(e.segs, segs)) || entries.set.some((e) => matches(e.segs, segs));
  return entries.call.some((e) => matches(e.segs, segs));
}

/**
 * The part of a host's type map that a key with `ops` may be told: a field is kept only if an entry of an operation the key holds allows its path. (The host
 * uses this for its `types` answer; the map itself was checked when the host was created.)
 */
export function narrowTypes({ root, ops, allow, types }) {
  const entries = Object.fromEntries(OPS.map((op) => [op, ops.includes(op) ? entriesFor(root, allow, op) : []]));
  const out = {};
  for (const [key, spec] of Object.entries(types ?? {})) {
    const at = key.indexOf('@');
    const segs = (at < 0 ? key : key.slice(0, at)).split('.');
    if (segs[0] !== root) continue;
    const kept = {};
    for (const [field, text] of Object.entries(spec)) if (fieldAllowed(entries, field, segs, at < 0 ? undefined : key.slice(at + 1))) kept[field] = text;
    if (Object.keys(kept).length) out[key] = kept;
  }
  return out;
}

/**
 * Text of a `.d.ts` file for one root.
 *
 * @param {{
 *   root: string,
 *   ops?: Array<'get' | 'call' | 'set' | 'on'>,
 *   allow: { get?: string[], call?: string[], set?: string[], on?: string[] },
 *   eventFields?: Record<string, string[]>,
 *   types?: Record<string, { value?: string, args?: string, result?: string, data?: string }>,
 * }} description - the host's `types` answer for one root (paths qualified with the root, as in `allow`), or the allow-lists a host holds. `ops` is what the key
 *   may do on this root (default: all four).
 * @param {{ name?: string }} [options] - the name of the exported type (default: the root's name, capitalised, plus `Remote`)
 * @returns {string}
 */
export function describeRootTypes(description, { name } = {}) {
  if (description === null || typeof description !== 'object' || Array.isArray(description)) throw bad('the description must be an object');
  const { root } = description;
  if (typeof root !== 'string' || !ROOT_NAME.test(root)) throw bad('root must be the name of a root');
  const typeName = name ?? `${root.replace(/[^A-Za-z0-9_$]/g, '_').replace(/^./, (c) => c.toUpperCase())}Remote`;
  if (typeof typeName !== 'string' || !IDENT.test(typeName) || typeName.length > 64 || RESERVED.has(typeName)) throw bad(`name ${JSON.stringify(String(typeName).slice(0, 40))} is not a usable type name`);
  const ops = description.ops === undefined ? OPS : description.ops;
  if (!Array.isArray(ops) || !ops.every((o) => OPS.includes(o))) throw bad('ops must list some of get, call, set, on');
  const allow = description.allow;
  if (allow === null || typeof allow !== 'object' || Array.isArray(allow)) throw bad('allow must be { get, call, set, on }');
  for (const k of Object.keys(allow)) if (!OPS.includes(k)) throw bad(`allow.${k} is not an operation`);

  // 1. The entries the key may use: an operation it was not granted contributes nothing.
  const entries = { get: [], call: [], set: [], on: [] };
  for (const op of OPS) {
    entriesFor(root, allow, op); // shape of every list is checked, granted or not
    if (ops.includes(op)) entries[op] = entriesFor(root, allow, op);
  }

  // 2. Event fields: only the ones for types the key may subscribe to.
  const eventFields = {};
  const rawFields = description.eventFields ?? {};
  if (rawFields === null || typeof rawFields !== 'object' || Array.isArray(rawFields)) throw bad('eventFields must be { [type]: [names] }');
  if (Object.keys(rawFields).length > OBJECTS_TYPES_LIMITS.maxEvents) throw bad('too many eventFields');
  for (const [type, names] of Object.entries(rawFields)) {
    if (type !== '*' && !EVENT_TYPE.test(type)) throw bad('an eventFields key must be an event type');
    if (!Array.isArray(names) || names.length > 64 || !names.every((n) => typeof n === 'string' && FIELD_NAME.test(n))) throw bad(`eventFields[${JSON.stringify(type.slice(0, 40))}] must be an array of property names`);
    eventFields[type] = [...new Set(names)].sort();
  }

  // 3. The type map: host-authored text, checked, and only for what an entry allows.
  const typeMap = new Map();
  const rawTypes = description.types ?? {};
  if (rawTypes === null || typeof rawTypes !== 'object' || Array.isArray(rawTypes)) throw bad('types must be an object of paths');
  if (Object.keys(rawTypes).length > TYPE_TEXT_LIMITS.maxEntries) throw bad(`types has more than ${TYPE_TEXT_LIMITS.maxEntries} entries`);
  let total = 0;
  for (const [key, spec] of Object.entries(rawTypes)) {
    if (spec === null || typeof spec !== 'object' || Array.isArray(spec)) throw bad(`types[${JSON.stringify(key.slice(0, 60))}] must be an object`);
    const at = key.indexOf('@');
    const pathText = at < 0 ? key : key.slice(0, at);
    const eventType = at < 0 ? undefined : key.slice(at + 1);
    if (key.length > OBJECTS_TYPES_LIMITS.maxEntryChars) throw bad('a types path is too long');
    const segs = splitPath(pathText, 'types path');
    if (segs.some((s) => s.includes('*'))) throw bad(`types path ${JSON.stringify(pathText.slice(0, 60))} must be literal, with no wildcard`);
    for (const field of Object.keys(spec)) {
      if (!['value', 'args', 'result', 'data'].includes(field)) throw bad(`types[${JSON.stringify(key.slice(0, 60))}].${field} is not one of value, args, result, data`);
      const text = checkTypeText(spec[field], `types[${JSON.stringify(key.slice(0, 60))}].${field}`);
      total += text.length;
      if (total > TYPE_TEXT_LIMITS.maxTotalChars) throw bad(`the type texts are over ${TYPE_TEXT_LIMITS.maxTotalChars} characters together`);
      const op = field === 'value' ? 'get' : field === 'data' ? 'on' : 'call';
      if ((field === 'data') !== (eventType !== undefined)) throw bad(`types[${JSON.stringify(key.slice(0, 60))}]: "data" belongs to an event ("path@type"), the other fields to a path`);
      if (!fieldAllowed(entries, field, segs, eventType)) throw bad(`types[${JSON.stringify(key.slice(0, 60))}].${field}: no ${op === 'get' ? 'get or set' : op} entry allows that path (a type is written only for what the key may do)`);
    }
    typeMap.set(key, spec);
  }

  // 4. The tree the entries make.
  let nodeCount = 0;
  const fresh = () => { if (++nodeCount > OBJECTS_TYPES_LIMITS.maxNodes) throw bad(`the entries make more than ${OBJECTS_TYPES_LIMITS.maxNodes} nodes`); return new Node(); };
  const top = fresh();
  const reach = (segs) => {
    let node = top;
    // `root.a.b()`: the first segment is the root itself.
    for (let i = 1; i < segs.length; i++) {
      const s = segs[i];
      if (s === '*' || s === '**') { node.wild = true; return { node, wild: true }; }
      const call = s.endsWith('()') && s.length > 2;
      const key = call ? s.slice(0, -2) : s;
      let kid = node.kids.get(key);
      if (!kid) { kid = fresh(); node.kids.set(key, kid); }
      if (call) { kid.result ??= fresh(); node = kid.result; } else node = kid;
    }
    return { node, wild: false };
  };
  for (const op of OPS) {
    for (const e of entries[op]) {
      if (e.segs[0] !== root) { top.wild = true; continue; } // a pattern that starts with a wildcard: any root, any path
      if (op === 'set') {
        if (e.segs.length < 2) continue; // the root itself is not assigned
        // The last segment is the property that may be assigned: it belongs to its parent's `set` brand.
        const parentSegs = e.segs.slice(0, -1);
        const last = e.segs[e.segs.length - 1];
        const { node, wild } = reach(parentSegs.length ? parentSegs : [root]);
        if (wild) continue;
        if (last === '*' || last === '**') node.setWild = true; else node.setKeys.add(last.endsWith('()') ? last.slice(0, -2) : last);
        continue;
      }
      const { node, wild } = reach(e.segs);
      if (wild) { /* the pattern ends in a wildcard: its parent's members are not enumerated */ }
      if (op === 'on') { if (!wild) node.on.add(e.type); continue; }
      if (!wild || e.segs[e.segs.length - 1] === '**') node[op] = true;
    }
  }

  // 5. The text.
  const member = (key) => (IDENT.test(key) ? key : JSON.stringify(key));
  const pathOf = (segs) => segs.join('.');
  const eventFor = (type, path) => {
    const spec = typeMap.get(`${path}@${type}`);
    const fields = [...new Set([...(eventFields[type] ?? []), ...(eventFields['*'] ?? [])])].sort();
    const fieldUnion = fields.length ? fields.map((f) => JSON.stringify(f)).join(' | ') : 'never';
    const data = spec?.data ?? `RemoteEventData<${fieldUnion}>`;
    return `${JSON.stringify(type)}: { data: ${data}; fields: ${fieldUnion} }`;
  };
  const render = (node, segs, indent) => {
    const path = pathOf(segs);
    const pad = '  '.repeat(indent + 1);
    const parts = [];
    const spec = typeMap.get(path);
    if (node.get) parts.push(`RemoteValue<${spec?.value ?? 'unknown'}>`);
    const members = [...node.kids.keys()].sort();
    const lines = [];
    for (const key of members) {
      const kid = node.kids.get(key);
      lines.push(`${pad}readonly ${member(key)}: ${render(kid, [...segs, key], indent + 1)};`);
    }
    if (node.wild) lines.push(`${pad}readonly [key: string]: RemoteUntyped;`);
    if (lines.length) parts.push(`{\n${lines.join('\n')}\n${'  '.repeat(indent)}}`);
    if (node.on.size) parts.push(`WithEvents<{ ${[...node.on].sort().map((t) => eventFor(t, path)).join('; ')} }>`);
    if (node.setWild) parts.push('WithSet<Record<string, unknown>>');
    else if (node.setKeys.size) parts.push(`WithSet<{ ${[...node.setKeys].sort().map((k) => `${member(k)}: ${typeMap.get(`${path}.${k}`)?.value ?? 'unknown'}`).join('; ')} }>`);
    if (node.call) {
      const callSpec = typeMap.get(path);
      const args = callSpec?.args ?? 'unknown[]';
      const result = callSpec?.result ?? 'unknown';
      const resultNode = node.result;
      const members2 = resultNode ? render(resultNode, [...segs.slice(0, -1), `${segs[segs.length - 1]}()`], indent) : 'unknown';
      parts.push(`RemoteCall<${args}, ${result}, ${members2}>`);
    }
    return parts.length ? parts.join(' & ') : '{}';
  };
  const body = render(top, [root], 0);

  return [
    `// Generated by describeRootTypes of @johnhenry/wsh for the root ${JSON.stringify(root)}. It describes what ONE key may do on this root and nothing more:`,
    '// a path that is not here is refused, an operation that is not here is refused, and a type is advisory (it is erased before anything runs).',
    '// Values are unknown unless the host supplied a type; the host\'s type texts are copied as written and never evaluated. Do not edit: fetch it again.',
    "import type { RemoteValue, RemoteCall, RemoteUntyped, RemoteHandle, NonValue, WithEvents, WithSet, RemoteEventData } from '@johnhenry/wsh/objects';",
    '',
    `export type ${typeName} = ${body};`,
    '',
  ].join('\n');
}
