/**
 * A small, bounded subset of JSON Schema, for the arguments of an MCP tool made from an object path (#219). The host writes the schema; the far side's arguments are
 * checked against it BEFORE anything runs (before the person at the page is asked, and before the page's function is called). The rule that keeps what is advertised
 * equal to what is enforced: a schema that uses a keyword this validator does not enforce is refused when the host is configured (`compileSchema` throws), so a schema
 * can never promise a check that is not made.
 *
 * Enforced: `type` (one name or a list), `enum`, `const`, `properties`, `required`, `additionalProperties` (a boolean or a schema), `items` (one schema), `minItems`,
 * `maxItems`, `minLength`, `maxLength`, `minimum`, `maximum` and `anyOf`. Annotations that assert nothing are accepted and ignored: `description`, `title`, `default`,
 * `examples`, `format`, `$comment`, `$schema`. Everything else (`$ref`, `pattern`, `oneOf`, `allOf`, `not`, `patternProperties`, `if`, ...) is refused: a regular
 * expression of the host's would run against the far side's text, and a reference needs a resolver.
 *
 * What it checks of a VALUE, whatever the schema says: it is plain data (a JSON-shaped value: no function, no class instance), it nests no deeper than `maxDepth` and has
 * no more than `maxNodes` nodes, and no object has a key that climbs to a prototype (`__proto__`, `constructor`, `prototype`, ...).
 */

export const SCHEMA_LIMITS = Object.freeze({
  /** Nesting of a schema, and of a value checked against one. */
  maxDepth: 8,
  /** Nodes of a schema, and nodes visited when a value is checked. */
  maxNodes: 2000,
  /** Properties one object schema lists. */
  maxProperties: 64,
  /** Members of an `enum`, entries of `required` and of `anyOf`. */
  maxList: 64,
});

const TYPES = new Set(['string', 'number', 'integer', 'boolean', 'null', 'object', 'array']);
const ANNOTATIONS = new Set(['description', 'title', 'default', 'examples', 'format', '$comment', '$schema']);
const ENFORCED = new Set(['type', 'enum', 'const', 'properties', 'required', 'additionalProperties', 'items', 'minItems', 'maxItems', 'minLength', 'maxLength', 'minimum', 'maximum', 'anyOf']);
const NEVER_KEYS = new Set(['__proto__', 'prototype', 'constructor', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__']);

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const bad = (what, message) => new TypeError(`${what}: ${message}`);

const same = (a, b) => {
  if (a === b) return true;
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
  try { return JSON.stringify(a) === JSON.stringify(b); } catch { return false; }
};

/**
 * Check a schema and return `{ validate(value) }`, which returns `null` when the value fits and a sentence when it does not (the first problem).
 * @param {object} schema
 * @param {{ what?: string }} [options] - what the schema is for, for the messages
 */
export function compileSchema(schema, { what = 'inputSchema' } = {}) {
  let nodes = 0;
  const check = (s, depth, at) => {
    if (!isObj(s)) throw bad(what, `${at} must be a schema object`);
    if (depth > SCHEMA_LIMITS.maxDepth) throw bad(what, `${at} nests deeper than ${SCHEMA_LIMITS.maxDepth}`);
    if (++nodes > SCHEMA_LIMITS.maxNodes) throw bad(what, `has more than ${SCHEMA_LIMITS.maxNodes} nodes`);
    for (const k of Object.keys(s)) {
      if (ENFORCED.has(k) || ANNOTATIONS.has(k)) continue;
      throw bad(what, `${at}: the keyword "${k}" is not supported (it could not be enforced, so it would promise a check that is not made)`);
    }
    if (s.type !== undefined) {
      const list = Array.isArray(s.type) ? s.type : [s.type];
      if (list.length === 0 || list.length > TYPES.size || !list.every((t) => TYPES.has(t))) throw bad(what, `${at}.type must be one of ${[...TYPES].join(', ')} (or a list of them)`);
    }
    if (s.enum !== undefined && (!Array.isArray(s.enum) || s.enum.length === 0 || s.enum.length > SCHEMA_LIMITS.maxList)) throw bad(what, `${at}.enum must be a list of 1 to ${SCHEMA_LIMITS.maxList} values`);
    if (s.required !== undefined && (!Array.isArray(s.required) || s.required.length > SCHEMA_LIMITS.maxList || !s.required.every((r) => typeof r === 'string' && !NEVER_KEYS.has(r)))) throw bad(what, `${at}.required must be a list of at most ${SCHEMA_LIMITS.maxList} property names`);
    for (const k of ['minItems', 'maxItems', 'minLength', 'maxLength']) if (s[k] !== undefined && (!Number.isSafeInteger(s[k]) || s[k] < 0)) throw bad(what, `${at}.${k} must be a whole number of at least 0`);
    for (const k of ['minimum', 'maximum']) if (s[k] !== undefined && (typeof s[k] !== 'number' || !Number.isFinite(s[k]))) throw bad(what, `${at}.${k} must be a number`);
    if (s.properties !== undefined) {
      if (!isObj(s.properties)) throw bad(what, `${at}.properties must be an object of schemas`);
      const keys = Object.keys(s.properties);
      if (keys.length > SCHEMA_LIMITS.maxProperties) throw bad(what, `${at}.properties lists more than ${SCHEMA_LIMITS.maxProperties} properties`);
      for (const k of keys) {
        if (NEVER_KEYS.has(k)) throw bad(what, `${at}.properties names "${k}", which is never accepted`);
        check(s.properties[k], depth + 1, `${at}.properties.${k}`);
      }
    }
    if (s.additionalProperties !== undefined && typeof s.additionalProperties !== 'boolean') check(s.additionalProperties, depth + 1, `${at}.additionalProperties`);
    if (s.items !== undefined) check(s.items, depth + 1, `${at}.items`);
    if (s.anyOf !== undefined) {
      if (!Array.isArray(s.anyOf) || s.anyOf.length === 0 || s.anyOf.length > SCHEMA_LIMITS.maxList) throw bad(what, `${at}.anyOf must be a list of 1 to ${SCHEMA_LIMITS.maxList} schemas`);
      s.anyOf.forEach((sub, i) => check(sub, depth + 1, `${at}.anyOf[${i}]`));
    }
  };
  check(schema, 0, '');

  const typeOk = (t, v) => {
    switch (t) {
      case 'string': return typeof v === 'string';
      case 'number': return typeof v === 'number' && Number.isFinite(v);
      case 'integer': return typeof v === 'number' && Number.isInteger(v);
      case 'boolean': return typeof v === 'boolean';
      case 'null': return v === null;
      case 'object': return isObj(v);
      case 'array': return Array.isArray(v);
      default: return false;
    }
  };
  const label = (at) => (at === '' ? 'the arguments' : `"${at}"`);

  /** The first problem of `value` against `s`, or null. `budget.nodes` counts what is visited. */
  const walk = (s, value, depth, at, budget) => {
    if (++budget.nodes > SCHEMA_LIMITS.maxNodes) return `${label(at)}: the arguments are too large to check (more than ${SCHEMA_LIMITS.maxNodes} values)`;
    if (depth > SCHEMA_LIMITS.maxDepth) return `${label(at)}: nested deeper than ${SCHEMA_LIMITS.maxDepth}`;
    if (value === undefined || typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') return `${label(at)} is not plain data`;
    if (s.type !== undefined) {
      const list = Array.isArray(s.type) ? s.type : [s.type];
      if (!list.some((t) => typeOk(t, value))) return `${label(at)} must be ${list.join(' or ')}`;
    }
    if (s.enum !== undefined && !s.enum.some((e) => same(e, value))) return `${label(at)} must be one of ${JSON.stringify(s.enum).slice(0, 120)}`;
    if (s.const !== undefined && !same(s.const, value)) return `${label(at)} must be ${JSON.stringify(s.const).slice(0, 80)}`;
    if (typeof value === 'string') {
      if (s.minLength !== undefined && [...value].length < s.minLength) return `${label(at)} must be at least ${s.minLength} characters`;
      if (s.maxLength !== undefined && [...value].length > s.maxLength) return `${label(at)} must be at most ${s.maxLength} characters`;
    }
    if (typeof value === 'number') {
      if (s.minimum !== undefined && value < s.minimum) return `${label(at)} must be at least ${s.minimum}`;
      if (s.maximum !== undefined && value > s.maximum) return `${label(at)} must be at most ${s.maximum}`;
    }
    if (Array.isArray(value)) {
      if (s.minItems !== undefined && value.length < s.minItems) return `${label(at)} must have at least ${s.minItems} items`;
      if (s.maxItems !== undefined && value.length > s.maxItems) return `${label(at)} must have at most ${s.maxItems} items`;
      for (let i = 0; i < value.length; i++) {
        const p = s.items === undefined ? (value[i] !== null && typeof value[i] === 'object' ? walk({}, value[i], depth + 1, `${at}[${i}]`, budget) : null) : walk(s.items, value[i], depth + 1, `${at}[${i}]`, budget);
        if (p) return p;
      }
    } else if (isObj(value)) {
      const keys = Object.keys(value);
      for (const k of keys) if (NEVER_KEYS.has(k)) return `${label(at)} has the key "${k}", which is never accepted`;
      for (const r of s.required ?? []) if (!Object.hasOwn(value, r)) return `missing required argument "${at === '' ? r : `${at}.${r}`}"`;
      for (const k of keys) {
        const child = at === '' ? k : `${at}.${k}`;
        const known = s.properties !== undefined && Object.hasOwn(s.properties, k);
        if (known) { const p = walk(s.properties[k], value[k], depth + 1, child, budget); if (p) return p; continue; }
        if (s.additionalProperties === false) return `${label(at)} has an argument that is not allowed: "${k}"`;
        const p = walk(isObj(s.additionalProperties) ? s.additionalProperties : {}, value[k], depth + 1, child, budget);
        if (p) return p;
      }
    }
    if (s.anyOf !== undefined) {
      // Every branch sees the same budget, so a hostile value cannot be walked once per branch past the bound.
      if (!s.anyOf.some((sub) => walk(sub, value, depth, at, budget) === null)) return `${label(at)} matches none of the allowed forms`;
    }
    return null;
  };

  return { schema, validate: (value) => walk(schema, value, 0, '', { nodes: 0 }) };
}
