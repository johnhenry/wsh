/**
 * A small JSON Schema validator for `@johnhenry/wsh/server`'s MCP tools.
 *
 * MCP arguments come off the wire from an authenticated-but-untrusted client,
 * so the tool's `inputSchema` is enforced before `call()` runs. The package has
 * no runtime dependencies, so this covers the keywords tool schemas actually
 * use rather than all of JSON Schema: `type`, `enum`, `const`, `properties`,
 * `required`, `additionalProperties`, `items`, `min/maxItems`, `uniqueItems`,
 * `min/maxLength`, `pattern`, `minimum`/`maximum` (and exclusive forms),
 * `multipleOf`, `allOf`/`anyOf`/`oneOf`/`not`, and local `$ref` (`#/...`).
 * `format`, `title`, `description`, `default` and other annotations are ignored.
 *
 * A schema that uses a keyword this does not understand is refused up front
 * (`assertSupportedSchema`) rather than silently validating less than the
 * operator wrote.
 */

const TYPES = new Set(['string', 'number', 'integer', 'boolean', 'null', 'object', 'array']);
const IGNORED = new Set([
  '$schema', '$id', '$comment', 'title', 'description', 'default', 'examples', 'format',
  'definitions', '$defs', 'deprecated', 'readOnly', 'writeOnly',
]);
const KNOWN = new Set([
  'type', 'enum', 'const', 'properties', 'required', 'additionalProperties', 'items',
  'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'pattern', 'minimum',
  'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf', 'allOf', 'anyOf',
  'oneOf', 'not', '$ref', 'minProperties', 'maxProperties',
]);
const MAX_DEPTH = 64;

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}

function matchesType(v, t) {
  const actual = typeOf(v);
  return actual === t || (t === 'number' && actual === 'integer');
}

/** Structural JSON equality (for `enum` / `const` / `uniqueItems`). */
function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => Object.hasOwn(b, k) && deepEqual(a[k], b[k]));
}

/**
 * Throw if `schema` uses a keyword this validator does not implement, or is
 * otherwise malformed. Run once when the operator's tools are configured.
 */
export function assertSupportedSchema(schema, path = '#', depth = 0) {
  if (depth > MAX_DEPTH) throw new TypeError(`inputSchema at ${path} is nested too deeply`);
  if (schema === true || schema === false) return;
  if (!isObject(schema)) throw new TypeError(`inputSchema at ${path} must be an object`);
  for (const key of Object.keys(schema)) {
    if (!KNOWN.has(key) && !IGNORED.has(key)) {
      throw new TypeError(`inputSchema at ${path} uses unsupported keyword "${key}"`);
    }
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    for (const t of types) if (!TYPES.has(t)) throw new TypeError(`inputSchema at ${path} has unknown type ${JSON.stringify(t)}`);
  }
  if (schema.pattern !== undefined) {
    try { new RegExp(schema.pattern, 'u'); } catch { throw new TypeError(`inputSchema at ${path} has an invalid pattern`); }
  }
  if (schema.required !== undefined && !(Array.isArray(schema.required) && schema.required.every((r) => typeof r === 'string'))) {
    throw new TypeError(`inputSchema at ${path}: required must be an array of strings`);
  }
  if (isObject(schema.properties)) {
    for (const [k, s] of Object.entries(schema.properties)) assertSupportedSchema(s, `${path}/properties/${k}`, depth + 1);
  } else if (schema.properties !== undefined) {
    throw new TypeError(`inputSchema at ${path}: properties must be an object`);
  }
  if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== 'boolean') {
    assertSupportedSchema(schema.additionalProperties, `${path}/additionalProperties`, depth + 1);
  }
  if (schema.items !== undefined) assertSupportedSchema(schema.items, `${path}/items`, depth + 1);
  for (const k of ['allOf', 'anyOf', 'oneOf']) {
    if (schema[k] === undefined) continue;
    if (!Array.isArray(schema[k])) throw new TypeError(`inputSchema at ${path}: ${k} must be an array`);
    schema[k].forEach((s, i) => assertSupportedSchema(s, `${path}/${k}/${i}`, depth + 1));
  }
  if (schema.not !== undefined) assertSupportedSchema(schema.not, `${path}/not`, depth + 1);
  for (const k of ['definitions', '$defs']) {
    if (isObject(schema[k])) for (const [n, s] of Object.entries(schema[k])) assertSupportedSchema(s, `${path}/${k}/${n}`, depth + 1);
  }
  if (schema.$ref !== undefined && !(typeof schema.$ref === 'string' && schema.$ref.startsWith('#'))) {
    throw new TypeError(`inputSchema at ${path}: only local "#..." $ref is supported`);
  }
}

function resolveRef(root, ref) {
  if (ref === '#') return root;
  if (!ref.startsWith('#/')) return undefined;
  let node = root;
  for (const raw of ref.slice(2).split('/')) {
    const seg = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (!isObject(node) && !Array.isArray(node)) return undefined;
    if (!Object.hasOwn(node, seg)) return undefined;
    node = node[seg];
  }
  return node;
}

/**
 * Validate `value` against `schema`.
 * @returns {string | null} `null` when valid, otherwise a short reason naming the path.
 */
export function validateSchema(schema, value) {
  const fail = (path, msg) => `${path || '/'}: ${msg}`;

  function check(s, v, path, depth) {
    if (depth > MAX_DEPTH) return fail(path, 'schema or value nested too deeply');
    if (s === true) return null;
    if (s === false) return fail(path, 'no value is allowed here');
    if (s.$ref !== undefined) {
      const target = resolveRef(schema, s.$ref);
      if (target === undefined) return fail(path, `unresolvable $ref ${s.$ref}`);
      const r = check(target, v, path, depth + 1);
      if (r) return r;
    }
    if (s.type !== undefined) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      if (!types.some((t) => matchesType(v, t))) return fail(path, `expected ${types.join(' | ')}, got ${typeOf(v)}`);
    }
    if (s.enum !== undefined && !s.enum.some((e) => deepEqual(e, v))) return fail(path, 'not one of the allowed values');
    if (s.const !== undefined && !deepEqual(s.const, v)) return fail(path, 'does not equal the required constant');

    if (typeof v === 'string') {
      const len = [...v].length;
      if (s.minLength !== undefined && len < s.minLength) return fail(path, `shorter than ${s.minLength}`);
      if (s.maxLength !== undefined && len > s.maxLength) return fail(path, `longer than ${s.maxLength}`);
      if (s.pattern !== undefined && !new RegExp(s.pattern, 'u').test(v)) return fail(path, 'does not match the required pattern');
    }
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) return fail(path, 'must be a finite number');
      if (s.minimum !== undefined && v < s.minimum) return fail(path, `below the minimum ${s.minimum}`);
      if (s.maximum !== undefined && v > s.maximum) return fail(path, `above the maximum ${s.maximum}`);
      if (typeof s.exclusiveMinimum === 'number' && v <= s.exclusiveMinimum) return fail(path, `must be above ${s.exclusiveMinimum}`);
      if (typeof s.exclusiveMaximum === 'number' && v >= s.exclusiveMaximum) return fail(path, `must be below ${s.exclusiveMaximum}`);
      if (s.multipleOf !== undefined) {
        const q = v / s.multipleOf;
        if (Math.abs(q - Math.round(q)) > 1e-9) return fail(path, `not a multiple of ${s.multipleOf}`);
      }
    }
    if (Array.isArray(v)) {
      if (s.minItems !== undefined && v.length < s.minItems) return fail(path, `fewer than ${s.minItems} items`);
      if (s.maxItems !== undefined && v.length > s.maxItems) return fail(path, `more than ${s.maxItems} items`);
      if (s.uniqueItems === true) {
        for (let i = 0; i < v.length; i++) {
          for (let j = i + 1; j < v.length; j++) if (deepEqual(v[i], v[j])) return fail(path, 'items are not unique');
        }
      }
      if (s.items !== undefined) {
        for (let i = 0; i < v.length; i++) {
          const r = check(s.items, v[i], `${path}/${i}`, depth + 1);
          if (r) return r;
        }
      }
    }
    if (isObject(v)) {
      const keys = Object.keys(v);
      if (s.minProperties !== undefined && keys.length < s.minProperties) return fail(path, `fewer than ${s.minProperties} properties`);
      if (s.maxProperties !== undefined && keys.length > s.maxProperties) return fail(path, `more than ${s.maxProperties} properties`);
      for (const r of s.required ?? []) if (!Object.hasOwn(v, r)) return fail(path, `missing required property "${r}"`);
      const props = isObject(s.properties) ? s.properties : {};
      for (const k of keys) {
        if (Object.hasOwn(props, k)) {
          const r = check(props[k], v[k], `${path}/${k}`, depth + 1);
          if (r) return r;
        } else if (s.additionalProperties === false) {
          return fail(path, `unexpected property "${k}"`);
        } else if (s.additionalProperties !== undefined && s.additionalProperties !== true) {
          const r = check(s.additionalProperties, v[k], `${path}/${k}`, depth + 1);
          if (r) return r;
        }
      }
    }

    for (const sub of s.allOf ?? []) {
      const r = check(sub, v, path, depth + 1);
      if (r) return r;
    }
    if (s.anyOf && !s.anyOf.some((sub) => check(sub, v, path, depth + 1) === null)) return fail(path, 'matches none of the anyOf alternatives');
    if (s.oneOf) {
      const n = s.oneOf.filter((sub) => check(sub, v, path, depth + 1) === null).length;
      if (n !== 1) return fail(path, `matches ${n} of the oneOf alternatives, expected exactly 1`);
    }
    if (s.not !== undefined && check(s.not, v, path, depth + 1) === null) return fail(path, 'matches a schema it must not match');
    return null;
  }

  return check(schema, value, '', 0);
}
