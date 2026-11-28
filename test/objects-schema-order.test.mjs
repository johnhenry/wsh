// A decoded object arrives with its keys in canonical (sorted) order after the canonical-CBOR change (#325), so `enum` / `const` must not depend on key order.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compileSchema } from '../src/objects-schema.mjs';

const v = (schema, value) => compileSchema(schema).validate(value);

describe('enum / const compare objects without regard to key order', () => {
  it('const: the same object in another key order fits', () => {
    const schema = { type: 'object', properties: { mode: { const: { name: 'fast', id: 1 } } } };
    assert.equal(v(schema, { mode: { id: 1, name: 'fast' } }), null);
    assert.equal(v(schema, { mode: { name: 'fast', id: 1 } }), null);
  });
  it('enum: nested objects and arrays, any key order', () => {
    const schema = { enum: [{ a: { x: 1, y: [1, { p: 1, q: 2 }] }, b: 2 }] };
    assert.equal(v(schema, { b: 2, a: { y: [1, { q: 2, p: 1 }], x: 1 } }), null);
  });
  it('still refuses a different value, a different array order, and extra or missing keys', () => {
    const schema = { enum: [{ a: 1, b: [1, 2] }] };
    assert.notEqual(v(schema, { a: 1, b: [2, 1] }), null);
    assert.notEqual(v(schema, { a: 1 }), null);
    assert.notEqual(v(schema, { a: 1, b: [1, 2], c: 3 }), null);
    assert.notEqual(v(schema, { a: 2, b: [1, 2] }), null);
  });
});
