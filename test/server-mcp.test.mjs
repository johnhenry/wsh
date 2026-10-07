// test/server-mcp.test.mjs -- `@johnhenry/wsh/server`'s MCP tools (#71), driven
// by the stock client and the stock WshMcpBridge.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, WshMcpBridge, generateKeyPair, exportPublicKeySSH, MSG } from '@johnhenry/wsh';
import { validateSchema, assertSupportedSchema } from '../src/server/json-schema.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('server MCP tools', () => {
  let keyPair;
  let authorizedKeys;
  let ctx;
  const calls = [];
  const aborted = [];

  const tools = [
    { name: 'echo', description: 'Echo a message',
      inputSchema: { type: 'object', properties: { message: { type: 'string' } }, required: ['message'], additionalProperties: false },
      call: async ({ message }, { user }) => ({ success: true, output: `${user}: ${message}` }) },
    { name: 'add', description: 'Add two integers',
      inputSchema: { type: 'object', properties: { a: { type: 'integer' }, b: { type: 'integer', minimum: 0 } }, required: ['a', 'b'] },
      call: ({ a, b }) => a + b },
    { name: 'slow', description: 'Replies late', call: async () => { await sleep(80); return { success: true, output: 'RESULT OF slow' }; } },
    { name: 'fast', description: 'Replies at once', call: async () => ({ success: true, output: 'RESULT OF fast' }) },
    { name: 'boom', description: 'Always throws', call: async () => { throw new Error('kaboom'); } },
    { name: 'hang', description: 'Waits for its signal',
      call: (args, { signal }) => new Promise((resolve) => {
        calls.push('hang-started');
        signal.addEventListener('abort', () => { aborted.push('hang'); resolve('aborted'); }, { once: true });
      }) },
    { name: 'secret', description: 'Only for bob', call: () => 'classified' },
  ];

  const connect = async (username = 'alice') => {
    const client = new WshClient();
    await client.connect(ctx.url, { username, keyPair });
    return client;
  };

  before(async () => {
    keyPair = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} test\n`;
    const server = createWshServer({
      auth: { authorizedKeys },
      mcp: {
        tools,
        authorize: (user, tool) => tool.name !== 'secret' || user === 'bob',
        maxConcurrent: 4,
        timeoutMs: 400,
      },
    });
    const { port } = await server.listen();
    ctx = { server, url: `ws://127.0.0.1:${port}` };
  });
  after(() => ctx.server.close());

  it('advertises mcp-call-id so the client correlates calls', async () => {
    const client = await connect();
    try { assert.ok(client.hasFeature('mcp-call-id')); } finally { await client.disconnect?.(); }
  });

  it('discoverTools() lists the operator\'s tools with their schemas, minus those authorize() hides', async () => {
    const client = await connect('alice');
    try {
      const listed = await client.discoverTools();
      assert.deepEqual(listed.map((t) => t.name).sort(), ['add', 'boom', 'echo', 'fast', 'hang', 'slow']);
      const echo = listed.find((t) => t.name === 'echo');
      assert.equal(echo.description, 'Echo a message');
      assert.deepEqual(echo.parameters.required, ['message']);
      const bob = await connect('bob');
      try { assert.ok((await bob.discoverTools()).some((t) => t.name === 'secret')); } finally { await bob.disconnect?.(); }
    } finally { await client.disconnect?.(); }
  });

  it('WshMcpBridge.discover() and call() work against it', async () => {
    const client = await connect();
    try {
      const bridge = new WshMcpBridge(client);
      const specs = await bridge.discover();
      assert.ok(specs.some((t) => t.name === 'echo'));
      assert.deepEqual(await bridge.call('echo', { message: 'hi' }), { success: true, output: 'alice: hi', error: undefined });
    } finally { await client.disconnect?.(); }
  });

  it('callTool() returns a tool\'s plain return value as the result', async () => {
    const client = await connect();
    try { assert.equal(await client.callTool('add', { a: 2, b: 3 }), 5); } finally { await client.disconnect?.(); }
  });

  it('concurrent calls each get their own result, even when a later one finishes first (#32)', async () => {
    const client = await connect();
    try {
      const [slow, fast, sum] = await Promise.all([
        client.callTool('slow', {}), client.callTool('fast', {}), client.callTool('add', { a: 1, b: 1 }),
      ]);
      assert.equal(slow.output, 'RESULT OF slow');
      assert.equal(fast.output, 'RESULT OF fast');
      assert.equal(sum, 2);
      const bridge = new WshMcpBridge(client);
      const [bs, bf] = await Promise.all([bridge.call('slow', {}), bridge.call('fast', {})]);
      assert.equal(bs.output, 'RESULT OF slow');
      assert.equal(bf.output, 'RESULT OF fast');
    } finally { await client.disconnect?.(); }
  });

  it('echoes call_id verbatim on the wire', async () => {
    const client = await connect();
    try {
      const seen = [];
      client.addControlListener((msg) => { if (msg.type === MSG.MCP_RESULT) seen.push(msg); });
      await client.callTool('fast', {});
      assert.equal(seen.length, 1);
      assert.match(seen[0].call_id, /^mcp-/);
    } finally { await client.disconnect?.(); }
  });

  it('an unknown tool is an error result, not a hang', async () => {
    const client = await connect();
    try {
      const r = await client.callTool('nope', {});
      assert.equal(r.success, false);
      assert.match(r.error, /unknown tool: nope/);
    } finally { await client.disconnect?.(); }
  });

  it('a tool hidden by authorize() is indistinguishable from an unknown one', async () => {
    const client = await connect('alice');
    try {
      const r = await client.callTool('secret', {});
      assert.equal(r.success, false);
      assert.match(r.error, /unknown tool: secret/);
      const bob = await connect('bob');
      try { assert.equal(await bob.callTool('secret', {}), 'classified'); } finally { await bob.disconnect?.(); }
    } finally { await client.disconnect?.(); }
  });

  it('refuses arguments that do not satisfy inputSchema, without running the tool', async () => {
    const client = await connect();
    try {
      for (const [tool, args, why] of [
        ['echo', {}, /missing required property "message"/],
        ['echo', { message: 5 }, /expected string/],
        ['echo', { message: 'x', extra: 1 }, /unexpected property "extra"/],
        ['add', { a: 1.5, b: 1 }, /expected integer/],
        ['add', { a: 1, b: -1 }, /below the minimum/],
      ]) {
        const r = await client.callTool(tool, args);
        assert.equal(r.success, false, `${tool} ${JSON.stringify(args)}`);
        assert.match(r.error, /invalid arguments/);
        assert.match(r.error, why);
      }
    } finally { await client.disconnect?.(); }
  });

  it('a tool that throws yields an error result and the connection keeps working', async () => {
    const client = await connect();
    try {
      const r = await client.callTool('boom', {});
      assert.deepEqual(r, { success: false, error: 'kaboom' });
      assert.equal((await client.callTool('fast', {})).output, 'RESULT OF fast');
    } finally { await client.disconnect?.(); }
  });

  it('a tool that never returns is cut off at timeoutMs and its signal fires', async () => {
    const client = await connect();
    try {
      aborted.length = 0;
      const r = await client.callTool('hang', {});
      assert.equal(r.success, false);
      assert.match(r.error, /timed out after 400ms/);
      assert.deepEqual(aborted, ['hang']);
    } finally { await client.disconnect?.(); }
  });

  it('aborts in-flight calls when the client disconnects', async () => {
    const client = await connect();
    aborted.length = 0;
    calls.length = 0;
    const pending = client.callTool('hang', {}, 5000).catch(() => {});
    for (let i = 0; i < 100 && !calls.length; i++) await sleep(10);
    assert.deepEqual(calls, ['hang-started']);
    await client.disconnect?.();
    for (let i = 0; i < 100 && !aborted.length; i++) await sleep(10);
    assert.deepEqual(aborted, ['hang']);
    await pending;
  });

  it('caps concurrent calls per connection', async () => {
    const client = await connect();
    try {
      const results = await Promise.all(Array.from({ length: 6 }, () => client.callTool('slow', {})));
      const refused = results.filter((r) => r.success === false);
      assert.equal(refused.length, 2);
      assert.ok(refused.every((r) => /too many concurrent/.test(r.error)));
      assert.equal(results.filter((r) => r.output === 'RESULT OF slow').length, 4);
    } finally { await client.disconnect?.(); }
  });

  it('answers MCP only after authentication', async () => {
    // Speak the handshake by hand and send McpDiscover/McpCall before authenticating.
    const { WebSocketTransport } = await import('../src/transport-ws.mjs');
    const { hello, mcpDiscover, mcpCall } = await import('../src/messages.gen.mjs');
    const transport = new WebSocketTransport();
    const heard = [];
    transport.onControl = (m) => heard.push(m.type);
    await transport.connect(ctx.url);
    await transport.sendControl(hello({ username: 'alice' }));
    await transport.sendControl(mcpDiscover());
    await transport.sendControl(mcpCall({ tool: 'fast', arguments: {}, callId: 'x' }));
    await sleep(200);
    await transport.close();
    assert.ok(heard.includes(MSG.SERVER_HELLO));
    assert.ok(!heard.includes(MSG.MCP_TOOLS) && !heard.includes(MSG.MCP_RESULT), `heard ${heard.join(',')}`);
  });
});

describe('server MCP: without an mcp option', () => {
  it('answers McpDiscover with no tools and McpCall with an error instead of leaving the client to time out', async () => {
    const keyPair = await generateKeyPair(true);
    const server = createWshServer({ auth: { authorizedKeys: `${await exportPublicKeySSH(keyPair.publicKey)} t\n` } });
    const { port } = await server.listen();
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      assert.equal(client.hasFeature('mcp-call-id'), false);
      assert.deepEqual(await client.discoverTools(), []);
      const r = await client.callTool('anything', {});
      assert.equal(r.success, false);
      assert.match(r.error, /not enabled/);
    } finally { await client.disconnect?.(); await server.close(); }
  });
});

describe('server MCP: proxying an MCP client', () => {
  it('lists and calls the proxied client\'s tools, validating against their schemas', async () => {
    const keyPair = await generateKeyPair(true);
    const seen = [];
    const fake = {
      listTools: async () => ({ tools: [
        { name: 'ping', description: 'p', inputSchema: { type: 'object', properties: { n: { type: 'number' } }, required: ['n'] } },
        { name: 'bad', description: 'uses an unsupported keyword', inputSchema: { type: 'object', patternProperties: { '.': {} } } },
      ] }),
      callTool: async (params) => {
        seen.push(params);
        if (params.name === 'ping' && params.arguments.n === 0) return { isError: true, content: [{ type: 'text', text: 'zero' }] };
        return { content: [{ type: 'text', text: `pong ${params.arguments.n}` }] };
      },
    };
    const server = createWshServer({
      auth: { authorizedKeys: `${await exportPublicKeySSH(keyPair.publicKey)} t\n` },
      mcp: { client: fake, tools: [{ name: 'local', description: 'l', call: () => 'L' }] },
    });
    const { port } = await server.listen();
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      assert.deepEqual((await client.discoverTools()).map((t) => t.name).sort(), ['local', 'ping']);
      assert.deepEqual(await client.callTool('ping', { n: 3 }), [{ type: 'text', text: 'pong 3' }]);
      assert.deepEqual(seen, [{ name: 'ping', arguments: { n: 3 } }]);
      assert.match((await client.callTool('ping', { n: 'x' })).error, /invalid arguments/);
      assert.deepEqual(await client.callTool('ping', { n: 0 }), { success: false, error: 'zero' });
      assert.match((await client.callTool('bad', {})).error, /unknown tool/); // unenforceable schema: not exposed
      assert.equal(await client.callTool('local', {}), 'L');
      assert.equal(seen.length, 2, 'invalid calls never reach the proxied client');
    } finally { await client.disconnect?.(); await server.close(); }
  });
});

describe('server MCP: configuration', () => {
  it('rejects tools it cannot run or enforce when the server is created', () => {
    assert.throws(() => createWshServer({ mcp: { tools: [{ name: 'x' }] } }), /needs a call/);
    assert.throws(() => createWshServer({ mcp: { tools: [{ name: 'x', call() {}, inputSchema: { type: 'object', patternProperties: {} } }] } }), /unsupported keyword "patternProperties"/);
    assert.throws(() => createWshServer({ mcp: { tools: [{ name: 'x', call() {} }, { name: 'x', call() {} }] } }), /duplicate/);
    assert.throws(() => createWshServer({ mcp: { client: {} } }), /listTools/);
  });
  it('accepts a { name: spec } map', () => {
    createWshServer({ mcp: { tools: { x: { description: 'd', call() {} } } } });
  });
});

describe('JSON Schema subset', () => {
  const ok = (schema, v) => assert.equal(validateSchema(schema, v), null, JSON.stringify(v));
  const bad = (schema, v, re) => assert.match(validateSchema(schema, v) ?? '', re ?? /./, JSON.stringify(v));
  it('types, enums, ranges, lengths', () => {
    ok({ type: 'integer' }, 3); bad({ type: 'integer' }, 3.5); ok({ type: 'number' }, 3);
    ok({ type: ['string', 'null'] }, null); bad({ type: ['string', 'null'] }, 1);
    ok({ enum: ['a', 1] }, 1); bad({ enum: ['a'] }, 'b');
    bad({ type: 'string', maxLength: 2 }, 'abc'); bad({ type: 'string', pattern: '^a' }, 'b');
    bad({ type: 'number', exclusiveMaximum: 1 }, 1); bad({ type: 'number', multipleOf: 2 }, 3);
  });
  it('objects, arrays, combinators and local $ref', () => {
    bad({ type: 'array', items: { type: 'string' } }, ['a', 1], /\/1/);
    bad({ type: 'array', uniqueItems: true }, [{ a: 1 }, { a: 1 }]);
    ok({ oneOf: [{ type: 'string' }, { type: 'number' }] }, 1); bad({ oneOf: [{ type: 'number' }, { type: 'integer' }] }, 1);
    ok({ anyOf: [{ type: 'string' }, { type: 'number' }] }, 'x'); bad({ not: { type: 'string' } }, 'x');
    const schema = { type: 'object', properties: { n: { $ref: '#/$defs/n' } }, $defs: { n: { type: 'integer' } } };
    ok(schema, { n: 1 }); bad(schema, { n: 'x' });
    bad({ type: 'object', additionalProperties: { type: 'number' } }, { a: 'x' });
    // inherited names are not properties
    bad({ type: 'object', required: ['toString'] }, {});
  });
  it('refuses schemas that use keywords it does not implement', () => {
    assert.throws(() => assertSupportedSchema({ type: 'object', if: {} }), /unsupported keyword "if"/);
    assert.throws(() => assertSupportedSchema({ $ref: 'http://x' }), /local/);
  });
});
