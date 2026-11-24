/** Type-only fixture: `@johnhenry/wsh/objects` (#190), values mode: the host handler, the lazy references, the helpers. */
import { exposeObjects, createObjectsServer, createObjectsClient, createDuplexPeer, get, set, call, construct, snapshot, describe, on, off, use, release, RemoteHandle, closeObjects, NonValue, ObjectsError, OBJECTS_DEFAULT_LIMITS, type ObjectsHandler } from '@johnhenry/wsh/objects';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createPageHost } from '@johnhenry/wsh/page';
import { WshClient } from '@johnhenry/wsh';

declare const win: Window;

const handler: ObjectsHandler = exposeObjects({
  roots: { window: win },
  mode: 'values',
  handles: { window: { nodes: false } },
  allow: { get: ['window.document.title', 'window.app.**'], call: ['window.app.**'], set: [] },
  authorize: (who, op) => who.username === 'alice' && op.kind !== 'set' && op.path.length > 0,
  limits: { maxOps: 16, maxValueBytes: 65536 },
});
const host = createMemoryHost({ auth: { authorizedKeys: 'ssh-ed25519 AAAA' }, rpc: { 'wsh-objects': handler } });
void [host, handler.rootNames, handler.limits.maxDepth, handler.closeSessions('bye', 'ab'), OBJECTS_DEFAULT_LIMITS.maxOps];

async function farSide(client: WshClient): Promise<void> {
  const page = await client.openObjects<{ window: any }>();
  const title: string = await page.window.document.title;
  const n = await page.window.app.cart.items.length;
  await set(page.window.document, 'title', 'Paid');
  const r = await call(page.window.app.cart.add, { sku: 'A1' });
  const c = await construct(page.window.app.Cart, 'x');
  const state = await snapshot(page.window.app.state, { depth: 3, maxBytes: 256_000 });
  const shape = await describe(page.window.app);
  const then = await get(page.window.app, 'then');
  if (c instanceof NonValue) void [c.kind, c.type, c.text];
  void [title, n, r, state, shape.keys[0]?.key, then];
  const stop = await on(page.window.app.bus, 'ready', (data, { type, seq, dropped }) => { void [data, type, seq, dropped]; }, { fields: ['detail'], onError: (e) => { void e; } });
  await off(stop);
  const cb = (x: unknown): void => { void x; };
  await page.window.app.subscribe(cb);
  await release(cb);
  void createObjectsClient(createDuplexPeer({ send: () => {} }), { onCallbackError: (e) => { void e; }, onCallbackDropped: ({ dropped, fn }) => { void [dropped, fn]; } });
  const cart = await page.window.app.cart;
  if (cart instanceof RemoteHandle) { void [cart.kind, cart.type, cart.preview?.keys]; await use(cart).add({ sku: 'A1' }); const stopCart = await on(use(cart).bus, 'ready', (data) => { void data; }); await off(stopCart); await release(cart); }
  await closeObjects(page);
}
void exposeObjects({ roots: { window: win }, allow: { on: ['window.app.bus@ready'] }, eventFields: { hashchange: ['newURL'] }, limits: { maxSubscriptions: 4, maxEventsPerSecond: 5 } });

const peer = createDuplexPeer({ send: () => {} });
const server = createObjectsServer({ roots: { app: {} }, allow: { get: ['app.**'] } });
server.attach(peer, { who: { username: 'u', fingerprint: null } });
void [farSide, createObjectsClient(peer), new ObjectsError(-32003, 'x', { reason: 'not-allowed' }).reason];

// The page host: object access beside the MCP bridge, paths relative to the root.
void createPageHost({
  window: win, relay: 'wss://relay.example/pipe', name: 'tab', authorizedKeys: ['ssh-ed25519 AAAA'],
  expose: { window: { mode: 'handles', nodes: false, allow: { get: ['document.title', 'app.**'], call: ['app.**'] }, limits: { maxOps: 8, maxHandles: 8 } } },
});
