/** Type-only fixture: typed remotes (#219). A generated `.d.ts` (test/types/fixtures/window-remote.d.ts is what `describeRootTypes` writes, checked by test/objects-types.test.mjs) and the hand-written `Remote<T>`. */
import { set, on, use, rootDescription, RemoteHandle, type Remote, type RemoteRoots } from '@johnhenry/wsh/objects';
import { describeRootTypes, checkTypeText, type RootDescription } from '@johnhenry/wsh/objects-types';
import { exposeObjects } from '@johnhenry/wsh/objects';
import { WshClient } from '@johnhenry/wsh';
import type { WindowRemote } from './fixtures/window-remote.js';

declare const client: WshClient;

async function generated(): Promise<void> {
  const { window } = await client.openObjects<{ window: WindowRemote }>();
  const title: string = await window.document.title;
  // @ts-expect-error a value the host typed as a string is not a number
  const wrong: number = await window.document.title;
  const total: number = await window.app.cart.add({ sku: 'A1', qty: 2 });
  // @ts-expect-error the argument is { sku: string; qty?: number }
  void window.app.cart.add({ sku: 5 });
  // @ts-expect-error a path the file does not name does not exist: nothing is said about what is refused
  void window.app.secret;
  // @ts-expect-error title was allowed as a value, not as a method
  void window.document.title();
  const items = await window.app.cart.items;
  const sku: string = items[0]?.sku ?? '';
  const ping = await window.app.makeBus().ping();
  void (await window.app.config.anything.deep);
  // @ts-expect-error note may be assigned, not read: the key holds no get entry for it
  void window.app.cart.note;
  void [title, wrong, total, sku, ping];

  await set(window.document, 'title', 'x');
  // @ts-expect-error title is a string
  await set(window.document, 'title', 5);
  // @ts-expect-error only title may be assigned on document
  await set(window.document, 'bogus', 1);

  const stop = await on(window.hash, 'hashchange', (data) => { const url: string = data.newURL; void url; }, { fields: ['newURL', 'oldURL'] });
  await stop();
  await on(window.app.bus, 'ready', (data, info) => { void [data.type, info.seq]; });
  // @ts-expect-error the host offers hashchange here, not click
  await on(window.hash, 'click', () => {});
  // @ts-expect-error the field "target" is not one the host offers
  await on(window.hash, 'hashchange', () => {}, { fields: ['target'] });
  // @ts-expect-error a source that offers "ready" does not offer "hashchange"
  await on(window.app.bus, 'hashchange', () => {});
}

interface Item { sku: string; qty?: number }
interface Cart { items: Item[]; add(item: Item): number; note: string; readonly bytes: Uint8Array }
type Shop = { cart: Cart; title: string; count: number };

async function handWritten(): Promise<void> {
  const { shop } = await client.openObjects<RemoteRoots<{ shop: Shop }>>();
  const n: number = await shop.cart.add({ sku: 'A' });
  // @ts-expect-error the argument is an Item
  void shop.cart.add({ sku: 1 });
  const title: string = await shop.title;
  const length: number = await shop.cart.items.length;
  const first: string = await shop.cart.items[0].sku;
  const bytes: Uint8Array = await shop.cart.bytes;
  const whole: Shop = await shop;
  await set(shop, 'title', 'x');
  // @ts-expect-error title is a string
  await set(shop, 'title', 3);
  const typed: Remote<Item> = shop.cart.items[0];
  void [n, title, length, first, bytes, whole, typed];
}

async function untyped(): Promise<void> {
  // The default is today's: anything goes.
  const page = await client.openObjects();
  void (await page.window.document.title);
  await on(page.window.bus, 'whatever', (data) => { void data; }, { fields: ['x'] });
  await set(page.window, 'x', 1);
  const any: any = page;
  await on(any.window.bus, 'ready', () => {});
}

async function handles(): Promise<void> {
  const typed = null as unknown as RemoteHandle<Cart>;
  const cart = use(typed);
  const n: number = await cart.add({ sku: 'A' });
  // @ts-expect-error the argument is an Item
  void cart.add(5);
  const loose = null as unknown as RemoteHandle;
  void (await use(loose).anything.goes);
  void n;
}

async function description(page: { window: unknown }): Promise<void> {
  const d = await rootDescription(page.window);
  const text: string = describeRootTypes(d, { name: 'WindowRemote' });
  const own: RootDescription = { root: 'window', allow: { get: ['window.a'] }, types: { 'window.a': { value: 'string' } } };
  void [text, own, checkTypeText('string'), d.ops, d.handles];
  void exposeObjects({ roots: { window: {} }, allow: { call: ['window.app.add'] }, types: { 'window.app.add': { args: '[a: number]', result: 'number' } } });
}
void [generated, handWritten, untyped, handles, description];
