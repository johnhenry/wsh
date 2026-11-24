// A window-shaped object for the tests of `@johnhenry/wsh/page`: a tiny DOM (elements, attributes, text, focus, events), a location,
// a WebSocket constructor, and timers a test can drive. No test of the page entry point touches the real global.
import { WebSocket as WsClient } from 'ws';
import { webcrypto } from 'node:crypto';

class FakeEvent {
  constructor(type, props = {}) { this.type = type; Object.assign(this, props); this.defaultPrevented = false; }
  preventDefault() { this.defaultPrevented = true; }
}

export class FakeElement {
  constructor(doc, tag) {
    this.ownerDocument = doc; this.tagName = tag.toUpperCase(); this.attributes = new Map(); this.children = []; this.parentNode = null;
    this.listeners = new Map(); this._text = '';
  }
  setAttribute(k, v) { this.attributes.set(k, String(v)); }
  getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  appendChild(c) { if (c.parentNode) c.remove(); c.parentNode = this; this.children.push(c); return c; }
  remove() { if (this.parentNode) { this.parentNode.children = this.parentNode.children.filter((c) => c !== this); this.parentNode = null; } }
  get isConnected() { let n = this; while (n.parentNode) n = n.parentNode; return n === this.ownerDocument.documentElement; }
  addEventListener(type, fn) { if (!this.listeners.has(type)) this.listeners.set(type, []); this.listeners.get(type).push(fn); }
  dispatch(type, props) { const ev = new FakeEvent(type, props); for (const fn of this.listeners.get(type) ?? []) fn(ev); return ev; }
  click() { return this.dispatch('click'); }
  focus() { this.ownerDocument.activeElement = this; }
  /** Every descendant (and this element) for which `pred` holds. */
  findAll(pred, out = []) { if (pred(this)) out.push(this); for (const c of this.children) c.findAll(pred, out); return out; }
}

export function createFakeWindow({ origin = 'https://shop.example', WebSocket = WsClient, document = true } = {}) {
  const win = {
    location: { origin },
    closed: false,
    WebSocket,
    crypto: webcrypto,
    navigator: {},
    listeners: new Map(),
    addEventListener(type, fn) { if (!this.listeners.has(type)) this.listeners.set(type, []); this.listeners.get(type).push(fn); },
    removeEventListener(type, fn) { this.listeners.set(type, (this.listeners.get(type) ?? []).filter((f) => f !== fn)); },
    fire(type) { for (const fn of this.listeners.get(type) ?? []) fn(new FakeEvent(type)); },
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id),
    setInterval: (fn, ms) => setInterval(fn, ms),
    clearInterval: (id) => clearInterval(id),
  };
  if (document) {
    const doc = { activeElement: null };
    doc.createElement = (tag) => new FakeElement(doc, tag);
    doc.documentElement = new FakeElement(doc, 'html');
    doc.body = new FakeElement(doc, 'body');
    doc.documentElement.appendChild(doc.body);
    doc.find = (attr, value) => doc.documentElement.findAll((e) => e.attributes.get('data-wsh-page') === attr && (value === undefined || e.attributes.get('data-fingerprint') === value));
    win.document = doc;
  }
  return win;
}

/** Timers a test drives by hand: `run()` fires every pending timeout, `tick()` every interval once. */
export function manualTimers() {
  let next = 1;
  const timeouts = new Map();
  const intervals = new Map();
  return {
    timeouts, intervals,
    setTimeout: (fn, ms) => { const id = next++; timeouts.set(id, { fn, ms }); return id; },
    clearTimeout: (id) => { timeouts.delete(id); },
    setInterval: (fn, ms) => { const id = next++; intervals.set(id, { fn, ms }); return id; },
    clearInterval: (id) => { intervals.delete(id); },
    /** Fire the pending timeouts (each once). */
    run() { for (const [id, t] of [...timeouts]) { timeouts.delete(id); t.fn(); } },
    tick() { for (const t of [...intervals.values()]) t.fn(); },
  };
}

/** The part of `window.document` a test looks at: elements the library made, by their `data-wsh-page` value. */
export const byRole = (win, role, fingerprint) => win.document.find(role, fingerprint);
