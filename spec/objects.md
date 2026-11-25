# The `wsh-objects` protocol (remote objects)

Status: describes what `@johnhenry/wsh/objects` (`src/objects-core.mjs`, `src/objects.mjs`) serves and speaks as of 0.50.0, and what the Rust client
(`wsh_client::objects`, `wsh objects`) speaks. It adds nothing to the wire: this file only writes down what the code does. The JavaScript
implementation is the reference; where this text and `src/objects-core.mjs` differ, the code is right and this file is a bug.

A host names some **roots** (objects: a page's `window`, a worker's `self`, a Node object). A peer reaches into them **by path** and only
**cloneable values** cross: plain data, or a name for what is not plain data. There is no distributed object graph. What may be read, called,
set or listened to is decided by the host's allow-lists (paths with `*` and `**`), by `authorize`, and by the key's capabilities
(`objects:ROOT[:OP]`, `spec/capabilities.md`); the protocol only carries the request and the refusal.

## 1. The channel

An rpc channel of protocol `wsh-objects` (`rpc-protocol:wsh-objects` in `ServerHello.features`), opened as any rpc channel is: `Open { kind: rpc,
command: "wsh-objects" }`. On a sealed session or behind a relay the host states `rpc-virtual` and the channel rides `SessionData` (inside the
seal) with `GatewayCredit` backpressure; otherwise it is a data stream. Messages are a CBOR sequence (RFC 8742) of JSON-RPC 2.0 messages
(`{ jsonrpc: "2.0", id, method, params }`, `{ jsonrpc, id, result }`, `{ jsonrpc, id, error: { code, message, data? } }`, notifications without
`id`), bounded by `rpc-max-message:<n>` (default 1 MiB). `$/cancel { id }` cancels a request; `$/progress` is not used by this protocol.

A path is an array of segments in requests (`["app","cart","items"]`), and text with dots for people (`window.app.cart.items`). The first segment of
the text form is the root.

## 2. Requests (peer to host)

Every `params` is an object. A request names where it starts: `root: "window"` (a root the host listed) or `handle: "<id>"` (section 5), never both.

| method | params | result |
|---|---|---|
| `roots` | `{ features?: [string…] }` | `{ roots: [name…], features: [string…] }` |
| `resolve` | `{ root \| handle, ops: [op…] }` | a **wire value** (section 3) |
| `set` | `{ root \| handle, path: [seg…], value }` | `{ ok: true }` |
| `describe` | `{ root \| handle, path?: [seg…] }` | `{ type, keys: [{ key, type, own }…], truncated? }` |
| `snapshot` | `{ root \| handle, path?: [seg…], depth?, maxBytes? }` | a wire value; `truncated: true` when a subtree deeper than `depth` was cut to `null` |
| `subscribe` | `{ id, root, path?: [seg…], type, fields?: [name…] }` | `{ ok: true }` |
| `unsubscribe` | `{ id }` | `{ ok: true, dropped }` |
| `release` | `{ handle }` | `{ ok: true }` |
| `releaseCallback` | `{ id }` | `{ ok: true }` |
| `callbackResult` | `{ rid, value? \| error?: true }` | `{ ok }` (peer to host, section 6) |

`roots` lists only the roots the key may use (`objects:ROOT[:OP]`). `features` is what the host supports: `events`, `callbacks`, `types`, `callback-returns`
(only when an allow-list entry lets a callback return a value) and (when a root opted in) `handles` and `handle-events`. A host that says nothing (before 0.48.0)
supports none of them; a peer must not use a feature the host did not state. A peer says what it can do in the optional `features` of its `roots` request:
`callback-returns` means it answers a callback that asks for a return value (section 6). A host that predates the field ignores it.

**`resolve`** walks a whole chain in one request. `ops` is up to 32 operations, each an object with exactly one of:

- `{ get: key }` read a member;
- `{ call: key, args?: [value…], callbacks?: [[index, id]…] }` call the method `key` of the current value (`this` is the current value);
- `{ construct: key, args?, callbacks? }` `new` the constructor `key`.

The chain continues on the result of each step, so `window.app.getCart().items` is `get app, call getCart, get items`. The path an operation is
judged by is the keys so far, with `()` after a called one (`window.app.getCart().items`): that is what an allow-list entry names. The last operation
is the one the allow-list must allow (`get`, or `call`/`construct` from the `call` list); the ones before it need only be on the way to something
the host allows. At most 16 arguments (`maxArgs`). `callbacks` are section 6.

`set` assigns the last segment of `path` on the object the rest of it reaches. `describe` lists the names the allow-lists could walk to from the path
(`type` is `null`, `boolean`, `number`, `string`, `array`, `object`, `function`, `accessor`…). `snapshot` is a bounded deep copy: `depth` (whole
number, at most the host's `maxDepth`, 8) and `maxBytes` bound it.

**`subscribe`** listens to an event source named by an `allow.on` entry `path@type`: the object at `path` must have `addEventListener` /
`removeEventListener` or `on` / `off`. `id` is a whole number chosen by the peer, at least 1, not yet used on the channel. `type` is a name of
letters, digits and `_ $ : . -` (up to 128). `fields` (at most 16) are extra event properties the host lists for the type (`eventFields`); a field it
does not offer is `not-allowed`. A subscription cannot be made through a handle (0.50.0): `subscribe` takes a `root` only.

## 3. Wire values

The result of `resolve`, `snapshot` is one of:

| shape | meaning |
|---|---|
| `{ v: <plain> }` | plain data, plus `truncated: true` on a `snapshot` that cut something |
| `{ u: <kind>, type?, text? }` | a **named non-value**: something that cannot be cloned |
| `{ h: <id>, kind, type?, preview?: { keys: [name…] } }` | an opaque **handle** (section 5), only on a root that opted in and only if `features` has `handles` |

**Plain data** is `null`, booleans, numbers (integers as CBOR integers, others as floats), text, **bytes** (a CBOR byte string: an `ArrayBuffer`,
a typed array or a `DataView` on the host), arrays and plain objects with text keys. Inside an object or array the rule is JSON's: a member that
cannot be cloned (a function, a node, a class instance, a symbol, an accessor property, `undefined`, a cycle) is left out of an object and is `null`
in an array; the keys `__proto__`, `constructor` and `prototype` are never copied. An integer of 2^63 or more is not plain data (a non-value
`number`). A value is at most `maxDepth` (8) deep and `maxValueBytes` (256 KiB, and under the channel's message bound less 4096) long, else the
request is refused with `limit`.

**Named non-values**, `u` is one of:

| `u` | what it names | `type` / `text` |
|---|---|---|
| `undefined` | `undefined` | |
| `function` | a function | `type`: its name, when printable |
| `symbol` | a symbol | |
| `bigint` | a bigint | `text`: its digits |
| `number` | an integer too large for the wire | `text`: its rendering |
| `Date` | a date | `text`: ISO 8601 (or `Invalid Date`) |
| `RegExp` | a regular expression | `text`: its source and flags |
| `Error` | an error or `DOMException` | `type`: class name, `text`: its message (up to 200 characters) |
| `object` | any other object: a class instance, a node, a Map | `type`: its class name |

`type` is up to 64 printable ASCII characters. **Everything in `type`, `text`, names, previews and strings is the page's own text: untrusted.** A
peer prints it escaped and never interprets it.

**Values sent to the host** (`args`, `set`'s `value`) are plain data only: `null`, booleans, numbers, text, bytes, arrays, plain objects. The host
refuses any other kind (`bad-request`), a key `__proto__`, `constructor` or `prototype` (`always-refused`), values deeper than 8 or longer than
`maxValueBytes`.

## 4. Always-refused names and the rules that hold for every allow-list

Whatever an allow-list says, these are refused (reason `always-refused`): the path segments `__proto__`, `prototype`, `constructor`,
`__defineGetter__`, `__defineSetter__`, `__lookupGetter__`, `__lookupSetter__`, `eval`, `Function`, `import`, `execScript`; `call`, `apply` and
`bind` of a function; `setTimeout`, `setInterval` and `setImmediate` called with a string. A segment is a string of 1 to 256 characters with no
`.`. The names in `NEEDS_LISTING` (`document.cookie`, `localStorage`, `sessionStorage`, `indexedDB`, `navigator.credentials`, `fetch`,
`XMLHttpRequest`, `postMessage`, `open`; and on a root with handles the members that climb back to the window or document) are refused (reason
`needs-listing`) until an allow-list entry **names** them: a wildcard does not.

## 5. Handles

On a root that the host says opts in (`features` has `handles`), a function or an object that is not plain data comes back as a handle
`{ h, kind: "function" | "object", type?, preview? }` instead of a named non-value. A handle is **path-bound**: it stands at the path that produced
it, and every operation through it (`resolve`, `set`, `describe`, `snapshot` with `handle` in place of `root`) is judged by the allow-lists for that
path extended by the member named; a handle never widens what the path grants. `preview.keys` (up to 8 names) is told only where a `get` of the
path would be allowed. The id is 22 characters of base64url from the host's CSPRNG, valid on this channel only (another channel or key finds
nothing: `bad-request` "no such handle"). The table holds 64 handles per channel (`maxHandles`); more is `limit` and **nothing is evicted**. A
handle is given back by `release` and all of them when the channel ends. A handle is not an argument: it means something only on its own channel.

## 6. Callbacks

A function of the peer may be passed to a `call` or `construct` whose allow-list entry ends in `(callback)`: its place in `args` is `null` and
`callbacks` lists `[argumentIndex, id]` (`id` a whole number from 1, the same function the same id). The host's stub is **one-way**: calling it
copies its arguments as plain data, queues a `callback` notification and returns `undefined` at once. The host sends
`callback { id, seq, args: [value…], dropped? }`; calls beyond `maxCallbacksPerSecond` (20), larger than `maxCallbackBytes` (16 KiB), or when the
queue is full are dropped and counted (`dropped`, told with the next delivered call). There are at most 16 callbacks per channel
(`maxCallbacks`). `releaseCallback` kills a stub. `features` has `callbacks`.

**Return values (optional, off unless the host says so).** The allow-list entry is `(callback)` for a one-way stub, `(callback:returns)` when every function it takes
may return a value, `(callback:returns=I,J)` for the functions at those argument positions only (0 to 99). Such a stub returns a promise to the page's code, never
blocks, and the host settles it at the latest `callbackReturnTimeoutMs` (default 2000, at most 30000) after the call: with the value, or with `undefined` in every
other case (timeout, an error in the peer's function, a value that is not plain data or is over `maxCallbackResultBytes` (16384), a call dropped by the rate or size
bound, a full table of waiting calls (`maxPendingCallbackReturns`, default 8, at most 64: such a call is not sent), a released callback, the end of the channel).
A host asks only a peer that listed `callback-returns` in its `roots` request, and says it supports this in `features` (`callback-returns`). The `callback`
notification then has one more field, `rid` (a whole number from 1, per channel): `callback { id, seq, args, dropped?, rid? }`. The peer answers once with the request
`callbackResult { rid, value }` (`value` plain data, left out for `undefined`) or `callbackResult { rid, error: true }` (an error, a function, a handle, anything that
is not plain data: the text of an error is never sent), result `{ ok: true }`, or `{ ok: false }` for a `rid` nobody waits for (late, unknown or already answered);
the host counts such an answer against `maxRequestsPerSecond` and ignores it. A peer that does not answer costs the page the timeout, once per call; a host never has
more than `maxPendingCallbackReturns` calls waiting. In the `types` answer the entry is told as `(callback)`.

## 7. Notifications (host to peer)

- `event { id, seq, data, dropped? }`: `id` is the subscription's, `seq` counts the delivered events of that subscription from 1. `data` is plain: for
  an EventTarget source `{ type, timeStamp, isTrusted, ...fields }`, for an emitter `{ type, args: [value…] }`. `dropped` (when present) is the
  number of events the host dropped (rate `maxEventsPerSecond` 20 per subscription, size `maxEventBytes` 16 KiB, queue `maxQueuedEvents` 100 per
  channel, a slow reader) since the last one it delivered for that subscription. At most 16 subscriptions per channel.
- `callback { id, seq, args, dropped? }`: section 6.
- `closing { reason }`: the host is about to end the channel (the page left, Stop was pressed, a key was revoked).

A peer treats a notification for an id it does not know as noise.

## 8. Errors and limits

An error response is `{ code, message, data: { reason, ... } }`. `message` is a sentence for a person and may carry page-controlled text.

| `code` | meaning | `reason` (in `data`) |
|---|---|---|
| `-32003` | refused | `always-refused`, `not-allowed` (allow-list, or an event type or field the host does not offer), `needs-listing`, `authorize` (the host's `authorize` said no), `not-permitted` (the key's `objects:` capability does not allow the operation on the root), `gone` (the page left) |
| `-32002` | a bound | `limit`, with `limit` (the name: `maxOps`, `maxArgs`, `maxDepth`, `maxValueBytes`, `maxRequestsPerSecond`, `maxHandles`, `maxCallbacks`, `maxSubscriptions`, `callTimeoutMs`) and `max` |
| `-32602` | invalid | `bad-request`, `no-such-root` |
| `-32000` | failed | `bad-path` (reading a member of `null` or `undefined`), `not-a-function`, `threw` (the called code threw), `refused-by-object` (a read-only or frozen assignment), `not-an-event-source`, `cancelled`, `closed` |
| `-32601`, `-32600`, `-32603`, `-32001` | the rpc layer's own: method not found, invalid request, internal error, cancelled | |

`-32002` is also the rpc layer's `stream-limit` (more than 64 requests in flight). The bounds, per attached channel: 32 operations per `resolve`,
16 arguments, depth 8, 256 KiB per value, 200 keys per `describe`, 50 requests per second, 30 s for a call that returns a promise, and the counts
of sections 5 to 7.

## 9. Keys and the host's switches

The caller's key may carry `capabilities="objects:ROOT[:OP]"` (`spec/capabilities.md`): a key that names any `objects:` entry is limited to what they
name (the operation is `get`, `call` (also `construct`), `set` or `on`; `get` also covers `describe`, `snapshot` and walking), may open the
channel without `rpc:wsh-objects`, and is told only of the roots it can use. A key with no `objects:` entry is limited by `rpc:wsh-objects` alone.
The key's capability is asked again for every operation (an expiry holds at call time).

## 10. What a peer must do

- Open the channel only if the host states `rpc-protocol:wsh-objects`; on a sealed session also `rpc-virtual`.
- Ask `roots` first, and use only `features` the host stated; refuse locally, with a name, what it did not state, rather than send what a host
  that does not know it would drop (a function it does not know is `null`).
- Treat every byte of text from the host as untrusted data; never interpret it, never let it reach a terminal unescaped.
- Bound what it accepts: the channel's message bound applies in both directions, and a subscriber that cannot keep up must drop and count, not stop
  reading (stopping reading stops the host's credit, which is the host's backstop, but also every answer behind it).

## 11. What the released peers do

- JavaScript (`@johnhenry/wsh` 0.46.0 to 0.50.0): the reference described above. 0.46.0 and 0.47.0 hosts have no `features` in `roots`, no events, handles or
  callbacks; a peer sees an empty `features`.
- `callback-returns` (callback return values): a 0.51.0 client against a host that states it is never asked for an answer (it did not list the feature), so the page gets
  `undefined` at once and the callback is delivered one-way; a 0.51.0 host ignores the `features` of a `roots` request. The Rust client has no callbacks.
- Rust `wsh-server`: serves no `wsh-objects` channel and no page host, and refuses a key line with an `objects:` capability (an unknown capability
  fails closed). Rust released before the `wsh_client::objects` client (`rust-v0.17.1` and earlier) has no objects client at all.
