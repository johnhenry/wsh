# wsh key capabilities: notation and evaluation

Version 1 of the notation (the `version` field of `capabilities.vectors.json`).

This document states, in one place, what a capability list means: the grammar of one capability, what the wildcards
match, how a request is checked against a list, and what an implementation does with something it does not understand.
It is written so that an implementation other than `@johnhenry/wsh` (the Rust `wsh-server`, a mesh registry in another
package) can be tested against the same vectors and agree. The words MUST and MUST NOT are meant as in RFC 2119.

Two files go with it and are published in the npm package:

- `spec/capabilities.vectors.json` (`@johnhenry/wsh/spec/capabilities.vectors.json`): "does a holder of list L permit
  request R" as data. The JS evaluation (`permits` in `@johnhenry/wsh/capabilities`) and the Rust `wsh-server` run
  these vectors in their own test suites. An implementation claims conformance by passing the cases that name its host
  class (see "Host classes").
- `spec/key-options.vectors.json`: the `authorized_keys` option syntax (`restrict`, `permit-*`, `command=`,
  `capabilities=`, `expires=`) and the checks of the options themselves. Capabilities are one option of that line.

## Where a list comes from

A capability list is an ordered collection of strings. It reaches an implementation from:

- the `capabilities="a,b,c"` option of an `authorized_keys` line (a comma-separated string);
- the value an `authorize()` callback of a host returns instead of `true` (`{ capabilities: 'a,b' | ['a', 'b'], expires }`);
- a registry of grants in another system that uses the same notation.

The list is **default-deny**: a holder may do exactly what an entry names and nothing else. An empty list (`capabilities=""`)
permits nothing. A key line that has no `capabilities` option has no list and is limited by its other options only
(`restrict`, `permit-*`, `command=`, `max-sessions=`); `permits()` of the JS package treats "no list" as "no grant"
(it returns `false`), because the meaning "this key carries no list" belongs to the options layer.

## Grammar

```
capability  = simple / gateway / unix / named / objects
simple      = "exec" / "pty" / "relay" / "fs:read" / "fs:write"
gateway     = "gateway:tcp:" hostport / "gateway:udp:" hostport / "gateway:listen:tcp:" port
unix        = "unix:" path / "unix:listen:" path
named       = ("endpoint:" / "target:" / "mcp:") name-or-star / "rpc:" name
objects     = "objects:" root [ ":" op ]
hostport    = host ":" port
host        = "*" / "*." domain / domain / "[" ipv6 "]"
port        = "*" / 1..65535        ; decimal, no leading zero
path        = "/*" / dir "/*" / dir ; absolute, see below
op          = "get" / "call" / "set" / "on"
```

- **Whitespace** anywhere in an entry, an empty entry, or an entry that is not a string makes the whole list invalid
  (`bad-capability`).
- `domain`: letters, digits, `.`, `_` and `-`, starting and ending with a letter or digit. A host is compared case
  insensitively (the pattern is lower-cased when parsed, the request's host when checked).
- IP literals: an IPv4 address is a `domain`; an IPv6 address is written in brackets (`[::1]`) in the capability, and a
  request's `host` may be given with or without the brackets.
- `name` (of `endpoint:`, `target:`): 1 to 64 characters, letters, digits, `.`, `_`, `-`, starting with a letter or digit.
  `tool` (of `mcp:`): 1 to 128 characters of letters, digits, `_`, `.`, `:`, `-`, not starting with `.`, `:` or `-`.
  `rpc:NAME` follows the `name` rule and has **no** `*` form.
- `root` (of `objects:`): `*`, or 1 to 64 characters of letters, digits, `_`, `$`, `-`, starting with a letter, `_` or `$`.
- `path`: absolute (`/` first), no empty, `.` or `..` segment, none of space or control characters, `,`, `"`, `'`, `\`.

## What a wildcard matches

There is no general glob. A `*` is only meaningful in the positions below; anywhere else the entry is `bad-capability`.

| Where | Pattern | Matches | Does not match |
| --- | --- | --- | --- |
| host | `*` | every host | |
| host | `*.example.com` | `a.example.com`, `a.b.example.com` | `example.com` (the apex), `evilexample.com`, `example.com.evil.net` |
| host | `db.internal` | `db.internal`, `DB.Internal` | any other name |
| port | `*` | every port | |
| port | `443` | `443` | any other port |
| path | `/srv/*` | any path below `/srv` (`/srv/a`, `/srv/a/b.sock`) | `/srv` itself, `/srvx/a`, a path with `.` or `..` |
| path | `/*` | any absolute path with at least one segment | `/` |
| path | `/run/app.sock` | exactly that path | any other path |
| `endpoint:` `target:` `mcp:` | `*` | every name | |
| `endpoint:` `target:` `mcp:` | `logs` | exactly `logs` (case sensitive) | `Logs`, `logs2` |
| `objects:` root | `*` | every root | |
| `objects:` root | `window` | exactly `window` | `windows` |
| `objects:` operation | absent | all four operations (`get`, `call`, `set`, `on`) and walking | |
| `objects:` operation | `get` | `get`, and walking toward something (`walk`) | `call`, `set`, `on` |

A request path with a `.` or `..` segment, an empty segment, or one that is not absolute matches no path capability.
A wildcard never matches across a different capability kind: `gateway:tcp:*:*` does not allow UDP, `gateway:*` is not a
capability, `unix:` does not grant `unix:listen:`.

## Requests, and what each needs

A request is an object with a `kind`. The capability needed (the name a refusal reports in `capability`) is:

| Request | Needs |
| --- | --- |
| `{ kind: 'open', channel: 'pty' }` | `pty` |
| `{ kind: 'open', channel: 'exec' }` | `exec` |
| `{ kind: 'open', channel: 'file', direction: 'download' }` | `fs:read` |
| `{ kind: 'open', channel: 'file', direction: 'upload' }` | `fs:write` |
| `{ kind: 'open', channel: 'rpc', protocol: 'wsh-fs' }` | `fs:read` and `fs:write` |
| `{ kind: 'open', channel: 'rpc', protocol: 'mcp' }` | `mcp:*` (an `mcp:TOOL` key opens it only through a handler that narrows by tool itself, `scoped: true`) |
| `{ kind: 'open', channel: 'rpc', protocol: 'wsh-objects', scoped: true }` | `rpc:wsh-objects` or any `objects:` entry |
| `{ kind: 'open', channel: 'rpc', protocol: P }` | `rpc:P` |
| `{ kind: 'open', channel: 'rpc', protocol: P, authorizesItself: true }` | nothing from the list: a handler that asks the host's own `permits` for every call (`handler.authorizesItself = true`) is opened by any key the options and expiry let in; its own checks decide |
| `{ kind: 'file-op', op }` | `fs:read` for `stat`, `list`, `read`; `fs:write` for every other `op` |
| `{ kind: 'mcp' }` (discovery) | any `mcp:` entry |
| `{ kind: 'mcp-call' | 'mcp-tool', tool }` | `mcp:TOOL` or `mcp:*` |
| `{ kind: 'objects', root, op }` | `objects:ROOT[:OP]` that names `root` and `op` (see below) |
| `{ kind: 'relay' }` | `relay` |
| `{ kind: 'key-admin' }` | nothing can: a key with a list may never install another key |
| `{ kind: 'tcp' \| 'udp', host, port }` | `gateway:tcp:` / `gateway:udp:` with a matching host and port |
| `{ kind: 'dns', name }` | a `gateway:tcp:` entry whose host matches `name` (any port) |
| `{ kind: 'listen-tcp', port }` | `gateway:listen:tcp:` with a matching port |
| `{ kind: 'unix' \| 'listen-unix', path }` | `unix:` / `unix:listen:` with a matching path |
| `{ kind: 'endpoint', name }` | `endpoint:NAME` or `endpoint:*` |
| `{ kind: 'target', name }` | `target:NAME` or `target:*` |

A request of `kind` `open`, `file-op` or `endpoint` MAY carry `target`: the execution target it names. Then the list
needs `target:NAME` (or `target:*`) in addition to the capability above. A request with no `target` (the host's own
backends) needs no `target:` entry. A request of a `kind` not in this table is refused, whatever the list holds.

### Objects

`objects:ROOT[:OP]` scopes the remote-object protocol `wsh-objects`:

- a request is `{ kind: 'objects', root, op }` with `op` one of `get`, `call`, `set`, `on`, or `walk` (reading on the way to
  something else). `describe` and `snapshot` are `get`; a `construct` is a `call`;
- `objects:ROOT` (no operation) covers every operation on `ROOT`; `objects:ROOT:get` covers `get` and `walk` on `ROOT`;
- a list that has **no** `objects:` entry is limited by `rpc:wsh-objects` alone: all roots, every operation (the behaviour
  before `objects:` existed). A list that names any `objects:` entry is limited to what its `objects:` entries name,
  whatever `rpc:wsh-objects` says;
- the capability decides what a key MAY do on a root; the host's own allow-lists and `authorize()` decide what exists.
  Both must allow.

## Order of the checks

1. **Expiry.** A key with an `expires` timestamp (RFC 3339, `2030-01-01T00:00:00Z`; an offset is honoured; fractional seconds
   are dropped; lower-case `t`/`z`, a date without a time and leap seconds are refused as `bad-value`) is refused
   with `key-expired` at the instant it is reached (`now >= expires`), for every request including the login.
2. **The options**: `restrict` and the `permit-*` flags, `command=`, `max-sessions=` (see `key-options.vectors.json`).
   `restrict` alone grants nothing; each `permit-*` flag grants one family back; `command="..."` ties the key to one
   command. The options are checked before the capabilities, so an option that refuses wins over a capability that would grant.
3. **The capability list**, when the key has one. A request that no entry covers is refused with `capability-missing`,
   and the refusal names the capability that was needed (`refusal.capability`, e.g. `gateway:tcp:db.internal:22`).

`expires` and the options are properties of the key, not entries of the list; `permits()` of the JS package takes `expires`
and `now` as options and evaluates the list only.

## Unknown and malformed entries: fail closed

An implementation MUST NOT skip an entry it does not understand and grant the rest:

- an entry that matches no known form is `unknown-capability` (`capabilities="exec,teleport"`);
- an entry of a known form with a bad argument is `bad-capability` (`gateway:tcp:host` with no port, `objects:window:fly`);
- either one invalidates the whole list: the key is refused outright (the host does not load it), and `permits()` returns
  `false` for every request.

A newer revision of the notation will add forms; an implementation of this revision therefore refuses a list that uses
them, and a list is only as portable as the oldest implementation that will read it.

## Host classes

Not every implementation serves every capability. A vector case names the host classes it applies to in `hosts`
(default: all of them):

- `node`: the JS implementation (`@johnhenry/wsh/server`, the memory host, the page host) and anything that adopts the JS
  evaluation.
- `rust`: the Rust `wsh-server`. It has no named endpoints, no execution targets and no `wsh-objects`.

The Rust server states its subset by refusing, not by ignoring: a key line with an `objects:` entry is refused at load with
`unknown-capability`. That is the conservative choice: a capability that is silently ignored would look like a grant that
was withheld, and a key that is meant for a page would sit unnoticed on a machine whose server cannot honour it. The
vectors record this as `rust` outcomes of the `lists` cases. `endpoint:` and `target:` entries parse on both; the Rust
server serves neither, so its request vectors for them carry `hosts: ["node"]`.

## What the vectors do not pin

- Which request kinds an implementation can issue. A vector marked `node` is not a promise that every Node host issues it.
- The wording of a refusal `reason`; only `code` and `capability` are stable.
- Anything about how a list is transported (the `capabilities=` quoting is the options syntax of `key-options.vectors.json`).
