# Agent playbook

`@johnhenry/wsh` — browser-native remote command execution over
WebTransport/WebSocket with Ed25519 authentication. Single npm package
(no workspaces), Node >= 26, `node --test` (`npm test`), ships source
directly (`src/`, no build step for the JS SDK). A separate Cargo
workspace under `crates/` (`wsh-core`, `wsh-client`, `wsh-cli`,
`wsh-server`) is a native Rust implementation of the same wire protocol,
versioned and released independently of the npm package. Protocol message
types are generated from `spec/wsh-v1.yaml` into both languages — never
hand-edit a `*.gen.*` file.

`CLAUDE.md` in this directory is a symlink to this file.

## The verification loop (before every push)

```bash
npm test                # node --test test/*.test.mjs -- JS SDK only
npm run codegen:check   # spec/wsh-v1.yaml vs the three generated outputs
cargo build --workspace # if crates/ changed
cargo test --workspace  # if crates/ changed
cargo fmt --all -- --check
```

- `npm run codegen:check` regenerates all three codegen outputs
  (`src/messages.gen.mjs`, `spec/wsh-v1.md`,
  `crates/wsh-core/src/messages.gen.rs`) into a scratch dir and diffs
  against the checked-in copies -- run it after any `spec/wsh-v1.yaml`
  change, and run `npm run codegen` to actually update the checked-in files
  before committing.
- `npm run test:rust` (`test/rust/*.test.mjs`) spawns the real
  `wsh-server` binary and drives it with this repo's own JS client. It is
  **not** part of `npm test` so JS-only contributors never need a Rust
  toolchain; build the release binary first (`cargo build --release -p
  wsh-server`) or set `WSH_SERVER_BIN`.
- `npm run examples` -- every file in `examples/0*.mjs` is self-verifying;
  CI runs it as a smoke test.
- A genuinely fresh clone before a release:
  `git clone . /tmp/wsh-verifyN && cd $_ && npm ci && npm test`.

CI (`.github/workflows/ci.yml`) runs the Node suite and a separate `rust`
job (fmt/build/test blocking, clippy non-blocking); match both locally
before pushing a change that touches `crates/`.

## Repo-specific gotchas

- **Generated files are not source.** `src/messages.gen.mjs`,
  `spec/wsh-v1.md`, and `crates/wsh-core/src/messages.gen.rs` all come from
  `spec/wsh-v1.yaml` via `spec/codegen.mjs`. Hand-editing any of them is
  invisible until `npm run codegen:check` (or CI) catches the drift.
- **Two peers racing `initiateE2E()` at once used to stall (#33).**
  `#handleControl` discards a `KEY_EXCHANGE` no waiter is listening for; if
  the waiter is registered *after* the local key pair finishes generating,
  whichever peer finishes first sends into the other's blind window and the
  message is never repeated. Both round-1 and round-2 waiters must be
  registered before the `await`s they're racing, not after.
- **The E2E frame role tag must be checked on receive, not just written on
  send (#35).** Before this was fixed, a peer's own frame could be
  reflected back at it and `openFrame()` would accept it. Any change to the
  E2E frame path needs a test that a self-reflected frame is rejected.
- **`WshSession.onClose` has two independent close paths that must agree
  (#36, #37).** A parked file chunk is settled on one path and wasn't on
  the other before the fix; `closeReason` and both teardown paths need to
  move together, not be patched independently.
- **`ServerHello.host_fingerprint` (TOFU host identity, wsh #59) is a
  populated spec field with no populating implementation yet.** Don't
  write code, docs, or tests that assume any real server pins its host
  identity today -- see the README's [Security model](README.md#security-model).
- **Release binary target names are a stable external contract.** The
  `x86_64-unknown-linux-gnu` / `aarch64-apple-darwin` /
  `x86_64-apple-darwin` / `i686-unknown-linux-musl` archive names under a
  `rust-vX.Y.Z` release are pinned and downloaded by `clawser`. Don't
  rename them without coordinating downstream.

## Definition of done

A change is done when all of the following hold, not just when tests pass:
- A regression test exists for any bug fixed.
- Anything the feature does **not** do is stated in the README (the
  capability matrix under [Rust implementation](README.md#rust-implementation)
  for JS/Rust asymmetries, or [Security model](README.md#security-model) for
  trust-boundary caveats), not only in an issue comment.
- `CHANGELOG.md` has an entry citing the issue/PR, in the style the rest of
  the file already uses.
- If `spec/wsh-v1.yaml` changed, `npm run codegen` was run and all three
  generated outputs are committed.

## Non-goals

Interop with standard asciicast players (`asciinema play`) is explicitly
not a rename target -- both `SessionRecorder` implementations capture
lifecycle events (`open`/`exit`/`Snapshot`) asciicast v2's three event
codes can't represent, and `RecordingExport`'s `format: "asciicast"` option
is accepted on the wire but not implemented server-side. See the README's
"Session recording" feature note before treating this as a bug.

## Releases

**npm (`@johnhenry/wsh`):** bump `version` in `package.json`, add the
`CHANGELOG.md` entry, merge, then `npm version <bump> && git push
--follow-tags` (or push a `v*` tag directly) -- `.github/workflows/publish.yml`
is deliberately tag-triggered rather than the family's usual `release:
published` (see the workflow's own header comment), gated on the full JS
suite, then idempotent (`npm view` pre-flight guard) with `--provenance
--access public`.

**Rust binaries (`wsh-cli`/`wsh-server`):** tag `rust-vX.Y.Z` (workspace
version in `Cargo.toml`, independent of the npm package's version) to
trigger `.github/workflows/release-rust.yml`, which builds and publishes
prebuilt binaries for four targets to a GitHub Release. Not published to
crates.io.
