/**
 * Type-only regression fixture for wsh #63.
 *
 * Not executed -- `npm run typecheck` runs `tsc --noEmit` over this file.
 * It exists to catch two regressions automatically instead of relying on
 * someone eyeballing src/index.d.ts:
 *
 *  1. Importing "@johnhenry/wsh" by its published package name (as any
 *     real consumer does) must resolve to the shipped declarations. Before
 *     wsh #63, package.json's `exports["."]` had no `types` condition, so
 *     under Node16/NodeNext module resolution TypeScript reported TS7016
 *     ("could not find a declaration file") even though a top-level
 *     `types` field existed -- that legacy field is not consulted once
 *     `exports` is present under this resolution mode.
 *  2. `WshClient.fileList` / `WshClient.fileRemove` are implemented and
 *     reachable at runtime (see src/client.mjs) but were missing from
 *     src/index.d.ts entirely, so any TypeScript consumer got a "Property
 *     'fileList' does not exist" compile error despite the method working
 *     fine at runtime.
 */
import type { WshClient, WshFileOperationResult } from '@johnhenry/wsh';

declare const client: WshClient;

// fileList: takes a path (and optional timeout) and resolves the raw
// FileResult wire shape -- exercised with and without the timeout arg.
const listResult: Promise<WshFileOperationResult> = client.fileList('/tmp');
void client.fileList('/tmp', 5000);

// The resolved value's fields must be typed, not `any`.
async function inspectList() {
  const result = await listResult;
  const success: boolean = result.success;
  const firstEntryName: string | undefined = result.entries[0]?.name;
  const firstEntrySize: number | undefined = result.entries[0]?.size;
  return { success, firstEntryName, firstEntrySize };
}
void inspectList;

// fileRemove: same shape, takes a path (and optional timeout).
const removeResult: Promise<WshFileOperationResult> = client.fileRemove('/tmp/stale-file');
void client.fileRemove('/tmp/stale-file', 5000);

async function inspectRemove() {
  const result = await removeResult;
  const errorMessage: string | undefined = result.error_message;
  return errorMessage;
}
void inspectRemove;

// 0.19: host key pinning + fileWrite / fileRename
import { WshClient as Client19, WshKnownHosts, HostKeyError, type WshHostKey } from '@johnhenry/wsh';
declare const c19: Client19;
const hostKey19: WshHostKey | null = c19.hostKey;
c19.onHostKey = (hk) => hk.status !== 'unknown';
const connected19: Promise<string> = c19.connect('ws://h', {
  username: 'a', password: 'p', expectHostKey: 'ab', knownHosts: new WshKnownHosts(), trustOnFirstUse: true,
});
const w19: Promise<{ success: boolean }> = c19.fileWrite('p', 'text', 0);
const r19: Promise<{ success: boolean }> = c19.fileRename('a', 'b');
const code19: string | undefined = (new HostKeyError('HOST_KEY_MISSING', 'x') as HostKeyError).code;
export { hostKey19, connected19, w19, r19, code19 };
