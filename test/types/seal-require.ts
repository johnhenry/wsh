/**
 * Type-only fixture for #240: `who.sealRequired` in `auth`, and `sealSession` / `onSealed` on createWshServer.
 */
import { createWshServer } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';

createWshServer({
  hostKey: true,
  sealSession: 'require',
  auth: (who) => who.sealRequired === true ? true : who.username === 'alice',
  onSealed: (who) => { const name: string | null = who.username; const fp: string | null = who.fingerprint; void name; void fp; },
});

createMemoryHost({
  hostKey: true,
  dataStreams: false,
  sealSession: 'require',
  auth: { authorize: (who) => { const required: true | undefined = who.sealRequired; return required === undefined; } },
  onSealed: () => {},
});

// @ts-expect-error -- sealSession is false, 'offer' or 'require'
createWshServer({ hostKey: true, sealSession: 'always' });
// @ts-expect-error -- onSealed is a function
createWshServer({ hostKey: true, sealSession: 'require', onSealed: 1 });
