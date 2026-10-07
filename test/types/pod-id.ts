/**
 * Type-only fixture for wsh #66: the pod ID helpers are declared on the
 * package root with the right shapes. Run by `npm run typecheck`.
 */
import { podId, fingerprintToPodId, podIdToFingerprint, fingerprint } from '@johnhenry/wsh';

export async function check(raw: Uint8Array): Promise<void> {
  const id: string = await podId(raw);
  const fp: string = await fingerprint(raw);
  const viaFp: string = fingerprintToPodId(fp);
  const back: string = podIdToFingerprint(id);
  void [viaFp, back];
}
