/**
 * Type-only fixture for #220: `@johnhenry/wsh/identity` and `@johnhenry/wsh/capabilities` are declared with the right shapes.
 * Run by `npm run typecheck`.
 */
import {
  fingerprint, podId, fingerprintToPodId, podIdToFingerprint, rawKeyToOpenSsh, publicKeyToOpenSsh, parseOpenSshKey, openSshToRawKey,
  identityOf, normalizeIdentity, authorizedKeyLine,
  type WshIdentity,
} from '@johnhenry/wsh/identity';
import { permits, checkCapabilities, parseCapabilityList, CAPABILITIES_NOTATION_VERSION, type CapabilityRequest } from '@johnhenry/wsh/capabilities';

export async function identity(raw: Uint8Array, key: CryptoKey): Promise<void> {
  const fp: string = await fingerprint(raw);
  const id: string = await podId(raw);
  const viaFp: string = fingerprintToPodId(fp);
  const back: string = podIdToFingerprint(id);
  const line: string = rawKeyToOpenSsh(raw, 'comment');
  const fromKey: string = await publicKeyToOpenSsh(key);
  const parsed: { raw: Uint8Array; comment: string } = parseOpenSshKey(line);
  const rawAgain: Uint8Array = openSshToRawKey(line);
  const all = await identityOf(raw);
  const who: WshIdentity = normalizeIdentity({ podId: id });
  const authorized: string = authorizedKeyLine(raw, { capabilities: ['exec'], expires: new Date(), comment: 'x' });
  const open: string = authorizedKeyLine(line, { allowFullAccess: true });
  void [viaFp, back, fromKey, parsed, rawAgain, all.podId, who.fingerprint, authorized, open];
}

export function capabilities(): void {
  const request: CapabilityRequest = { kind: 'tcp', host: 'example.com', port: 443 };
  const yes: boolean = permits(['gateway:tcp:*.example.com:443'], request, { now: Date.now() });
  const why = checkCapabilities('exec', { kind: 'open', channel: 'exec' });
  const parsed = parseCapabilityList(['exec']);
  const version: 1 = CAPABILITIES_NOTATION_VERSION;
  void [yes, why?.code, parsed.ok, version];
}
