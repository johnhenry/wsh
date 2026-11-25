/**
 * Type-only fixture: `@johnhenry/wsh/address-guard` resolves by its published subpath and types the classifier, the policy
 * check, the name-resolution helper and the two checked dials.
 */
import {
  isPublicAddress, classifyAddress, checkAddress, resolveChecked, dialChecked, dialUdpChecked, ADDRESS_CLASSES, AddressGuardError,
  type AddressClass, type AddressPolicy, type AddressCheck, type CheckedAddress, type ResolveOptions, type AddressGuardErrorCode,
} from '@johnhenry/wsh/address-guard';

const pub: boolean = isPublicAddress('8.8.8.8');
const cls: AddressClass = classifyAddress('169.254.169.254');
const known: AddressClass = 'metadata';
const classes: readonly AddressClass[] = ADDRESS_CLASSES;
void pub; void cls; void known; void classes;

const policy: AddressPolicy = { allowPrivate: true, allow: ['10.0.0.0/8', 'fd00::/8'], deny: ['10.9.0.0/16'] };
const check: AddressCheck = checkAddress('10.1.1.1', policy);
const why: 'class' | 'deny' | undefined = check.reason;
void why;

async function main(signal: AbortSignal): Promise<void> {
  const opts: ResolveOptions = { ...policy, family: 4, timeoutMs: 5000, signal, refuseMixed: true, lookup: async (name, { family }) => (family === 6 ? [] : [{ address: `${name.length}.0.0.1` }, '8.8.8.8']) };
  const found: CheckedAddress[] = await resolveChecked('example.com', opts);
  const first: string = found[0].address;
  const family: 4 | 6 = found[0].family;
  const firstClass: AddressClass = found[0].class;
  void first; void family; void firstClass;

  // The dial reports the address it dialled, with its family and class.
  const tcp = await dialChecked('example.com', 443, { allowPrivate: false, timeoutMs: 3000, signal });
  const dialled: string = tcp.address;
  const dialledFamily: 4 | 6 = tcp.family;
  void dialled; void dialledFamily;
  tcp.socket.destroy();

  const udp = await dialUdpChecked('example.com', 53, { family: 6 });
  const udpClass: AddressClass = udp.class;
  void udpClass;
  udp.socket.close();

  try { await dialChecked('10.0.0.1', 80); } catch (e) {
    if (e instanceof AddressGuardError) {
      const code: AddressGuardErrorCode = e.code;
      const refused: ReadonlyArray<{ address: string; class: AddressClass }> | undefined = e.refused;
      void code; void refused;
    }
  }
}
void main;

// @ts-expect-error -- not a class
const bad: AddressClass = 'internal';
// @ts-expect-error -- allowPrivate is a boolean; CIDR blocks go in `allow`
const badPolicy: AddressPolicy = { allowPrivate: ['10.0.0.0/8'] };
// @ts-expect-error -- family is 0, 4 or 6
const badFamily: ResolveOptions = { family: 5 };
// @ts-expect-error -- the port is a number
void dialChecked('example.com', '443');
// @ts-expect-error -- the list is read only
ADDRESS_CLASSES.push('x');
void bad; void badPolicy; void badFamily;
