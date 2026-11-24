/** The operations of `wsh-objects` a key may hold on a root. */
export type ObjectsOp = 'get' | 'call' | 'set' | 'on';

/**
 * What a host says one key may do on one root: its `types` answer (`rootDescription(page.window)` fetches it), or the allow-lists a host holds (paths qualified with the
 * root, as in `allow`). `ops` is what the key's capabilities grant on this root (default: all four).
 */
export interface RootDescription {
  root: string;
  ops?: ObjectsOp[];
  allow: { get?: string[]; call?: string[]; set?: string[]; on?: string[] };
  /** Extra event fields a subscriber may ask for, by event type (`'*'`: any type). */
  eventFields?: Record<string, string[]>;
  /**
   * Host-authored TypeScript type texts, by literal path (`'window.app.cart.add'`; an event as `'window.app.bus@ready'`): `value` (the awaited value of a get),
   * `args` (a tuple type) and `result` (the awaited value) of a call, `data` (what a listener receives) of an event. Checked by `checkTypeText`, bounded, and only
   * for a path an entry allows. Untrusted text: copied into the file, never evaluated.
   */
  types?: Record<string, { value?: string; args?: string; result?: string; data?: string }>;
  version?: number;
  handles?: boolean;
}

/**
 * The text of a `.d.ts` file for one root: only what the key may do, values `unknown` unless the host supplied a type, calls `(...args: unknown[]) => PromiseLike<unknown>`,
 * wildcards untyped, events as typed `on` overloads. Pure: reads nothing, writes nothing, evaluates nothing; throws a `TypeError` on a description or type text it does not accept.
 * @param options.name - the exported type's name (default: the root's name, capitalised, plus `Remote`: `WindowRemote`)
 */
export function describeRootTypes(description: RootDescription, options?: { name?: string }): string;

/** Check the text of one type: returns it, or throws a `TypeError` naming the rule. A conservative subset of type syntax; see the README. */
export function checkTypeText(text: unknown, what?: string): string;

export const TYPE_TEXT_LIMITS: Readonly<{ maxTextChars: number; maxStringChars: number; maxNesting: number; maxEntries: number; maxTotalChars: number }>;
export const OBJECTS_TYPES_LIMITS: Readonly<{ maxEntries: number; maxEntryChars: number; maxNodes: number; maxEvents: number }>;

/** The part of a host's type map that a key holding `ops` may be told. */
export function narrowTypes(options: { root: string; ops: ObjectsOp[]; allow: RootDescription['allow']; types?: RootDescription['types'] }): NonNullable<RootDescription['types']>;
