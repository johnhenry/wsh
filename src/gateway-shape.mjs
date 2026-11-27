/**
 * The cheap, synchronous shape check of a `gateway` option that names an injected network (#299), kept apart from the gateway session so a host
 * can make it at creation, and throw at once on a typo, without loading the session (the session, the address guard and the UDP and reverse
 * policies are fetched by a dynamic import only when a host is given a gateway). The full validation (`normalizeGateway`) runs when that module has loaded.
 * Browser-safe, imports nothing.
 */

const METHODS = ['connectTcp', 'resolve', 'openUdp', 'listenTcp'];

/** Every key of a `gateway` option that names an injected network. A key outside it is a typo, not an option that silently does nothing. */
const KNOWN_KEYS = new Set([
  'allow', 'allowPrivate', 'maxConnections', 'maxBufferedBytes', 'maxClientBufferedBytes', 'connectTimeoutMs', 'halfCloseIdleMs', 'halfCloseProbeMs',
  'losslessClose', 'halfCloseProbeAnswers', 'halfCloseProbeRemoteMs', 'udpIdleMs', 'udp', 'dns', 'reverse', 'network', 'log', 'socks', 'unix', 'tcp', 'endpoints',
]);

/**
 * Unknown keys and wrongly typed switches (`dns`, `reverse`, `udp`) of a gateway with a network, the same for every host that takes one.
 * @param {object} gateway
 * @param {string} who prefix of the error
 * @param {string[]} [extraKeys] keys this host also takes (the reverse host's `trustRelayIdentity`)
 */
export function checkGatewayOptions(gateway, who, extraKeys = []) {
  for (const k of Object.keys(gateway)) if (!KNOWN_KEYS.has(k) && !extraKeys.includes(k)) throw new TypeError(`${who}: unknown gateway option "${k}"`);
  if (gateway.dns !== undefined && typeof gateway.dns !== 'boolean') throw new TypeError(`${who}: gateway.dns must be a boolean`);
  const objectOrBool = (v) => v === undefined || v === null || typeof v === 'boolean' || (typeof v === 'object' && !Array.isArray(v));
  if (!objectOrBool(gateway.udp)) throw new TypeError(`${who}: gateway.udp must be true, false or an options object`);
  if (!objectOrBool(gateway.reverse)) throw new TypeError(`${who}: gateway.reverse must be true, false or an options object`);
}

/** A reverse host's gateway starts only when the owner chose how operators' identities are taken (#289): proof and a sealed bridge, or an explicit trust of the relay's word. */
export function checkReverseTrust(gateway, hostOptions, who) {
  if (hostOptions.requireOperatorProof !== true && gateway.trustRelayIdentity !== true) {
    throw new TypeError(`${who}: a gateway needs requireOperatorProof: true (operators prove themselves and the bridge is sealed), or gateway.trustRelayIdentity: true to say you trust the relay's word about who is asking (a relay can then open what an accepted operator could)`);
  }
}

/**
 * @param {unknown} gateway the option
 * @param {string} who the prefix of the error ("createMemoryHost")
 */
export function checkGatewayShape(gateway, who, extraKeys = []) {
  if (gateway === true || typeof gateway !== 'object' || gateway === null || Array.isArray(gateway)) {
    throw new TypeError(`${who}: gateway needs a network and an explicit allow list (default deny): { network: { connectTcp, ... }, allow: ["host:port", ...] }`);
  }
  const n = gateway.network;
  if (n === undefined || n === null) throw new TypeError(`${who}: gateway needs a network (a page has no sockets to dial): gateway.network = { ${METHODS.join(', ')} }`);
  if (typeof n !== 'object' || Array.isArray(n)) throw new TypeError(`${who}: gateway.network must be an object: { ${METHODS.join(', ')} }`);
  for (const k of Object.keys(n)) if (!METHODS.includes(k)) throw new TypeError(`${who}: gateway.network.${k} is not a network method (${METHODS.join(', ')})`);
  for (const k of METHODS) if (n[k] !== undefined && typeof n[k] !== 'function') throw new TypeError(`${who}: gateway.network.${k} must be a function`);
  if (!METHODS.some((k) => typeof n[k] === 'function')) throw new TypeError(`${who}: gateway.network needs at least one of ${METHODS.join(', ')}`);
  if (!Array.isArray(gateway.allow)) throw new TypeError(`${who}: gateway.allow is required with gateway.network (default deny): { allow: ["host:port", ...] }, an empty list reaches nothing`);
  checkGatewayOptions(gateway, who, extraKeys);
}
