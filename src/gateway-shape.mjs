/**
 * The cheap, synchronous shape check of a `gateway` option that names an injected network (#299), kept apart from the gateway session so a host
 * can make it at creation, and throw at once on a typo, without loading the session (the session, the address guard and the UDP and reverse
 * policies are fetched by a dynamic import only when a host is given a gateway). The full validation (`normalizeGateway`) runs when that module has loaded.
 * Browser-safe, imports nothing.
 */

const METHODS = ['connectTcp', 'resolve', 'openUdp', 'listenTcp'];

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
export function checkGatewayShape(gateway, who) {
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
}
