/**
 * The destination-address classifier of the gateway now lives in `../address-class.mjs` (pure, no Node import) and is
 * public as `@johnhenry/wsh/address-guard`; this module keeps the old path for the code that imports it from here.
 */
export { isPublicAddress, parseIp, parseCidr, addressInCidr, sameAddress, classifyAddress } from '../address-class.mjs';
