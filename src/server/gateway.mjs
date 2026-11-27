/**
 * The gateway of the Node server. The session itself (`gateway-session.mjs`) has no Node import, so a host in a page serves the same
 * session over a network its embedder supplies (`@johnhenry/wsh/gateway`); this module is the name `@johnhenry/wsh/server` has always
 * imported it by, and the one place that names the Node-only parts (the machine's sockets, unix sockets, the SOCKS5 client) with LITERAL
 * dynamic imports: a bundler of a Node server therefore includes them, and the browser entries, which never import this file, do not.
 * The configuration `normalizeGateway` returns here carries them to the session (`cfg.nodeLoaders`).
 */

import { normalizeGateway as normalizeSessionGateway } from './gateway-session.mjs';

export * from './gateway-session.mjs';

/** What the session loads, on first use, when it dials the machine's own network. */
export const nodeLoaders = Object.freeze({
  net: async () => (await import('node:net')).default,
  unix: () => import('./unix-policy.mjs'),
  socks: () => import('./socks.mjs'),
});

/** `normalizeGateway` of the session, for a gateway that may dial this machine: the configuration is given the Node loaders. */
export function normalizeGateway(opts) {
  const cfg = normalizeSessionGateway(opts);
  if (cfg) cfg.nodeLoaders = nodeLoaders;
  return cfg;
}
