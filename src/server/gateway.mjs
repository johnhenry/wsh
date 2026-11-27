/**
 * The gateway of the Node server. The session itself (`gateway-session.mjs`) has no Node import, so a host in a page serves the same
 * session over a network its embedder supplies (`@johnhenry/wsh/gateway`); this module is the name `@johnhenry/wsh/server` has always
 * imported it by. What only Node has (the SOCKS5 client in `socks.mjs`, unix sockets, the machine's own sockets) is loaded by the
 * session when it is used.
 */

export * from './gateway-session.mjs';
