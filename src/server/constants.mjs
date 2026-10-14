/**
 * Limits shared by the connection handler and the Node-only modules that also export them
 * (kept here so the connection handler imports nothing from `node:*` -- see `src/memory-host.mjs`).
 */

/** Size of one FileChunk when a file is streamed to the client. */
export const FILE_CHUNK_BYTES = 64 * 1024;

/** Most clients attached to one detached-session at once. */
export const MAX_ATTACHMENTS = 16;
