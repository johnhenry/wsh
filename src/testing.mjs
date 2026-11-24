/**
 * `@johnhenry/wsh/testing` -- the QMux record and frame codec primitives a test needs to look inside what travels on a connection,
 * change it and put it back (re-wrap a STREAM frame around altered bytes, build a malformed frame, split a record at a chosen
 * byte). They are the same functions `QMuxConnection` uses.
 *
 * NOT PART OF THE STABLE API. This entry point exists for tests of code that embeds the package (a transport, a relay, an
 * alternate host); a release may rename, change or remove anything here, and it is not covered by the compatibility policy
 * the rest of the package follows. Application code should use `WshClient`, `createWshServer` and the other entry points.
 *
 * Pure JavaScript, no Node built-in: it bundles for a browser like the rest.
 */

export {
  encodeVarint, decodeVarint, varintLength,
  FRAME_TYPE, QX_TRANSPORT_PARAMETERS_TYPE, ERROR_CODE as QMUX_ERROR_CODE,
  encodeRecord, RecordDecoder, decodeFrames,
  encodePadding, encodeStream, encodeResetStream, encodeResetStreamAt, encodeStopSending,
  encodeMaxData, encodeMaxStreamData, encodeMaxStreams, encodeDataBlocked, encodeStreamDataBlocked, encodeStreamsBlocked,
  encodeConnectionClose, encodeDatagram, encodeTransportParameters, TRANSPORT_PARAM_ID,
  QMuxProtocolError,
} from './qmux.mjs';

/** Machine-readable form of the notice above, so a test (or a reader) can check what it imported. */
export const QMUX_TESTING_API = Object.freeze({
  stable: false,
  notice: 'The primitives of @johnhenry/wsh/testing are not part of the stable API: they may change or disappear in any release.',
});
