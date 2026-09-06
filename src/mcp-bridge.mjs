/**
 * WshMcpBridge — bridges remote MCP tools over the wsh meta channel.
 *
 * Sends MCP_DISCOVER and MCP_CALL messages through the wsh control channel,
 * enabling a wsh client to discover and invoke MCP tools hosted on the
 * remote server. Tool specs are cached after discovery for efficient reuse.
 */

import { MSG, mcpDiscover, mcpCall } from './messages.mjs';
import { waitForControlMessage } from './control-listener.mjs';
import { MCP_CALL_ID_FEATURE } from './client.mjs';

/** Default timeout for MCP operations (15 seconds). */
const MCP_TIMEOUT_MS = 15_000;

export class WshMcpBridge {
  /** @type {object} WshClient reference. */
  #client;

  /** @type {Map<string, object>} Cached tool specs: name -> { name, description, parameters } */
  #tools = new Map();

  /** @type {number} Monotonically increasing counter for call_id. */
  #callCounter = 0;

  /**
   * Tail of the serialised call chain, used only against servers that do not
   * advertise `mcp-call-id`. Never rejects.
   * @type {Promise<void>}
   */
  #queue = Promise.resolve();

  /**
   * @param {object} client - A `WshClient`, a `WshTransport`, or any object
   *   exposing:
   *   - sendControl(msg): send a control message
   *   - addControlListener(fn) / removeControlListener(fn): message listeners
   *     (or a `_controlListeners` array, or a settable `onControl` callback)
   *
   *   `sendControl` is checked here rather than at first use: without it
   *   `discover()` failed with `TypeError: this.#client.sendControl is not
   *   a function` from inside a promise, naming a private field and not
   *   the argument that was actually wrong.
   */
  constructor(client) {
    if (!client) throw new Error('WshMcpBridge requires a client');
    if (typeof client.sendControl !== 'function') {
      throw new TypeError(
        'WshMcpBridge requires a client exposing sendControl() — pass a WshClient or a WshTransport'
      );
    }
    this.#client = client;
  }

  /**
   * Discover available MCP tools on the remote server.
   *
   * Sends an MCP_DISCOVER message and waits for the MCP_TOOLS response
   * containing the list of available tools with their schemas.
   *
   * @param {object} [opts]
   * @param {number} [opts.timeout] - Timeout in ms (default 15s)
   * @returns {Promise<Array<{ name: string, description: string, parameters: object }>>}
   */
  async discover({ timeout = MCP_TIMEOUT_MS } = {}) {
    await this.#client.sendControl(mcpDiscover());

    const response = await this._waitForMessage(
      (msg) => msg.type === MSG.MCP_TOOLS || msg.type === MSG.ERROR,
      timeout
    );

    if (response.type === MSG.ERROR) {
      throw new Error(`MCP discovery failed: ${response.message || response.code || 'unknown error'}`);
    }

    const tools = response.tools || [];

    // Cache the discovered tools
    this.#tools.clear();
    for (const tool of tools) {
      if (tool && tool.name) {
        this.#tools.set(tool.name, {
          name: tool.name,
          description: tool.description || '',
          parameters: tool.parameters || {},
        });
      }
    }

    return Array.from(this.#tools.values());
  }

  /**
   * Call a remote MCP tool by name.
   *
   * Sends an MCP_CALL message and waits for the MCP_RESULT response.
   *
   * Safe to call concurrently. Against a server advertising `mcp-call-id`
   * each call carries a correlation id and takes only its own reply;
   * otherwise calls are queued one at a time, because without an id on the
   * wire the replies are indistinguishable and `{ success, output }`
   * normalisation strips whatever the payload might have identified itself
   * by.
   *
   * @param {string} toolName - Name of the tool to invoke
   * @param {object} [args={}] - Arguments to pass to the tool
   * @param {object} [opts]
   * @param {number} [opts.timeout] - Timeout in ms (default 15s)
   * @returns {Promise<{ success: boolean, output: *, error?: string }>}
   */
  async call(toolName, args = {}, { timeout = MCP_TIMEOUT_MS } = {}) {
    if (!toolName || typeof toolName !== 'string') {
      throw new Error('toolName is required');
    }

    // Validate against cached tools if discovery has been performed
    if (this.#tools.size > 0 && !this.#tools.has(toolName)) {
      throw new Error(
        `Unknown tool "${toolName}". Available tools: ${Array.from(this.#tools.keys()).join(', ')}`
      );
    }

    if (this.#correlates()) return this.#callOnce(toolName, args, timeout);

    const run = this.#queue.then(
      () => this.#callOnce(toolName, args, timeout),
      () => this.#callOnce(toolName, args, timeout),
    );
    this.#queue = run.then(() => undefined, () => undefined);
    return run;
  }

  /** True when the connected server echoes call_id. @private */
  #correlates() {
    return this.#client?.hasFeature?.(MCP_CALL_ID_FEATURE) === true;
  }

  /** @private */
  async #callOnce(toolName, args, timeout) {
    const callId = this.#correlates()
      ? `bridge-${++this.#callCounter}-${Date.now()}`
      : undefined;

    await this.#client.sendControl(
      mcpCall({ tool: toolName, arguments: args, callId })
    );

    const response = await this._waitForMessage(
      (msg) => {
        // ERROR carries no call_id and cannot be attributed to one call;
        // it is taken by whichever call is waiting.
        if (msg.type === MSG.ERROR) return true;
        if (msg.type !== MSG.MCP_RESULT) return false;
        if (callId === undefined) return true;
        return msg.call_id === undefined || msg.call_id === callId;
      },
      timeout
    );

    if (response.type === MSG.ERROR) {
      return {
        success: false,
        output: null,
        error: response.message || `Error code: ${response.code}`,
      };
    }

    const result = response.result;

    // Normalize result into the standard { success, output, error? } shape
    if (result && typeof result === 'object' && 'success' in result) {
      return {
        success: Boolean(result.success),
        output: result.output ?? result.data ?? null,
        error: result.error || undefined,
      };
    }

    // If the server returned a raw value, wrap it
    return {
      success: true,
      output: result,
    };
  }

  /**
   * Get cached tool specs (after discover() has been called).
   *
   * Returns tool specifications in a format compatible with the BrowserTool
   * interface used by the Clawser agent, making it easy to register remote
   * tools alongside local ones.
   *
   * @returns {Array<{ name: string, description: string, parameters: object }>}
   */
  getToolSpecs() {
    return Array.from(this.#tools.values()).map((tool) => ({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
    }));
  }

  /**
   * Check whether a specific tool is available (based on cached discovery).
   *
   * @param {string} toolName
   * @returns {boolean}
   */
  hasTool(toolName) {
    return this.#tools.has(toolName);
  }

  /**
   * Get the number of cached tools.
   * @returns {number}
   */
  get toolCount() {
    return this.#tools.size;
  }

  /**
   * Clear the cached tool specs. Call discover() again to refresh.
   */
  clearCache() {
    this.#tools.clear();
  }

  // ── Internal ──────────────────────────────────────────────────────

  /**
   * Wait for a control message matching a predicate.
   *
   * Subscribes to the client's control message flow and resolves when a
   * matching message arrives (or rejects on timeout). Deregistration is
   * `control-listener.mjs`'s job — the version inlined here leaked one
   * permanent `onControl` wrapper per operation against any client whose
   * only hook is that property.
   *
   * @param {function(object): boolean} predicate
   * @param {number} timeoutMs
   * @returns {Promise<object>}
   */
  _waitForMessage(predicate, timeoutMs) {
    return waitForControlMessage(this.#client, predicate, timeoutMs, 'MCP operation');
  }
}
