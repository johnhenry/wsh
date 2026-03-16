/**
 * WshMcpBridge — bridges remote MCP tools over the wsh meta channel.
 *
 * Sends MCP_DISCOVER and MCP_CALL messages through the wsh control channel,
 * enabling a wsh client to discover and invoke MCP tools hosted on the
 * remote server. Tool specs are cached after discovery for efficient reuse.
 */

import { MSG, mcpDiscover, mcpCall } from './messages.mjs';

/** Default timeout for MCP operations (15 seconds). */
const MCP_TIMEOUT_MS = 15_000;

export class WshMcpBridge {
  /** @type {object} WshClient reference. */
  #client;

  /** @type {Map<string, object>} Cached tool specs: name -> { name, description, parameters } */
  #tools = new Map();

  /**
   * @param {object} client - A WshClient or transport exposing:
   *   - sendControl(msg): send a control message
   *   - addControlListener(fn) / removeControlListener(fn): message listeners
   *     (or _controlListeners array, or onControl callback)
   */
  constructor(client) {
    if (!client) throw new Error('WshMcpBridge requires a client');
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

    await this.#client.sendControl(mcpCall({ tool: toolName, arguments: args }));

    const response = await this._waitForMessage(
      (msg) => msg.type === MSG.MCP_RESULT || msg.type === MSG.ERROR,
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
   * Temporarily hooks into the client's control message flow and resolves
   * when a matching message arrives (or rejects on timeout).
   *
   * @param {function(object): boolean} predicate
   * @param {number} timeoutMs
   * @returns {Promise<object>}
   */
  _waitForMessage(predicate, timeoutMs) {
    return new Promise((resolve, reject) => {
      let timer = null;
      let settled = false;

      const cleanup = () => {
        settled = true;
        if (timer !== null) clearTimeout(timer);
        // Remove listener
        if (this.#client.removeControlListener) {
          this.#client.removeControlListener(listener);
        } else if (this.#client._controlListeners) {
          const idx = this.#client._controlListeners.indexOf(listener);
          if (idx !== -1) this.#client._controlListeners.splice(idx, 1);
        }
      };

      const listener = (msg) => {
        if (settled) return;
        if (predicate(msg)) {
          cleanup();
          resolve(msg);
        }
      };

      // Register listener on the client
      if (this.#client.addControlListener) {
        this.#client.addControlListener(listener);
      } else if (this.#client._controlListeners) {
        this.#client._controlListeners.push(listener);
      } else {
        // Fallback: wrap existing onControl
        const prev = this.#client.onControl;
        this.#client.onControl = (msg) => {
          prev?.(msg);
          listener(msg);
        };
      }

      timer = setTimeout(() => {
        if (!settled) {
          cleanup();
          reject(new Error(`MCP operation timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);
    });
  }
}
