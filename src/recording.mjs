/**
 * Session recording and playback for wsh PTY sessions.
 *
 * Records all terminal I/O with timestamps for later replay.
 * The export format is compatible with the asciicast v2 structure
 * used by asciinema, enabling interop with standard terminal players.
 */

// ── SessionRecorder ──────────────────────────────────────────────────

/**
 * Records PTY I/O events with relative timestamps for session replay.
 */
export class SessionRecorder {
  /** @type {string} */
  sessionId;

  /** @type {number} Unix epoch ms when recording started. */
  startTime;

  /** @type {Array<{ t: number, type: string, data: * }>} */
  entries = [];

  /** @type {number} Terminal width at recording start. */
  #width = 80;

  /** @type {number} Terminal height at recording start. */
  #height = 24;

  /**
   * @param {string} sessionId - Unique identifier for the recorded session
   * @param {object} [opts]
   * @param {number} [opts.width=80] - Initial terminal width
   * @param {number} [opts.height=24] - Initial terminal height
   */
  constructor(sessionId, { width = 80, height = 24 } = {}) {
    if (!sessionId) throw new Error('sessionId is required');
    this.sessionId = sessionId;
    this.startTime = Date.now();
    this.entries = [];
    this.#width = width;
    this.#height = height;
  }

  /**
   * Record an event.
   *
   * @param {'input' | 'output' | 'resize' | 'open' | 'exit'} type - Event type
   * @param {*} data - Event payload:
   *   - input/output: string of terminal data
   *   - resize: { cols, rows }
   *   - open: { command?, env? }
   *   - exit: { code }
   */
  record(type, data) {
    const t = Date.now() - this.startTime;
    this.entries.push({ t, type, data });

    // Track terminal dimensions on resize
    if (type === 'resize' && data) {
      if (data.cols) this.#width = data.cols;
      if (data.rows) this.#height = data.rows;
    }
  }

  /**
   * Export the recording as a JSON-serializable object.
   *
   * The format is compatible with asciicast v2:
   *   - version: 2
   *   - width, height: terminal dimensions at start
   *   - timestamp: Unix epoch seconds when recording started
   *   - env: optional environment metadata
   *   - events: array of [time_seconds, event_type, data]
   *
   * Event types in asciicast:
   *   "o" = output, "i" = input, "r" = resize
   * We extend with: "open", "exit" for session lifecycle.
   *
   * @returns {object}
   */
  toJSON() {
    const events = this.entries.map(({ t, type, data }) => {
      const timeSec = t / 1000;
      const eventType = ASCIICAST_TYPE_MAP[type] || type;

      // Serialize data depending on type
      let eventData;
      if (type === 'resize' && data) {
        eventData = `${data.cols}x${data.rows}`;
      } else if (type === 'exit' && data) {
        eventData = String(data.code ?? 0);
      } else if (type === 'open' && data) {
        eventData = JSON.stringify(data);
      } else {
        eventData = typeof data === 'string' ? data : JSON.stringify(data);
      }

      return [timeSec, eventType, eventData];
    });

    return {
      version: 2,
      width: this.#width,
      height: this.#height,
      timestamp: Math.floor(this.startTime / 1000),
      env: { TERM: 'xterm-256color', SHELL: '/bin/bash' },
      sessionId: this.sessionId,
      events,
    };
  }

  /**
   * Import a recording from JSON (as produced by toJSON or parsed from asciicast).
   *
   * @param {object | string} json - Recording object or JSON string
   * @returns {SessionRecorder}
   */
  static fromJSON(json) {
    const data = typeof json === 'string' ? JSON.parse(json) : json;

    if (!data.version || data.version < 2) {
      throw new Error(`Unsupported recording version: ${data.version}`);
    }

    const recorder = new SessionRecorder(data.sessionId || 'imported', {
      width: data.width || 80,
      height: data.height || 24,
    });

    recorder.startTime = (data.timestamp || Math.floor(Date.now() / 1000)) * 1000;
    recorder.entries = [];

    if (Array.isArray(data.events)) {
      for (const event of data.events) {
        if (!Array.isArray(event) || event.length < 3) continue;

        const [timeSec, eventType, eventData] = event;
        const t = Math.round(timeSec * 1000);
        const type = REVERSE_TYPE_MAP[eventType] || eventType;

        // Parse data back into structured form
        let parsedData;
        if (type === 'resize' && typeof eventData === 'string') {
          const match = eventData.match(/^(\d+)x(\d+)$/);
          parsedData = match
            ? { cols: parseInt(match[1], 10), rows: parseInt(match[2], 10) }
            : eventData;
        } else if (type === 'exit') {
          parsedData = { code: parseInt(eventData, 10) || 0 };
        } else if (type === 'open') {
          try {
            parsedData = JSON.parse(eventData);
          } catch {
            parsedData = eventData;
          }
        } else {
          parsedData = eventData;
        }

        recorder.entries.push({ t, type, data: parsedData });
      }
    }

    return recorder;
  }

  /**
   * Get the total duration of the recording in milliseconds.
   * @returns {number}
   */
  get duration() {
    if (this.entries.length === 0) return 0;
    return this.entries[this.entries.length - 1].t;
  }

  /**
   * Get the number of recorded events.
   * @returns {number}
   */
  get length() {
    return this.entries.length;
  }
}

// Asciicast type mapping
const ASCIICAST_TYPE_MAP = {
  output: 'o',
  input: 'i',
  resize: 'r',
  open: 'open',
  exit: 'exit',
};

const REVERSE_TYPE_MAP = {
  o: 'output',
  i: 'input',
  r: 'resize',
};

// ── SessionPlayer ────────────────────────────────────────────────────

/**
 * Replays a recorded session with original timing.
 */
export class SessionPlayer {
  /** @type {object} The recording data (from toJSON / fromJSON). */
  #recording;

  /** @type {Array<{ t: number, type: string, data: * }>} Parsed entries. */
  #entries;

  /**
   * @param {object} recording - Recording from SessionRecorder.toJSON() or fromJSON().toJSON()
   */
  constructor(recording) {
    if (!recording) throw new Error('Recording is required');

    // Accept either a SessionRecorder instance or plain JSON object
    const data = recording.toJSON ? recording.toJSON() : recording;
    this.#recording = data;

    // Pre-parse events back into internal format
    this.#entries = (data.events || []).map(([timeSec, eventType, eventData]) => ({
      t: Math.round(timeSec * 1000),
      type: REVERSE_TYPE_MAP[eventType] || eventType,
      data: eventData,
    }));
  }

  /**
   * Get the recording metadata.
   * @returns {{ width: number, height: number, duration: number, eventCount: number }}
   */
  get metadata() {
    const lastEntry = this.#entries[this.#entries.length - 1];
    return {
      width: this.#recording.width,
      height: this.#recording.height,
      duration: lastEntry ? lastEntry.t : 0,
      eventCount: this.#entries.length,
    };
  }

  /**
   * Replay the recording with original timing.
   *
   * Calls `onData(data)` for each output event at the recorded time intervals,
   * adjusted by the speed multiplier.
   *
   * @param {function(string): void} onData - Callback for output data
   * @param {object} [opts]
   * @param {number} [opts.speed=1] - Playback speed multiplier (2 = double speed)
   * @param {function(string, *): void} [opts.onEvent] - Callback for all events (type, data)
   * @returns {{ pause: function, resume: function, stop: function, seek: function(number) }}
   */
  play(onData, { speed = 1, onEvent } = {}) {
    if (typeof onData !== 'function') {
      throw new Error('onData callback is required');
    }
    if (speed <= 0) {
      throw new Error('Speed must be positive');
    }

    let currentIndex = 0;
    let paused = false;
    let stopped = false;
    let timerId = null;
    let pauseTime = 0;       // When playback was paused (relative ms)
    let playbackStart = 0;   // When playback began (performance.now)
    let timeOffset = 0;      // Accumulated pause time offset

    const entries = this.#entries;

    const getElapsed = () => {
      return (performance.now() - playbackStart - timeOffset) * speed;
    };

    const scheduleNext = () => {
      if (stopped || paused || currentIndex >= entries.length) return;

      const entry = entries[currentIndex];
      const elapsed = getElapsed();
      const delay = Math.max(0, (entry.t - elapsed) / speed);

      timerId = setTimeout(() => {
        if (stopped || paused) return;

        const { type, data } = entries[currentIndex];
        currentIndex++;

        // Deliver output data
        if (type === 'output' || type === 'o') {
          try {
            onData(data);
          } catch { /* ignore callback errors */ }
        }

        // Deliver all events if listener registered
        if (onEvent) {
          try {
            onEvent(type, data);
          } catch { /* ignore callback errors */ }
        }

        // Schedule the next event
        scheduleNext();
      }, delay);
    };

    // Start playback
    playbackStart = performance.now();
    scheduleNext();

    // Return playback controller
    const controller = {
      /**
       * Pause playback.
       */
      pause() {
        if (paused || stopped) return;
        paused = true;
        pauseTime = performance.now();
        if (timerId !== null) {
          clearTimeout(timerId);
          timerId = null;
        }
      },

      /**
       * Resume playback after pause.
       */
      resume() {
        if (!paused || stopped) return;
        paused = false;
        timeOffset += performance.now() - pauseTime;
        scheduleNext();
      },

      /**
       * Stop playback entirely.
       */
      stop() {
        stopped = true;
        paused = false;
        if (timerId !== null) {
          clearTimeout(timerId);
          timerId = null;
        }
      },

      /**
       * Seek to a specific time in the recording.
       *
       * Immediately replays all output events up to the target time,
       * then resumes normal timed playback from that point.
       *
       * @param {number} timeMs - Target time in milliseconds from start
       */
      seek(timeMs) {
        if (stopped) return;
        if (timeMs < 0) timeMs = 0;

        // Cancel any pending timer
        if (timerId !== null) {
          clearTimeout(timerId);
          timerId = null;
        }

        // Find the entry index at or just past the target time
        let seekIndex = 0;
        for (let i = 0; i < entries.length; i++) {
          if (entries[i].t > timeMs) break;
          seekIndex = i + 1;

          // Replay output events up to the seek point
          const { type, data } = entries[i];
          if (type === 'output' || type === 'o') {
            try {
              onData(data);
            } catch { /* ignore */ }
          }
        }

        currentIndex = seekIndex;

        // Reset timing to match the seek position
        playbackStart = performance.now();
        timeOffset = 0;
        // Adjust so elapsed time starts at the seek position
        playbackStart -= timeMs / speed;

        // Resume scheduling if not paused
        if (!paused) {
          scheduleNext();
        }
      },
    };

    return controller;
  }
}
