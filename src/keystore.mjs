/**
 * WshKeyStore — Ed25519 key management via IndexedDB with OPFS encrypted backup.
 *
 * Keys are stored as non-extractable CryptoKey objects in IndexedDB for
 * day-to-day use. An optional passphrase-encrypted backup can be written
 * to OPFS (requires extractable keys at generation time).
 */

import {
  generateKeyPair,
  exportPublicKeySSH,
  exportPublicKeyRaw,
  fingerprint,
  exportPrivateKeyPKCS8,
  importPrivateKeyPKCS8,
  importPublicKeyRaw,
} from './auth.mjs';

const DB_NAME = 'wsh-keystore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const BACKUP_FILENAME = 'wsh-keys.backup';
const BACKUP_DIR = 'wsh-keystore';

// PBKDF2 parameters for passphrase-derived key
const PBKDF2_ITERATIONS = 310_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

export class WshKeyStore {
  /** @type {IDBDatabase | null} */
  _db = null;

  // ── Database lifecycle ──────────────────────────────────────────────

  /**
   * Open or create the IndexedDB database.
   * @returns {Promise<void>}
   */
  async open() {
    await this._ensureDb();
  }

  /**
   * Close the database connection.
   */
  close() {
    if (this._db) {
      this._db.close();
      this._db = null;
    }
  }

  // ── Key management ──────────────────────────────────────────────────

  /**
   * Generate a new Ed25519 key pair and store it in IndexedDB.
   *
   * @param {string} [name='default'] - Key name / identifier
   * @param {object} [opts]
   * @param {boolean} [opts.extractable=false] - Whether the private key can be exported
   * @returns {Promise<{ name: string, fingerprint: string, publicKeySSH: string }>}
   */
  async generateKey(name = 'default', { extractable = false } = {}) {
    await this._ensureDb();

    const existing = await this.getKey(name);
    if (existing) {
      throw new Error(`Key "${name}" already exists. Delete it first or choose a different name.`);
    }

    const { publicKey, privateKey } = await generateKeyPair(extractable);
    const fp = await this._fingerprint(publicKey);
    const publicKeySSH = await exportPublicKeySSH(publicKey);
    const createdAt = Date.now();

    const entry = {
      name,
      publicKey,
      privateKey,
      createdAt,
      fingerprint: fp,
    };

    await this._put(entry);

    return { name, fingerprint: fp, publicKeySSH };
  }

  /**
   * Get a stored key entry by name.
   *
   * @param {string} name
   * @returns {Promise<{ name: string, publicKey: CryptoKey, privateKey: CryptoKey, createdAt: number, fingerprint: string } | null>}
   */
  async getKey(name) {
    await this._ensureDb();
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(name);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(new Error(`Failed to get key "${name}": ${req.error?.message}`));
    });
  }

  /**
   * List all stored key names and fingerprints.
   *
   * @returns {Promise<Array<{ name: string, fingerprint: string, createdAt: number }>>}
   */
  async listKeys() {
    await this._ensureDb();
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.getAll();
      req.onsuccess = () => {
        const keys = (req.result || []).map(({ name, fingerprint: fp, createdAt }) => ({
          name,
          fingerprint: fp,
          createdAt,
        }));
        resolve(keys);
      };
      req.onerror = () => reject(new Error(`Failed to list keys: ${req.error?.message}`));
    });
  }

  /**
   * Delete a key by name.
   *
   * @param {string} name
   * @returns {Promise<boolean>} true if the key existed and was deleted
   */
  async deleteKey(name) {
    await this._ensureDb();
    const existing = await this.getKey(name);
    if (!existing) return false;

    return new Promise((resolve, reject) => {
      const tx = this._db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.delete(name);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(new Error(`Failed to delete key "${name}": ${req.error?.message}`));
    });
  }

  /**
   * Export a public key as an SSH-formatted string.
   *
   * @param {string} name
   * @returns {Promise<string>} ssh-ed25519 AAAA... format
   */
  async exportPublicKey(name) {
    const entry = await this.getKey(name);
    if (!entry) throw new Error(`Key "${name}" not found`);
    return exportPublicKeySSH(entry.publicKey);
  }

  /**
   * Get the CryptoKey pair for a named key.
   *
   * @param {string} name
   * @returns {Promise<{ publicKey: CryptoKey, privateKey: CryptoKey }>}
   */
  async getKeyPair(name) {
    const entry = await this.getKey(name);
    if (!entry) throw new Error(`Key "${name}" not found`);
    return { publicKey: entry.publicKey, privateKey: entry.privateKey };
  }

  // ── Encrypted OPFS backup ──────────────────────────────────────────

  /**
   * Export all extractable keys, encrypt with a passphrase, and store in OPFS.
   *
   * Uses PBKDF2 to derive an AES-256-GCM key from the passphrase.
   * Only keys whose private key was created with extractable=true can be backed up;
   * non-extractable keys are silently skipped.
   *
   * @param {string} passphrase
   * @returns {Promise<{ backedUp: number, skipped: number }>}
   */
  async backup(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') {
      throw new Error('Passphrase is required for backup');
    }

    await this._ensureDb();
    const allEntries = await this._getAll();
    const exportable = [];
    let skipped = 0;

    for (const entry of allEntries) {
      try {
        const privBytes = await exportPrivateKeyPKCS8(entry.privateKey);
        const pubBytes = await exportPublicKeyRaw(entry.publicKey);
        exportable.push({
          name: entry.name,
          createdAt: entry.createdAt,
          fingerprint: entry.fingerprint,
          privateKey: Array.from(privBytes),
          publicKey: Array.from(pubBytes),
        });
      } catch {
        // Non-extractable key — skip silently
        skipped++;
      }
    }

    if (exportable.length === 0 && allEntries.length > 0) {
      throw new Error(
        'No extractable keys found. Keys must be generated with extractable=true to support backup.'
      );
    }

    const plaintext = new TextEncoder().encode(JSON.stringify(exportable));
    const ciphertext = await this._encrypt(plaintext, passphrase);
    await this._writeOPFS(ciphertext);

    return { backedUp: exportable.length, skipped };
  }

  /**
   * Restore keys from an OPFS encrypted backup.
   *
   * Decrypts the backup with the provided passphrase and imports keys into IndexedDB.
   * Existing keys with the same name are NOT overwritten; they are skipped.
   *
   * @param {string} passphrase
   * @returns {Promise<{ restored: number, skipped: number }>}
   */
  async restore(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') {
      throw new Error('Passphrase is required for restore');
    }

    await this._ensureDb();
    const ciphertext = await this._readOPFS();
    if (!ciphertext) {
      throw new Error('No backup found in OPFS');
    }

    let plaintext;
    try {
      plaintext = await this._decrypt(ciphertext, passphrase);
    } catch {
      throw new Error('Decryption failed — wrong passphrase or corrupted backup');
    }

    const entries = JSON.parse(new TextDecoder().decode(plaintext));
    let restored = 0;
    let skipped = 0;

    for (const entry of entries) {
      const existing = await this.getKey(entry.name);
      if (existing) {
        skipped++;
        continue;
      }

      const privateKey = await importPrivateKeyPKCS8(
        new Uint8Array(entry.privateKey),
        false // imported keys are non-extractable by default for security
      );
      const publicKey = await importPublicKeyRaw(new Uint8Array(entry.publicKey));

      await this._put({
        name: entry.name,
        publicKey,
        privateKey,
        createdAt: entry.createdAt,
        fingerprint: entry.fingerprint,
      });
      restored++;
    }

    return { restored, skipped };
  }

  // ── Internal: IndexedDB helpers ────────────────────────────────────

  /**
   * Ensure the database is open, opening it if necessary.
   * @returns {Promise<void>}
   */
  async _ensureDb() {
    if (this._db) return;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'name' });
        }
      };

      request.onsuccess = (event) => {
        this._db = event.target.result;

        // Handle unexpected close (e.g. browser deletes DB)
        this._db.onclose = () => {
          this._db = null;
        };

        resolve();
      };

      request.onerror = () => {
        reject(new Error(`Failed to open IndexedDB "${DB_NAME}": ${request.error?.message}`));
      };

      request.onblocked = () => {
        reject(new Error(`IndexedDB "${DB_NAME}" is blocked by another connection`));
      };
    });
  }

  /**
   * Put a key entry into the object store.
   * @param {{ name: string, publicKey: CryptoKey, privateKey: CryptoKey, createdAt: number, fingerprint: string }} entry
   * @returns {Promise<void>}
   */
  async _put(entry) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.put(entry);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(new Error(`Failed to store key "${entry.name}": ${req.error?.message}`));
    });
  }

  /**
   * Get all entries from the object store.
   * @returns {Promise<Array>}
   */
  async _getAll() {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(new Error(`Failed to read keys: ${req.error?.message}`));
    });
  }

  /**
   * Compute a SHA-256 fingerprint of a CryptoKey's raw bytes.
   * @param {CryptoKey} publicKey
   * @returns {Promise<string>} hex-encoded fingerprint
   */
  async _fingerprint(publicKey) {
    const raw = await exportPublicKeyRaw(publicKey);
    return fingerprint(raw);
  }

  // ── Internal: AES-GCM encryption with PBKDF2 ──────────────────────

  /**
   * Derive an AES-256-GCM key from a passphrase using PBKDF2.
   * @param {string} passphrase
   * @param {Uint8Array} salt
   * @returns {Promise<CryptoKey>}
   */
  async _deriveKey(passphrase, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt plaintext with AES-256-GCM using a passphrase-derived key.
   * Output: [16-byte salt][12-byte IV][ciphertext+tag]
   *
   * @param {Uint8Array} plaintext
   * @param {string} passphrase
   * @returns {Promise<Uint8Array>}
   */
  async _encrypt(plaintext, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const key = await this._deriveKey(passphrase, salt);

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      plaintext
    );

    const result = new Uint8Array(SALT_BYTES + IV_BYTES + ciphertext.byteLength);
    result.set(salt, 0);
    result.set(iv, SALT_BYTES);
    result.set(new Uint8Array(ciphertext), SALT_BYTES + IV_BYTES);
    return result;
  }

  /**
   * Decrypt ciphertext produced by _encrypt.
   *
   * @param {Uint8Array} data - [salt][iv][ciphertext+tag]
   * @param {string} passphrase
   * @returns {Promise<Uint8Array>}
   */
  async _decrypt(data, passphrase) {
    if (data.length < SALT_BYTES + IV_BYTES + 1) {
      throw new Error('Backup data too short to be valid');
    }
    const salt = data.slice(0, SALT_BYTES);
    const iv = data.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
    const ciphertext = data.slice(SALT_BYTES + IV_BYTES);

    const key = await this._deriveKey(passphrase, salt);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    return new Uint8Array(plaintext);
  }

  // ── Internal: OPFS storage ─────────────────────────────────────────

  /**
   * Write encrypted data to OPFS.
   * @param {Uint8Array} data
   * @returns {Promise<void>}
   */
  async _writeOPFS(data) {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle(BACKUP_DIR, { create: true });
    const fileHandle = await dir.getFileHandle(BACKUP_FILENAME, { create: true });
    const writable = await fileHandle.createWritable();
    try {
      await writable.write(data);
    } finally {
      await writable.close();
    }
  }

  /**
   * Read encrypted data from OPFS.
   * @returns {Promise<Uint8Array | null>}
   */
  async _readOPFS() {
    try {
      const root = await navigator.storage.getDirectory();
      const dir = await root.getDirectoryHandle(BACKUP_DIR);
      const fileHandle = await dir.getFileHandle(BACKUP_FILENAME);
      const file = await fileHandle.getFile();
      const buffer = await file.arrayBuffer();
      return new Uint8Array(buffer);
    } catch (err) {
      if (err.name === 'NotFoundError') return null;
      throw err;
    }
  }
}
