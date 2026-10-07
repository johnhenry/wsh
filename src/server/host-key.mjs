/**
 * The server's own Ed25519 identity (see ../host-key.mjs for the wire shape).
 *
 * `hostKey` option forms:
 *  - `true`                          ephemeral key, new every start (TOFU clients will see "changed" after a restart -- tests/demos only)
 *  - `{ file: '/path/host_key' }`    PKCS#8 PEM; created (mode 0600) on first start, reused after -- the normal choice
 *  - a `CryptoKeyPair`               your own key, e.g. from `generateKeyPair()`
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { exportPublicKeyRaw, importPublicKeyRaw, exportPublicKeySSH, sign, fingerprint } from '../auth.mjs';

const PEM_OPTS = { type: 'pkcs8', format: 'pem' };

function fromNodePrivateKey(priv) {
  const x = createPublicKey(priv).export({ format: 'jwk' }).x;
  return Buffer.from(x, 'base64url');
}

/**
 * @returns {Promise<{ publicKey: Uint8Array, fingerprint: string, openssh: string, sign(data: Uint8Array): Promise<Uint8Array> }>}
 */
export async function loadHostKey(option) {
  let raw;
  let signFn;

  if (option === true) {
    const priv = generateKeyPairSync('ed25519').privateKey;
    raw = new Uint8Array(fromNodePrivateKey(priv));
    signFn = async (data) => new Uint8Array(nodeSign(null, data, priv));
  } else if (option && typeof option === 'object' && typeof option.file === 'string') {
    let pem;
    try {
      pem = await readFile(option.file, 'utf8');
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      await mkdir(path.dirname(path.resolve(option.file)), { recursive: true });
      const fresh = generateKeyPairSync('ed25519').privateKey.export(PEM_OPTS);
      try {
        await writeFile(option.file, fresh, { mode: 0o600, flag: 'wx' });
        pem = fresh;
      } catch (e) {
        if (e.code !== 'EEXIST') throw e;
        pem = await readFile(option.file, 'utf8'); // another start won the race
      }
    }
    const priv = createPrivateKey(pem);
    if (priv.asymmetricKeyType !== 'ed25519') throw new TypeError(`createWshServer: hostKey.file ${option.file} is not an Ed25519 key`);
    raw = new Uint8Array(fromNodePrivateKey(priv));
    signFn = async (data) => new Uint8Array(nodeSign(null, data, priv));
  } else if (option && option.privateKey && option.publicKey) {
    raw = await exportPublicKeyRaw(option.publicKey);
    signFn = (data) => sign(option.privateKey, data);
  } else {
    throw new TypeError('createWshServer: hostKey must be true, { file }, or a CryptoKeyPair');
  }

  return {
    publicKey: raw,
    fingerprint: await fingerprint(raw),
    openssh: await exportPublicKeySSH(await importPublicKeyRaw(raw)),
    sign: signFn,
  };
}
