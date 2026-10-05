import { createPublicKey, KeyObject } from 'node:crypto';
import { MIN_HMAC_SECRET_BYTES, MIN_RSA_MODULUS_BITS } from './constants.js';
import { JwtError } from './errors.js';

export type VerifyKey = string | Uint8Array | KeyObject;

const PEM_MARKER = '-----BEGIN';
const DER_PUBLIC_KEY_TYPES = ['spki', 'pkcs1'] as const;

export function isVerifyKey(value: unknown): value is VerifyKey {
  return typeof value === 'string' || value instanceof Uint8Array || value instanceof KeyObject;
}

function bytesOf(key: string | Uint8Array): Buffer {
  return typeof key === 'string' ? Buffer.from(key, 'utf8') : Buffer.from(key);
}

function parsesAsDerPublicKey(bytes: Buffer, type: (typeof DER_PUBLIC_KEY_TYPES)[number]): boolean {
  try {
    createPublicKey({ key: bytes, format: 'der', type });
    return true;
  } catch {
    return false;
  }
}

function resemblesAsymmetricKey(bytes: Buffer): boolean {
  return (
    bytes.includes(PEM_MARKER) ||
    DER_PUBLIC_KEY_TYPES.some((type) => parsesAsDerPublicKey(bytes, type))
  );
}

export function toHmacSecret(key: VerifyKey): Buffer {
  let bytes: Buffer;
  if (key instanceof KeyObject) {
    if (key.type !== 'secret') {
      throw new JwtError('key_mismatch', 'HS256 requires a shared secret, not an asymmetric key');
    }
    bytes = key.export();
  } else {
    bytes = bytesOf(key);
  }
  if (resemblesAsymmetricKey(bytes)) {
    throw new JwtError(
      'key_mismatch',
      'HS256 requires a shared secret, but the key is a PEM or DER key',
    );
  }
  if (bytes.length < MIN_HMAC_SECRET_BYTES) {
    throw new JwtError('weak_key', `HS256 secret must be at least ${MIN_HMAC_SECRET_BYTES} bytes`);
  }
  return bytes;
}

export function toRsaPublicKey(key: VerifyKey): KeyObject {
  if (key instanceof KeyObject && key.type === 'secret') {
    throw new JwtError('key_mismatch', 'RS256 requires an RSA key, not a shared secret');
  }
  let publicKey: KeyObject;
  try {
    publicKey =
      key instanceof KeyObject && key.type === 'public'
        ? key
        : createPublicKey(key instanceof KeyObject ? key : bytesOf(key));
  } catch {
    throw new JwtError('invalid_key', 'RS256 key is not a valid PEM or KeyObject RSA key');
  }
  if (publicKey.asymmetricKeyType !== 'rsa') {
    throw new JwtError('key_mismatch', 'RS256 requires an RSA key');
  }
  const modulusLength = publicKey.asymmetricKeyDetails?.modulusLength;
  if (modulusLength === undefined || modulusLength < MIN_RSA_MODULUS_BITS) {
    throw new JwtError('weak_key', `RSA key must be at least ${MIN_RSA_MODULUS_BITS} bits`);
  }
  return publicKey;
}
