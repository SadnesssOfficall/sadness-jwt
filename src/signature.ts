import { createHmac, timingSafeEqual, verify as verifyRsa } from 'node:crypto';
import type { Algorithm } from './algorithms.js';
import { toHmacSecret, toRsaPublicKey, type VerifyKey } from './keys.js';

const DIGEST = 'sha256';

export function verifySignature(
  algorithm: Algorithm,
  signingInput: string,
  signature: Buffer,
  key: VerifyKey,
): boolean {
  const data = Buffer.from(signingInput, 'ascii');
  if (algorithm === 'HS256') {
    const expected = createHmac(DIGEST, toHmacSecret(key)).update(data).digest();
    return signature.length === expected.length && timingSafeEqual(signature, expected);
  }
  return verifyRsa(DIGEST, data, toRsaPublicKey(key), signature);
}
