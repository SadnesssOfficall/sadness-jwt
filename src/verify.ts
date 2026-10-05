import { isNoneAlgorithm, isSupportedAlgorithm, type Algorithm } from './algorithms.js';
import { resolveClaimOptions, validateClaims, type ClaimOptions } from './claims.js';
import { JwtError } from './errors.js';
import { isVerifyKey, type VerifyKey } from './keys.js';
import { isNonEmptyString, resolveAlgorithms, resolveMaxTokenLength } from './options.js';
import { verifySignature } from './signature.js';
import { parseToken, type JwtHeader, type JwtPayload } from './token.js';

export interface VerifyOptions extends ClaimOptions {
  algorithms: readonly Algorithm[];
  key: VerifyKey;
  keyId?: string;
  maxTokenLength?: number;
}

export interface VerifiedToken {
  header: JwtHeader;
  payload: JwtPayload;
  algorithm: Algorithm;
}

function selectAlgorithm(header: JwtHeader, allowed: readonly Algorithm[]): Algorithm {
  const algorithm = header['alg'];
  if (typeof algorithm !== 'string') {
    throw new JwtError('invalid_header', 'header "alg" must be a string');
  }
  if (isNoneAlgorithm(algorithm)) {
    throw new JwtError('algorithm_none', 'unsigned tokens (alg "none") are never accepted');
  }
  if (!isSupportedAlgorithm(algorithm) || !allowed.includes(algorithm)) {
    throw new JwtError('algorithm_not_allowed', 'token algorithm is not in the allowed list');
  }
  return algorithm;
}

function assertHeaderPolicy(header: JwtHeader, keyId: string | undefined): void {
  if (header['crit'] !== undefined) {
    throw new JwtError(
      'unsupported_critical_header',
      'tokens with a "crit" header are not supported',
    );
  }
  if (keyId !== undefined && header['kid'] !== keyId) {
    throw new JwtError('key_id_mismatch', 'token "kid" does not match the expected key id');
  }
}

export function verify(token: string, options: VerifyOptions): VerifiedToken {
  const allowed = resolveAlgorithms(options.algorithms);
  const key: unknown = options.key;
  if (!isVerifyKey(key)) {
    throw new JwtError('invalid_key', 'key must be a string, Uint8Array or KeyObject');
  }
  if (options.keyId !== undefined && !isNonEmptyString(options.keyId)) {
    throw new JwtError('invalid_options', 'keyId must be a non-empty string');
  }
  const claimOptions = resolveClaimOptions(options);
  const parsed = parseToken(token, resolveMaxTokenLength(options.maxTokenLength));
  const algorithm = selectAlgorithm(parsed.header, allowed);
  assertHeaderPolicy(parsed.header, options.keyId);
  if (parsed.signatureBytes.length === 0) {
    throw new JwtError('missing_signature', 'token has no signature');
  }
  if (!verifySignature(algorithm, parsed.signingInput, parsed.signatureBytes, key)) {
    throw new JwtError('invalid_signature', 'signature verification failed');
  }
  validateClaims(parsed.payload, claimOptions);
  return { header: parsed.header, payload: parsed.payload, algorithm };
}
