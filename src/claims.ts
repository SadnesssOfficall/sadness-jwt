import { JwtError } from './errors.js';
import {
  resolveClockTolerance,
  resolveMaxAge,
  resolveNowSeconds,
  resolveStringList,
} from './options.js';
import type { JwtPayload } from './token.js';

export interface ClaimOptions {
  issuer?: string | readonly string[];
  audience?: string | readonly string[];
  clockToleranceSeconds?: number;
  maxAgeSeconds?: number;
  requireExpiration?: boolean;
  now?: Date;
}

export interface ResolvedClaimOptions {
  issuer: readonly string[] | undefined;
  audience: readonly string[] | undefined;
  toleranceSeconds: number;
  maxAgeSeconds: number | undefined;
  requireExpiration: boolean;
  nowSeconds: number;
}

export function resolveClaimOptions(options: ClaimOptions): ResolvedClaimOptions {
  return {
    issuer: resolveStringList(options.issuer, 'issuer'),
    audience: resolveStringList(options.audience, 'audience'),
    toleranceSeconds: resolveClockTolerance(options.clockToleranceSeconds),
    maxAgeSeconds: resolveMaxAge(options.maxAgeSeconds),
    requireExpiration: options.requireExpiration ?? true,
    nowSeconds: resolveNowSeconds(options.now),
  };
}

function numericDate(payload: JwtPayload, name: string): number | undefined {
  const value = payload[name];
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new JwtError('invalid_claim', `"${name}" must be a finite number`);
  }
  return value;
}

function requireClaim(value: number | undefined, name: string): number {
  if (value === undefined) throw new JwtError('missing_claim', `"${name}" claim is required`);
  return value;
}

function audiencesOf(value: unknown): readonly string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return value;
  }
  throw new JwtError('invalid_claim', '"aud" must be a string or a list of strings');
}

function validateTimes(payload: JwtPayload, options: ResolvedClaimOptions): void {
  const { nowSeconds, toleranceSeconds } = options;
  const exp = numericDate(payload, 'exp');
  const nbf = numericDate(payload, 'nbf');
  const iat = numericDate(payload, 'iat');
  if (exp === undefined && options.requireExpiration) requireClaim(exp, 'exp');
  if (exp !== undefined && nowSeconds >= exp + toleranceSeconds) {
    throw new JwtError('token_expired', 'token has expired');
  }
  if (nbf !== undefined && nowSeconds + toleranceSeconds < nbf) {
    throw new JwtError('token_not_yet_valid', 'token is not valid yet');
  }
  if (iat !== undefined && iat > nowSeconds + toleranceSeconds) {
    throw new JwtError('issued_in_future', 'token was issued in the future');
  }
  if (options.maxAgeSeconds !== undefined) {
    const issuedAt = requireClaim(iat, 'iat');
    if (nowSeconds - issuedAt > options.maxAgeSeconds + toleranceSeconds) {
      throw new JwtError('token_too_old', 'token is older than the allowed maximum age');
    }
  }
}

function validateIssuer(payload: JwtPayload, expected: readonly string[]): void {
  const issuer = payload['iss'];
  if (issuer === undefined) throw new JwtError('missing_claim', '"iss" claim is required');
  if (typeof issuer !== 'string') throw new JwtError('invalid_claim', '"iss" must be a string');
  if (!expected.includes(issuer)) {
    throw new JwtError('issuer_mismatch', 'token issuer is not accepted');
  }
}

function validateAudience(payload: JwtPayload, expected: readonly string[]): void {
  const audience = payload['aud'];
  if (audience === undefined) throw new JwtError('missing_claim', '"aud" claim is required');
  if (!audiencesOf(audience).some((value) => expected.includes(value))) {
    throw new JwtError('audience_mismatch', 'token audience is not accepted');
  }
}

export function validateClaims(payload: JwtPayload, options: ResolvedClaimOptions): void {
  validateTimes(payload, options);
  if (options.issuer) validateIssuer(payload, options.issuer);
  if (options.audience) validateAudience(payload, options.audience);
}
