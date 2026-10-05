import { ALGORITHM_INFO, isNoneAlgorithm, isSupportedAlgorithm } from './algorithms.js';
import { MILLISECONDS_PER_SECOND } from './constants.js';
import { resolveClockTolerance, resolveMaxTokenLength, resolveNowSeconds } from './options.js';
import { parseToken, type JwtHeader, type JwtPayload } from './token.js';

export interface InspectOptions {
  now?: Date;
  clockToleranceSeconds?: number;
  maxTokenLength?: number;
}

export interface TimeClaimInfo {
  value: number;
  iso: string;
  secondsFromNow: number;
}

export interface InspectResult {
  header: JwtHeader;
  payload: JwtPayload;
  algorithm: { name: string | undefined; supported: boolean; description: string };
  signature: { present: boolean; bytes: number };
  issuer: string | undefined;
  subject: string | undefined;
  audience: readonly string[];
  keyId: string | undefined;
  expiresAt: TimeClaimInfo | undefined;
  notBefore: TimeClaimInfo | undefined;
  issuedAt: TimeClaimInfo | undefined;
  expired: boolean;
  notYetValid: boolean;
  warnings: readonly string[];
}

const UNTRUSTED_HEADERS = ['jku', 'x5u', 'jwk', 'x5c'] as const;

function describeAlgorithm(name: unknown): InspectResult['algorithm'] {
  if (typeof name !== 'string') {
    return { name: undefined, supported: false, description: 'missing or not a string' };
  }
  if (isSupportedAlgorithm(name)) {
    return { name, supported: true, description: ALGORITHM_INFO[name].description };
  }
  if (isNoneAlgorithm(name)) {
    return { name, supported: false, description: 'unsecured (no signature)' };
  }
  return { name, supported: false, description: 'not supported for verification' };
}

function timeClaim(
  payload: JwtPayload,
  name: string,
  nowSeconds: number,
  warnings: string[],
): TimeClaimInfo | undefined {
  const value = payload[name];
  if (value === undefined) return undefined;
  const date = typeof value === 'number' ? new Date(value * MILLISECONDS_PER_SECOND) : undefined;
  if (typeof value !== 'number' || date === undefined || Number.isNaN(date.getTime())) {
    warnings.push(`"${name}" is not a valid NumericDate`);
    return undefined;
  }
  return { value, iso: date.toISOString(), secondsFromNow: value - nowSeconds };
}

function stringClaim(payload: JwtPayload, name: string, warnings: string[]): string | undefined {
  const value = payload[name];
  if (value === undefined) return undefined;
  if (typeof value === 'string') return value;
  warnings.push(`"${name}" is not a string`);
  return undefined;
}

function audienceClaim(payload: JwtPayload, warnings: string[]): readonly string[] {
  const value = payload['aud'];
  if (value === undefined) return [];
  if (typeof value === 'string') return [value];
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
    return value;
  }
  warnings.push('"aud" is not a string or a list of strings');
  return [];
}

function headerWarnings(header: JwtHeader, signatureBytes: number): string[] {
  const warnings: string[] = [];
  const algorithm = header['alg'];
  if (isNoneAlgorithm(algorithm)) {
    warnings.push('alg is "none": the token is unsigned and must never be trusted');
  } else if (typeof algorithm !== 'string') {
    warnings.push('header has no valid "alg"');
  } else if (!isSupportedAlgorithm(algorithm)) {
    warnings.push(`algorithm ${JSON.stringify(algorithm)} cannot be verified by this tool`);
  }
  if (signatureBytes === 0 && !isNoneAlgorithm(algorithm)) warnings.push('signature is empty');
  for (const name of UNTRUSTED_HEADERS) {
    if (header[name] !== undefined) {
      warnings.push(`header "${name}" is present; it is never followed or trusted`);
    }
  }
  if (header['crit'] !== undefined) {
    warnings.push('header "crit" is present; verify rejects tokens that use it');
  }
  return warnings;
}

export function inspect(token: string, options: InspectOptions = {}): InspectResult {
  const parsed = parseToken(token, resolveMaxTokenLength(options.maxTokenLength));
  const tolerance = resolveClockTolerance(options.clockToleranceSeconds);
  const nowSeconds = resolveNowSeconds(options.now);
  const { header, payload } = parsed;
  const warnings = headerWarnings(header, parsed.signatureBytes.length);
  const expiresAt = timeClaim(payload, 'exp', nowSeconds, warnings);
  const notBefore = timeClaim(payload, 'nbf', nowSeconds, warnings);
  const issuedAt = timeClaim(payload, 'iat', nowSeconds, warnings);
  if (payload['exp'] === undefined) warnings.push('token has no "exp" claim');
  const keyId = header['kid'];
  return {
    header,
    payload,
    algorithm: describeAlgorithm(header['alg']),
    signature: { present: parsed.signatureBytes.length > 0, bytes: parsed.signatureBytes.length },
    issuer: stringClaim(payload, 'iss', warnings),
    subject: stringClaim(payload, 'sub', warnings),
    audience: audienceClaim(payload, warnings),
    keyId: typeof keyId === 'string' ? keyId : undefined,
    expiresAt,
    notBefore,
    issuedAt,
    expired: expiresAt !== undefined && nowSeconds >= expiresAt.value + tolerance,
    notYetValid: notBefore !== undefined && nowSeconds + tolerance < notBefore.value,
    warnings,
  };
}
