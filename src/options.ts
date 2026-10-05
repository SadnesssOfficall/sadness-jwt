import { isNoneAlgorithm, isSupportedAlgorithm, type Algorithm } from './algorithms.js';
import {
  DEFAULT_MAX_TOKEN_LENGTH,
  MAX_CLOCK_TOLERANCE_SECONDS,
  MAX_TOKEN_LENGTH_LIMIT,
  MILLISECONDS_PER_SECOND,
} from './constants.js';
import { JwtError } from './errors.js';

function invalid(message: string): JwtError {
  return new JwtError('invalid_options', message);
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

export function resolveMaxTokenLength(value: number | undefined): number {
  if (value === undefined) return DEFAULT_MAX_TOKEN_LENGTH;
  if (!Number.isInteger(value) || value < 1 || value > MAX_TOKEN_LENGTH_LIMIT) {
    throw invalid(`maxTokenLength must be an integer between 1 and ${MAX_TOKEN_LENGTH_LIMIT}`);
  }
  return value;
}

export function resolveClockTolerance(value: number | undefined): number {
  if (value === undefined) return 0;
  if (!Number.isFinite(value) || value < 0 || value > MAX_CLOCK_TOLERANCE_SECONDS) {
    throw invalid(`clockToleranceSeconds must be between 0 and ${MAX_CLOCK_TOLERANCE_SECONDS}`);
  }
  return value;
}

export function resolveMaxAge(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value) || value <= 0) {
    throw invalid('maxAgeSeconds must be a positive number');
  }
  return value;
}

export function resolveNowSeconds(value: Date | undefined): number {
  const date = value ?? new Date();
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    throw invalid('now must be a valid Date');
  }
  return date.getTime() / MILLISECONDS_PER_SECOND;
}

export function resolveStringList(
  value: string | readonly string[] | undefined,
  name: string,
): readonly string[] | undefined {
  if (value === undefined) return undefined;
  const list: readonly unknown[] = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(list) || list.length === 0 || !list.every(isNonEmptyString)) {
    throw invalid(`${name} must be a non-empty string or a non-empty list of non-empty strings`);
  }
  return list;
}

export function resolveAlgorithms(value: readonly Algorithm[]): readonly Algorithm[] {
  const list: unknown = value;
  if (!Array.isArray(list) || list.length === 0) {
    throw invalid('algorithms must be a non-empty list');
  }
  for (const name of list as unknown[]) {
    if (isNoneAlgorithm(name)) throw invalid('the "none" algorithm is never accepted');
    if (!isSupportedAlgorithm(name)) throw invalid('algorithms contains an unsupported algorithm');
  }
  return value;
}
