export const SUPPORTED_ALGORITHMS = ['HS256', 'RS256'] as const;

export type Algorithm = (typeof SUPPORTED_ALGORITHMS)[number];

export interface AlgorithmInfo {
  family: 'HMAC' | 'RSA';
  description: string;
}

export const ALGORITHM_INFO: Readonly<Record<Algorithm, AlgorithmInfo>> = {
  HS256: { family: 'HMAC', description: 'HMAC using SHA-256 (shared secret)' },
  RS256: { family: 'RSA', description: 'RSASSA-PKCS1-v1_5 using SHA-256 (public key)' },
};

export function isSupportedAlgorithm(value: unknown): value is Algorithm {
  return typeof value === 'string' && (SUPPORTED_ALGORITHMS as readonly string[]).includes(value);
}

export function isNoneAlgorithm(value: unknown): boolean {
  return typeof value === 'string' && value.trim().toLowerCase() === 'none';
}
