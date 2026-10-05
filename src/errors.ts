export type JwtErrorCode =
  | 'invalid_options'
  | 'invalid_key'
  | 'weak_key'
  | 'key_mismatch'
  | 'token_too_large'
  | 'malformed_token'
  | 'invalid_base64url'
  | 'invalid_header'
  | 'invalid_payload'
  | 'algorithm_none'
  | 'algorithm_not_allowed'
  | 'unsupported_critical_header'
  | 'key_id_mismatch'
  | 'missing_signature'
  | 'invalid_signature'
  | 'token_expired'
  | 'token_not_yet_valid'
  | 'issued_in_future'
  | 'token_too_old'
  | 'missing_claim'
  | 'invalid_claim'
  | 'issuer_mismatch'
  | 'audience_mismatch';

const CONFIGURATION_CODES: ReadonlySet<JwtErrorCode> = new Set([
  'invalid_options',
  'invalid_key',
  'weak_key',
  'key_mismatch',
]);

export class JwtError extends Error {
  override name = 'JwtError';

  constructor(
    readonly code: JwtErrorCode,
    message: string,
  ) {
    super(message);
  }
}

export function isConfigurationError(error: JwtError): boolean {
  return CONFIGURATION_CODES.has(error.code);
}
