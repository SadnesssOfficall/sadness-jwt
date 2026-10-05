import { decodeBase64Url } from './base64url.js';
import { TOKEN_SEGMENT_COUNT } from './constants.js';
import { JwtError } from './errors.js';
import { parseJsonObject, type JsonObject } from './json.js';
import { resolveMaxTokenLength } from './options.js';

export type JwtHeader = JsonObject;
export type JwtPayload = JsonObject;

export interface DecodeOptions {
  maxTokenLength?: number;
}

export interface DecodedToken {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
}

export interface ParsedToken extends DecodedToken {
  signingInput: string;
  signatureBytes: Buffer;
}

export function parseToken(token: unknown, maxTokenLength: number): ParsedToken {
  if (typeof token !== 'string') {
    throw new JwtError('malformed_token', 'token must be a string');
  }
  if (token.length > maxTokenLength) {
    throw new JwtError('token_too_large', `token exceeds the ${maxTokenLength} character limit`);
  }
  const segments = token.split('.');
  const [encodedHeader, encodedPayload, signature] = segments;
  if (
    segments.length !== TOKEN_SEGMENT_COUNT ||
    encodedHeader === undefined ||
    encodedPayload === undefined ||
    signature === undefined
  ) {
    throw new JwtError(
      'malformed_token',
      `token must have exactly ${TOKEN_SEGMENT_COUNT} dot-separated segments`,
    );
  }
  const header = parseJsonObject(
    decodeBase64Url(encodedHeader, 'header'),
    'header',
    'invalid_header',
  );
  const payload = parseJsonObject(
    decodeBase64Url(encodedPayload, 'payload'),
    'payload',
    'invalid_payload',
  );
  return {
    header,
    payload,
    signature,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signatureBytes: decodeBase64Url(signature, 'signature'),
  };
}

export function decode(token: string, options: DecodeOptions = {}): DecodedToken {
  const { header, payload, signature } = parseToken(
    token,
    resolveMaxTokenLength(options.maxTokenLength),
  );
  return { header, payload, signature };
}
