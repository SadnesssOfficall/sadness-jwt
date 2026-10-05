import { JwtError } from './errors.js';

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

export function decodeBase64Url(segment: string, label: string): Buffer {
  if (!BASE64URL_PATTERN.test(segment)) {
    throw new JwtError('invalid_base64url', `${label} is not valid base64url`);
  }
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) {
    throw new JwtError('invalid_base64url', `${label} is not canonical base64url`);
  }
  return bytes;
}
