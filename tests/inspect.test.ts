import { describe, expect, it } from 'vitest';
import { inspect } from '../src/index.js';
import { formatRelative } from '../src/cli/format.js';
import {
  AUDIENCE,
  b64,
  codeOf,
  ISSUER,
  NOW,
  NOW_SECONDS,
  payloadFor,
  signHs256,
  signRs256,
} from './helpers.js';

describe('inspect', () => {
  it('summarises a healthy HS256 token', () => {
    const result = inspect(signHs256(), { now: NOW });
    expect(result.algorithm).toEqual({
      name: 'HS256',
      supported: true,
      description: 'HMAC using SHA-256 (shared secret)',
    });
    expect(result.signature).toEqual({ present: true, bytes: 32 });
    expect(result.issuer).toBe(ISSUER);
    expect(result.subject).toBe('user-1');
    expect(result.audience).toEqual([AUDIENCE]);
    expect(result.expiresAt).toEqual({
      value: NOW_SECONDS + 3600,
      iso: '2026-10-05T13:00:00.000Z',
      secondsFromNow: 3600,
    });
    expect(result.issuedAt?.secondsFromNow).toBe(-60);
    expect(result.expired).toBe(false);
    expect(result.notYetValid).toBe(false);
    expect(result.warnings).toEqual([]);
  });

  it('reports RS256 signature size', () => {
    expect(inspect(signRs256(), { now: NOW }).signature.bytes).toBe(256);
  });

  it('flags expired and not-yet-valid tokens, honouring tolerance', () => {
    expect(inspect(signHs256(payloadFor({ exp: NOW_SECONDS - 10 })), { now: NOW }).expired).toBe(
      true,
    );
    expect(
      inspect(signHs256(payloadFor({ exp: NOW_SECONDS - 10 })), {
        now: NOW,
        clockToleranceSeconds: 11,
      }).expired,
    ).toBe(false);
    expect(
      inspect(signHs256(payloadFor({ nbf: NOW_SECONDS + 10 })), { now: NOW }).notYetValid,
    ).toBe(true);
  });

  it('warns about unsigned tokens', () => {
    const token = `${b64({ alg: 'none' })}.${b64({ sub: 'x' })}.`;
    const result = inspect(token, { now: NOW });
    expect(result.signature.present).toBe(false);
    expect(result.algorithm.supported).toBe(false);
    expect(result.warnings).toContain(
      'alg is "none": the token is unsigned and must never be trusted',
    );
    expect(result.warnings).toContain('token has no "exp" claim');
  });

  it('warns about an empty signature on a signed algorithm', () => {
    const token = `${b64({ alg: 'HS256' })}.${b64(payloadFor())}.`;
    expect(inspect(token, { now: NOW }).warnings).toContain('signature is empty');
  });

  it('warns about headers that must never be followed', () => {
    const header = {
      alg: 'HS256',
      jku: 'https://x.test',
      x5u: 'https://x.test',
      jwk: {},
      x5c: [],
      crit: ['b64'],
    };
    const { warnings } = inspect(signHs256(payloadFor(), 'k'.repeat(32), header), { now: NOW });
    expect(warnings).toEqual(
      expect.arrayContaining([
        'header "jku" is present; it is never followed or trusted',
        'header "x5u" is present; it is never followed or trusted',
        'header "jwk" is present; it is never followed or trusted',
        'header "x5c" is present; it is never followed or trusted',
        'header "crit" is present; verify rejects tokens that use it',
      ]),
    );
  });

  it('warns about unsupported or missing algorithms', () => {
    expect(
      inspect(signHs256(payloadFor(), 'k', { alg: 'ES256' }), { now: NOW }).warnings,
    ).toContain('algorithm "ES256" cannot be verified by this tool');
    expect(inspect(signHs256(payloadFor(), 'k', { typ: 'JWT' }), { now: NOW }).warnings).toContain(
      'header has no valid "alg"',
    );
  });

  it('survives malformed claim types without throwing', () => {
    const payload = { exp: 'soon', nbf: 1e20, iat: null, iss: 5, sub: [], aud: [1] };
    const result = inspect(signHs256(payload), { now: NOW });
    expect(result.expiresAt).toBeUndefined();
    expect(result.notBefore).toBeUndefined();
    expect(result.issuedAt).toBeUndefined();
    expect(result.issuer).toBeUndefined();
    expect(result.audience).toEqual([]);
    expect(result.expired).toBe(false);
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        '"exp" is not a valid NumericDate',
        '"nbf" is not a valid NumericDate',
        '"iat" is not a valid NumericDate',
        '"iss" is not a string',
        '"sub" is not a string',
        '"aud" is not a string or a list of strings',
      ]),
    );
  });

  it('accepts audience as a list and exposes the key id', () => {
    const header = { alg: 'HS256', kid: 'k1' };
    const result = inspect(signHs256(payloadFor({ aud: ['a', 'b'] }), 'k'.repeat(32), header), {
      now: NOW,
    });
    expect(result.audience).toEqual(['a', 'b']);
    expect(result.keyId).toBe('k1');
  });

  it('applies the decode safeguards', () => {
    expect(codeOf(() => inspect('a.b'))).toBe('malformed_token');
    expect(codeOf(() => inspect(signHs256(), { maxTokenLength: 5 }))).toBe('token_too_large');
    expect(codeOf(() => inspect(signHs256(), { clockToleranceSeconds: -1 }))).toBe(
      'invalid_options',
    );
  });
});

describe('formatRelative', () => {
  it.each([
    [0, 'now'],
    [0.4, 'now'],
    [45, 'in 45s'],
    [-45, '45s ago'],
    [3600, 'in 1h'],
    [3661, 'in 1h 1m'],
    [-90_061, '1d 1h ago'],
  ])('%s -> %s', (seconds, expected) => {
    expect(formatRelative(seconds)).toBe(expected);
  });
});
