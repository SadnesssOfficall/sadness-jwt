import { describe, expect, it } from 'vitest';
import { verify, type VerifyOptions } from '../src/index.js';
import {
  AUDIENCE,
  codeOf,
  ISSUER,
  NOW,
  NOW_SECONDS,
  payloadFor,
  payloadWithout,
  SECRET,
  signHs256,
  signRawHs256,
} from './helpers.js';

const HS: VerifyOptions = { algorithms: ['HS256'], key: SECRET, now: NOW };

function check(payload: Record<string, unknown>, options: Partial<VerifyOptions> = {}) {
  return codeOf(() => verify(signHs256(payload), { ...HS, ...options }));
}

describe('exp', () => {
  it('accepts a token that expires in the future', () => {
    expect(check(payloadFor({ exp: NOW_SECONDS + 1 }))).toBeUndefined();
  });

  it('rejects a token that expired in the past', () => {
    expect(check(payloadFor({ exp: NOW_SECONDS - 3600 }))).toBe('token_expired');
  });

  it('treats the expiry second itself as expired', () => {
    expect(check(payloadFor({ exp: NOW_SECONDS }))).toBe('token_expired');
  });

  it('applies clock tolerance', () => {
    const payload = payloadFor({ exp: NOW_SECONDS - 30 });
    expect(check(payload, { clockToleranceSeconds: 30 })).toBe('token_expired');
    expect(check(payload, { clockToleranceSeconds: 31 })).toBeUndefined();
  });

  it('requires exp by default and allows opting out', () => {
    const withoutExp = payloadWithout('exp');
    expect(check(withoutExp)).toBe('missing_claim');
    expect(check(withoutExp, { requireExpiration: false })).toBeUndefined();
  });

  it.each([
    ['a string', '9999999999'],
    ['null', null],
    ['a boolean', true],
    ['an object', {}],
    ['an array', [NOW_SECONDS + 100]],
  ])('rejects exp that is %s', (_name, exp) => {
    expect(check(payloadFor({ exp }))).toBe('invalid_claim');
  });

  it('rejects exp that overflows to Infinity', () => {
    const token = signRawHs256('{"alg":"HS256"}', '{"exp":1e999}');
    expect(codeOf(() => verify(token, HS))).toBe('invalid_claim');
  });

  it('rejects an expired token even when every other claim is valid', () => {
    expect(
      check(payloadFor({ exp: NOW_SECONDS - 1 }), { issuer: ISSUER, audience: AUDIENCE }),
    ).toBe('token_expired');
  });
});

describe('nbf', () => {
  it('rejects a token that is not valid yet', () => {
    expect(check(payloadFor({ nbf: NOW_SECONDS + 600 }))).toBe('token_not_yet_valid');
  });

  it('accepts a token that is valid exactly now', () => {
    expect(check(payloadFor({ nbf: NOW_SECONDS }))).toBeUndefined();
  });

  it('applies clock tolerance', () => {
    const payload = payloadFor({ nbf: NOW_SECONDS + 30 });
    expect(check(payload, { clockToleranceSeconds: 29 })).toBe('token_not_yet_valid');
    expect(check(payload, { clockToleranceSeconds: 30 })).toBeUndefined();
  });

  it('rejects a non-numeric nbf', () => {
    expect(check(payloadFor({ nbf: 'tomorrow' }))).toBe('invalid_claim');
  });
});

describe('iat and maxAgeSeconds', () => {
  it('rejects a token issued in the future', () => {
    expect(check(payloadFor({ iat: NOW_SECONDS + 600 }))).toBe('issued_in_future');
    expect(
      check(payloadFor({ iat: NOW_SECONDS + 600 }), { clockToleranceSeconds: 600 }),
    ).toBeUndefined();
  });

  it('rejects a token older than the maximum age', () => {
    const payload = payloadFor({ iat: NOW_SECONDS - 1000 });
    expect(check(payload, { maxAgeSeconds: 999 })).toBe('token_too_old');
    expect(check(payload, { maxAgeSeconds: 1000 })).toBeUndefined();
    expect(check(payload, { maxAgeSeconds: 999, clockToleranceSeconds: 1 })).toBeUndefined();
  });

  it('requires iat when a maximum age is set', () => {
    const withoutIat = payloadWithout('iat');
    expect(check(withoutIat, { maxAgeSeconds: 100 })).toBe('missing_claim');
    expect(check(withoutIat)).toBeUndefined();
  });

  it('rejects a non-numeric iat', () => {
    expect(check(payloadFor({ iat: 'now' }))).toBe('invalid_claim');
  });
});

describe('iss', () => {
  it('accepts a matching issuer, single or from a list', () => {
    expect(check(payloadFor(), { issuer: ISSUER })).toBeUndefined();
    expect(check(payloadFor(), { issuer: ['https://other.example', ISSUER] })).toBeUndefined();
  });

  it.each([ISSUER.toUpperCase(), `${ISSUER}/`, 'https://issuer.example.evil.test', ''])(
    'rejects the issuer %j',
    (iss) => {
      expect(check(payloadFor({ iss }), { issuer: ISSUER })).toBe('issuer_mismatch');
    },
  );

  it('rejects a missing or non-string issuer', () => {
    const withoutIss = payloadWithout('iss');
    expect(check(withoutIss, { issuer: ISSUER })).toBe('missing_claim');
    expect(check(payloadFor({ iss: [ISSUER] }), { issuer: ISSUER })).toBe('invalid_claim');
    expect(check(payloadFor({ iss: 1 }), { issuer: ISSUER })).toBe('invalid_claim');
  });

  it('is not enforced when no issuer is configured', () => {
    expect(check(payloadFor({ iss: 'anyone' }))).toBeUndefined();
  });
});

describe('aud', () => {
  it('accepts a matching string audience or a list containing one', () => {
    expect(check(payloadFor(), { audience: AUDIENCE })).toBeUndefined();
    expect(check(payloadFor({ aud: ['x', AUDIENCE] }), { audience: AUDIENCE })).toBeUndefined();
    expect(check(payloadFor({ aud: ['x'] }), { audience: ['y', 'x'] })).toBeUndefined();
  });

  it.each(['orders', `${AUDIENCE}-admin`, `${AUDIENCE}/`, AUDIENCE.toUpperCase(), ''])(
    'rejects the audience %j',
    (aud) => {
      expect(check(payloadFor({ aud }), { audience: AUDIENCE })).toBe('audience_mismatch');
    },
  );

  it('rejects an empty audience list', () => {
    expect(check(payloadFor({ aud: [] }), { audience: AUDIENCE })).toBe('audience_mismatch');
  });

  it('rejects a missing or malformed audience', () => {
    const withoutAud = payloadWithout('aud');
    expect(check(withoutAud, { audience: AUDIENCE })).toBe('missing_claim');
    expect(check(payloadFor({ aud: 5 }), { audience: AUDIENCE })).toBe('invalid_claim');
    expect(check(payloadFor({ aud: [AUDIENCE, 5] }), { audience: AUDIENCE })).toBe('invalid_claim');
    expect(check(payloadFor({ aud: null }), { audience: AUDIENCE })).toBe('invalid_claim');
  });

  it('is not enforced when no audience is configured', () => {
    expect(check(payloadFor({ aud: 'anyone' }))).toBeUndefined();
  });
});

describe('ordering', () => {
  it('reports signature problems before claim problems', () => {
    const token = signHs256(payloadFor({ exp: 1 }), 'x'.repeat(40));
    expect(codeOf(() => verify(token, HS))).toBe('invalid_signature');
  });
});
