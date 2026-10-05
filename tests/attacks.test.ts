import { createHmac, createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { JwtError, verify, type VerifyOptions } from '../src/index.js';
import {
  attacker,
  b64,
  codeOf,
  NOW,
  payloadFor,
  rawToken,
  SECRET,
  signHs256,
  signRs256,
  trusted,
} from './helpers.js';

const HS: VerifyOptions = { algorithms: ['HS256'], key: SECRET, now: NOW };
const RS: VerifyOptions = { algorithms: ['RS256'], key: trusted.publicPem, now: NOW };

const hs = () => signHs256();

function messageOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    if (error instanceof JwtError) return error.message;
  }
  return '';
}

describe('alg none', () => {
  it.each(['none', 'None', 'NONE', ' none', 'none '])(
    'rejects alg %j with an empty signature',
    (alg) => {
      const token = `${b64({ alg })}.${b64(payloadFor())}.`;
      expect(codeOf(() => verify(token, HS))).toBe('algorithm_none');
      expect(codeOf(() => verify(token, RS))).toBe('algorithm_none');
    },
  );

  it('rejects alg none even when a signature is attached', () => {
    const token = `${b64({ alg: 'none' })}.${b64(payloadFor())}.${Buffer.from('x').toString('base64url')}`;
    expect(codeOf(() => verify(token, HS))).toBe('algorithm_none');
  });

  it('cannot be enabled through the allowed list', () => {
    const token = `${b64({ alg: 'none' })}.${b64(payloadFor())}.`;
    expect(codeOf(() => verify(token, { ...HS, algorithms: ['none' as never] }))).toBe(
      'invalid_options',
    );
  });
});

describe('algorithm confusion', () => {
  const forged = (publicPem: string) =>
    signHs256(payloadFor({ sub: 'admin' }), publicPem, { alg: 'HS256', typ: 'JWT' });

  it('refuses to use a public PEM as an HMAC secret', () => {
    const token = forged(trusted.publicPem);
    expect(codeOf(() => verify(token, { ...HS, key: trusted.publicPem }))).toBe('key_mismatch');
    expect(codeOf(() => verify(token, { ...HS, key: Buffer.from(trusted.publicPem) }))).toBe(
      'key_mismatch',
    );
    expect(codeOf(() => verify(token, { ...HS, key: trusted.publicKey }))).toBe('key_mismatch');
    expect(codeOf(() => verify(token, { ...HS, key: trusted.privateKey }))).toBe('key_mismatch');
  });

  it('refuses a PEM with altered surrounding whitespace', () => {
    const padded = `\n\n  ${trusted.publicPem}\n`;
    expect(codeOf(() => verify(forged(padded), { ...HS, key: padded }))).toBe('key_mismatch');
  });

  it('refuses DER encoded public keys as HMAC secrets', () => {
    const spki = trusted.publicKey.export({ type: 'spki', format: 'der' });
    const pkcs1 = createPublicKey(trusted.publicPem).export({ type: 'pkcs1', format: 'der' });
    const token = signHs256(payloadFor(), spki);
    expect(codeOf(() => verify(token, { ...HS, key: spki }))).toBe('key_mismatch');
    expect(codeOf(() => verify(signHs256(payloadFor(), pkcs1), { ...HS, key: pkcs1 }))).toBe(
      'key_mismatch',
    );
  });

  it('never accepts the forged token when both algorithms are allowed', () => {
    const options: VerifyOptions = {
      algorithms: ['HS256', 'RS256'],
      key: trusted.publicPem,
      now: NOW,
    };
    expect(codeOf(() => verify(forged(trusted.publicPem), options))).toBe('key_mismatch');
  });

  it('rejects an HS256 header when only RS256 is allowed', () => {
    expect(codeOf(() => verify(forged(trusted.publicPem), RS))).toBe('algorithm_not_allowed');
  });

  it('rejects an RS256 header when only HS256 is allowed', () => {
    expect(codeOf(() => verify(signRs256(), HS))).toBe('algorithm_not_allowed');
  });

  it.each([
    ['lowercase', 'hs256'],
    ['unsupported', 'HS512'],
    ['EdDSA', 'EdDSA'],
    ['empty', ''],
  ])('rejects an alg header that is %s', (_name, alg) => {
    expect(codeOf(() => verify(signHs256(payloadFor(), SECRET, { alg }), HS))).toBe(
      'algorithm_not_allowed',
    );
  });

  it.each([123, null, ['HS256'], { a: 1 }, true])('rejects a non-string alg %j', (alg) => {
    expect(codeOf(() => verify(signHs256(payloadFor(), SECRET, { alg }), HS))).toBe(
      'invalid_header',
    );
  });

  it('rejects a header without alg', () => {
    expect(codeOf(() => verify(signHs256(payloadFor(), SECRET, { typ: 'JWT' }), HS))).toBe(
      'invalid_header',
    );
  });

  it('rejects an attacker-chosen duplicate alg key', () => {
    const input = `${Buffer.from('{"alg":"none","alg":"HS256"}').toString('base64url')}.${b64(payloadFor())}`;
    const signature = createHmac('sha256', SECRET).update(input).digest('base64url');
    expect(codeOf(() => verify(`${input}.${signature}`, HS))).toBe('invalid_header');
  });
});

describe('signature tampering', () => {
  const hs = signHs256();
  const rs = signRs256();
  const signatureOf = (token: string) =>
    Buffer.from(token.slice(token.lastIndexOf('.') + 1), 'base64url');
  const withSignature = (token: string, bytes: Buffer) =>
    `${token.slice(0, token.lastIndexOf('.') + 1)}${bytes.toString('base64url')}`;

  it('rejects an empty signature', () => {
    expect(codeOf(() => verify(hs.slice(0, hs.lastIndexOf('.') + 1), HS))).toBe(
      'missing_signature',
    );
    expect(codeOf(() => verify(rs.slice(0, rs.lastIndexOf('.') + 1), RS))).toBe(
      'missing_signature',
    );
  });

  it('rejects a truncated signature', () => {
    expect(codeOf(() => verify(withSignature(hs, signatureOf(hs).subarray(0, 16)), HS))).toBe(
      'invalid_signature',
    );
    expect(codeOf(() => verify(withSignature(hs, signatureOf(hs).subarray(0, 1)), HS))).toBe(
      'invalid_signature',
    );
    expect(codeOf(() => verify(withSignature(rs, signatureOf(rs).subarray(0, 128)), RS))).toBe(
      'invalid_signature',
    );
  });

  it('rejects a signature cut at an arbitrary character', () => {
    expect(['invalid_signature', 'invalid_base64url']).toContain(
      codeOf(() => verify(hs.slice(0, -4), HS)),
    );
    expect(['invalid_signature', 'invalid_base64url']).toContain(
      codeOf(() => verify(rs.slice(0, -8), RS)),
    );
  });

  it('rejects an extended signature', () => {
    const padding = Buffer.alloc(4);
    expect(
      codeOf(() => verify(withSignature(hs, Buffer.concat([signatureOf(hs), padding])), HS)),
    ).toBe('invalid_signature');
    expect(
      codeOf(() => verify(withSignature(rs, Buffer.concat([signatureOf(rs), padding])), RS)),
    ).toBe('invalid_signature');
  });

  it('rejects a signature with a flipped bit', () => {
    const bytes = signatureOf(hs);
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    expect(codeOf(() => verify(withSignature(hs, bytes), HS))).toBe('invalid_signature');
  });

  it('rejects a signature taken from another token', () => {
    const other = signHs256(payloadFor({ sub: 'someone-else' }));
    expect(codeOf(() => verify(withSignature(hs, signatureOf(other)), HS))).toBe(
      'invalid_signature',
    );
  });

  it('rejects a token with an extra segment', () => {
    expect(codeOf(() => verify(`${hs}.extra`, HS))).toBe('malformed_token');
  });
});

describe('untrusted headers', () => {
  it('does not trust a key embedded in the token', () => {
    const jwk = attacker.publicKey.export({ format: 'jwk' });
    const token = signRs256(payloadFor(), attacker.privateKey, {
      alg: 'RS256',
      jwk,
      jku: 'https://attacker.example/keys.json',
      x5u: 'https://attacker.example/cert.pem',
      x5c: ['AAAA'],
      kid: 'attacker-key',
    });
    expect(codeOf(() => verify(token, RS))).toBe('invalid_signature');
  });

  it('ignores jku, x5u and kid on a token signed with the trusted key', () => {
    const token = signRs256(payloadFor(), trusted.privateKey, {
      alg: 'RS256',
      jku: 'https://attacker.example/keys.json',
      x5u: 'https://attacker.example/cert.pem',
      kid: '../../etc/passwd',
    });
    expect(verify(token, RS).algorithm).toBe('RS256');
  });

  it('rejects critical header extensions', () => {
    const token = signHs256(payloadFor(), SECRET, { alg: 'HS256', crit: ['exp'], exp: 1 });
    expect(codeOf(() => verify(token, HS))).toBe('unsupported_critical_header');
  });
});

describe('hostile input', () => {
  it('rejects oversized tokens before decoding', () => {
    const big = signHs256({ ...payloadFor(), blob: 'x'.repeat(20_000) });
    expect(codeOf(() => verify(big, HS))).toBe('token_too_large');
    expect(verify(big, { ...HS, maxTokenLength: 40_000 }).algorithm).toBe('HS256');
  });

  it.each([
    ['padding', (s: string) => `${s}=`],
    ['standard alphabet plus', (s: string) => `${s}+`],
    ['standard alphabet slash', (s: string) => `${s}/`],
    ['leading whitespace', (s: string) => ` ${s}`],
    [
      'newline',
      (s: string) => `${s}
`,
    ],
    ['non-ascii', (s: string) => `${s}é`],
  ])('rejects base64url with %s in the payload', (_name, mutate) => {
    const [header, payload, signature] = hs().split('.') as [string, string, string];
    expect(codeOf(() => verify(`${header}.${mutate(payload)}.${signature}`, HS))).toBe(
      'invalid_base64url',
    );
  });

  it('rejects non-JSON and non-object payloads', () => {
    expect(codeOf(() => verify(rawToken('{"alg":"HS256"}', 'not json', 'AAAA'), HS))).toBe(
      'invalid_payload',
    );
    expect(codeOf(() => verify(rawToken('{"alg":"HS256"}', '[]', 'AAAA'), HS))).toBe(
      'invalid_payload',
    );
  });

  it('does not let a __proto__ claim change verification behaviour', () => {
    const token = signHs256({ ...payloadFor(), constructor: { prototype: { admin: true } } });
    verify(token, HS);
    expect(({} as Record<string, unknown>)['admin']).toBeUndefined();
  });
});

describe('error hygiene', () => {
  it('never puts the key or the token into error messages', () => {
    const token = signHs256();
    const [, payload, signature] = token.split('.') as [string, string, string];
    const attempts: (() => unknown)[] = [
      () => verify(token, { ...HS, key: 'z'.repeat(40) }),
      () => verify(token, { ...HS, key: 'short-secret-LEAK' }),
      () => verify(token, { ...HS, key: trusted.publicPem }),
      () => verify(`${token}x`, HS),
      () => verify(signHs256({ exp: 1 }), HS),
      () => verify(token, { ...HS, issuer: 'someone-else' }),
    ];
    for (const attempt of attempts) {
      const message = messageOf(attempt);
      expect(message).not.toBe('');
      for (const secretLike of [SECRET, 'LEAK', payload, signature, 'z'.repeat(40), 'BEGIN']) {
        expect(message).not.toContain(secretLike);
      }
    }
  });
});
