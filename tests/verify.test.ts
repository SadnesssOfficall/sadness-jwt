import { createSecretKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verify, type VerifyOptions } from '../src/index.js';
import {
  AUDIENCE,
  attacker,
  codeOf,
  createRsaKeyPair,
  ISSUER,
  NOW,
  payloadFor,
  SECRET,
  signHs256,
  signRs256,
  trusted,
} from './helpers.js';

const HS: VerifyOptions = { algorithms: ['HS256'], key: SECRET, now: NOW };
const RS: VerifyOptions = { algorithms: ['RS256'], key: trusted.publicPem, now: NOW };

describe('verify HS256', () => {
  it('accepts a correctly signed token and returns its contents', () => {
    const result = verify(signHs256(), HS);
    expect(result.algorithm).toBe('HS256');
    expect(result.header).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(result.payload).toMatchObject({ iss: ISSUER, aud: AUDIENCE });
  });

  it('accepts string, Buffer, Uint8Array and secret KeyObject keys', () => {
    const token = signHs256();
    expect(verify(token, { ...HS, key: Buffer.from(SECRET) }).algorithm).toBe('HS256');
    expect(verify(token, { ...HS, key: new Uint8Array(Buffer.from(SECRET)) }).algorithm).toBe(
      'HS256',
    );
    expect(verify(token, { ...HS, key: createSecretKey(Buffer.from(SECRET)) }).algorithm).toBe(
      'HS256',
    );
  });

  it('rejects a wrong secret and a tampered payload', () => {
    expect(codeOf(() => verify(signHs256(payloadFor(), 'x'.repeat(40)), HS))).toBe(
      'invalid_signature',
    );
    const [header, , signature] = signHs256().split('.');
    const forged = Buffer.from(JSON.stringify(payloadFor({ sub: 'admin' }))).toString('base64url');
    expect(codeOf(() => verify(`${header}.${forged}.${signature}`, HS))).toBe('invalid_signature');
  });

  it.each(['', 'short', 'x'.repeat(31)])('rejects the weak secret %j', (secret) => {
    expect(codeOf(() => verify(signHs256(payloadFor(), secret), { ...HS, key: secret }))).toBe(
      'weak_key',
    );
  });

  it('accepts a secret of exactly 32 bytes', () => {
    const secret = 'y'.repeat(32);
    expect(verify(signHs256(payloadFor(), secret), { ...HS, key: secret }).algorithm).toBe('HS256');
  });
});

describe('verify RS256', () => {
  it('accepts PEM string, Buffer, public KeyObject and private key material', () => {
    const token = signRs256();
    expect(verify(token, RS).algorithm).toBe('RS256');
    expect(verify(token, { ...RS, key: Buffer.from(trusted.publicPem) }).algorithm).toBe('RS256');
    expect(verify(token, { ...RS, key: trusted.publicKey }).algorithm).toBe('RS256');
    expect(verify(token, { ...RS, key: trusted.privateKey }).algorithm).toBe('RS256');
  });

  it('rejects a token signed by another key', () => {
    expect(codeOf(() => verify(signRs256(payloadFor(), attacker.privateKey), RS))).toBe(
      'invalid_signature',
    );
  });

  it('rejects keys that are not RSA public keys', () => {
    expect(codeOf(() => verify(signRs256(), { ...RS, key: 'not a pem' }))).toBe('invalid_key');
    expect(codeOf(() => verify(signRs256(), { ...RS, key: SECRET }))).toBe('invalid_key');
    expect(
      codeOf(() => verify(signRs256(), { ...RS, key: createSecretKey(Buffer.from(SECRET)) })),
    ).toBe('key_mismatch');
  });

  it('rejects RSA keys shorter than 2048 bits', () => {
    const weak = createRsaKeyPair(1024);
    expect(
      codeOf(() =>
        verify(signRs256(payloadFor(), weak.privateKey), { ...RS, key: weak.publicPem }),
      ),
    ).toBe('weak_key');
  });
});

describe('verify with several allowed algorithms', () => {
  const options = (key: VerifyOptions['key']): VerifyOptions => ({
    algorithms: ['HS256', 'RS256'],
    key,
    now: NOW,
  });

  it('picks the algorithm from the token but only within the allowed list and key type', () => {
    expect(verify(signHs256(), options(SECRET)).algorithm).toBe('HS256');
    expect(verify(signRs256(), options(trusted.publicPem)).algorithm).toBe('RS256');
    expect(codeOf(() => verify(signRs256(), options(SECRET)))).toBe('invalid_key');
    expect(codeOf(() => verify(signHs256(), options(trusted.publicPem)))).toBe('key_mismatch');
  });
});

describe('verify options', () => {
  const token = signHs256();

  it.each([
    ['empty algorithm list', { algorithms: [] }],
    ['none', { algorithms: ['none'] }],
    ['None', { algorithms: ['None'] }],
    ['unsupported algorithm', { algorithms: ['ES256'] }],
    ['lowercase algorithm', { algorithms: ['hs256'] }],
    ['non-array algorithms', { algorithms: 'HS256' }],
    ['missing key', { key: undefined }],
    ['numeric key', { key: 12345 }],
    ['null key', { key: null }],
    ['negative tolerance', { clockToleranceSeconds: -1 }],
    ['excessive tolerance', { clockToleranceSeconds: 3601 }],
    ['NaN tolerance', { clockToleranceSeconds: Number.NaN }],
    ['zero max age', { maxAgeSeconds: 0 }],
    ['infinite max age', { maxAgeSeconds: Infinity }],
    ['invalid now', { now: new Date('nope') }],
    ['non-date now', { now: 1_791_201_600 }],
    ['empty issuer', { issuer: '' }],
    ['empty issuer list', { issuer: [] }],
    ['empty audience entry', { audience: ['a', ''] }],
    ['empty key id', { keyId: '' }],
    ['zero token length', { maxTokenLength: 0 }],
  ])('rejects %s', (_name, override) => {
    const options = { ...HS, ...override } as unknown as VerifyOptions;
    expect(codeOf(() => verify(token, options))).toMatch(/^(invalid_options|invalid_key)$/);
  });

  it('checks the expected key id without using it to look anything up', () => {
    const withKid = signHs256(payloadFor(), SECRET, { alg: 'HS256', kid: 'key-1' });
    expect(verify(withKid, { ...HS, keyId: 'key-1' }).header['kid']).toBe('key-1');
    expect(codeOf(() => verify(withKid, { ...HS, keyId: 'key-2' }))).toBe('key_id_mismatch');
    expect(codeOf(() => verify(token, { ...HS, keyId: 'key-1' }))).toBe('key_id_mismatch');
    expect(verify(withKid, HS).header['kid']).toBe('key-1');
  });

  it('uses the current time when now is omitted', () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const live = signHs256({ exp: nowSeconds + 60 });
    expect(verify(live, { algorithms: ['HS256'], key: SECRET }).algorithm).toBe('HS256');
    expect(
      codeOf(() =>
        verify(signHs256({ exp: nowSeconds - 60 }), { algorithms: ['HS256'], key: SECRET }),
      ),
    ).toBe('token_expired');
  });
});
