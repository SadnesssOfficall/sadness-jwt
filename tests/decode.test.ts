import { describe, expect, it } from 'vitest';
import { decodeBase64Url } from '../src/base64url.js';
import { hasDuplicateKeys } from '../src/json.js';
import { decode } from '../src/index.js';
import { b64, codeOf, rawToken, signHs256 } from './helpers.js';

describe('decode', () => {
  it('returns header, payload and the raw signature', () => {
    const token = signHs256({ sub: 'abc', admin: false });
    const decoded = decode(token);
    expect(decoded.header).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(decoded.payload).toEqual({ sub: 'abc', admin: false });
    expect(decoded.signature).toBe(token.split('.')[2]);
  });

  it('decodes unsigned tokens without verifying anything', () => {
    const token = `${b64({ alg: 'none' })}.${b64({ sub: 'x' })}.`;
    expect(decode(token)).toMatchObject({ signature: '', payload: { sub: 'x' } });
  });

  it('handles unicode claims', () => {
    expect(decode(signHs256({ name: 'Şeyma \u{1F600}' })).payload).toEqual({
      name: 'Şeyma \u{1F600}',
    });
  });

  it('keeps __proto__ as plain data and does not pollute Object.prototype', () => {
    const token = rawToken('{"alg":"HS256"}', '{"__proto__":{"polluted":true},"a":1}');
    const { payload } = decode(token);
    expect(Object.hasOwn(payload, '__proto__')).toBe(true);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    expect(Object.getPrototypeOf(payload)).toBe(Object.prototype);
  });

  it.each([
    ['non-string input', 123 as never, 'malformed_token'],
    ['no dots', 'abc', 'malformed_token'],
    ['two segments', 'a.b', 'malformed_token'],
    ['four segments', 'a.b.c.d', 'malformed_token'],
    ['five segments (JWE shape)', 'a.b.c.d.e', 'malformed_token'],
    ['empty string', '', 'malformed_token'],
    ['whitespace inside', `${b64({ alg: 'x' })} .${b64({})}.`, 'invalid_base64url'],
    ['Bearer prefix', `Bearer ${signHs256()}`, 'invalid_base64url'],
  ])('rejects %s', (_name, token, code) => {
    expect(codeOf(() => decode(token))).toBe(code);
  });

  it.each([
    ['header is an array', '[1]', '{}', 'invalid_header'],
    ['header is null', 'null', '{}', 'invalid_header'],
    ['header is a string', '"x"', '{}', 'invalid_header'],
    ['header is not JSON', '{alg:1}', '{}', 'invalid_header'],
    ['payload is an array', '{}', '[]', 'invalid_payload'],
    ['payload is a number', '{}', '1', 'invalid_payload'],
    ['payload is empty', '{}', '', 'invalid_payload'],
    ['payload has trailing data', '{}', '{} x', 'invalid_payload'],
    ['header has a BOM', '﻿{}', '{}', 'invalid_header'],
    ['payload repeats a key', '{}', '{"sub":"a","sub":"b"}', 'invalid_payload'],
    ['header repeats alg', '{"alg":"HS256","alg":"none"}', '{}', 'invalid_header'],
  ])('rejects when %s', (_name, header, payload, code) => {
    expect(codeOf(() => decode(rawToken(header, payload)))).toBe(code);
  });

  it('rejects invalid UTF-8 in the header', () => {
    const header = Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]).toString('base64url');
    expect(codeOf(() => decode(`${header}.${b64({})}.`))).toBe('invalid_header');
  });

  it('rejects a non-canonical or malformed signature segment', () => {
    const [header, payload] = signHs256().split('.');
    expect(codeOf(() => decode(`${header}.${payload}.YR`))).toBe('invalid_base64url');
    expect(codeOf(() => decode(`${header}.${payload}.a`))).toBe('invalid_base64url');
    expect(codeOf(() => decode(`${header}.${payload}.YQ==`))).toBe('invalid_base64url');
  });

  it('enforces the size limit before parsing', () => {
    const token = signHs256({ blob: 'x'.repeat(10_000) });
    expect(codeOf(() => decode(token))).toBe('token_too_large');
    expect(codeOf(() => decode('!'.repeat(9000)))).toBe('token_too_large');
    expect(decode(token, { maxTokenLength: 20_000 }).payload['blob']).toHaveLength(10_000);
    expect(codeOf(() => decode(signHs256(), { maxTokenLength: 10 }))).toBe('token_too_large');
  });

  it.each([0, -1, 1.5, Number.NaN, 2_000_000])('rejects maxTokenLength %s', (value) => {
    expect(codeOf(() => decode(signHs256(), { maxTokenLength: value }))).toBe('invalid_options');
  });
});

describe('decodeBase64Url', () => {
  it('accepts canonical unpadded base64url', () => {
    expect(decodeBase64Url('', 'x')).toHaveLength(0);
    expect(decodeBase64Url('YQ', 'x').toString()).toBe('a');
    expect(decodeBase64Url('_-8', 'x')).toEqual(Buffer.from([0xff, 0xef]));
  });

  it.each(['YQ==', 'a+b/', 'a b', 'a\n', 'é', 'YR', 'Y'])('rejects %j', (value) => {
    expect(codeOf(() => decodeBase64Url(value, 'x'))).toBe('invalid_base64url');
  });
});

describe('hasDuplicateKeys', () => {
  it.each([
    ['{"a":1,"a":2}', true],
    ['{"a":1,"\\u0061":2}', true],
    ['{"x":{"a":1,"a":2}}', true],
    ['[{"a":1},{"a":2}]', false],
    ['{"a":{"a":1}}', false],
    ['{"a":"a","b":"a"}', false],
    ['{"a":"} { \\" :","b":1}', false],
    ['{ "a" : 1 , "b" : [ "a" , "a" ] }', false],
    ['{}', false],
  ])('%s -> %s', (json, expected) => {
    expect(hasDuplicateKeys(json)).toBe(expected);
  });
});
