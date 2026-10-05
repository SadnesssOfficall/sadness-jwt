import { describe, expect, it } from 'vitest';
import {
  attacker,
  b64,
  cli,
  ISSUER,
  AUDIENCE,
  NOW_SECONDS,
  payloadFor,
  payloadWithout,
  SECRET,
  signHs256,
  signRs256,
  trusted,
  workspace,
} from './helpers.js';

const ENV = { JWT_SECRET: SECRET };
const VERIFY_HS = ['verify', '--alg', 'HS256', '--secret-env', 'JWT_SECRET'];

describe('top level', () => {
  it('prints help and exits 0', () => {
    const result = cli(['--help']);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('sadness-jwt verify');
  });

  it('prints help for a subcommand', () => {
    expect(cli(['verify', '--help']).code).toBe(0);
  });

  it('prints the package version', () => {
    expect(cli(['--version']).stdout).toMatch(/^\d+\.\d+\.\d+\n$/);
  });

  it('exits 2 with usage when called without a command', () => {
    const result = cli([]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('Usage:');
  });

  it('exits 2 for unknown commands and options', () => {
    expect(cli(['bogus']).code).toBe(2);
    expect(cli(['decode', '--nope', signHs256()]).code).toBe(2);
  });

  it('does not accept a secret as a command line argument', () => {
    const result = cli(['verify', signHs256(), '--alg', 'HS256', '--secret', SECRET]);
    expect(result.code).toBe(2);
    expect(result.stdout + result.stderr).not.toContain(SECRET);
  });
});

describe('decode', () => {
  it('prints header and payload', () => {
    const result = cli(['decode', signHs256()]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('"alg": "HS256"');
    expect(result.stdout).toContain(`"iss": "${ISSUER}"`);
  });

  it('prints machine-readable JSON', () => {
    const parsed = JSON.parse(cli(['decode', '--json', signHs256()]).stdout) as Record<
      string,
      unknown
    >;
    expect(parsed['header']).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(parsed['payload']).toMatchObject({ sub: 'user-1' });
  });

  it('reads the token from stdin, ignoring surrounding whitespace', () => {
    const result = cli(['decode', '-'], { stdin: `  ${signHs256()}\n` });
    expect(result.code).toBe(0);
  });

  it('exits 1 for a malformed token', () => {
    const result = cli(['decode', 'abc']);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('malformed_token');
  });

  it('reports failures as JSON on stdout with --json', () => {
    const result = cli(['decode', '--json', 'abc']);
    expect(result.code).toBe(1);
    expect(JSON.parse(result.stdout)).toEqual({
      error: { code: 'malformed_token', message: expect.any(String) as string },
    });
  });

  it('exits 2 without exactly one token', () => {
    expect(cli(['decode']).code).toBe(2);
    expect(cli(['decode', 'a', 'b']).code).toBe(2);
  });

  it('escapes terminal control characters in claims', () => {
    const result = cli(['decode', signHs256({ note: '\u001b[31mred\u001b]0;pwn\u0007' })]);
    expect(result.stdout).not.toContain('\u001b');
    expect(result.stdout).not.toContain('\u0007');
  });
});

describe('inspect', () => {
  it('prints a summary with timing', () => {
    const result = cli(['inspect', signHs256()]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('Summary (unverified)');
    expect(result.stdout).toContain('HS256');
    expect(result.stdout).toContain('expires    2026-10-05T13:00:00.000Z (in 1h)');
    expect(result.stdout).toContain('inside its validity window');
  });

  it('reports expiry and warnings', () => {
    const token = `${b64({ alg: 'none', jku: 'https://x.test' })}.${b64({ exp: NOW_SECONDS - 5 })}.`;
    const result = cli(['inspect', token]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('expired');
    expect(result.stdout).toContain('Warnings');
    expect(result.stdout).toContain('"jku" is present');
  });

  it('prints JSON', () => {
    const parsed = JSON.parse(cli(['inspect', '--json', signHs256()]).stdout) as Record<
      string,
      unknown
    >;
    expect(parsed['expired']).toBe(false);
    expect(parsed['algorithm']).toMatchObject({ name: 'HS256', supported: true });
  });

  it('exits 1 for a malformed token', () => {
    expect(cli(['inspect', 'a.b.c']).code).toBe(1);
  });
});

describe('verify', () => {
  it('accepts a valid token using a secret from the environment', () => {
    const result = cli([...VERIFY_HS, signHs256()], { env: ENV });
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('valid (HS256)');
  });

  it('prints JSON on success', () => {
    const result = cli([...VERIFY_HS, '--json', signHs256()], { env: ENV });
    expect(JSON.parse(result.stdout)).toMatchObject({ valid: true, algorithm: 'HS256' });
  });

  it('exits 1 and never prints the secret when the signature is wrong', () => {
    const result = cli([...VERIFY_HS, signHs256(payloadFor(), 'q'.repeat(40))], { env: ENV });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('invalid_signature');
    expect(result.stdout + result.stderr).not.toContain(SECRET);
  });

  it('prints JSON on failure', () => {
    const result = cli([...VERIFY_HS, '--json', signHs256({ exp: 1 })], { env: ENV });
    expect(result.code).toBe(1);
    expect(JSON.parse(result.stdout)).toMatchObject({
      valid: false,
      error: { code: 'token_expired' },
    });
  });

  it('reads the secret from a file and drops one trailing line break', () => {
    const cwd = workspace({ 'secret.txt': `${SECRET}\n` });
    const result = cli(['verify', '--alg', 'HS256', '--key-file', 'secret.txt', signHs256()], {
      cwd,
    });
    expect(result.code).toBe(0);
    const windows = workspace({ 'secret.txt': `${SECRET}\r\n` });
    expect(
      cli(['verify', '--alg', 'HS256', '--key-file', 'secret.txt', signHs256()], { cwd: windows })
        .code,
    ).toBe(0);
  });

  it('reads the secret from stdin', () => {
    const result = cli(['verify', '--alg', 'HS256', '--secret-stdin', signHs256()], {
      stdin: `${SECRET}\n`,
    });
    expect(result.code).toBe(0);
  });

  it('verifies RS256 with a public key file', () => {
    const cwd = workspace({ 'public.pem': trusted.publicPem });
    const args = ['verify', '--alg', 'RS256', '--key-file', 'public.pem'];
    expect(cli([...args, signRs256()], { cwd }).code).toBe(0);
    expect(cli([...args, signRs256(payloadFor(), attacker.privateKey)], { cwd }).code).toBe(1);
  });

  it('verifies RS256 with a PEM from the environment', () => {
    const result = cli(['verify', '--alg', 'RS256', '--secret-env', 'PUB', signRs256()], {
      env: { PUB: trusted.publicPem },
    });
    expect(result.code).toBe(0);
  });

  it('rejects an HS256 token forged with the public key as secret', () => {
    const forged = signHs256(payloadFor({ sub: 'admin' }), trusted.publicPem);
    const cwd = workspace({ 'public.pem': trusted.publicPem });
    expect(
      cli(['verify', '--alg', 'HS256', '--key-file', 'public.pem', forged], { cwd }).code,
    ).toBe(2);
    expect(
      cli(['verify', '--alg', 'RS256', '--key-file', 'public.pem', forged], { cwd }).code,
    ).toBe(1);
  });

  it('rejects unsigned tokens', () => {
    const token = `${b64({ alg: 'none' })}.${b64(payloadFor())}.`;
    const result = cli([...VERIFY_HS, token], { env: ENV });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('algorithm_none');
  });

  it('enforces issuer, audience and key id', () => {
    const token = signHs256(payloadFor(), SECRET, { alg: 'HS256', kid: 'k1' });
    const run = (...extra: string[]) => cli([...VERIFY_HS, ...extra, token], { env: ENV }).code;
    expect(run('--issuer', ISSUER, '--audience', AUDIENCE, '--kid', 'k1')).toBe(0);
    expect(run('--issuer', 'https://evil.example')).toBe(1);
    expect(run('--audience', 'other')).toBe(1);
    expect(run('--kid', 'k2')).toBe(1);
    expect(run('--issuer', 'a', '--issuer', ISSUER)).toBe(0);
  });

  it('applies tolerance, max age and --allow-no-exp', () => {
    const expired = signHs256(payloadFor({ exp: NOW_SECONDS - 10 }));
    expect(cli([...VERIFY_HS, expired], { env: ENV }).code).toBe(1);
    expect(cli([...VERIFY_HS, '--tolerance', '11', expired], { env: ENV }).code).toBe(0);
    const old = signHs256(payloadFor({ iat: NOW_SECONDS - 500 }));
    expect(cli([...VERIFY_HS, '--max-age', '100', old], { env: ENV }).code).toBe(1);
    const noExp = payloadWithout('exp');
    expect(cli([...VERIFY_HS, signHs256(noExp)], { env: ENV }).code).toBe(1);
    expect(cli([...VERIFY_HS, '--allow-no-exp', signHs256(noExp)], { env: ENV }).code).toBe(0);
  });

  it('reads the token from stdin', () => {
    expect(cli([...VERIFY_HS, '-'], { env: ENV, stdin: `${signHs256()}\n` }).code).toBe(0);
  });
});

describe('verify usage errors', () => {
  const token = signHs256();

  it.each([
    ['no key source', ['verify', '--alg', 'HS256', token], {}],
    ['two key sources', [...VERIFY_HS, '--secret-stdin', token], ENV],
    ['no --alg', ['verify', '--secret-env', 'JWT_SECRET', token], ENV],
    ['--alg none', ['verify', '--alg', 'none', '--secret-env', 'JWT_SECRET', token], ENV],
    ['--alg ES256', ['verify', '--alg', 'ES256', '--secret-env', 'JWT_SECRET', token], ENV],
    ['unset variable', [...VERIFY_HS, token], {}],
    ['empty variable', [...VERIFY_HS, token], { JWT_SECRET: '' }],
    ['weak secret', [...VERIFY_HS, token], { JWT_SECRET: 'short' }],
    ['bad tolerance', [...VERIFY_HS, '--tolerance', 'abc', token], ENV],
    ['negative tolerance', [...VERIFY_HS, '--tolerance', '-5', token], ENV],
    ['excessive tolerance', [...VERIFY_HS, '--tolerance', '99999', token], ENV],
    ['bad max age', [...VERIFY_HS, '--max-age', '0', token], ENV],
    ['missing key file', ['verify', '--alg', 'HS256', '--key-file', 'missing.txt', token], ENV],
    ['empty stdin key', ['verify', '--alg', 'HS256', '--secret-stdin', token], ENV],
    ['token and key both on stdin', ['verify', '--alg', 'HS256', '--secret-stdin', '-'], ENV],
    ['no token', [...VERIFY_HS], ENV],
  ])('exits 2 for %s', (_name, args, env) => {
    const result = cli(args, { env, stdin: '' });
    expect(result.code).toBe(2);
    expect(result.stdout + result.stderr).not.toContain(SECRET);
  });

  it('refuses oversized key files without reading them', () => {
    const cwd = workspace({ 'big.key': 'k'.repeat(70_000) });
    const result = cli(['verify', '--alg', 'HS256', '--key-file', 'big.key', token], { cwd });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('exceeds');
  });

  it('does not echo key file contents when the key is invalid', () => {
    const cwd = workspace({ 'bad.pem': 'SUPER-SECRET-NOT-A-KEY' });
    const result = cli(['verify', '--alg', 'RS256', '--key-file', 'bad.pem', signRs256()], { cwd });
    expect(result.code).toBe(2);
    expect(result.stdout + result.stderr).not.toContain('SUPER-SECRET');
  });
});
