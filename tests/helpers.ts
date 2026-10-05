import { createHmac, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach } from 'vitest';
import { run } from '../src/cli/main.js';
import { JwtError } from '../src/errors.js';

export const NOW = new Date('2026-10-05T12:00:00Z');
export const NOW_SECONDS = NOW.getTime() / 1000;
export const SECRET = 'correct-horse-battery-staple-0123456789';
export const ISSUER = 'https://issuer.example';
export const AUDIENCE = 'orders-api';

export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  publicPem: string;
}

export function createRsaKeyPair(modulusLength = 2048): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength });
  return {
    publicKey,
    privateKey,
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

export const trusted = createRsaKeyPair();
export const attacker = createRsaKeyPair();

export function b64(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

export function payloadFor(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: 'user-1',
    iat: NOW_SECONDS - 60,
    exp: NOW_SECONDS + 3600,
    ...overrides,
  };
}

export function payloadWithout(name: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(payloadFor()).filter(([key]) => key !== name));
}

export function signHs256(
  payload: Record<string, unknown> = payloadFor(),
  secret: string | Buffer = SECRET,
  header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' },
): string {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

export function signRs256(
  payload: Record<string, unknown> = payloadFor(),
  privateKey: KeyObject = trusted.privateKey,
  header: Record<string, unknown> = { alg: 'RS256', typ: 'JWT' },
): string {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${sign('sha256', Buffer.from(input), privateKey).toString('base64url')}`;
}

export function rawToken(headerJson: string, payloadJson: string, signature = ''): string {
  const encode = (text: string) => Buffer.from(text).toString('base64url');
  return `${encode(headerJson)}.${encode(payloadJson)}.${signature}`;
}

export function signRawHs256(headerJson: string, payloadJson: string): string {
  const input = rawToken(headerJson, payloadJson).slice(0, -1);
  return `${input}.${createHmac('sha256', SECRET).update(input).digest('base64url')}`;
}

const workspaces: string[] = [];

afterEach(() => {
  for (const directory of workspaces.splice(0)) rmSync(directory, { recursive: true, force: true });
});

export function workspace(files: Record<string, string | Buffer> = {}): string {
  const directory = mkdtempSync(join(tmpdir(), 'sadness-jwt-'));
  workspaces.push(directory);
  for (const [name, content] of Object.entries(files)) {
    const path = join(directory, name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  return directory;
}

export interface CliOptions {
  cwd?: string;
  env?: Record<string, string>;
  stdin?: string;
}

export function cli(args: string[], options: CliOptions = {}) {
  let stdout = '';
  let stderr = '';
  const code = run(args, {
    stdout: { write: (text) => (stdout += text) },
    stderr: { write: (text) => (stderr += text) },
    cwd: options.cwd ?? workspace(),
    env: options.env ?? {},
    readStdin: () => options.stdin ?? '',
    now: () => NOW,
  });
  return { code, stdout, stderr };
}

export function codeOf(action: () => unknown): string | undefined {
  try {
    action();
  } catch (error) {
    return error instanceof JwtError ? error.code : 'unexpected';
  }
  return undefined;
}
