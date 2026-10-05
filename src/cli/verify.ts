import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { type Algorithm } from '../algorithms.js';
import { verify } from '../verify.js';
import { formatDecoded } from './format.js';
import {
  parseOptions,
  readToken,
  reportFailure,
  STDIN_MARKER,
  UsageError,
  type CliIo,
} from './runtime.js';

const MAX_KEY_FILE_BYTES = 65_536;
const LINE_FEED = 0x0a;
const CARRIAGE_RETURN = 0x0d;
const NUMBER_PATTERN = /^\d+(\.\d+)?$/;

const OPTIONS = {
  alg: { type: 'string', multiple: true },
  'secret-env': { type: 'string' },
  'key-file': { type: 'string' },
  'secret-stdin': { type: 'boolean' },
  issuer: { type: 'string', multiple: true },
  audience: { type: 'string', multiple: true },
  kid: { type: 'string' },
  tolerance: { type: 'string' },
  'max-age': { type: 'string' },
  'allow-no-exp': { type: 'boolean' },
  json: { type: 'boolean' },
} as const;

function stripTrailingLineBreak(bytes: Buffer): Buffer {
  let end = bytes.length;
  if (end > 0 && bytes[end - 1] === LINE_FEED) end--;
  if (end > 0 && bytes[end - 1] === CARRIAGE_RETURN) end--;
  return bytes.subarray(0, end);
}

function readKeyFile(path: string): Buffer {
  try {
    if (statSync(path).size > MAX_KEY_FILE_BYTES) {
      throw new UsageError(`key file exceeds ${MAX_KEY_FILE_BYTES} bytes`);
    }
    return readFileSync(path);
  } catch (error) {
    if (error instanceof UsageError) throw error;
    throw new UsageError(`cannot read key file ${path}`);
  }
}

function loadKey(
  values: { 'secret-env'?: string; 'key-file'?: string; 'secret-stdin'?: boolean },
  io: CliIo,
): Buffer {
  const name = values['secret-env'];
  const file = values['key-file'];
  const fromStdin = values['secret-stdin'] === true;
  const sources = [name !== undefined, file !== undefined, fromStdin].filter(Boolean).length;
  if (sources !== 1) {
    throw new UsageError('provide exactly one of --secret-env, --key-file or --secret-stdin');
  }
  let key: Buffer;
  if (name !== undefined) {
    const value = io.env[name];
    if (value === undefined || value === '') {
      throw new UsageError(`environment variable ${name} is not set or is empty`);
    }
    key = Buffer.from(value, 'utf8');
  } else if (file !== undefined) {
    key = stripTrailingLineBreak(readKeyFile(resolve(io.cwd, file)));
  } else {
    key = stripTrailingLineBreak(Buffer.from(io.readStdin(), 'utf8'));
  }
  if (key.length === 0) throw new UsageError('the key is empty');
  return key;
}

function parseSeconds(name: string, value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!NUMBER_PATTERN.test(value)) {
    throw new UsageError(`--${name} must be a non-negative number of seconds`);
  }
  return Number(value);
}

export function runVerify(args: string[], io: CliIo): number {
  const { values, positionals } = parseOptions(args, OPTIONS);
  const json = values.json === true;
  if (values.alg === undefined || values.alg.length === 0) {
    throw new UsageError('--alg is required (for example --alg HS256)');
  }
  if (positionals[0] === STDIN_MARKER && values['secret-stdin'] === true) {
    throw new UsageError('the token and the key cannot both be read from stdin');
  }
  const key = loadKey(values, io);
  const token = readToken(positionals, io);
  try {
    const result = verify(token, {
      algorithms: values.alg as Algorithm[],
      key,
      issuer: values.issuer,
      audience: values.audience,
      keyId: values.kid,
      clockToleranceSeconds: parseSeconds('tolerance', values.tolerance),
      maxAgeSeconds: parseSeconds('max-age', values['max-age']),
      requireExpiration: values['allow-no-exp'] !== true,
      now: io.now(),
    });
    io.stdout.write(
      json
        ? `${JSON.stringify({ valid: true, ...result })}\n`
        : `valid (${result.algorithm})\n\n${formatDecoded(result)}`,
    );
    return 0;
  } catch (error) {
    return reportFailure(error, json, io, { valid: false });
  }
}
