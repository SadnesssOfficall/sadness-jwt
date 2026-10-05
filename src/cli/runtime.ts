import { readFileSync } from 'node:fs';
import { parseArgs, type ParseArgsConfig } from 'node:util';
import { JwtError, isConfigurationError } from '../errors.js';

export const STDIN_MARKER = '-';
export const MAX_STDIN_BYTES = 1_048_576;
const STDIN_FD = 0;

export interface CliIo {
  stdout: { write(text: string): unknown };
  stderr: { write(text: string): unknown };
  cwd: string;
  env: Readonly<Record<string, string | undefined>>;
  readStdin(): string;
  now(): Date;
}

export class UsageError extends Error {
  override name = 'UsageError';
}

export function parseOptions<const Options extends NonNullable<ParseArgsConfig['options']>>(
  args: string[],
  options: Options,
) {
  try {
    return parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? '';
    if (code.startsWith('ERR_PARSE_ARGS')) throw new UsageError((error as Error).message);
    throw error;
  }
}

export function readProcessStdin(): string {
  let data: Buffer;
  try {
    data = readFileSync(STDIN_FD);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EOF') return '';
    throw new UsageError('cannot read standard input');
  }
  if (data.length > MAX_STDIN_BYTES) {
    throw new UsageError(`standard input exceeds ${MAX_STDIN_BYTES} bytes`);
  }
  return data.toString('utf8');
}

export function readToken(positionals: readonly string[], io: CliIo): string {
  const value = positionals[0];
  if (positionals.length !== 1 || value === undefined) {
    throw new UsageError(
      `expected exactly one token (use "${STDIN_MARKER}" to read it from stdin)`,
    );
  }
  return (value === STDIN_MARKER ? io.readStdin() : value).trim();
}

export function reportFailure(
  error: unknown,
  json: boolean,
  io: CliIo,
  base: Record<string, unknown> = {},
): number {
  if (!(error instanceof JwtError) || isConfigurationError(error)) throw error;
  if (json) {
    io.stdout.write(
      `${JSON.stringify({ ...base, error: { code: error.code, message: error.message } })}\n`,
    );
  } else {
    io.stderr.write(`sadness-jwt: ${error.message} (${error.code})\n`);
  }
  return 1;
}
