import { readFileSync } from 'node:fs';
import { JwtError } from '../errors.js';
import { runDecode, runInspect } from './read.js';
import { UsageError, type CliIo } from './runtime.js';
import { runVerify } from './verify.js';

const HELP = `sadness-jwt - decode, inspect and verify JSON Web Tokens

Usage:
  sadness-jwt decode  <token | -> [--json]
  sadness-jwt inspect <token | -> [--json]
  sadness-jwt verify  <token | -> --alg <HS256|RS256>... (--secret-env <NAME> | --key-file <path> | --secret-stdin)
                      [--issuer <iss>]... [--audience <aud>]... [--kid <id>]
                      [--tolerance <seconds>] [--max-age <seconds>] [--allow-no-exp] [--json]

Commands:
  decode   Print the header and payload. Nothing is verified.
  inspect  Decode and summarise algorithm, claims, timing and risky headers. Nothing is verified.
  verify   Check the signature against an explicit algorithm list, then the claims.

Keys are never accepted as command line arguments. Use an environment variable,
a file, or standard input. A single trailing line break is removed from files and stdin.
Pass "-" as the token to read it from standard input.

Exit codes:
  0  success / token is valid
  1  token is malformed or rejected
  2  usage, key or file error

Options:
  -h, --help       Show this help
  -v, --version    Show the version
`;

function version(): string {
  const manifest = new URL('../../package.json', import.meta.url);
  return (JSON.parse(readFileSync(manifest, 'utf8')) as { version: string }).version;
}

export function run(argv: string[], io: CliIo): number {
  const [command, ...rest] = argv;
  try {
    if (command === undefined) {
      io.stderr.write(HELP);
      return 2;
    }
    if (command === '-v' || command === '--version') {
      io.stdout.write(`${version()}\n`);
      return 0;
    }
    if (
      command === '-h' ||
      command === '--help' ||
      command === 'help' ||
      rest.includes('--help') ||
      rest.includes('-h')
    ) {
      io.stdout.write(HELP);
      return 0;
    }
    switch (command) {
      case 'decode':
        return runDecode(rest, io);
      case 'inspect':
        return runInspect(rest, io);
      case 'verify':
        return runVerify(rest, io);
      default:
        throw new UsageError(`unknown command "${command}"`);
    }
  } catch (error) {
    if (error instanceof UsageError || error instanceof JwtError) {
      io.stderr.write(`sadness-jwt: ${error.message}\n`);
      return 2;
    }
    throw error;
  }
}
