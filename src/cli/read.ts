import { inspect } from '../inspect.js';
import { decode } from '../token.js';
import { formatDecoded, formatInspect } from './format.js';
import { parseOptions, readToken, reportFailure, type CliIo } from './runtime.js';

const JSON_OUTPUT = { json: { type: 'boolean' } } as const;

export function runDecode(args: string[], io: CliIo): number {
  const { values, positionals } = parseOptions(args, JSON_OUTPUT);
  const json = values.json === true;
  try {
    const decoded = decode(readToken(positionals, io));
    io.stdout.write(json ? `${JSON.stringify(decoded)}\n` : formatDecoded(decoded));
    return 0;
  } catch (error) {
    return reportFailure(error, json, io);
  }
}

export function runInspect(args: string[], io: CliIo): number {
  const { values, positionals } = parseOptions(args, JSON_OUTPUT);
  const json = values.json === true;
  try {
    const result = inspect(readToken(positionals, io), { now: io.now() });
    io.stdout.write(json ? `${JSON.stringify(result)}\n` : formatInspect(result));
    return 0;
  } catch (error) {
    return reportFailure(error, json, io);
  }
}
