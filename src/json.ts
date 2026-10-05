import { JwtError, type JwtErrorCode } from './errors.js';

export type JsonObject = Readonly<Record<string, unknown>>;

const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function findStringEnd(json: string, start: number): number {
  let index = start + 1;
  while (json.charAt(index) !== '"') {
    index += json.charAt(index) === '\\' ? 2 : 1;
  }
  return index;
}

function isObjectKey(json: string, afterString: number): boolean {
  let index = afterString;
  while (/\s/.test(json.charAt(index))) index++;
  return json.charAt(index) === ':';
}

export function hasDuplicateKeys(json: string): boolean {
  const scopes: (Set<string> | null)[] = [];
  let index = 0;
  while (index < json.length) {
    const char = json.charAt(index);
    if (char === '"') {
      const end = findStringEnd(json, index);
      const scope = scopes.at(-1);
      if (scope && isObjectKey(json, end + 1)) {
        const key = JSON.parse(json.slice(index, end + 1)) as string;
        if (scope.has(key)) return true;
        scope.add(key);
      }
      index = end + 1;
      continue;
    }
    if (char === '{') scopes.push(new Set());
    else if (char === '[') scopes.push(null);
    else if (char === '}' || char === ']') scopes.pop();
    index++;
  }
  return false;
}

export function parseJsonObject(
  bytes: Buffer,
  label: string,
  code: Extract<JwtErrorCode, 'invalid_header' | 'invalid_payload'>,
): JsonObject {
  let text: string;
  let value: unknown;
  try {
    text = UTF8.decode(bytes);
    value = JSON.parse(text);
  } catch {
    throw new JwtError(code, `${label} is not valid UTF-8 JSON`);
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new JwtError(code, `${label} must be a JSON object`);
  }
  if (hasDuplicateKeys(text)) {
    throw new JwtError(code, `${label} contains duplicate keys`);
  }
  return value as JsonObject;
}
