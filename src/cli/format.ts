import type { DecodedToken } from '../token.js';
import type { InspectResult, TimeClaimInfo } from '../inspect.js';

const JSON_INDENT = 2;
const DURATION_UNITS = [
  ['d', 86_400],
  ['h', 3600],
  ['m', 60],
  ['s', 1],
] as const;
const MAX_DURATION_PARTS = 2;

export function formatRelative(seconds: number): string {
  const rounded = Math.round(seconds);
  if (rounded === 0) return 'now';
  let remaining = Math.abs(rounded);
  const parts: string[] = [];
  for (const [label, size] of DURATION_UNITS) {
    const count = Math.floor(remaining / size);
    if (count > 0) {
      parts.push(`${count}${label}`);
      remaining -= count * size;
    }
    if (parts.length === MAX_DURATION_PARTS) break;
  }
  const text = parts.join(' ');
  return rounded > 0 ? `in ${text}` : `${text} ago`;
}

export function formatDecoded(decoded: Pick<DecodedToken, 'header' | 'payload'>): string {
  return [
    'Header',
    JSON.stringify(decoded.header, null, JSON_INDENT),
    '',
    'Payload',
    JSON.stringify(decoded.payload, null, JSON_INDENT),
    '',
  ].join('\n');
}

function formatTime(label: string, claim: TimeClaimInfo | undefined): string[] {
  if (claim === undefined) return [];
  return [`  ${label} ${claim.iso} (${formatRelative(claim.secondsFromNow)})`];
}

function formatStatus(result: InspectResult): string {
  if (result.expired) return 'expired';
  if (result.notYetValid) return 'not yet valid';
  return 'inside its validity window';
}

export function formatInspect(result: InspectResult): string {
  const signature = result.signature.present
    ? `present (${result.signature.bytes} bytes, not verified)`
    : 'absent';
  const lines = [
    formatDecoded(result),
    'Summary (unverified)',
    `  algorithm  ${result.algorithm.name === undefined ? 'unknown' : JSON.stringify(result.algorithm.name)} - ${result.algorithm.description}`,
    `  signature  ${signature}`,
  ];
  if (result.issuer !== undefined) lines.push(`  issuer     ${JSON.stringify(result.issuer)}`);
  if (result.subject !== undefined) lines.push(`  subject    ${JSON.stringify(result.subject)}`);
  if (result.audience.length > 0) {
    lines.push(`  audience   ${result.audience.map((value) => JSON.stringify(value)).join(', ')}`);
  }
  if (result.keyId !== undefined) lines.push(`  key id     ${JSON.stringify(result.keyId)}`);
  lines.push(
    ...formatTime('expires   ', result.expiresAt),
    ...formatTime('not before', result.notBefore),
    ...formatTime('issued at ', result.issuedAt),
    `  status     ${formatStatus(result)}`,
  );
  if (result.warnings.length > 0) {
    lines.push('', 'Warnings', ...result.warnings.map((warning) => `  - ${warning}`));
  }
  return `${lines.join('\n')}\n`;
}
