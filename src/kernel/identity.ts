import { createHash } from 'node:crypto';

import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from './canonical.js';
import type { ArtifactRef, RunFrontier } from './types.js';

export const ARTIFACT_REF_PATTERN = /^[0-9a-f]{64}$/;
export const REQUEST_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const ADMISSION_KEY_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const CANONICAL_TIME_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$/;

export function assertArtifactRef(value: string): asserts value is ArtifactRef {
  if (!ARTIFACT_REF_PATTERN.test(value)) {
    throw new TypeError(`invalid artifact ref: ${JSON.stringify(value)}`);
  }
}

export function identityHash(...values: unknown[]): string {
  return Buffer.from(canonicalSha256(values), 'hex').toString('base64url');
}

export function modelOperationId(runId: string, frontier: Extract<RunFrontier, { kind: 'agent' }>): string {
  return identityHash('cliq-model-operation-v1', runId, frontier.turnId, frontier.phase,
    ...(frontier.compactionPlanRef ? [frontier.compactionPlanRef] : []));
}

export function digestOmitting<T extends Record<string, unknown>>(
  value: T,
  digestKey: keyof T & string
): string {
  const rest: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    if (key === digestKey) continue;
    rest[key] = value[key];
  }
  return canonicalSha256(rest);
}

export function sha256Bytes(bytes: Uint8Array): ArtifactRef {
  return createHash('sha256').update(bytes).digest('hex');
}

export function unsignedDecimalId(value: number | bigint): string {
  const numeric = typeof value === 'bigint' ? value : BigInt(value);
  if (numeric < 0n) {
    throw new TypeError(`device/file id must be an unsigned decimal, received ${numeric}`);
  }
  return numeric.toString(10);
}

export function encodeCanonicalTime(unixMs: number): string {
  if (!Number.isSafeInteger(unixMs) || unixMs < 0) {
    throw new TypeError('canonical time must be a nonnegative safe-integer Unix millisecond');
  }
  const date = new Date(unixMs);
  const year = date.getUTCFullYear();
  if (year < 1970 || year > 9999) {
    throw new TypeError('canonical time year must be in 1970..9999');
  }
  return date.toISOString();
}

export function parseCanonicalTime(value: string): number {
  const match = CANONICAL_TIME_PATTERN.exec(value);
  if (match === null) {
    throw new TypeError(`invalid canonical time: ${JSON.stringify(value)}`);
  }
  const year = Number(match[1]);
  if (year < 1970 || year > 9999) {
    throw new TypeError('canonical time year must be in 1970..9999');
  }
  const unixMs = Date.parse(value);
  if (!Number.isSafeInteger(unixMs) || encodeCanonicalTime(unixMs) !== value) {
    throw new TypeError(`non-canonical time spelling: ${JSON.stringify(value)}`);
  }
  return unixMs;
}

export function addCanonicalDuration(start: string, durationMs: number): string {
  if (!Number.isSafeInteger(durationMs) || durationMs <= 0) {
    throw new TypeError('duration must be a positive safe integer');
  }
  const next = parseCanonicalTime(start) + durationMs;
  if (!Number.isSafeInteger(next)) {
    throw new TypeError('canonical duration overflowed the safe-integer range');
  }
  return encodeCanonicalTime(next);
}

export function normalizeBoundedText(value: string, minBytes: number, maxBytes: number): string {
  const normalized = normalizeCanonicalText(value);
  const byteCount = Buffer.byteLength(normalized, 'utf8');
  if (byteCount < minBytes || byteCount > maxBytes) {
    throw new TypeError(`text must be ${minBytes}..${maxBytes} UTF-8 bytes, received ${byteCount}`);
  }
  return normalized;
}

export function normalizeAbsolutePath(value: string): string {
  const normalized = normalizeCanonicalText(value);
  if (!normalized.startsWith('/')) {
    throw new TypeError('workspace path must be an absolute UTF-8 path');
  }
  if (normalized.includes('\0') || normalized.includes('\\')) {
    throw new TypeError('workspace path must not contain NUL or backslash');
  }
  const byteCount = Buffer.byteLength(normalized, 'utf8');
  if (byteCount === 0 || byteCount > 4096) {
    throw new TypeError('workspace path must be 1..4096 UTF-8 bytes');
  }
  const parts = normalized.split('/');
  for (const part of parts.slice(1)) {
    if (part === '' || part === '.' || part === '..') {
      throw new TypeError('workspace path must not contain empty, ".", or ".." components');
    }
  }
  return normalized;
}

export function assertRequestId(requestId: string): void {
  if (!REQUEST_ID_PATTERN.test(requestId)) {
    throw new TypeError('requestId must be a lowercase UUIDv7');
  }
}

export function assertAdmissionKey(admissionKey: string): void {
  if (!ADMISSION_KEY_PATTERN.test(admissionKey)) {
    throw new TypeError('admissionKey must be base64url of 22..128 bytes');
  }
}

export function requiredSafeInteger(value: unknown, label: string): number {
  if (typeof value === 'bigint') {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new TypeError(`${label} is outside the safe-integer range`);
    }
    return Number(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return value;
  }
  throw new TypeError(`${label} must be a safe integer`);
}

export function canonicalJsonUtf8(value: unknown): Buffer {
  return canonicalJsonBytes(value);
}
