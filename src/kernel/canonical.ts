import crypto from 'node:crypto';

export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | CanonicalJsonValue[]
  | { [key: string]: CanonicalJsonValue };

function assertUnicodeScalarString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError('canonical JSON string contains an unpaired surrogate');
      }
      index += 1;
      continue;
    }
    if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError('canonical JSON string contains an unpaired surrogate');
    }
  }
}

export function normalizeCanonicalText(value: string): string {
  if (value.includes('\0')) {
    throw new TypeError('canonical text must not contain NUL');
  }
  assertUnicodeScalarString(value);
  return value.normalize('NFC');
}

function serializeCanonical(value: unknown, ancestors: Set<object>): string {
  if (value === null) {
    return 'null';
  }

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError('canonical JSON numbers must be finite');
      }
      return JSON.stringify(value);
    case 'string':
      assertUnicodeScalarString(value);
      return JSON.stringify(value);
    case 'undefined':
      throw new TypeError('canonical JSON does not permit undefined');
    case 'bigint':
      throw new TypeError('canonical JSON does not permit bigint');
    case 'function':
    case 'symbol':
      throw new TypeError(`canonical JSON does not permit ${typeof value}`);
    case 'object':
      break;
    default:
      throw new TypeError('unsupported canonical JSON value');
  }

  if (ancestors.has(value)) {
    throw new TypeError('canonical JSON does not permit cycles');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => serializeCanonical(entry, ancestors)).join(',')}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('canonical JSON objects must be plain objects');
    }

    const objectValue = value as Record<string, unknown>;
    const entries = Object.keys(objectValue)
      .sort()
      .map((key) => {
        assertUnicodeScalarString(key);
        return `${JSON.stringify(key)}:${serializeCanonical(objectValue[key], ancestors)}`;
      });
    return `{${entries.join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalJsonBytes(value: unknown): Buffer {
  return Buffer.from(serializeCanonical(value, new Set()), 'utf8');
}

export function canonicalSha256(value: unknown): string {
  return crypto.createHash('sha256').update(canonicalJsonBytes(value)).digest('hex');
}
