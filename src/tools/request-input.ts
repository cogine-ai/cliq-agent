import { Ajv2020, type AnySchema, type ValidateFunction } from 'ajv/dist/2020.js';
import { canonicalJsonBytes, normalizeCanonicalText } from '../kernel/canonical.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import type { UserInputValue } from '../kernel/user-input.js';
import { immutableSnapshot } from '../model/immutable.js';
import { compileInputSchema } from './input-schema.js';

export type RequestInput = {
  prompt: string; maximumResponseBytes: number;
} & ({ responseKind: 'text'; responseSchema?: never } | { responseKind: 'json'; responseSchema: Record<string, unknown> });

const KEYWORDS = new Set(['type', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const',
  'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems']);

/** The RFC's bounded, non-executable 2020-12 subset, not the ordinary tool-schema dialect. */
export function compileInputResponse(schema: unknown): (value: unknown) => boolean {
  assertBoundedJsonValue(schema, 'input response schema');
  if (canonicalJsonBytes(schema).byteLength > 65_536) throw new TypeError('input response schema exceeds 64 KiB');
  const visit = (value: unknown): void => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('input response schemas must be objects');
    const node = value as Record<string, unknown>;
    if (Object.keys(node).some((key) => !KEYWORDS.has(key)) ||
        (Object.hasOwn(node, 'additionalProperties') && node.additionalProperties !== false)) {
      throw new TypeError('unsupported input response schema keyword');
    }
    if (Object.hasOwn(node, 'properties')) {
      if (!node.properties || typeof node.properties !== 'object' || Array.isArray(node.properties)) throw new TypeError('invalid schema properties');
      for (const child of Object.values(node.properties)) visit(child);
    }
    if (Object.hasOwn(node, 'items')) visit(node.items);
  };
  visit(schema);
  const validate: ValidateFunction = new Ajv2020({ strict: true, ownProperties: true, allowUnionTypes: true })
    .compile(immutableSnapshot(schema) as AnySchema);
  return (value) => { assertBoundedJsonValue(value, 'user input'); return validate(value); };
}

const fields = { prompt: { type: 'string', minLength: 1, maxLength: 262_144 },
  maximumResponseBytes: { type: 'integer', minimum: 1, maximum: 1_048_576 } };
const inputSchema = immutableSnapshot({ oneOf: [
  { type: 'object', additionalProperties: false, properties: { ...fields, responseKind: { const: 'text' } },
    required: ['prompt', 'responseKind', 'maximumResponseBytes'] },
  { type: 'object', additionalProperties: false, properties: { ...fields, responseKind: { const: 'json' }, responseSchema: { type: 'object' } },
    required: ['prompt', 'responseKind', 'maximumResponseBytes', 'responseSchema'] }
] });
const parse = compileInputSchema<RequestInput>(inputSchema);

/** A control transition: it has no policy channel, OperationGrant or external dispatch. */
export const requestInputContract = Object.freeze({
  name: 'request_input', version: '1', access: 'control' as const, replayClass: 'manual' as const, inputSchema,
  parseInput(value: unknown) {
    const input = parse(value);
    if (!input) return undefined;
    try {
      const prompt = normalizeCanonicalText(input.prompt);
      if (!prompt.trim() || Buffer.byteLength(prompt) > 262_144) return undefined;
      if (input.responseKind === 'json') compileInputResponse(input.responseSchema);
      return immutableSnapshot({ input: { ...input, prompt }, display: { title: 'Input requested', detail: prompt } });
    } catch (error) { if (error instanceof Error) return undefined; throw error; }
  }
});

/** Preserve typed JSON; text must already be canonical so control-request identity never changes on replay. */
export function validateUserInput(request: RequestInput, input: UserInputValue): number {
  if (!input || Object.keys(input).length !== 2 || !Object.hasOwn(input, 'kind') || !Object.hasOwn(input, 'value') ||
      input.kind !== request.responseKind) throw new TypeError('user input kind differs from its prompt');
  let byteCount: number;
  if (input.kind === 'text') {
    if (typeof input.value !== 'string' || normalizeCanonicalText(input.value) !== input.value) throw new TypeError('input text must be NFC and contain no NUL');
    byteCount = Buffer.byteLength(input.value);
  } else {
    if (request.responseKind !== 'json' || !compileInputResponse(request.responseSchema)(input.value)) throw new TypeError('user input violates its response schema');
    byteCount = canonicalJsonBytes(input.value).byteLength;
  }
  if (byteCount > request.maximumResponseBytes) throw new TypeError('user input exceeds its prompt byte bound');
  return byteCount;
}
