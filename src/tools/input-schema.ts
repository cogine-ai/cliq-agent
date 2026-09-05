import { Ajv, type AnySchema, type ValidateFunction } from 'ajv';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';

/** A self-contained, synchronous schema. Never coerce, repair, apply defaults or resolve remote references. */
export function compileInputSchema<T extends Record<string, unknown>>(inputSchema: unknown): (value: unknown) => T | undefined {
  assertBoundedJsonValue(inputSchema, 'tool input schema');
  let validate: ValidateFunction<T>;
  try { validate = new Ajv({ strict: true, ownProperties: true }).compile<T>(immutableSnapshot(inputSchema) as AnySchema); }
  catch (error) { throw new TypeError('invalid or unsupported tool input schema', { cause: error }); }
  if ('$async' in validate && validate.$async) throw new TypeError('tool input schemas must be synchronous');
  return (value) => {
    assertBoundedJsonValue(value, 'tool input');
    if (!validate(value) || value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
    return immutableSnapshot(value);
  };
}
