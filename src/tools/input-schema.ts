import { Ajv, type AnySchema, type ValidateFunction } from 'ajv';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';

/** A self-contained, synchronous schema. Never coerce, repair, apply defaults or resolve remote references. */
export function compileInputSchema<T extends Record<string, unknown>>(inputSchema: unknown): (value: unknown) => T | undefined {
  const validate = compileOutputSchema(inputSchema);
  return (value) => {
    if (!validate(value) || value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
    return immutableSnapshot(value as T);
  };
}

/** Output schemas admit the entire finite JSON domain; validation never transforms the adapter's value. */
export function compileOutputSchema(schema: unknown): (value: unknown) => boolean {
  assertBoundedJsonValue(schema, 'tool schema');
  let validate: ValidateFunction;
  try { validate = new Ajv({ strict: true, ownProperties: true }).compile(immutableSnapshot(schema) as AnySchema); }
  catch (error) { throw new TypeError('invalid or unsupported tool schema', { cause: error }); }
  if ('$async' in validate && validate.$async) throw new TypeError('tool schemas must be synchronous');
  return (value) => {
    assertBoundedJsonValue(value, 'tool value');
    return validate(value);
  };
}
