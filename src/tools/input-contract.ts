import { Ajv, type AnySchema } from 'ajv';
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ResolveToolInput } from '../model/attempt.js';
import type { RunAssemblyToolAuthority } from '../model/run-assembly.js';

/** Compile the frozen schemas once. No I/O, coercion, defaults, repair, or caller-supplied validator. */
export function createToolInputResolver(tools: readonly RunAssemblyToolAuthority[]): ResolveToolInput {
  const contracts = new Map(tools.map((tool) => {
    assertBoundedJsonValue(tool.inputSchema, 'tool input schema');
    const schema = immutableSnapshot(tool.inputSchema);
    if (canonicalSha256(schema) !== tool.inputSchemaRef || tool.inputSchemaRef !== tool.inputSchemaDigest) {
      throw new TypeError('tool input schema does not match its frozen reference');
    }
    // Each schema is self-contained: a $id in another tool cannot change local $ref resolution.
    const validate = new Ajv({ strict: true, ownProperties: true }).compile(schema as AnySchema);
    if ('$async' in validate && validate.$async) throw new TypeError('tool input schemas must be synchronous');
    return [tool.name, { ref: tool.inputSchemaRef, digest: tool.inputSchemaDigest, validate }] as const;
  }));
  if (contracts.size !== tools.length) throw new TypeError('tool names must be unique');
  return ({ callId, index, toolName, observedInput }) => {
    const contract = contracts.get(toolName);
    if (contract && observedInput.encoding === 'jcs_json') {
      const value = observedInput.value;
      assertBoundedJsonValue(value, 'tool input');
      if (value !== null && typeof value === 'object' && !Array.isArray(value) && contract.validate(value)) {
        return { kind: 'resolved', inputSchemaRef: contract.ref, inputSchemaDigest: contract.digest,
          value: immutableSnapshot(value as Record<string, unknown>) };
      }
    }
    // Keep rejected arguments out of diagnostics and ordinary model-visible error content.
    const base = { schemaVersion: 1, format: 'cliq-tool-input-diagnostic-v1', callId, index, toolName,
      code: contract ? 'TOOL_INPUT_INVALID' : 'TOOL_NOT_FOUND' };
    const diagnosticDigest = canonicalSha256(base);
    const diagnostic = planCanonicalArtifact({ ...base, diagnosticDigest }, base.format);
    return contract
      ? { kind: 'invalid_input', inputSchemaRef: contract.ref, inputSchemaDigest: contract.digest, diagnostic, diagnosticDigest }
      : { kind: 'unknown_tool', diagnostic, diagnosticDigest };
  };
}
