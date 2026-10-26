// Compiled data contracts only. Normalization cannot create a child, grant,
// model request, lease, filesystem scope or accounting authority.
import { canonicalJsonBytes, normalizeCanonicalText } from '../kernel/canonical.js';
import type { AwaitChildrenRequest, DelegateRequest } from '../kernel/children.js';
import { assertControlWireJson, controlWireRecord } from '../kernel/control-wire-data.js';
import { mergeBudgets } from '../kernel/control-submit.js';
import { assertArtifactRef } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';

const object = (properties: Record<string, unknown>, required = Object.keys(properties)) =>
  ({ type: 'object', properties, required, additionalProperties: false });
const integer = (minimum: number, maximum: number) => ({ type: 'integer', minimum, maximum });
const names = { type: 'array', maxItems: 32, uniqueItems: true,
  items: { type: 'string', minLength: 1, maxLength: 128 } };
const budget = object({ wallTimeMs: integer(1000, 2592000000), modelTokens: integer(1, 100000000), costMicros: integer(1, 1e12),
  toolCalls: integer(1, 1000000), repairAttempts: integer(0, 64), childDepth: integer(0, 8), childConcurrency: integer(1, 64) });
const capabilities = object({ builtinToolNames: names, registeredMcpServerIds: names,
  allowShell: { type: 'boolean' }, allowSourceWrite: { type: 'boolean' } });
const compare = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));
function ids(value: unknown, maximum: number, refs = false): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new TypeError('invalid child identity array');
  const result = value.map(value => {
    if (typeof value !== 'string' || !value || value.includes('\0') || Buffer.byteLength(value) > (refs ? 64 : 128))
      throw new TypeError('invalid child identity');
    const text = normalizeCanonicalText(value); if (refs) assertArtifactRef(text); return text;
  });
  if (new Set(result).size !== result.length) throw new TypeError('duplicate child identity');
  return result;
}
export function decodeDelegateRequest(value: unknown): DelegateRequest {
  assertControlWireJson(value);
  const input = controlWireRecord(value, ['objective', 'mode', 'context', 'requestedBudgets', 'capabilities', 'verifierMode', 'allowUnverifiedHelper']);
  if (typeof input.objective !== 'string' || !['read_only', 'mutating'].includes(input.mode as string) ||
      !['inherit_parent', 'none'].includes(input.verifierMode as string) || typeof input.allowUnverifiedHelper !== 'boolean')
    throw new TypeError('invalid delegate request');
  const objective = normalizeCanonicalText(input.objective);
  if (!objective.trim() || Buffer.byteLength(objective) > 262144) throw new TypeError('child objective exceeds its bound');
  const context = controlWireRecord(input.context, ['source', 'additionalArtifactRefs']);
  const caps = controlWireRecord(input.capabilities, ['builtinToolNames', 'registeredMcpServerIds', 'allowShell', 'allowSourceWrite']);
  if (!['parent_current', 'parent_summary'].includes(context.source as string) || typeof caps.allowShell !== 'boolean' ||
      typeof caps.allowSourceWrite !== 'boolean' || input.mode === 'read_only' && caps.allowSourceWrite ||
      input.verifierMode === 'none' && !input.allowUnverifiedHelper)
    throw new TypeError('child mode or verifier consent conflicts with requested capabilities');
  const requested = controlWireRecord(input.requestedBudgets, ['wallTimeMs', 'modelTokens', 'costMicros', 'toolCalls', 'repairAttempts', 'childDepth', 'childConcurrency']);
  const result: DelegateRequest = { objective, mode: input.mode as DelegateRequest['mode'],
    context: { source: context.source as DelegateRequest['context']['source'], additionalArtifactRefs: ids(context.additionalArtifactRefs, 32, true).sort(compare) },
    requestedBudgets: mergeBudgets(requested as DelegateRequest['requestedBudgets']),
    capabilities: { builtinToolNames: ids(caps.builtinToolNames, 32).sort(compare), registeredMcpServerIds: ids(caps.registeredMcpServerIds, 32).sort(compare),
      allowShell: caps.allowShell, allowSourceWrite: caps.allowSourceWrite },
    verifierMode: input.verifierMode as DelegateRequest['verifierMode'], allowUnverifiedHelper: input.allowUnverifiedHelper };
  if (canonicalJsonBytes(result).byteLength > 1_048_576) throw new TypeError('delegate request exceeds the existing frame limit');
  return immutableSnapshot(result);
}
export function decodeAwaitChildrenRequest(value: unknown): AwaitChildrenRequest {
  assertControlWireJson(value);
  const input = controlWireRecord(value, ['childRunIds']);
  const childRunIds = ids(input.childRunIds, 64);
  if (!childRunIds.length) throw new TypeError('await requires a nonempty exact child set');
  return immutableSnapshot({ childRunIds }); // supplied order is semantic
}
export const delegateInputContract = Object.freeze({ name: 'delegate', version: '1', access: 'exec' as const, replayClass: 'retry' as const,
  inputSchema: immutableSnapshot(object({ objective: { type: 'string', minLength: 1, maxLength: 262144 }, mode: { enum: ['read_only', 'mutating'] },
    context: object({ source: { enum: ['parent_current', 'parent_summary'] }, additionalArtifactRefs: {
      type: 'array', maxItems: 32, uniqueItems: true, items: { type: 'string', pattern: '^[a-f0-9]{64}$' } } }),
    requestedBudgets: budget, capabilities, verifierMode: { enum: ['inherit_parent', 'none'] }, allowUnverifiedHelper: { type: 'boolean' } })),
  parseInput(value: unknown) {
    try { const input = decodeDelegateRequest(value); return immutableSnapshot({ input: input as unknown as Record<string, unknown>,
      channel: { kind: 'named-action' as const, action: input.mode === 'read_only' ? 'child_read_only' as const : 'child_mutating' as const },
      display: { title: input.mode === 'read_only' ? 'Allow read-only child Run?' : 'Allow mutating child Run?', detail: input.objective } }); }
    catch (error) { if (error instanceof TypeError) return undefined; throw error; }
  }
});
export const awaitChildrenInputContract = Object.freeze({ name: 'await_children', version: '1', access: 'control' as const, replayClass: 'manual' as const,
  inputSchema: immutableSnapshot(object({ childRunIds: { type: 'array', minItems: 1, maxItems: 64, uniqueItems: true,
    items: { type: 'string', minLength: 1, maxLength: 128 } } })),
  parseInput(value: unknown) {
    try { const input = decodeAwaitChildrenRequest(value); return immutableSnapshot({ input: input as unknown as Record<string, unknown>,
      display: { title: 'Wait for child Runs', detail: `${input.childRunIds.length} children` } }); }
    catch (error) { if (error instanceof TypeError) return undefined; throw error; }
  }
});
