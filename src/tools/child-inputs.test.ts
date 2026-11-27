// Pure typed request projections only; none of these values creates a Run,
// grants capabilities, reserves budgets or proves any process lifecycle.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeAwaitChildrenRequest, decodeDelegateRequest, delegateInputContract } from './child-inputs.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { loadToolContracts } from './input-contract.js';

function request() { return { objective: 'Inspect the code', mode: 'read_only',
  context: { source: 'parent_current', additionalArtifactRefs: [] as string[] },
  requestedBudgets: { wallTimeMs: 60000, modelTokens: 10000, costMicros: 5000, toolCalls: 10, repairAttempts: 0, childDepth: 0, childConcurrency: 1 },
  capabilities: { builtinToolNames: ['read', 'find'], registeredMcpServerIds: [], allowShell: false, allowSourceWrite: false },
  verifierMode: 'none', allowUnverifiedHelper: true }; }

test('delegate normalizes exact inline data, preserving verifier consent and narrowing without inventing authority', () => {
  const input = request(), before = JSON.stringify(input), result = decodeDelegateRequest(input);
  assert.deepEqual(result.capabilities.builtinToolNames, ['find', 'read']);
  assert.equal(JSON.stringify(input), before); assert(Object.isFrozen(result));
  const shellRequested = request(); shellRequested.capabilities.allowShell = true;
  assert.equal(decodeDelegateRequest(shellRequested).capabilities.allowShell, true);
  const inherit = request(); inherit.verifierMode = 'inherit_parent';
  assert.equal(decodeDelegateRequest(inherit).allowUnverifiedHelper, true); // does not create consent or waive required verification
  for (const mutate of [
    (r: ReturnType<typeof request>) => { r.capabilities.allowSourceWrite = true; },
    (r: ReturnType<typeof request>) => { r.allowUnverifiedHelper = false; },
    (r: ReturnType<typeof request>) => { r.capabilities.builtinToolNames.push('read'); },
    (r: ReturnType<typeof request>) => { r.context.additionalArtifactRefs.push('foreign'); },
    (r: ReturnType<typeof request>) => { r.requestedBudgets.childDepth = 9; },
  ]) { const bad = request(); mutate(bad); assert.throws(() => decodeDelegateRequest(bad)); }
  assert.throws(() => decodeDelegateRequest({ ...input, capabilityGrantRef: 'a'.repeat(64) }));
  assert.equal(delegateInputContract.parseInput({ ...input, objective: '\0' }), undefined);
});

test('await preserves the supplied unique direct-child order; empty and duplicate sets are invalid', () => {
  assert.deepEqual(decodeAwaitChildrenRequest({ childRunIds: ['child-z', 'child-a'] }), { childRunIds: ['child-z', 'child-a'] });
  for (const value of [{ childRunIds: [] }, { childRunIds: ['a', 'a'] }, { childRunIds: ['a'], grant: 'x' },
    { childRunIds: Array.from({ length: 65 }, (_, i) => String(i)) }]) assert.throws(() => decodeAwaitChildrenRequest(value));
});

test('delegate uses a separate signed Supervisor local-operation identity and named mode policy intent', () => {
  const contract = delegateInputContract, schemaRef = canonicalSha256(contract.inputSchema);
  const entry = { name: contract.name, version: '1', description: 'Delegate one ordinary child Run', access: contract.access,
    replayClass: contract.replayClass, inputSchema: contract.inputSchema, inputSchemaRef: schemaRef, inputSchemaDigest: schemaRef,
    execution: { kind: 'supervisor_operation' as const, handlerId: 'delegate' as const,
      supervisorEntryId: 'supervisor', supervisorEntryVersion: 'real-entry-version', supervisorExecutableDigest: 'a'.repeat(64) } };
  const view = loadToolContracts([entry]).projectInvocation({ callId: 'c', index: 0, toolName: 'delegate', input: decodeDelegateRequest(request()) as never });
  assert.equal(view.kind, 'tool'); if (view.kind !== 'tool') throw new Error('permission intent expected');
  assert.deepEqual(view.subject.channel, { kind: 'named-action', action: 'child_read_only' });
  assert.equal(view.execution.kind, 'supervisor_operation');
  assert.throws(() => loadToolContracts([{ ...entry, execution: { ...entry.execution, kind: 'builtin' } } as never]));
});

test('hostile child request data executes no accessors or proxy traps', () => {
  let traps = 0;
  const getter = request(); Object.defineProperty(getter, 'requestedBudgets', { enumerable: true, get() { traps++; return {}; } });
  assert.throws(() => decodeDelegateRequest(getter)); assert.equal(traps, 0);
  const proxy = new Proxy(request(), { getPrototypeOf() { traps++; return Object.prototype; }, ownKeys() { traps++; return []; } });
  assert.throws(() => decodeDelegateRequest(proxy)); assert.equal(traps, 0);
});
