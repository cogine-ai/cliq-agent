import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { InvocationJournalEntry, RunAssemblyV1 } from '../kernel/types.js';
import { ref, testFixture } from '../model/testing/fixtures.js';
import { MODEL_BROKER_ENTRY_ID } from './model-broker-native.js';
import { hasOnlySettledInstalledModelUnknowns, openWorkerInvocations } from './worker-recovery.js';
import { assertInstalledBrokerQuiescence } from './store.js';

// Pure eligibility data only: no fixture below creates an installed owner,
// validates retained artifacts, or proves native producer quiescence.
function installedAssembly(): RunAssemblyV1 {
  const assembly = testFixture('openai-compatible').assembly;
  assembly.provider.adapter = { ...assembly.provider.adapter, adapterId: MODEL_BROKER_ENTRY_ID, version: '1' };
  assembly.provider.negotiation.streaming = false;
  return assembly;
}

function settledUnknown(opId = 'model-call'): InvocationJournalEntry[] {
  const prepared: InvocationJournalEntry = { seq: 1, runId: 'run', opId, opKind: 'model', attempt: 0,
    leaseEpoch: 1, phase: 'prepared', target: ref(16), requestRef: ref(40), grantRef: ref(41), replayClass: 'retry',
    budgetDelta: { modelTokens: 100, costMicros: 200, toolCalls: 0, repairAttempts: 0 }, timestamp: '2026-09-05T00:00:02.000Z' };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: 'dispatch',
    supervisorInstanceId: 'supervisor', stateOwnerEpoch: 1, brokerFenceTokenDigest: ref(42),
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 } };
  return [prepared, claim, { ...claim, seq: 3, phase: 'unknown', budgetDelta: { ...prepared.budgetDelta },
    budgetSettlementRef: ref(43), evidenceRef: ref(44), evidenceDigest: ref(45) }];
}

test('fully charged installed model unknown is eligible data, without resolving its ambiguity', () => {
  const assembly = installedAssembly(), journal = settledUnknown();
  const before = structuredClone({ assembly, journal });
  assert.equal(hasOnlySettledInstalledModelUnknowns(assembly, journal), true);
  assert.deepEqual({ assembly, journal }, before);
});

test('eligible data and a structural callback cannot supply genuine broker quiescence', () => {
  assert.equal(hasOnlySettledInstalledModelUnknowns(installedAssembly(), settledUnknown()), true);
  let called = false;
  for (const value of [undefined, null, {}, { assertHeld() { called = true; } }]) {
    // Invalid proof must fail before any missing physical owner is touched.
    // This constructs no StateOwner, native receipt or positive authority.
    assert.throws(() => Reflect.apply(assertInstalledBrokerQuiescence, undefined, [value, undefined, undefined, 'run']),
      { code: 'ARTIFACT_MISMATCH' });
  }
  assert.equal(called, false);
});

const otherRecipes: Array<[string, (assembly: RunAssemblyV1) => void]> = [
  ['another provider', assembly => { assembly.provider.name = 'openai'; }],
  ['an unregistered endpoint', assembly => { assembly.provider.endpoint = testFixture('ollama').assembly.provider.endpoint; }],
  ['another adapter', assembly => { assembly.provider.adapter.adapterId = 'other-broker'; }],
  ['another adapter version', assembly => { assembly.provider.adapter.version = '1.0.0'; }],
  ['a streaming recipe', assembly => { assembly.provider.negotiation.streaming = true; }],
];
for (const [label, change] of otherRecipes) {
  test(`settled unknown from ${label} is not installed broker quarantine eligibility`, () => {
    const assembly = installedAssembly();
    change(assembly);
    assert.equal(hasOnlySettledInstalledModelUnknowns(assembly, settledUnknown()), false);
  });
}

for (const phase of ['prepared', 'dispatch_claimed'] as const) {
  test(`one ${phase} attempt among settled model unknowns prevents eligibility`, () => {
    const pending = settledUnknown('pending').slice(0, phase === 'prepared' ? 1 : 2)
      .map(entry => ({ ...entry, seq: entry.seq + 3 }));
    assert.equal(hasOnlySettledInstalledModelUnknowns(installedAssembly(), [...settledUnknown(), ...pending]), false);
  });
}

for (const kind of ['tool', 'manual-model'] as const) {
  test(`one open ${kind} attempt among settled model unknowns prevents eligibility`, () => {
    const other = settledUnknown('other').map(entry => ({ ...entry, seq: entry.seq + 3,
      ...(kind === 'tool' ? { opKind: 'tool' as const } : { replayClass: 'manual' as const }) }));
    assert.equal(hasOnlySettledInstalledModelUnknowns(installedAssembly(), [...settledUnknown(), ...other]), false);
  });
}

test('an empty or completely resolved Journal is not the nonempty unknown branch', () => {
  const assembly = installedAssembly(), completed = settledUnknown();
  completed[2]!.phase = 'completed';
  assert.equal(hasOnlySettledInstalledModelUnknowns(assembly, []), false);
  assert.equal(hasOnlySettledInstalledModelUnknowns(assembly, completed), false);
});

test('every budget dimension and the settlement reference must retain the complete original reservation', () => {
  for (const key of ['modelTokens', 'costMicros', 'toolCalls', 'repairAttempts'] as const) {
    const journal = settledUnknown();
    journal[2]!.budgetDelta[key] += journal[2]!.budgetDelta[key] ? -1 : 1;
    assert.equal(hasOnlySettledInstalledModelUnknowns(installedAssembly(), journal), false, key);
  }
  const unsettled = settledUnknown();
  delete unsettled[2]!.budgetSettlementRef;
  assert.equal(hasOnlySettledInstalledModelUnknowns(installedAssembly(), unsettled), false);
  const missingDimension = settledUnknown();
  delete (missingDimension[2]!.budgetDelta as Partial<InvocationJournalEntry['budgetDelta']>).repairAttempts;
  assert.equal(hasOnlySettledInstalledModelUnknowns(installedAssembly(), missingDimension), false);
});

test('all eligible unknowns stay open witnesses, while a frozen prefix never follows later phases', () => {
  const journal = [...settledUnknown(), ...settledUnknown('second').map(entry => ({ ...entry, seq: entry.seq + 3 }))];
  const frozenPrefix = journal.slice(0, 5);
  const witnesses = [canonicalSha256(journal[0]!), canonicalSha256(journal[3]!)];
  assert.equal(hasOnlySettledInstalledModelUnknowns(installedAssembly(), journal), true);
  assert.deepEqual(openWorkerInvocations(journal).map(canonicalSha256), witnesses);
  assert.deepEqual(openWorkerInvocations(frozenPrefix).map(canonicalSha256), witnesses);
  journal.push({ ...journal[5]!, seq: 7, phase: 'abandoned' });
  assert.deepEqual(openWorkerInvocations(journal).map(canonicalSha256), [witnesses[0]]);
  assert.deepEqual(openWorkerInvocations(frozenPrefix).map(canonicalSha256), witnesses);
});
