// Fixed diagnostic data and source wiring only, never a successful retirement
// graph, native proof, StateOwner, Run authority or physical qualification.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { InstalledVerifierOutcomeError } from './installed-verifier-result.js';

const stages = ['public_cut', 'frozen_inputs', 'source_and_candidate', 'candidate_producer', 'candidate_source',
  'verifier_request', 'verifier_policy_and_attempt', 'verifier_settlement', 'verifier_receipt', 'verifier_retirement',
  'verifier_retirement_request', 'verifier_retirement_source', 'verifier_retirement_projection', 'verifier_retirement_launch',
  'verifier_retirement_child', 'verifier_retirement_parent', 'verifier_retirement_inspector', 'verifier_retirement_processes', 'verifier_retirement_output',
  'verifier_retirement_state', 'verifier_retirement_context', 'verifier_retirement_item_seq',
  'reverse_history_and_repair', 'terminal_result', 'session_publication'] as const;
const inspectorStages = (['assembly', 'bundle', 'history', 'history_open', 'history_snapshot', 'history_schema', 'history_rows',
  'history_records', 'history_fence', 'history_commit', 'owners', 'identity', 'binding', 'claim', 'process', 'lock', 'root',
  'acquisition', 'digests', 'fields'] as const).map(stage => `verifier_retirement_inspector_${stage}` as const);

test('the real installed verifier error retains the fixed old stages and three retirement assertion stages without a cause', () => {
  for (const stage of [...stages, ...inspectorStages]) {
    const error = new InstalledVerifierOutcomeError(stage);
    assert.equal(error.diagnosticStage, stage);
    assert.equal(error.code, 'INSTALLED_VERIFIER_OUTCOME_REFUSED');
    assert.equal(error.name, 'InstalledVerifierOutcomeError');
    assert.equal(error.message, `Installed verifier outcome refused at ${stage}`);
    assert.equal(Object.hasOwn(error, 'cause'), false, 'no original decoder error is retained as a cause');
  }
});

test('inspector diagnostics label the original deep checks and thread the real readonly SQL phases', () => {
  const source = readFileSync(new URL('./installed-verifier-evidence.ts', import.meta.url), 'utf8');
  for (const stage of inspectorStages) assert(source.includes(`'${stage}'`), stage);
  const ordered = [
    ["phase('verifier_retirement_inspector_assembly')", 'decodeRetainedRunAssembly(await object(requestContext.assemblyRef))'],
    ["phase('verifier_retirement_inspector_bundle')", 'const bundle = await object(assembly.runtime.runtimeBundleRef)'],
    ["phase('verifier_retirement_inspector_history')", 'const values = await input.readOwnerHistory(stage =>'],
    ["phase('verifier_retirement_inspector_owners')", 'const owners = values.map(value => decodeStateOwnerRecord(value))'],
    ["phase('verifier_retirement_inspector_identity')", 'const inspector = await object(observation.inspectorIdentityRef)'],
    ["phase('verifier_retirement_inspector_binding')", 'check(inspector.identityDigest === observation.inspectorIdentityDigest'],
    ["phase('verifier_retirement_inspector_claim')", 'if (observation === death) check(owner.ownerEpoch === claim.stateOwnerEpoch'],
    ["phase('verifier_retirement_inspector_process')", 'const process = decodePlatformProcessIdentity(await object(owner.processIdentityRef))'],
    ["phase('verifier_retirement_inspector_lock')", 'const lock = decodeStateLockIdentity(await object(owner.stateLockIdentityRef))'],
    ["phase('verifier_retirement_inspector_root')", 'const root = decodeStateRootIdentity(await object(lock.stateRootIdentityRef))'],
    ["phase('verifier_retirement_inspector_acquisition')", 'const acquired = decodeStateOwnerAcquisitionEvidence(await object(owner.acquisitionEvidenceRef))'],
    ["phase('verifier_retirement_inspector_digests')", 'check(process.identityDigest === owner.processIdentityDigest'],
    ["phase('verifier_retirement_inspector_fields')", "for (const field of ['ownerEpoch', 'supervisorInstanceId'"]
  ];
  const original = source.slice(source.indexOf('export async function assertInstalledVerifierRetirement('));
  for (const [note, operation] of ordered) assert(original.indexOf(note!) >= 0 && original.indexOf(note!) < original.indexOf(operation!), note);
  const consumer = readFileSync(new URL('./installed-node-journey.ts', import.meta.url), 'utf8');
  assert.equal(consumer.match(/readOwnerHistory: async \(observe\?: \(stage: InstalledOwnerHistoryReadStage\) => void\) => inspectInstalledOwnerHistory\(recipe.stateRoot, observe\)\.owners/gu)?.length, 5);
  assert(source.includes("typeof stage === 'string' && Object.hasOwn(ownerHistoryPhases, stage)"));
});

test('the real diagnostic class never treats arbitrary extra arguments as messages or cause options', () => {
  let touched = 0;
  const bad = () => { touched++; throw new Error('private-value-must-not-escape'); };
  for (const extra of ['private-workspace-message', { cause: new Error('private-cause') },
    Object.defineProperty({}, 'cause', { get: bad }),
    new Proxy({}, { get: bad, getPrototypeOf: bad, ownKeys: bad, getOwnPropertyDescriptor: bad })]) {
    const error = Reflect.construct(InstalledVerifierOutcomeError, ['verifier_retirement_context', extra]) as InstalledVerifierOutcomeError;
    assert.equal(error.message, 'Installed verifier outcome refused at verifier_retirement_context');
    assert.equal(error.diagnosticStage, 'verifier_retirement_context');
    assert.equal(Object.hasOwn(error, 'cause'), false);
  }
  assert.equal(touched, 0);
});

test('retirement stage labels preserve the exact original proof, state, context and item-sequence checks in order', () => {
  const source = readFileSync(new URL('./installed-verifier-result.ts', import.meta.url), 'utf8');
  const proof = source.indexOf("stage = 'verifier_retirement';");
  const physical = source.indexOf('const physical = await assertInstalledVerifierRetirement(', proof);
  const checkpoint = source.indexOf('const cp = physical.checkpoint;', physical);
  const stateStage = source.indexOf("stage = 'verifier_retirement_state';", checkpoint);
  const state = source.indexOf('await state(cp, source.entriesRef);', stateStage);
  const contextStage = source.indexOf("stage = 'verifier_retirement_context';", state);
  const context = source.indexOf('await context(cp);', contextStage);
  const itemStage = source.indexOf("stage = 'verifier_retirement_item_seq';", context);
  const item = source.indexOf('check(cp.runItemSeq === resultRow.itemSeq);', itemStage);
  const retained = source.indexOf('retirementIdentities.push(physical.identity);', item);
  assert(proof >= 0 && physical > proof && checkpoint > physical && stateStage > checkpoint && state > stateStage &&
    contextStage > state && context > contextStage && itemStage > context && item > itemStage && retained > item,
  'each fixed label must precede its unchanged original assertion, without skipping the original retirement graph');
  assert(source.includes('throw new InstalledVerifierOutcomeError(stage);'));
});

test('the shared retirement observer updates only the existing fixed outer error stage', () => {
  const source = readFileSync(new URL('./installed-verifier-result.ts', import.meta.url), 'utf8');
  const start = source.indexOf('const physical = await assertInstalledVerifierRetirement(');
  const end = source.indexOf('const cp = physical.checkpoint;', start);
  assert(start >= 0 && end > start, 'the complete shared retirement read must remain awaited');
  assert(source.slice(start, end).includes('readRetainedArtifact: bytes, readOwnerHistory: input.readOwnerHistory }, value => { stage = value; });'),
    'only the fixed observer phase may update the existing outer diagnostic stage');
});
