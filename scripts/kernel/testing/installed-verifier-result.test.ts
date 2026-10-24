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

test('the real installed verifier error retains the fixed old stages and three retirement assertion stages without a cause', () => {
  for (const stage of stages) {
    const error = new InstalledVerifierOutcomeError(stage);
    assert.equal(error.diagnosticStage, stage);
    assert.equal(error.code, 'INSTALLED_VERIFIER_OUTCOME_REFUSED');
    assert.equal(error.name, 'InstalledVerifierOutcomeError');
    assert.equal(error.message, `Installed verifier outcome refused at ${stage}`);
    assert.equal(Object.hasOwn(error, 'cause'), false, 'no original decoder error is retained as a cause');
  }
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
