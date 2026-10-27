// Closed pure-data subject selection. No Run, grant, StateOwner or native
// verification/publication authority is constructed by this regression.
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertRunPolicyDecisionSubject } from './agent-recovery.js';

test('policy decision subjects are closed independently for Agent and Delivery histories', () => {
  for (const subject of ['tool_call', 'child_merge', 'verifier_launch', 'dependency_install_scripts'])
    assert.doesNotThrow(() => assertRunPolicyDecisionSubject('agent', subject));
  for (const subject of ['verifier_launch', 'delivery_plan', 'dependency_install_scripts'])
    assert.doesNotThrow(() => assertRunPolicyDecisionSubject('delivery', subject));
  for (const subject of ['tool_call', 'child_merge', 'model', 'dependency_install_scripts_future', 'unknown', undefined])
    assert.throws(() => assertRunPolicyDecisionSubject('delivery', subject), /unsupported subject/);
  for (const subject of ['delivery_plan', 'model', 'dependency_install_scripts_future', 'unknown', undefined])
    assert.throws(() => assertRunPolicyDecisionSubject('agent', subject), /unsupported subject/);
  assert.throws(() => assertRunPolicyDecisionSubject('unknown' as never, 'verifier_launch'), /unsupported subject/);
});
