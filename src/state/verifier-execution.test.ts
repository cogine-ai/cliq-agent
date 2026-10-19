// Pure routing refusal only. This never constructs a verified-source graph,
// grants execution or substitutes for the installed inherited-delivery proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { assertLocalDeliveryVerifierSelection } from './verifier-execution.js';

test('the shared verifier gate refuses inherited delivery and every non-local mode', () => {
  assert.doesNotThrow(() => assertLocalDeliveryVerifierSelection({ kind: 'local' }));
  for (const mode of [{ kind: 'inherited' }, { kind: 'unknown' }, {}, undefined, null])
    assert.throws(() => assertLocalDeliveryVerifierSelection(mode as never), { code: 'STATE_TRANSITION_INVALID' });
});
