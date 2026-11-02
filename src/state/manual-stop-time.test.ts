import assert from 'node:assert/strict';
import test from 'node:test';
import { manualStopTimeOrderIsValid } from './manual-stop-time.js';

const at = (millisecond: number) => `2026-11-03T00:00:00.${String(millisecond).padStart(3, '0')}Z`;
const cut = {
  sourceCheckpointCreatedAt: at(100), sourceRunUpdatedAt: at(200), sourceSessionUpdatedAt: at(300),
  projectionAt: at(400), committedAt: at(900), lastAcceptedAt: at(350)
};

test('manual logical projection survives an unrelated healthy time-fence advance during CAS', () => {
  assert(manualStopTimeOrderIsValid(cut));
  for (const lastAcceptedAt of [at(400), at(500), at(899), at(900)]) {
    assert(manualStopTimeOrderIsValid({ ...cut, lastAcceptedAt }),
      'P remains the exact source projection while true C honors the newer fence');
  }
});

test('manual projection never regresses its selected Run, checkpoint, or Session and true C stays ordered', () => {
  for (const change of [
    { sourceRunUpdatedAt: at(401) }, { sourceCheckpointCreatedAt: at(401) }, { sourceSessionUpdatedAt: at(401) },
    { committedAt: at(399) }, { lastAcceptedAt: at(901) }
  ]) {
    assert.equal(manualStopTimeOrderIsValid({ ...cut, ...change }), false);
  }
});
