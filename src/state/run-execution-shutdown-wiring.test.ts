// Source wiring only. The real Linux timeout-retirement-failure campaign
// independently verifies the unchanged wait and retained live StateOwner.
// This test creates no task, native receipt, Run or recovery authority.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

test('worker probe closure preserves a completed result but cannot advance through retained cleanup uncertainty', async () => {
  const source = await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8');
  const start = source.indexOf('  async function closeProbe(');
  const end = source.indexOf('  async function closePublicationProbe(', start);
  assert(start >= 0 && end > start);
  const body = source.slice(start, end);
  const joined = body.indexOf('const receipt = await retained.task.cancelAndJoin();');
  const resultWins = body.indexOf('if (current.waitingOnRef !== retained.run.waitingOnRef)', joined);
  const completed = body.indexOf('if (shutdown) return current;', resultWins);
  const uncertain = body.indexOf('if (cleanupFailure !== undefined) throw cleanupFailure;', completed);
  const persist = body.indexOf('const result = await closeWorkerRecoveryProbe(', completed);
  assert(joined >= 0 && resultWins > joined && completed > resultWins && uncertain > completed && persist > uncertain,
    'a genuine result wins first; otherwise existing cleanup uncertainty must refuse before durable probe closure');
  assert.match(body, /if \(error instanceof ResourceRetirementError\) cleanupFailure \?\?= error;/u,
    'only resource retirement uncertainty becomes sticky; joined publication failures remain retryable');
  assert.match(body, /if \(retained\.closure === closingProbe\) retained\.closure = undefined;/u,
    'a failed persistence keeps the original task and permits its ordinary joined receipt retry');
  assert(!/cleanupFailure\s*=(?!=)/u.test(body), 'probe retries cannot erase the original cleanup failure');
});
