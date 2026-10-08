import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { openStateStore } from './store.js';

test('opening Run execution without an installed native backend leaves every retained authority unchanged', async () => {
  const fixture = await createAgentFixture('execution-installation', undefined, { tools: ['edit'], mode: 'accept-edits' });
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    await assert.rejects(fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material }),
      { code: process.platform === 'linux' ? 'UNSUPPORTED_EXECUTION_IDENTITY' : 'UNSUPPORTED_PLATFORM' });
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('Run execution reserves one resource owner during load and releases it when opening fails', async () => {
  const fixture = await createAgentFixture('execution-owner', undefined, { tools: ['edit'], mode: 'accept-edits' });
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const input = { runId: fixture.runId, material: fixture.authority.material };
    const refused = { code: process.platform === 'linux' ? 'UNSUPPORTED_EXECUTION_IDENTITY' : 'UNSUPPORTED_PLATFORM' };
    const first = assert.rejects(fixture.store.loadRunExecution(input), refused);
    await assert.rejects(fixture.store.loadRunExecution(input), { code: 'REVISION_CONFLICT' });
    await first;
    await assert.rejects(fixture.store.loadRunExecution(input), refused);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});

test('StateStore shutdown joins a refused resource-free execution opening and permits a successor', async () => {
  const fixture = await createAgentFixture('execution-refused-shutdown', undefined, { tools: ['edit'], mode: 'accept-edits' });
  try {
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const refused = assert.rejects(fixture.store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material }),
      { code: process.platform === 'linux' ? 'UNSUPPORTED_EXECUTION_IDENTITY' : 'UNSUPPORTED_PLATFORM' });
    const closing = fixture.store.close();
    await refused;
    await closing;
    fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
  } finally { await disposeFixture(fixture); }
});
