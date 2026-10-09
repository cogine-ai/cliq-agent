import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { KERNEL_CAS_DIRECTORY } from '../config.js';
import type { ToolContractManifestV1 } from '../kernel/types.js';
import type { AgentModelTurn, ToolCallInputV1 } from '../protocol/agent-ir.js';
import { ResourceRetirementError } from './errors.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { createQueuedFixture, disposeFixture } from './testing/fixtures.js';
import { batch } from './testing/tool-calls.js';

for (const operation of ['recovery read', 'agent opening'] as const) {
  test(`a failed ${operation} joins every real CAS handle and retains any retirement failure`, async () => {
    const agentFixture = operation === 'agent opening'
      ? await createAgentFixture('agent-opening-join', undefined, { tools: ['edit', 'read'] }) : undefined;
    const fixture = agentFixture ?? await createQueuedFixture('recovery-read-join');
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    let missingRef = before.run.specRef, delayedRef = before.run.frontierRef!;
    if (agentFixture) {
      const manifest = await fixture.store.artifacts.readCanonical<ToolContractManifestV1>(agentFixture.authority.assembly.tools.manifestRef);
      missingRef = manifest.entries[0]!.inputSchemaRef; delayedRef = manifest.entries[1]!.inputSchemaRef;
    }
    const missingPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, missingRef);
    const savedPath = `${missingPath}.fault-fixture`;
    const delayedPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, delayedRef);
    const failure = Object.assign(new Error('uncertainty after the actual CAS handle close'), { code: 'EIO' });
    const originalOpen = fs.open;
    let entered!: () => void, release!: () => void;
    const closing = new Promise<void>(resolve => { entered = resolve; });
    const held = new Promise<void>(resolve => { release = resolve; });
    let reading: Promise<unknown> | undefined, settled = false;
    await fs.rename(missingPath, savedPath); // A real missing artifact fails independently of the held read.
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args);
      if (args[0] === delayedPath) {
        const actualClose = handle.close.bind(handle);
        handle.close = async () => {
          await actualClose();
          entered();
          await held;
          throw failure;
        };
      }
      return handle;
    }) as typeof fs.open;
    try {
      reading = agentFixture ? fixture.store.loadAgentRun({ runId: fixture.runId, material: agentFixture.authority.material })
        : fixture.store.readRecoveryClosure(fixture.runId);
      void reading.then(() => { settled = true; }, () => { settled = true; });
      await closing;
      await nextTurn();
      assert.equal(settled, false, 'the missing artifact must not end inspection while another actual read is unjoined');
      release();
      await assert.rejects(reading, error => error instanceof ResourceRetirementError && error.cause === failure);
      fs.open = originalOpen;
      await fs.rename(savedPath, missingPath);
      assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    } finally {
      release();
      await reading?.catch(() => {});
      fs.open = originalOpen;
      await fs.rename(savedPath, missingPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
      await disposeFixture(fixture);
    }
  });
}

test('typed recovery preserves actual CAS retirement failure without tagging a missing model input', async () => {
  const fixture = await createAgentFixture('typed-recovery-retirement');
  const originalOpen = fs.open;
  let savedPath: string | undefined, observedPath: string | undefined;
  try {
    // The retained model prefix is offline; this test qualifies real CAS
    // retirement through the Store interface, not native worker execution.
    await batch(fixture, [{ name: 'read', input: { path: 'a' } }]);
    const before = await fixture.store.readRecoveryClosure(fixture.runId);
    const completed = before.journal.find(entry => entry.opKind === 'model' && entry.phase === 'completed')!;
    const turn = await fixture.store.artifacts.readCanonical<AgentModelTurn>(completed.resultRef!);
    const call = await fixture.store.artifacts.readCanonical<ToolCallInputV1>(turn.toolCalls[0]!.inputRef);
    observedPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, call.observedInputRef);
    const failure = Object.assign(new Error('uncertainty retiring the actual observed input handle'), { code: 'EIO' });
    fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args);
      if (args[0] === observedPath) {
        const actualClose = handle.close.bind(handle);
        handle.close = async () => { await actualClose(); throw failure; };
      }
      return handle;
    }) as typeof fs.open;
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId),
      error => error instanceof ResourceRetirementError && error.cause === failure);
    fs.open = originalOpen;
    assert.deepEqual(await fixture.store.readRecoveryClosure(fixture.runId), before);
    savedPath = `${observedPath}.fault-fixture`;
    await fs.rename(observedPath, savedPath);
    await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), error =>
      error instanceof Error && !(error instanceof ResourceRetirementError) &&
      'code' in error && error.code === 'RECOVERY_REQUIRED');
  } finally {
    fs.open = originalOpen;
    if (savedPath && observedPath) await fs.rename(savedPath, observedPath);
    await disposeFixture(fixture);
  }
});
