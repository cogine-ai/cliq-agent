import assert from 'node:assert/strict';
import { constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../kernel/execution.js';
import type { ContextManifest, ToolResultItem, ToolResultPayloadV1, WorkspaceEntryManifest, WorkspaceStateManifest } from '../kernel/types.js';
import { ARTIFACT_CHUNK_BYTES } from './cas.js';
import { ResourceRetirementError } from './errors.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { postEffectObservation, quiescedToolCheckpoint } from './testing/tool-effects.js';

test('completed mutating tool history consumes an existing large CAS file with bounded memory and retains integrity and cancellation guards', async t => {
  const clock = Date.now();
  t.mock.method(Date, 'now', () => clock);
  const fixture = await createAgentFixture('tool-history-stream', undefined, { mode: 'accept-edits', tools: ['edit'] });
  const reader = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
  const blobBytes = 64 * 1024 * 1024;
  let restoreBlob: (() => Promise<void>) | undefined;
  try {
    // Existing offline seal fixture over the real Store/SQLite/CAS. It grants
    // no native death or installed-platform qualification. Persist first;
    // allocation/read observations below cover only fresh retained recovery.
    await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } }]);
    const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
    const proof = await quiescedToolCheckpoint(fixture, prepared.checkpointId, 'p'.repeat(blobBytes));
    const result = await fixture.store.artifacts.readCanonical<import('../kernel/tool-authorization.js').ToolObservationV1>(
      await observation(fixture, claimed, { changed: true }));
    result.postEffect = proof.checkpoint; result.observationDigest = digestOmitting(result, 'observationDigest');
    const resultArtifact = await fixture.store.artifacts.publishCanonical(result, result.format);
    await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: 0,
      expectedRunRevision: prepared.run.revision, observationRef: resultArtifact.ref });
    const workspace = await fixture.store.artifacts.readCanonical<WorkspaceStateManifest>(proof.workspaceStateRef);
    const entries = await fixture.store.artifacts.readCanonical<WorkspaceEntryManifest>(workspace.entriesRef);
    const file = entries.entries[0]!;
    assert.equal(file.kind, 'file'); if (file.kind !== 'file') assert.fail('fixture requires its actual persisted file');
    assert.equal(file.size, blobBytes);
    const root = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY), target = path.join(root, file.blobRef);
    const open = fs.open.bind(fs), lstat = fs.lstat.bind(fs), allocate = Buffer.allocUnsafe;
    const overwriteLastByte = async (byte: number) => {
      await fs.chmod(target, 0o600);
      const held = await open(target, constants.O_WRONLY | constants.O_NOFOLLOW);
      try { assert.equal((await held.write(Buffer.from([byte]), 0, 1, blobBytes - 1)).bytesWritten, 1); }
      finally { await held.close(); await fs.chmod(target, 0o400); }
    };
    type Pass = { historyTool: boolean; bytes: number; reads: number; stats: number; closed: boolean; rootChecks: number };
    let historyTool = false, fault: 'none' | 'corrupt' | 'abort' | 'close' = 'none', injected = false;
    let controller = new AbortController(), rootChecks = 0, largestAllocation = 0, opened = 0, closed = 0, peak = 0;
    let passes: Pass[] = [];
    const active = new Set<object>(), cancellation = new Error('the original retained tool history read was cancelled');
    const closeFailure = new Error('the original history file really closed but returned retirement uncertainty');
    t.mock.method(Buffer, 'allocUnsafe', (size: number) => { largestAllocation = Math.max(largestAllocation, size); return allocate(size); });
    t.mock.method(fs, 'lstat', (...args: Parameters<typeof lstat>) => {
      if (args[0] === root) rootChecks++;
      return Reflect.apply(lstat, fs, args);
    });
    t.mock.method(fs, 'open', async (...args: Parameters<typeof open>) => {
      if (args[0] === target && historyTool && fault === 'corrupt' && !injected) {
        injected = true; restoreBlob = () => overwriteLastByte(0x70);
        await overwriteLastByte(0x21); // Same real inode/length; only full-byte hashing can accept/refuse its bytes.
      }
      const held = await open(...args);
      if (args[0] !== root && !String(args[0]).startsWith(`${root}/`)) return held;
      active.add(held); opened++; peak = Math.max(peak, active.size);
      const close = held.close.bind(held);
      const pass: Pass | undefined = args[0] === target ? { historyTool, bytes: 0, reads: 0, stats: 0, closed: false, rootChecks } : undefined;
      if (pass) {
        passes.push(pass);
        const read = held.read.bind(held), stat = held.stat.bind(held);
        t.mock.method(held, 'read', async (...values: Parameters<typeof read>) => {
          const result = await Reflect.apply(read, held, values); pass.bytes += result.bytesRead; pass.reads++;
          if (pass.historyTool && fault === 'abort' && !injected) { injected = true; controller.abort(cancellation); }
          return result;
        });
        t.mock.method(held, 'stat', (...values: Parameters<typeof stat>) => { pass.stats++; return Reflect.apply(stat, held, values); });
      }
      t.mock.method(held, 'close', async () => {
        await close(); assert(active.delete(held)); closed++;
        if (pass) { pass.closed = true; pass.rootChecks = rootChecks - pass.rootChecks; }
        if (pass?.historyTool && fault === 'close' && !injected) { injected = true; throw closeFailure; }
      });
      return held;
    });
    const recover = () => readRecoveryClosure(reader, fixture.store.artifacts.withReadSignal(controller.signal), fixture.runId,
      phase => { historyTool = phase === 'history_tool'; });
    const reset = (next: typeof fault) => {
      fault = next; injected = false; historyTool = false; controller = new AbortController();
      passes = []; rootChecks = 0; largestAllocation = 0; opened = 0; closed = 0; peak = 0;
    };
    const joined = () => { assert.equal(active.size, 0); assert.equal(opened, closed); assert(passes.every(pass => pass.closed)); };
    await t.test('complete original recovery reads every byte without allocating the file', async () => {
      reset('none');
      const recovered = await recover();
      assert.equal(recovered.run.budgetConsumed.toolCalls, 1); joined();
      const history = passes.filter(pass => pass.historyTool);
      assert.equal(history.length, 1); assert.ok(passes.length >= 4, 'every independent original workspace/history/seal consumer still reads');
      assert(passes.every(pass => pass.bytes === blobBytes && pass.stats >= 2), 'each issued original file read exhausts its bytes and held-file stat guards');
      assert.ok(largestAllocation <= ARTIFACT_CHUNK_BYTES, `retained recovery allocated ${largestAllocation} bytes for a ${blobBytes}-byte file`);
      assert.ok(history[0]!.rootChecks >= history[0]!.reads, 'the named root remains current between bounded streamed reads');
      t.diagnostic(JSON.stringify({ diagnosticOnly: true, existingBlobBytes: blobBytes, fullBytePasses: passes.length,
        historyByteCount: history[0]!.bytes, largestAllocation, opened, closed, actualCasFdPeak: peak,
        successor30sQualified: false, physicalPlatformQualified: false }));
    });
    await t.test('same-size corruption in the history consumer rejects after the actual last byte', async () => {
      reset('corrupt');
      try {
        await assert.rejects(recover(), /artifact [0-9a-f]{64} is corrupt/);
        assert.equal(injected, true); joined();
        assert.equal(passes.find(pass => pass.historyTool)!.bytes, blobBytes);
      } finally { await restoreBlob?.(); restoreBlob = undefined; }
    });
    await t.test('cancellation stops the original history stream and joins its real descriptors', async () => {
      reset('abort');
      await assert.rejects(recover(), error => error === cancellation || (error as Error).cause === cancellation);
      assert.equal(injected, true); joined();
      const history = passes.find(pass => pass.historyTool)!;
      assert.ok(history.bytes > 0 && history.bytes <= ARTIFACT_CHUNK_BYTES, 'cancellation cannot consume another workspace-file chunk');
    });
    await t.test('actual history close uncertainty survives recovery and all issued descriptors still join', async () => {
      reset('close');
      await assert.rejects(recover(), error => error instanceof ResourceRetirementError && error.cause === closeFailure);
      assert.equal(injected, true); joined();
      assert.equal(passes.find(pass => pass.historyTool)!.bytes, blobBytes);
    });
  } finally {
    try { await restoreBlob?.(); } finally { t.mock.restoreAll(); reader.close(); await disposeFixture(fixture); }
  }
});

for (const substituted of ['snapshot quiescence', 'final retirement'] as const) {
  test(`completed mutating tool recovery rejects a substituted ${substituted} proof in its immutable result`, async t => {
    const clock = Date.now();
    t.mock.method(Date, 'now', () => clock);
    const fixture = await createAgentFixture(`seal-result-${substituted}`, undefined, { mode: 'accept-edits', tools: ['edit'] });
    const writer = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    let restore: (() => void) | undefined;
    try {
      // Offline canonical closure over real SQLite/CAS, not native platform qualification.
      await batch(fixture, [{ name: 'edit', input: { path: 'a', old_text: 'old', new_text: 'new' } }]);
      const prepared = await prepareTool(fixture), claimed = await claimTool(fixture, prepared);
      const proof = await postEffectObservation(fixture, await observation(fixture, claimed, { changed: true }), prepared.checkpointId);
      const completed = await fixture.agent.completeTool({ opId: prepared.entry.opId, attempt: 0,
        expectedRunRevision: prepared.run.revision, observationRef: proof.observationRef });
      const original = await fixture.store.readRecoveryClosure(fixture.runId);
      assert.equal(original.workspaceGenerations[0]!.phase, 'sealed');
      assert.equal(original.run.budgetConsumed.toolCalls, 1);

      const result = structuredClone(proof.observation);
      if (substituted === 'snapshot quiescence') {
        const death = await fixture.store.artifacts.readCanonical<ProcessContainmentDeathEvidenceV1>(proof.snapshot.quiescenceEvidenceRef);
        death.launchNonceDigest = canonicalSha256('another-worker-launch');
        death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
        const candidate = { ...proof.snapshot, quiescenceEvidenceRef:
          (await fixture.store.artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1')).ref };
        candidate.evidenceDigest = digestOmitting(candidate, 'evidenceDigest');
        result.postEffect!.snapshotEvidenceRef = (await fixture.store.artifacts.publishCanonical(candidate, candidate.format)).ref;
      } else {
        const death = await fixture.store.artifacts.readCanonical<ProcessContainmentDeathEvidenceV1>(result.postEffect!.retirementEvidenceRef);
        death.launchNonceDigest = canonicalSha256('another-worker-launch');
        death.evidenceDigest = digestOmitting(death, 'evidenceDigest');
        result.postEffect!.retirementEvidenceRef = (await fixture.store.artifacts.publishCanonical(death, 'cliq-process-containment-death-evidence-v1')).ref;
      }
      result.observationDigest = digestOmitting(result, 'observationDigest');
      const resultRef = (await fixture.store.artifacts.publishCanonical(result, result.format)).ref;
      const row = original.items.at(-1)!;
      const item = await fixture.store.artifacts.readCanonical<ToolResultItem>(row.payloadRef);
      assert.equal(item.kind, 'tool_result');
      const payload = await fixture.store.artifacts.readCanonical<ToolResultPayloadV1>(item.resultRef);
      if (payload.outcome !== 'executed' || payload.source !== 'invocation') assert.fail('fixture must have an executed invocation result');
      payload.journalResultRef = resultRef;
      payload.journalResultDigest = result.observationDigest;
      payload.payloadDigest = digestOmitting(payload, 'payloadDigest');
      item.resultRef = (await fixture.store.artifacts.publishCanonical(payload, payload.format)).ref;
      const itemRef = (await fixture.store.artifacts.publishCanonical(item, 'cliq-tool-result-item-v1')).ref;
      const context = await fixture.store.artifacts.readCanonical<ContextManifest>(original.latestCheckpoint.contextManifestRef);
      const segment = context.segments.find(segment => segment.kind === 'raw' && segment.items.some(entry => entry.itemSeq === row.itemSeq));
      if (segment?.kind !== 'raw') assert.fail('fixture must retain its tool result in raw context');
      segment.items.find(entry => entry.itemSeq === row.itemSeq)!.itemRef = itemRef;
      context.projectionDigest = digestOmitting(context, 'projectionDigest');
      const contextRef = (await fixture.store.artifacts.publishCanonical(context, context.format)).ref;
      const guards = ['run_journal_immutable_update', 'items_immutable_update', 'checkpoints_immutable_update'].map(name => {
        const guard = writer.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?").get<{ sql: string }>(name);
        assert.ok(guard);
        return { name, sql: guard.sql };
      });

      // Bypass only storage guards at the existing corruption seam, repairing
      // every result/context reference while retaining the authoritative seal.
      writer.transaction(connection => {
        for (const guard of guards) connection.exec(`DROP TRIGGER ${guard.name}`);
        connection.prepare('UPDATE run_journal SET entry_json = ? WHERE run_id = ? AND seq = ?')
          .run(JSON.stringify({ ...completed.entry, resultRef }), fixture.runId, BigInt(completed.entry.seq));
        connection.prepare('UPDATE items SET payload_ref = ? WHERE item_id = ?').run(itemRef, row.itemId);
        connection.prepare('UPDATE checkpoints SET context_manifest_ref = ? WHERE id = ?').run(contextRef, original.latestCheckpoint.id);
      });
      restore = () => writer.transaction(connection => {
        connection.prepare('UPDATE run_journal SET entry_json = ? WHERE run_id = ? AND seq = ?')
          .run(JSON.stringify(completed.entry), fixture.runId, BigInt(completed.entry.seq));
        connection.prepare('UPDATE items SET payload_ref = ? WHERE item_id = ?').run(row.payloadRef, row.itemId);
        connection.prepare('UPDATE checkpoints SET context_manifest_ref = ? WHERE id = ?')
          .run(original.latestCheckpoint.contextManifestRef, original.latestCheckpoint.id);
        for (const guard of guards) connection.exec(guard.sql);
      });

      const rejection = { code: 'RECOVERY_REQUIRED', message: /completed mutating tool substitutes its sealed worker proof/ };
      await t.test('live public recovery', async () => {
        await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), rejection);
      });
      await fixture.store.close();
      fixture.store = await openStateStore(fixture.stateRoot, fixture.signed);
      await t.test('reopened public recovery', async () => {
        await assert.rejects(fixture.store.readRecoveryClosure(fixture.runId), rejection);
      });
    } finally {
      try { restore?.(); } finally { writer.close(); await disposeFixture(fixture); t.mock.restoreAll(); }
    }
  });
}
