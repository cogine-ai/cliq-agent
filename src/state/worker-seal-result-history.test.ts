import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1 } from '../kernel/execution.js';
import type { ContextManifest, ToolResultItem, ToolResultPayloadV1 } from '../kernel/types.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore } from './store.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture } from './testing/fixtures.js';
import { batch, claimTool, observation, prepareTool } from './testing/tool-calls.js';
import { postEffectObservation } from './testing/tool-effects.js';

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
