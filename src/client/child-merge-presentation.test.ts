import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { mergeChildResult } from '../state/child-merge.js';
import { createMergeApprovalFixture } from '../state/testing/child-merge-approval.js';
import { disposeFixture } from '../state/testing/fixtures.js';
import { readChildMergeWaitingPresentation } from './child-merge-presentation.js';

// Original genuine Store wait and CAS data. Client display itself is not a
// server currentness/permission, grant, native or platform proof.
test('a real child merge wait presents its exact original child and complete paths without exposing internal audit JSON', async () => {
  const f = await createMergeApprovalFixture('child-merge-client-presentation');
  try {
    const selected = await mergeChildResult(f.driver, f.store.artifacts, f.owner, { runId: f.runId,
      expectedRunRevision: f.store.getRun(f.runId).revision, releaseKeys: f.signed.releaseKeys });
    assert.equal(selected.run.status, 'waiting');
    const before = await f.store.readRecoveryClosure(f.runId), snapshot = { schemaVersion: 1 as const, operation: 'agent' as const,
      run: selected.run, latestRunItemSeq: before.items.length };
    const wait = await f.store.artifacts.readCanonical(selected.run.waitingOnRef!), refs: string[] = [];
    const reader = { artifact: async (ref: string) => { refs.push(ref); return f.store.artifacts.readBytes(ref); } };
    const presentation = await readChildMergeWaitingPresentation(reader, snapshot, wait);
    assert.equal(presentation.waitingOnRef, selected.run.waitingOnRef);
    assert.equal(presentation.text, `Merge completed child ${JSON.stringify(f.children[0]!.childRunId)}.\nScope: private parent workspace.\nChanged paths (1):\n  "a"`);
    assert.equal(refs.length, 3); assert.equal(new Set(refs).size, 3);
    for (const ref of refs) assert.equal(presentation.text.includes(ref), false);
    const broken = { artifact: async (_ref: string) => canonicalJsonBytes({ schemaVersion: 1, extra: 'untrusted alternate bytes' }) };
    await assert.rejects(readChildMergeWaitingPresentation(broken, snapshot, wait), /complete original bytes/);
    await assert.rejects(readChildMergeWaitingPresentation(reader, { ...snapshot, run: { ...selected.run, frontierRef: 'a'.repeat(64) } }, wait), /captured approval wait/);
    const stopped = new AbortController(); stopped.abort(new Error('original client closed'));
    await assert.rejects(readChildMergeWaitingPresentation(reader, snapshot, wait, stopped.signal), /original client closed/);
    assert.deepEqual(await f.store.readRecoveryClosure(f.runId), before);
  } finally { await disposeFixture(f); }
});
