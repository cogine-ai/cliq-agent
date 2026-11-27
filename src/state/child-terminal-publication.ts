// The ordinary terminal reducer owns result/physical-stop authority. This
// friend only plans and commits the same child's incoming allocation effect;
// it cannot terminate a Run, mutate its parent or release a native operation.
import { canonicalSha256 } from '../kernel/canonical.js';
import { planCanonicalArtifact } from '../kernel/artifact-plan.js';
import type { ChildAllocationTerminal, ChildAllocationV1, Run } from '../kernel/types.js';
import type { ChildResultModelContentV1 } from '../kernel/children.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact, readText } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readChildAdmission } from './child-admission.js';
import { childPatchManifest, childResultModelContent } from './child-result-artifacts.js';
import { KernelStorageError, joinResourceOperations } from './errors.js';
import { decodeChildAllocation, isZeroBudget } from './invariants.js';
import { readIncomingChildAllocation } from './repositories/child-allocations.js';
import { decodeRunResult, decodeWorkspaceDiff } from './result-artifacts.js';
import { readCandidateSource } from './result-source.js';
import { readCheckpoint, readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

export async function prepareChildTerminalAllocation(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: { run: Run } & ({ status: 'succeeded' | 'completed_unverified'; resultRef: string }
    | { status: 'failed' | 'cancelled'; terminalReason: NonNullable<Run['terminalReason']>; terminalDetailRef: string })) {
  assertActiveStateOwner(driver, owner);
  const admitted = await readChildAdmission(driver, artifacts, input.run.id), { allocation, spec } = admitted;
  requireEqual(admitted.run, input.run, 'child terminal exact original Run');
  if (allocation.state !== 'reserved' || 'resultRef' in input && !isZeroBudget(input.run.budgetReserved) ||
      driver.prepare("SELECT 1 FROM child_allocations WHERE parent_run_id=? AND state!='settled' LIMIT 1").get(input.run.id))
    throw new KernelStorageError('STATE_TRANSITION_INVALID', 'child terminal requires its original reservation and no unresolved subtree');
  const plans = [];
  let patchRef: string | undefined, content: ChildResultModelContentV1['content'];
  if ('resultRef' in input) {
    const result = decodeRunResult(await readCanonicalArtifact(artifacts, input.resultRef));
    const source = await readCandidateSource(artifacts, spec, readCheckpoint(driver, input.run.latestCheckpointId).workspaceStateRef);
    if (result.runId !== input.run.id || result.baseSourceRef !== spec.baseWorkspaceManifestRef ||
        result.resultSourceRef !== source.sourceRef || result.diffRef !== source.diffRef)
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'child result differs from its complete original ready source');
    const diff = decodeWorkspaceDiff(await readCanonicalArtifact(artifacts, result.diffRef));
    if (allocation.mode === 'mutating') {
      const patch = childPatchManifest(input.run.id, diff);
      const planned = planCanonicalArtifact(patch, 'cliq-child-patch-manifest-v1'); plans.push(planned); patchRef = planned.ref;
    } else if (diff.operations.length) throw new KernelStorageError('ARTIFACT_MISMATCH', 'read-only child changed its admitted fork');
    content = { status: input.status, summary: (await readText(artifacts, result.summaryRef)).utf8 };
  } else {
    await artifacts.readBytes(input.terminalDetailRef);
    content = { status: input.status, terminalReason: input.terminalReason };
  }
  const model = childResultModelContent(input.run.id, allocation.mode, content);
  const modelPlan = planCanonicalArtifact(model, model.format); plans.push(modelPlan);
  const terminal: ChildAllocationTerminal = 'resultRef' in input
    ? allocation.mode === 'mutating' ? { mode: 'mutating', status: input.status, resultRef: input.resultRef, patchManifestRef: patchRef!,
      modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest }
      : { mode: 'read_only', status: input.status, resultRef: input.resultRef, modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest }
    : { mode: allocation.mode, status: input.status, terminalDetailRef: input.terminalDetailRef,
      modelContentRef: modelPlan.ref, modelContentDigest: model.contentDigest };
  const metadata = await joinResourceOperations(plans.map(plan => artifacts.publishBytes(plan.bytes, plan.mediaType, plan.schemaKind)));
  return { metadata, commit(connection: SqliteConnection, terminalAt: string) {
    assertActiveStateOwner(connection, owner);
    for (const edge of [admitted, ...admitted.ancestors]) edge.assertUnchanged(connection);
    admitted.rootOrigin.assertUnchanged(connection);
    requireEqual(readIncomingChildAllocation(connection, input.run.id), allocation, 'child terminal original incoming allocation');
    const run = readRun(connection, input.run.id);
    requireEqual(run.budgetConsumed, input.run.budgetConsumed, 'child terminal preserves its actual inclusive charged usage');
    if (run.revision !== input.run.revision + 1 || run.status !== input.status || run.updatedAt !== terminalAt ||
        run.parentRunId !== allocation.parentRunId || run.activeWorkerLaunchId || !isZeroBudget(run.budgetReserved) ||
        ('resultRef' in input ? run.resultRef !== input.resultRef : run.terminalDetailRef !== input.terminalDetailRef))
      throw new KernelStorageError('REVISION_CONFLICT', 'child allocation is not its same atomic terminal Run effect');
    const row: ChildAllocationV1 = { ...allocation, state: 'child_terminal', terminal,
      inclusiveBudgetUsage: run.budgetConsumed, terminalAt };
    decodeChildAllocation(row);
    connection.prepare('UPDATE child_allocations SET state=?,row_json=? WHERE parent_run_id=? AND child_run_id=?')
      .run(row.state, JSON.stringify(row), row.parentRunId, row.childRunId);
  } };
}
