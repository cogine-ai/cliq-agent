// Complete retained child terminal data. This reader neither settles a parent
// allocation nor creates execution, merge, process-death or filesystem authority.
import { assertArtifactRef } from '../kernel/identity.js';
import type { ChildPatchManifest, ChildResultModelContentV1 } from '../kernel/children.js';
import type { RunResult } from '../kernel/result.js';
import type { TerminalDetail } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact, readText } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readChildAdmission } from './child-admission.js';
import { childPatchManifest, childResultModelContent } from './child-result-artifacts.js';
import { KernelStorageError } from './errors.js';
import { isZeroBudget } from './invariants.js';
import { BUDGET_FIELDS } from '../kernel/control-wire-data.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readChildAllocationsForRun, readIncomingChildAllocation } from './repositories/child-allocations.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { decodeRunResult, decodeWorkspaceDiff } from './result-artifacts.js';
import { checkpointFromRow, readRun } from './rows.js';
import { assertSqliteConnectionOwnedBy, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child terminal ${message}`); }


function sqlCut(connection: SqliteConnection | SqliteDriver, childRunId: string) {
  const run = readRun(connection, childRunId);
  const checkpoints = connection.prepare('SELECT * FROM checkpoints WHERE run_id = ? ORDER BY id')
    .all(childRunId).map(checkpointFromRow);
  const items = connection.prepare('SELECT item_id,item_seq,kind,payload_ref,created_at FROM items WHERE run_id = ? ORDER BY item_seq')
    .all<{ item_id: string; item_seq: bigint; kind: string; payload_ref: string; created_at: string }>(childRunId)
    .map(row => ({ itemId: row.item_id, itemSeq: Number(row.item_seq), kind: row.kind, payloadRef: row.payload_ref, createdAt: row.created_at }));
  return { run, checkpoints, items, journal: readInvocationJournal(connection, childRunId),
    workers: readWorkerLaunchesForRun(connection, childRunId), generations: readWorkspaceGenerationsForRun(connection, childRunId),
    allocations: readChildAllocationsForRun(connection, childRunId) };
}

/** No parent full-recovery traversal occurs here. Ordinary child recovery
 * validates its original admission graph only; it must never call this reader
 * from its allocation audit. Parent settlement consumes this outer data cut. */
export async function readChildTerminalData(driver: SqliteDriver, artifacts: ArtifactCatalog, childRunId: string,
  options: { signal?: AbortSignal } = {}) {
  const reads = options.signal ? artifacts.withReadSignal(options.signal) : artifacts;
  reads.assertReadActive();
  const captured = driver.readSnapshot(connection => sqlCut(connection, childRunId));
  const { run } = captured, allocation = readIncomingChildAllocation(driver, childRunId);
  if (!run.parentRunId || !allocation || allocation.parentRunId !== run.parentRunId || allocation.state === 'reserved')
    invalid('requires its unique committed incoming terminal allocation');
  if (!['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status) ||
      allocation.terminal.status !== run.status || allocation.terminal.mode !== allocation.mode ||
      allocation.terminalAt !== run.updatedAt || !isZeroBudget(run.budgetReserved) || run.nextStep !== null ||
      run.frontierRef || run.activeWorkerLaunchId || run.waitingOnRef || run.waitingReason || !run.terminalReason)
    invalid('Run, terminal allocation or quiescent counters differ');
  requireEqual(run.budgetConsumed, allocation.inclusiveBudgetUsage, 'child terminal inclusive original usage');
  if (BUDGET_FIELDS.some(field => allocation.inclusiveBudgetUsage[field] > allocation.grantedAdditiveCeilings[field]) ||
      captured.allocations.some(row => row.parentRunId === run.id && row.state !== 'settled'))
    invalid('inclusive usage exceeds its original grant or retains an unsettled direct descendant');
  // The existing complete recovery walk retains every own invocation, actual
  // seal/retirement, UNKNOWN disposition, Checkpoint, candidate and verifier.
  const cut = await readRecoveryClosure(driver, reads, childRunId);
  requireEqual(cut.run, run, 'child terminal complete Run recovery cut');
  requireEqual(cut.childAllocations, captured.allocations, 'child terminal complete allocation recovery cut');
  const admission = await readChildAdmission(driver, reads, childRunId, options);
  requireEqual(admission.run, run, 'child terminal original admitted Run');
  requireEqual(admission.allocation, allocation, 'child terminal original incoming allocation');
  if (cut.runSpec.operation !== 'agent') invalid('cannot use delivery execution or publication authority');
  requireEqual(cut.runSpec, admission.spec, 'child terminal original RunSpec');
  let result: RunResult | undefined, terminalDetail: TerminalDetail | undefined,
    patch: Readonly<ChildPatchManifest> | undefined, summary: Awaited<ReturnType<typeof readText>> | undefined;
  let content: ChildResultModelContentV1['content'];
  if (run.status === 'succeeded' || run.status === 'completed_unverified') {
    if (!run.resultRef || run.terminalDetailRef || !('resultRef' in allocation.terminal) || allocation.terminal.resultRef !== run.resultRef)
      invalid('successful result is not its original allocation result');
    result = decodeRunResult(await readCanonicalArtifact(reads, run.resultRef));
    if (result.runId !== run.id || result.baseSourceRef !== admission.spec.baseWorkspaceManifestRef || result.createdAt > run.updatedAt ||
        result.deliveryTerminalProjectionEvidenceRef || result.verificationProvenanceRef)
      invalid('result substituted its original child source or borrowed delivery authority');
    const diff = decodeWorkspaceDiff(await readCanonicalArtifact(reads, result.diffRef));
    if (diff.baseSourceRef !== result.baseSourceRef || diff.resultSourceRef !== result.resultSourceRef) invalid('result diff has another B/S source');
    summary = await readText(reads, result.summaryRef);
    if (!summary.utf8.trim()) invalid('successful summary is empty');
    if (allocation.mode === 'mutating') {
      if (!('patchManifestRef' in allocation.terminal) || typeof allocation.terminal.patchManifestRef !== 'string')
        invalid('mutating success lost its exact original patch');
      patch = childPatchManifest(childRunId, diff);
      requireEqual(await readCanonicalArtifact(reads, allocation.terminal.patchManifestRef), patch, 'child terminal exact B/S patch');
    } else if ('patchManifestRef' in allocation.terminal || diff.operations.length) invalid('read-only success cannot publish a patch or changed source');
    content = { status: run.status, summary: summary.utf8 };
  } else {
    if (!run.terminalDetailRef || run.resultRef || !('terminalDetailRef' in allocation.terminal) ||
        allocation.terminal.terminalDetailRef !== run.terminalDetailRef)
      invalid('failure is not its exact original terminal detail');
    terminalDetail = await readCanonicalArtifact<TerminalDetail>(reads, run.terminalDetailRef);
    if (terminalDetail.runId !== run.id || terminalDetail.reason !== run.terminalReason) invalid('failure detail belongs to another terminal Run');
    content = { status: run.status as 'failed' | 'cancelled', terminalReason: run.terminalReason };
  }
  const modelContent = childResultModelContent(childRunId, allocation.mode, content);
  assertArtifactRef(allocation.terminal.modelContentRef);
  if (modelContent.contentDigest !== allocation.terminal.modelContentDigest) invalid('model-safe content digest differs');
  requireEqual(await readCanonicalArtifact(reads, allocation.terminal.modelContentRef), modelContent, 'child terminal exact model-safe output');
  const assertUnchanged = (connection: SqliteConnection | SqliteDriver) => {
    assertSqliteConnectionOwnedBy(driver, connection); reads.assertReadActive();
    requireEqual(sqlCut(connection, childRunId), captured, 'child terminal complete original SQL cut');
    admission.rootOrigin.assertUnchanged(connection);
    for (const original of [admission, ...admission.ancestors]) original.assertUnchanged(connection);
  };
  assertUnchanged(driver);
  return Object.freeze({ ...immutableSnapshot({ run, spec: admission.spec, allocation,
    ...(result ? { result } : {}), ...(terminalDetail ? { terminalDetail } : {}), ...(patch ? { patch } : {}), ...(summary ? { summary } : {}),
    modelContent, inclusiveBudgetUsage: allocation.inclusiveBudgetUsage }), admission, assertUnchanged });
}
export type ChildTerminalData = Awaited<ReturnType<typeof readChildTerminalData>>;
