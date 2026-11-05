// Original MCP reconciliation wait and nonce ownership. These transitions use
// the existing Run pointer/Journal and never create a productive invocation.
import { decodeMcpInvocationWait, type McpInvocationWaitV1 } from '../kernel/mcp-status.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow } from './canonical-time.js';
import { KernelStorageError } from './errors.js';
import { assertRetiredGenerationCut } from './generation-retirement.js';
import { readMcpReconcileSource } from './mcp-status-source.js';
import { readInvocationJournal } from './repositories/journal.js';
import { readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { appendRunStateEvent, requireHealthyFence } from './reducers/invocation.js';

function fail(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
function assertMcpWaitCut(driver: SqliteDriver, cut: RecoveryClosureV1) {
  if (cut.runSpec.operation !== 'agent' || cut.run.activeWorkerLaunchId || cut.workerLaunches.length || !cut.run.frontierRef ||
      cut.run.nextStep !== 'tool' || cut.latestCheckpoint.journalSeq !== cut.journal.length || cut.latestCheckpoint.runItemSeq !== cut.items.length)
    fail('MCP status requires its complete original ready worker-free ordered tool cut');
  assertRetiredGenerationCut(driver, cut.run, cut.workspaceGenerations);
}
function assertSqlCut(connection: SqliteConnection, owner: StateOwnerContext, cut: RecoveryClosureV1) {
  assertActiveStateOwner(connection, owner);
  requireEqual(readRun(connection, cut.run.id), cut.run, 'MCP status original complete Run cut');
  requireEqual(readInvocationJournal(connection, cut.run.id), cut.journal, 'MCP status original complete invocation history');
}

export async function prepareMcpInvocationWait(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  input: Readonly<{ runId: string; opId: string; attempt: number; expectedRunRevision: number }>, signal?: AbortSignal) {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts; reads.assertReadActive();
  const cut = await (await import('./recovery-closure.js')).readRecoveryClosure(driver, reads, input.runId), run = cut.run;
  if (run.revision !== input.expectedRunRevision) throw new KernelStorageError('REVISION_CONFLICT', 'MCP status wait original revision changed');
  assertMcpWaitCut(driver, cut);
  if (run.status !== 'queued' || run.waitingOnRef || run.waitingReason) fail('MCP status wait cannot replace an existing wait or active lifecycle');
  const source = await readMcpReconcileSource(driver, reads, cut, input.opId, input.attempt);
  if (source.original.request.frontierRef !== run.frontierRef) fail('MCP status wait changed its original unanswered call frontier');
  const createdAt = sampleCanonicalNow();
  if (createdAt < run.updatedAt || createdAt < source.unknown.timestamp) fail('MCP status initial wait preparation regressed its original Run/UNKNOWN time');
  const wait = decodeMcpInvocationWait({ schemaVersion: 1, kind: 'reconciliation', runId: run.id,
    createdFromRevision: run.revision, createdAt, frontierRef: run.frontierRef, subject: source.subject,
    probeState: { phase: 'automatic_pending', automaticProbeCount: 0, userProbeCount: 0, nextProbeAt: createdAt } });
  reads.assertReadActive(); const artifact = await artifacts.publishCanonical(wait, 'cliq-waiting-subject-v1');
  let outcome: ReturnType<typeof advanceTimeFence> | undefined, updated!: typeof run;
  driver.transaction(connection => {
    reads.assertReadActive(); assertSqlCut(connection, owner, cut); source.registry.assertUnchanged(connection); source.original.history.assertUnchanged(connection);
    const now = sampleCanonicalNow(); outcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (outcome !== 'healthy') return;
    if (now < createdAt) fail('MCP status wait canonical preparation time regressed');
    insertArtifactMetadata(connection, artifact, now);
    const changed = connection.prepare("UPDATE runs SET status='waiting',waiting_reason='reconciliation',waiting_on_ref=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?")
      .run(artifact.ref, now, run.id, BigInt(run.revision));
    if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'MCP status wait lost its original current Run');
    updated = readRun(connection, run.id); appendRunStateEvent(connection, updated, now);
  });
  requireHealthyFence(outcome);
  await (await import('./mcp-server-retirement.js')).resumeOwnedMcpServerReconcileWait(driver, artifacts, owner, run.id, signal);
  return { run: immutableSnapshot(updated), wait };
}

/** Uses the already selected recovery cut; never recursively enters Run
 * recovery or treats schema-valid wait bytes as a native observation. */
export async function validateMcpInvocationWait(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1) {
  const run = cut.run;
  if (run.status !== 'waiting' || run.waitingReason !== 'reconciliation' || !run.waitingOnRef) fail('MCP status has no current exact reconciliation wait');
  assertMcpWaitCut(driver, cut);
  const wait = decodeMcpInvocationWait(await readCanonicalArtifact(artifacts, run.waitingOnRef));
  if (wait.runId !== run.id || wait.frontierRef !== run.frontierRef || wait.createdFromRevision >= run.revision || wait.createdAt > run.updatedAt)
    fail('MCP status wait substitutes its owning Run, revision, frontier or time');
  const { source } = await (await import('./mcp-status-history.js')).readMcpStatusWaitHistory(driver, artifacts, cut, wait);
  return { cut, run, wait, source };
}
