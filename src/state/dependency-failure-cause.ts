import { canonicalSha256 } from '../kernel/canonical.js';
import type { RecoveryClosureV1 } from '../kernel/types.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readDependencyHistory } from './dependency-history.js';
import { readStopSourceData } from './stop-source.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readCanonicalArtifact } from './agent-context.js';
import { decodeDependencyRetirement } from './dependency-retirement.js';

/** Reproduces a registered, positively received failed dependency result.
 * UNKNOWN, missing data and an arbitrary error never become this cause. */
export async function readDependencyFailureCause(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  observedAt: string, sourceCheckpointId?: string, sourceRunRevision?: number, registeredJournalSeq?: number) {
  if (!cut.runSpec.dependencyPolicyRef) return undefined;
  const original = readStopSourceData(driver, cut, observedAt, sourceCheckpointId, sourceRunRevision, registeredJournalSeq);
  const history = await readDependencyHistory(driver, artifacts, { ...cut, items: original.items, journal: original.journal });
  const failures = [...history.values()].filter(entry => entry.failed?.checkpointId === original.checkpoint.id);
  if (!failures.length) return undefined;
  if (failures.length !== 1) throw new TypeError('dependency failure has more than one original current result');
  const progress = failures[0]!, item = progress.failed!, row = original.items.at(-1);
  const terminal = original.journal.filter(entry => entry.opId === item.opId && entry.attempt === item.attempt).at(-1);
  if (!row || row.itemId !== item.itemId || row.payloadRef !== canonicalSha256(item) || row.itemSeq !== original.checkpoint.runItemSeq ||
      !terminal || terminal.phase !== 'failed' || terminal.errorRef !== item.receiptRef || terminal.seq !== original.checkpoint.journalSeq ||
      item.createdAt !== terminal.timestamp || terminal.timestamp > observedAt ||
      sourceCheckpointId === undefined && cut.run.frontierRef !== canonicalSha256(progress.initialFrontier))
    throw new TypeError('dependency failure is not its complete original current result, frontier and Checkpoint');
  return { frontierRef: canonicalSha256(progress.initialFrontier), frontierDigest: canonicalSha256(progress.initialFrontier),
    failingOpId: item.opId, failureKind: 'dependency_acquisition_failed' as const,
    dependencyPlanRef: progress.planRef, dependencyFailureItemRef: row.payloadRef, failedJournalSeq: terminal.seq };
}
export async function readDependencyAmbiguityCause(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  observedAt: string, sourceCheckpointId?: string, sourceRunRevision?: number, registeredJournalSeq?: number) {
  if (!cut.runSpec.dependencyPolicyRef) return undefined;
  const original = readStopSourceData(driver, cut, observedAt, sourceCheckpointId, sourceRunRevision, registeredJournalSeq);
  const history = await readDependencyHistory(driver, artifacts, { ...cut, items: original.items, journal: original.journal });
  if (!(await import('./dependency-unknown-retirement.js')).hasOnlySettledDependencyUnknowns(original.journal)) return undefined;
  const unknown = original.journal.filter(row => row.target === 'builtin:dependency-acquire' && row.phase === 'unknown').at(-1)!;
  const request = (await import('../kernel/dependency-invocation.js')).decodeDependencyRequest(await readCanonicalArtifact(artifacts, unknown.requestRef));
  const progress = history.get(request.candidateItemId);
  if (!progress || progress.ready || progress.failed || unknown.timestamp > observedAt ||
      sourceCheckpointId === undefined && cut.run.frontierRef !== canonicalSha256(progress.initialFrontier)) return undefined;
  return { frontierRef: canonicalSha256(progress.initialFrontier), frontierDigest: canonicalSha256(progress.initialFrontier),
    failingOpId: unknown.opId, failureKind: 'dependency_result_unavailable' as const, dependencyPlanRef: progress.planRef,
    ambiguityRef: unknown.evidenceRef!, unknownJournalSeq: unknown.seq };
}
export async function readDependencyIntegrityCause(driver: SqliteDriver, artifacts: ArtifactCatalog, cut: RecoveryClosureV1,
  observedAt: string, sourceCheckpointId?: string, sourceRunRevision?: number, registeredJournalSeq?: number) {
  const original = await readDependencyFailureCause(driver, artifacts, cut, observedAt, sourceCheckpointId, sourceRunRevision, registeredJournalSeq);
  if (!original) return undefined;
  const item = (await import('../kernel/dependency.js')).decodeDependencyFailureItem(await readCanonicalArtifact(artifacts, original.dependencyFailureItemRef));
  if (item.failureKind !== 'source_integrity') return undefined;
  const receipt = decodeDependencyRetirement(await readCanonicalArtifact(artifacts, item.receiptRef));
  if (!receipt.integrityEvidenceRef || !receipt.integrityEvidenceDigest)
    throw new TypeError('dependency protected-source failure lost its original integrity evidence');
  return { schemaVersion: 1 as const, runId: cut.run.id, createdAt: observedAt, origin: 'kernel_integrity' as const,
    targetStatus: 'failed' as const, reason: 'runtime_failed' as const, source: 'dependency_acquisition' as const,
    dependencyPlanRef: original.dependencyPlanRef, failingOpId: original.failingOpId,
    integrityEvidenceRef: receipt.integrityEvidenceRef, integrityEvidenceDigest: receipt.integrityEvidenceDigest };
}
