import { canonicalSha256 } from '../kernel/canonical.js';
import type { ContinuationItem, RecoveryClosureV1 } from '../kernel/types.js';
import type { AgentStopIntent } from '../runtime/stop.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { readDeliveryAuthorizationData } from './delivery-approval.js';
import { validatePublicationInvocationHistoryData } from './delivery-publication-authority.js';
import { assertPublicationReadCut, readPublicationPrefixData } from './delivery-publication-progress.js';
import { validateDeliveryRecoveryData } from './delivery-recovery.js';
import { readDeliveryTerminalProjectionData, readUnclaimedPublicationStopHistoryData } from './delivery-publication-recovery.js';
import { readAgentStopInDeliveryEpoch, readRetainedAgentStopInDeliveryEpoch } from './stop-recovery.js';
import { KernelStorageError } from './errors.js';
import { readDeliveryRunAdmission } from './reducers/delivery-admission.js';
import { readDeliveryResultData, readDeliveryVerificationBasis } from './run-result-recovery.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';

/** Private reader-family data, never an owner, proof or stored integrity
 * cache. Each complete fresh entry creates another instance; no operation,
 * retry, SQL transaction or StateOwner can transfer one into another entry. */
export function createDeliveryReadData(driver: SqliteDriver, reads: ArtifactCatalog, cut: RecoveryClosureV1) {
  let principalId: string | undefined;
  let admitted: Awaited<ReturnType<typeof readDeliveryRunAdmission>> | undefined;
  let merged: Awaited<ReturnType<typeof validateDeliveryRecoveryData>> | undefined;
  let authorized: { value: Awaited<ReturnType<typeof readDeliveryAuthorizationData>> } | undefined;
  let histories: Awaited<ReturnType<typeof validatePublicationInvocationHistoryData>> | undefined;
  let publication: Awaited<ReturnType<typeof readPublicationPrefixData>> | undefined;
  let resultBasis: Awaited<ReturnType<typeof readDeliveryResultData>> | undefined;
  const verified = new Map<string, Awaited<ReturnType<typeof readDeliveryVerificationBasis>>>();
  // Completed DAG nodes only. An ancestor is rejected before any wait; no
  // in-flight promise can turn a malformed dependency cycle into self-wait.
  const active = new Set<string>();
  function assertActive() {
    reads.assertReadActive();
  }
  async function enter<T>(node: string, read: () => Promise<T>): Promise<T> {
    assertActive();
    if (active.has(node)) throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery validation data contains a cycle');
    active.add(node);
    try { const result = await read(); assertActive(); return result; }
    finally { active.delete(node); }
  }
  function assertAdmission(value: NonNullable<typeof admitted>) {
    assertActive();
    if (canonicalSha256(value.run) !== canonicalSha256(cut.run) ||
        canonicalSha256(readRun(driver, cut.run.id)) !== canonicalSha256(value.run) ||
        canonicalSha256(readRun(driver, value.source.run.id)) !== canonicalSha256(value.source.run) ||
        readSessionPrincipalId(driver, value.run.sessionId) !== principalId ||
        readSession(driver, value.run.sessionId).workspaceIdentityRef !== value.target.workspaceIdentityRef ||
        readSessionPrincipalId(driver, value.source.session.id) !== principalId ||
        readSession(driver, value.source.session.id).workspaceIdentityRef !== value.source.session.workspaceIdentityRef)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery Run or original source/Session changed during retained admission validation');
  }
  async function assertCurrent() {
    assertActive(); await assertPublicationReadCut(driver, reads, cut);
    if (admitted) assertAdmission(admitted); assertActive();
  }
  const data = {
    async admission() {
      assertActive();
      principalId ??= readSessionPrincipalId(driver, cut.run.sessionId);
      if (!admitted) admitted = await enter('admission', () => readDeliveryRunAdmission(driver, reads, cut.run.id));
      assertAdmission(admitted); await assertCurrent(); return admitted;
    },
    async merges() {
      assertActive();
      if (!merged) merged = await enter('merge', async () => {
        const admission = await data.admission();
        const decoded = await reads.mapReads(cut.items, async row =>
          [row.itemId, await readCanonicalArtifact<ContinuationItem>(reads, row.payloadRef)] as const);
        const decodedItems = new Map(decoded);
        const checkpoints = driver.prepare('SELECT id FROM checkpoints WHERE run_id=? ORDER BY rowid').all<{ id: string }>(cut.run.id)
          .map(row => readCheckpoint(driver, row.id));
        return validateDeliveryRecoveryData(driver, reads, { ...cut, checkpoints, decodedItems }, admission);
      });
      await data.admission(); await assertCurrent(); return merged;
    },
    async basis() {
      assertActive();
      if (!resultBasis) resultBasis = await enter('basis', async () => readDeliveryResultData(driver, reads, cut,
        await data.admission(), await data.merges()));
      await assertCurrent(); await data.admission(); return resultBasis;
    },
    async verification(ref: string) {
      assertActive();
      let value = verified.get(ref);
      if (!value) {
        value = await enter(`verification:${ref}`, async () => readDeliveryVerificationBasis(driver, reads, cut, ref, await data.basis()));
        verified.set(ref, value);
      }
      await assertCurrent(); await data.admission(); return value;
    },
    async authorization() {
      assertActive();
      if (!authorized) authorized = { value: await enter('authorization', () => readDeliveryAuthorizationData(driver, reads, cut, data.verification)) };
      await assertCurrent(); return authorized.value;
    },
    async histories() {
      assertActive();
      if (!histories) histories = await enter('histories', () => validatePublicationInvocationHistoryData(driver, reads, cut, data.authorization));
      await assertCurrent(); return histories;
    },
    async prefix() {
      assertActive();
      if (!publication) publication = await enter('prefix', () => readPublicationPrefixData(driver, reads, cut, data));
      await assertCurrent(); return publication;
    },
    async terminalProjection(ref: string) {
      const value = await enter(`terminalProjection:${ref}`, () => readDeliveryTerminalProjectionData(driver, reads, cut, ref, data));
      await assertCurrent(); return value;
    },
    async stop(ref?: string): Promise<AgentStopIntent> {
      const value = await enter(`stop:${ref ?? 'current'}`, () => ref === undefined
        ? readAgentStopInDeliveryEpoch(driver, reads, cut, data)
        : readRetainedAgentStopInDeliveryEpoch(driver, reads, cut, ref, data));
      await assertCurrent(); return value;
    },
    async unclaimedStopHistory() {
      const value = await enter('unclaimedStopHistory', () => readUnclaimedPublicationStopHistoryData(driver, reads, cut, data.prefix));
      await assertCurrent(); return value;
    }
  };
  return data;
}

export type DeliveryReadData = ReturnType<typeof createDeliveryReadData>;
