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
import { readDeliveryResultData, readDeliveryResultDataInRecovery, readDeliveryVerificationBasis } from './run-result-recovery.js';
import { readCheckpoint, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { closeAgentRecoveryData, readAgentRecoveryData, type AgentRecoveryReadData } from './agent-recovery.js';

const deliveryReadBindings = new WeakMap<object, { driver: SqliteDriver; reads: ArtifactCatalog; cut: RecoveryClosureV1;
  assertActive(): void; complete(history: AgentRecoveryReadData): void; close(): void }>();

/** Private reader-family data, never an owner, proof or stored integrity
 * cache. Each complete fresh entry creates another instance; no operation,
 * retry, SQL transaction or StateOwner can transfer one into another entry. */
export function createDeliveryReadData(driver: SqliteDriver, reads: ArtifactCatalog, cut: RecoveryClosureV1) {
  let principalId: string | undefined, closed = false;
  let completedHistory: AgentRecoveryReadData | undefined;
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
    if (closed) throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery validation data scope is closed');
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
    if (completedHistory) readAgentRecoveryData(driver, reads, cut, completedHistory);
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
      if (!resultBasis) resultBasis = await enter('basis', async () => {
        const admission = await data.admission(), merges = await data.merges();
        return completedHistory ? readDeliveryResultDataInRecovery(driver, reads, cut, admission, merges, completedHistory)
          : readDeliveryResultData(driver, reads, cut, admission, merges);
      });
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
  deliveryReadBindings.set(data, { driver, reads, cut, assertActive,
    complete(history) {
      assertActive();
      if (active.size || resultBasis || completedHistory)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery completed history must precede its first result basis');
      completedHistory = history;
    },
    close() {
      closed = true;
      if (completedHistory) closeAgentRecoveryData(driver, reads, cut, completedHistory);
      completedHistory = undefined;
    } });
  return data;
}

export type DeliveryReadData = ReturnType<typeof createDeliveryReadData>;

/** Internal identity check only. Structural data cannot impersonate the
 * factory that owned this exact independent read entry. */
export function assertDeliveryReadData(driver: SqliteDriver, reads: ArtifactCatalog, cut: RecoveryClosureV1,
  data: DeliveryReadData): void {
  const binding = data !== null && typeof data === 'object' ? deliveryReadBindings.get(data) : undefined;
  if (!binding || binding.driver !== driver || binding.reads !== reads || binding.cut !== cut)
    throw new TypeError('Delivery history requires its exact original read family');
  binding.assertActive();
}

/** Only the completed original validator can supply this sharing node. */
export function completeDeliveryRecoveryHistory(driver: SqliteDriver, reads: ArtifactCatalog, cut: RecoveryClosureV1,
  data: DeliveryReadData, history: AgentRecoveryReadData): void {
  assertDeliveryReadData(driver, reads, cut, data);
  const original = readAgentRecoveryData(driver, reads, cut, history);
  if (original.delivery !== data || cut.run.activeWorkerLaunchId || cut.workerLaunches.length)
    throw new TypeError('Delivery history belongs to another family or a live worker cut');
  deliveryReadBindings.get(data)!.complete(history);
}

/** Called only after the enclosing reader joined. Invalidate callbacks even
 * after cancellation; closing data never claims that a resource has retired. */
export function closeDeliveryReadData(driver: SqliteDriver, reads: ArtifactCatalog, cut: RecoveryClosureV1,
  data: DeliveryReadData): void {
  const binding = deliveryReadBindings.get(data);
  if (!binding || binding.driver !== driver || binding.reads !== reads || binding.cut !== cut)
    throw new TypeError('cannot close another Delivery recovery read');
  try { binding.close(); } finally { deliveryReadBindings.delete(data); }
}
