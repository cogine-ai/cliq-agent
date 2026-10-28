import { readHeldInstalledUpgradeTransaction, type HeldInstalledRuntimeUpgrade } from './installed-runtime.js';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash, normalizeAbsolutePath, parseCanonicalTime, requiredSafeInteger, sha256Bytes } from '../kernel/identity.js';
import type { RuntimeUpgradeReceiptV1, RuntimeUpgradeRetirementV1 } from '../kernel/runtime-upgrade.js';
import type { KernelGenerationIdentityV1, StateOwnerAcquisitionEvidenceV1, StateOwnerRecordV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRuntimeBundle, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { ArtifactCatalog, insertArtifactMetadata, type PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, readTimeFence, sampleCanonicalNow, transferTimeFenceOwner } from './canonical-time.js';
import { ContentAddressedStore } from './cas.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';
import { isZeroBudget } from './invariants.js';
import { assertStateOwnerLock, loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { readWorkerLaunchesForRun } from './repositories/worker-launches.js';
import { readWorkspaceGenerationsForRun } from './repositories/workspace-generations.js';
import { readRun } from './rows.js';
import { readRuntimeUpgradeBoundary, readRuntimeUpgradeRetiredRows } from './runtime-upgrade-history.js';
import { publishUpgradeResourceGraph, UPGRADE_RESOURCE_FAMILY_ROWS } from './runtime-upgrade-resources.js';
import { applySignedKernelSchema7To8, assertKernelSchemaVersion, readSchemaUserVersion } from './schema.js';
import { readSignedSchemaConversion, schemaConversionProfile, signedKernelSchemaProfile } from './signed-schema.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import { readSourceInspectionRetirement } from './source-inspection-owner.js';
import { openSqliteDriver, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { readLatestStateOwner, contextFromStateOwner, gracefullyReleaseStateOwner } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { acquireSuccessorStateOwner, currentProcessIdentity, stateOwnerFilesystemFromArtifacts, type StateStoreRuntimeAuthority } from './store.js';

function refuse(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

/** Data-only equality of the actually captured owner and its own graceful
 * release. It is not a unit selector, process observation or upgrade permit. */
export function assertCapturedUpgradeOwnerReleased(captured: StateOwnerRecordV1, released: StateOwnerRecordV1): void {
  if (captured.state !== 'active' || released.state !== 'terminal' || released.terminalReason !== 'graceful_release' ||
      released.rowVersion !== captured.rowVersion + 1) refuse('upgrade original owner did not gracefully release its captured cut');
  const { state: _state, rowVersion: _version, rowDigest: _digest, ...original } = captured;
  const { state: _terminalState, rowVersion: _terminalVersion, rowDigest: _terminalDigest, releasedAt: _releasedAt,
    terminalReason: _reason, transitionEvidenceRef: _transitionRef, transitionEvidenceDigest: _transitionDigest, ...retained } = released;
  if (canonicalSha256(original) !== canonicalSha256(retained)) refuse('upgrade fixed unit changed its original captured StateOwner');
}
function versionCounter(connection: SqliteConnection, name: 'data_version' | 'total_changes'): number {
  const row = connection.prepare(name === 'data_version' ? 'PRAGMA data_version' : 'SELECT total_changes() AS total_changes').get<Record<string, unknown>>();
  return requiredSafeInteger(row?.[name], name);
}
const unretired = new Set<Readonly<{ lock: HeldStateOwnerLock; driver: SqliteDriver; error: ResourceRetirementError }>>();

/** Trusted bootstrap composition only. This entry grants no Run/tool execution
 * and never instantiates a productive Store. Installed callers additionally
 * require the held package/keeper lifecycle before entering this transaction. */
export async function upgradeRetiredRuntime(input: Readonly<{ stateRoot: string; target: StateStoreRuntimeAuthority; installation?: HeldInstalledRuntimeUpgrade }>): Promise<RuntimeUpgradeReceiptV1> {
  const installed = input.installation === undefined ? undefined : readHeldInstalledUpgradeTransaction(input.installation);
  const request = immutableSnapshot({ stateRoot: input.stateRoot, target: input.target }), stateRoot = normalizeAbsolutePath(request.stateRoot), target = request.target;
  if (stateRoot !== request.stateRoot) refuse('upgrade requires the original canonical StateRoot');
  verifyRuntimeBundle(target.bundle, target.releaseKeys);
  if (installed && (installed.stateRoot !== stateRoot || canonicalSha256(installed.bundle) !== canonicalSha256(target.bundle) ||
      canonicalSha256(installed.releaseKeys) !== canonicalSha256(target.releaseKeys))) refuse('upgrade stage differs from trusted target composition');
  installed?.notePhase?.('conversion_current');
  if (installed) await installed.assertCurrent();
  const native = installed?.native ?? await loadNativeStateOwner(target.bundle);
  const supervisor = target.bundle.entries.find(entry => entry.role === 'supervisor')!;
  const image = await native.observeCurrentProcess();
  if (image.executableImageDigest !== supervisor.digest) refuse('upgrade requires its actual signed target Supervisor image');
  const lock = Object.freeze(native.acquireLock(stateRoot, false));
  let driver: SqliteDriver | undefined;
  let failure: unknown;
  try {
    assertStateOwnerLock(lock);
    driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    const catalog = new ArtifactCatalog(new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY)), undefined, target.releaseKeys);
    const prior = readLatestStateOwner(driver);
    if (!prior) refuse('upgrade cannot bootstrap a missing original owner');
    installed?.notePhase?.('conversion_owner');
    await stateOwnerFilesystemFromArtifacts(stateRoot, catalog, prior, lock);
    const version = readSchemaUserVersion(driver), targetRef = canonicalSha256(target.bundle);
    if (version === 8) {
      installed?.notePhase?.('conversion_recovery');
      const history = await readRetainedStateOwnerHistory(driver, catalog, prior.ownerEpoch);
      const boundary = history.entries.find(entry => entry.acquisition.kind === 'runtime_upgrade');
      if (!boundary || boundary.acquisition.kind !== 'runtime_upgrade' || boundary.owner.runtimeBundleRef !== targetRef) refuse('schema8 is not this registered upgrade');
      const old = history.entries[boundary.owner.ownerEpoch - 2]!;
      const genesis = history.entries[0]!.acquisition;
      if (genesis.kind !== 'genesis') refuse('upgrade recovery lost its original genesis');
      const data = await readRuntimeUpgradeBoundary(driver, catalog, old.owner, boundary.owner, boundary.acquisition, genesis);
      driver.readSnapshot(connection => { assertStateOwnerLock(lock); history.assertUnchanged(connection); assertKernelSchemaVersion(connection, 8); });
      if (installed) {
        installed.assertOldProcessesDead();
        await installed.publishSelection(boundary.acquisition.upgradeReceiptRef, data.receipt);
        if (prior.state === 'active') {
          const currentOwner = await acquireSuccessorStateOwner(stateRoot, driver, catalog, prior, native, lock);
          await gracefullyReleaseStateOwner(driver, catalog, contextFromStateOwner(currentOwner, lock, {
            ref: history.lockIdentity.stateRootIdentityRef, digest: history.lockIdentity.stateRootIdentityDigest }));
        }
      }
      return data.receipt;
    }
    if (version !== 7 || prior.state !== 'terminal' || prior.terminalReason !== 'graceful_release')
      refuse('explicit upgrade requires schema7 and a real gracefully released original owner');
    assertKernelSchemaVersion(driver, 7);
    installed?.notePhase?.('conversion_schema');
    const source = await readCanonicalArtifact<RuntimeBundleManifest>(catalog, prior.runtimeBundleRef);
    verifyRuntimeBundle(source, target.releaseKeys);
    const schema = signedKernelSchemaProfile(), conversion = schemaConversionProfile(source);
    const published = await joinResourceOperations([
      catalog.publishCanonical(target.bundle, 'cliq-runtime-bundle-v1'),
      catalog.publishCanonical(schema, 'cliq-signed-kernel-schema-v1'),
      catalog.publishCanonical(conversion, 'cliq-signed-schema-conversion-v1')
    ]);
    // The full fixed profile must be named by the signed graph, not merely be
    // present in CAS. Nothing published so far is a commit or new owner.
    await readSignedSchemaConversion(catalog, source, target.bundle, target.releaseKeys);
    const reads = catalog.withRuntimeConversionSource(targetRef);
    installed?.notePhase?.('conversion_history');
    const history = await readRetainedStateOwnerHistory(driver, reads, prior.ownerEpoch);
    const genesis = history.entries[0]!.acquisition;
    if (genesis.kind !== 'genesis') refuse('upgrade has no original generation');
    const generation = await readCanonicalArtifact<KernelGenerationIdentityV1>(reads, genesis.kernelGenerationIdentityRef);
    if (generation.stateSchemaVersion !== 7) refuse('upgrade cannot replace the original schema birth');
    if (generation.origin === 'fresh_installed' ? !installed : installed !== undefined)
      refuse('upgrade installation source differs from its genuine original genesis');
    if (installed && (installed.source.sourceBundleDigest !== prior.runtimeBundleRef ||
        installed.supervisorBirth.identityDigest !== history.entries.at(-1)!.process.identityDigest))
      refuse('upgrade stage lost the exact original Supervisor source');
    if (installed) assertCapturedUpgradeOwnerReleased(installed.supervisorOwner, prior);
    installed?.assertOldProcessesDead();
    const originalProcess = history.entries.at(-1)!.process;
    lock.assertPriorProcessDead(originalProcess.pid, originalProcess.processStartToken);
    const counters = { data: versionCounter(driver, 'data_version'), changes: versionCounter(driver, 'total_changes') };
    installed?.notePhase?.('conversion_resources');
    for (const table of ['runs', 'worker_launches', 'workspace_generations', 'source_inspection_attempts']) {
      const count = requiredSafeInteger(driver.prepare(`SELECT count(*) AS count FROM ${table}`).get<{ count: unknown }>()?.count, 'upgrade resource count');
      if (count > UPGRADE_RESOURCE_FAMILY_ROWS) refuse('upgrade original resource family exceeds its complete fixed witness capacity');
    }
    const resourceObjects: PublishedArtifact[] = [], runTerminalRowRefs: string[] = [], workerLaunchRowRefs: string[] = [],
      workspaceGenerationRowRefs: string[] = [], sourceInspectionRowRefs: string[] = [];
    const retain = async (value: unknown, refs: string[]) => {
      const object = await reads.publishCanonical(value, 'cliq-retained-upgrade-resource-row-v1');
      resourceObjects.push(object); refs.push(object.ref);
    };
    for (const { id } of driver.prepare('SELECT id FROM runs ORDER BY id').iterate<{ id: string }>()) {
      const run = readRun(driver, id);
      if (!['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status) ||
          run.activeWorkerLaunchId !== undefined || !isZeroBudget(run.budgetReserved)) refuse('upgrade cannot retire a nonterminal or reserved Run');
      const closure = await readRecoveryClosure(driver, reads, id);
      if (closure.journal.some(entry => ['prepared', 'dispatch_claimed', 'unknown'].includes(entry.phase))) {
        // Historical prepared/claim prefixes are legal only when their exact
        // original attempt is conclusively settled, never inferred by opId.
        const last = new Map<string, string>();
        for (const entry of closure.journal) last.set(`${entry.opId}:${entry.attempt}`, entry.phase);
        if ([...last.values()].some(phase => !['completed', 'failed'].includes(phase))) refuse('upgrade has an unsettled or UNKNOWN attempt');
      }
      await retain(run, runTerminalRowRefs);
      for (const launch of readWorkerLaunchesForRun(driver, id)) {
        if (launch.phase !== 'retired') refuse('upgrade requires every original worker to be physically retired');
        await retain(launch, workerLaunchRowRefs);
      }
      for (const row of readWorkspaceGenerationsForRun(driver, id)) {
        if (row.phase !== 'retired') refuse('upgrade requires every original generation to be physically retired');
        await retain(row, workspaceGenerationRowRefs);
      }
    }
    for (const key of driver.prepare('SELECT principal_id,method,admission_key,admission_intent_digest FROM source_inspection_attempts ORDER BY inspection_id')
      .iterate<{ principal_id: string; method: 'run.submit' | 'run.apply'; admission_key: string; admission_intent_digest: string }>()) {
      const row = readSourceInspectionAttempt(driver, { principalId: key.principal_id, method: key.method, admissionKey: key.admission_key, admissionIntentDigest: key.admission_intent_digest })!;
      if (row.phase !== 'retired') refuse('upgrade requires the original source scope retirement');
      await readSourceInspectionRetirement(driver, reads, row, { runtimeBundleRef: prior.runtimeBundleRef, runtimeBundleManifestDigest: prior.runtimeBundleManifestDigest });
      await retain(row, sourceInspectionRowRefs);
    }
    // These families have no implemented legacy7 offline transition. Their
    // presence is not interpreted as proof of joined producers.
    for (const table of ['local_inference_activation_cycles', 'local_inference_launches', 'admin_operations', 'mcp_registrations'])
      if (driver.prepare(`SELECT 1 AS present FROM ${table} LIMIT 1`).get()) refuse('upgrade has an unsupported original producer family');
    const resources = await publishUpgradeResourceGraph(reads, { sourceOwnerEpoch: prior.ownerEpoch, sourceOwnerRowDigest: prior.rowDigest }, {
      run_terminal: runTerminalRowRefs, worker_launch: workerLaunchRowRefs,
      workspace_generation: workspaceGenerationRowRefs, source_inspection: sourceInspectionRowRefs });
    // Every page/index and complete original row is durable and independently
    // reread/joined before sampling the original final death/5s commit window.
    installed?.notePhase?.('conversion_rows');
    await readRuntimeUpgradeRetiredRows(driver, reads, resources.refs);
    resourceObjects.push(...resources.objects);
    installed?.notePhase?.('conversion_death');
    const acquiredAt = sampleCanonicalNow(), current = await currentProcessIdentity(native, acquiredAt);
    lock.assertPriorProcessDead(originalProcess.pid, originalProcess.processStartToken);
    const fence = readTimeFence(driver);
    if (!fence || fence.stateOwnerEpoch !== prior.ownerEpoch || fence.state !== 'healthy')
      refuse('upgrade requires the healthy original canonical time fence');
    if (acquiredAt < fence.lastAcceptedAt) {
      // This is the original single sticky fence, not an upgrade decision.
      // Persist its real regression before refusing outside the transaction;
      // throwing from that callback would incorrectly roll the fence back.
      driver.transaction(connection => {
        assertStateOwnerLock(lock); history.assertUnchanged(connection);
        if (versionCounter(connection, 'data_version') !== counters.data || versionCounter(connection, 'total_changes') !== counters.changes)
          refuse('original upgrade SQL cut changed');
        advanceTimeFence(connection, prior.ownerEpoch, acquiredAt);
      });
      refuse('upgrade observed a regressed original canonical time fence');
    }
    installed?.notePhase?.('conversion_receipt');
    const processObject = await reads.publishCanonical(current, 'cliq-platform-process-identity-v1');
    const ownerEpoch = prior.ownerEpoch + 1, supervisorInstanceId = identityHash('cliq-supervisor-instance-v1', current.identityDigest, acquiredAt, String(ownerEpoch));
    const instanceNonceDigest = sha256Bytes(randomBytes(32));
    const retirement: RuntimeUpgradeRetirementV1 = { schemaVersion: 1, format: 'cliq-retired-runtime-cut-v1', sourceOwnerEpoch: prior.ownerEpoch,
      sourceOwnerRowDigest: prior.rowDigest, sourceProcessIdentityRef: prior.processIdentityRef, sourceProcessIdentityDigest: prior.processIdentityDigest,
      sourceProcessObservation: 'absent_or_start_token_mismatch', resourceIndexRefs: resources.resourceIndexRefs, totalRowCount: resources.totalRowCount,
      sourceDataVersion: counters.data, sourceTotalChanges: counters.changes, observedAt: acquiredAt, retirementDigest: '' };
    retirement.retirementDigest = digestOmitting(retirement, 'retirementDigest');
    const retirementObject = await reads.publishCanonical(retirement, 'cliq-retired-runtime-cut-v1');
    const conversionEntry = target.bundle.entries.find(entry => entry.entryId === 'schema_conversion')!;
    const receipt: RuntimeUpgradeReceiptV1 = { schemaVersion: 1, format: 'cliq-runtime-upgrade-receipt-v1',
      sourceOwnerEpoch: prior.ownerEpoch, sourceOwnerRowDigest: prior.rowDigest, sourceRuntimeBundleRef: prior.runtimeBundleRef,
      sourceRuntimeBundleManifestDigest: prior.runtimeBundleManifestDigest, sourceGenerationRef: genesis.kernelGenerationIdentityRef,
      sourceGenerationDigest: genesis.kernelGenerationIdentityDigest, targetRuntimeBundleRef: targetRef, targetRuntimeBundleManifestDigest: target.bundle.manifestDigest,
      conversionRef: conversionEntry.digest, conversionDigest: conversion.profileDigest, targetSchemaRef: canonicalSha256(schema), targetSchemaDigest: schema.profileDigest,
      sourceSchemaVersion: 7, targetSchemaVersion: 8, stateRootIdentityRef: history.lockIdentity.stateRootIdentityRef,
      stateRootIdentityDigest: history.lockIdentity.stateRootIdentityDigest, stateLockIdentityRef: prior.stateLockIdentityRef,
      stateLockIdentityDigest: prior.stateLockIdentityDigest, retirementRef: retirementObject.ref, retirementDigest: retirement.retirementDigest, installation: installed?.source ?? { kind: 'not_installed' },
      targetOwner: { ownerEpoch, supervisorInstanceId, processIdentityRef: processObject.ref, processIdentityDigest: current.identityDigest,
        instanceNonceDigest, acquiredAt }, receiptDigest: '' };
    receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest');
    const receiptObject = await reads.publishCanonical(receipt, 'cliq-runtime-upgrade-receipt-v1');
    installed?.notePhase?.('conversion_selection');
    if (installed) await installed.prepareSelection(receiptObject.ref);
    const acquisition: StateOwnerAcquisitionEvidenceV1 = { schemaVersion: 1, format: 'cliq-state-owner-acquisition-evidence-v1',
      ...receipt.targetOwner, runtimeBundleRef: targetRef, runtimeBundleManifestDigest: target.bundle.manifestDigest,
      stateLockIdentityRef: prior.stateLockIdentityRef, stateLockIdentityDigest: prior.stateLockIdentityDigest,
      evidenceDigest: '', kind: 'runtime_upgrade', priorOwnerEpoch: prior.ownerEpoch, priorTerminalRowDigest: prior.rowDigest,
      priorTransitionEvidenceRef: prior.transitionEvidenceRef, priorTransitionEvidenceDigest: prior.transitionEvidenceDigest,
      priorTerminalReason: 'graceful_release', upgradeReceiptRef: receiptObject.ref, upgradeReceiptDigest: receipt.receiptDigest };
    acquisition.evidenceDigest = digestOmitting(acquisition, 'evidenceDigest');
    installed?.notePhase?.('conversion_acquisition');
    const acquisitionObject = await reads.publishCanonical(acquisition, 'cliq-state-owner-acquisition-evidence-v1');
    const owner: Extract<StateOwnerRecordV1, { state: 'active' }> = { schemaVersion: 1, ...receipt.targetOwner,
      runtimeBundleRef: targetRef, runtimeBundleManifestDigest: target.bundle.manifestDigest, supervisorEntryId: supervisor.entryId,
      supervisorEntryVersion: supervisor.version, supervisorExecutableDigest: current.executableImageDigest,
      stateLockIdentityRef: prior.stateLockIdentityRef, stateLockIdentityDigest: prior.stateLockIdentityDigest,
      acquisitionEvidenceRef: acquisitionObject.ref, acquisitionEvidenceDigest: acquisition.evidenceDigest,
      rowDigest: '', state: 'active', rowVersion: 1 };
    owner.rowDigest = digestOmitting(owner, 'rowDigest');
    installed?.notePhase?.('conversion_commit');
    const committed = driver.transaction(connection => {
      assertStateOwnerLock(lock); history.assertUnchanged(connection);
      if (versionCounter(connection, 'data_version') !== counters.data || versionCounter(connection, 'total_changes') !== counters.changes ||
          readLatestStateOwner(connection)?.rowDigest !== prior.rowDigest) refuse('original upgrade SQL cut changed');
      const committedAt = sampleCanonicalNow(), age = parseCanonicalTime(committedAt) - parseCanonicalTime(acquiredAt);
      if (committedAt < fence.lastAcceptedAt) {
        advanceTimeFence(connection, prior.ownerEpoch, committedAt);
        return false;
      }
      if (age < 0 || age > 5000) refuse('upgrade death observation is outside the original five-second commit window');
      lock.assertPriorProcessDead(originalProcess.pid, originalProcess.processStartToken);
      installed?.assertCommit(); installed?.assertOldProcessesDead();
      applySignedKernelSchema7To8(connection);
      transferTimeFenceOwner(connection, prior.ownerEpoch, ownerEpoch, committedAt);
      for (const object of [...published, ...(installed?.seed ?? []), ...resourceObjects, processObject, retirementObject, receiptObject, acquisitionObject])
        insertArtifactMetadata(connection, object, committedAt);
      connection.prepare("INSERT INTO state_owners (owner_epoch,supervisor_instance_id,record_json,state,row_digest) VALUES(?,?,?,'active',?)")
        .run(BigInt(ownerEpoch), supervisorInstanceId, JSON.stringify(owner), owner.rowDigest);
      return true;
    });
    if (!committed) refuse('upgrade commit observed a regressed original canonical time fence');
    installed?.notePhase?.('conversion_publish');
    if (installed) await installed.publishSelection(receiptObject.ref, receipt);
    installed?.notePhase?.('conversion_release');
    await gracefullyReleaseStateOwner(driver, reads, contextFromStateOwner(owner, lock, {
      ref: history.lockIdentity.stateRootIdentityRef, digest: history.lockIdentity.stateRootIdentityDigest }));
    return immutableSnapshot(receipt);
  } catch (error) { failure = error; throw error; }
  finally {
    if (failure instanceof ResourceRetirementError && driver) {
      // An uncertain original CAS/native producer still owns the exclusion.
      // Closing the database/flock would not join that producer.
      unretired.add(Object.freeze({ lock, driver, error: failure }));
    } else try { driver?.close(); lock.close(); }
    catch (error) {
      const retirement = new ResourceRetirementError('runtime upgrade database or original flock did not retire',
        new AggregateError(failure === undefined ? [error] : [failure, error]));
      if (driver) unretired.add(Object.freeze({ lock, driver, error: retirement }));
      throw retirement;
    }
  }
}
