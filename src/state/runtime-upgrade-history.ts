import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText, decodeWireRun } from '../kernel/control-wire-data.js';
import { digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import type { RuntimeUpgradeReceiptV1, RuntimeUpgradeRetirementV1 } from '../kernel/runtime-upgrade.js';
import type { StateOwnerRecordV1, StateOwnerAcquisitionEvidenceV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeWorkerLaunch, decodeWorkspaceGenerationState } from './invariants.js';
import { KernelStorageError } from './errors.js';
import { isZeroBudget } from './invariants.js';
import { readSignedSchemaConversion } from './signed-schema.js';
import { decodeSourceInspectionAttempt, readSourceInspectionAttempt } from './source-inspection.js';
import { readRun } from './rows.js';
import { readWorkerLaunch } from './repositories/worker-launches.js';
import { readWorkspaceGeneration } from './repositories/workspace-generations.js';
import type { SqliteDriver } from './sqlite-driver.js';
import { readUpgradeResourceGraph, readUpgradeResourceRow, UPGRADE_RESOURCE_FAMILIES, UPGRADE_RESOURCE_FAMILY_ROWS,
  type UpgradeResourceRefs } from './runtime-upgrade-resources.js';

function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'runtime upgrade receipt lacks its exact original retired source'); }
const receiptRefs = ['sourceOwnerRowDigest', 'sourceRuntimeBundleRef', 'sourceRuntimeBundleManifestDigest', 'sourceGenerationRef',
  'sourceGenerationDigest', 'targetRuntimeBundleRef', 'targetRuntimeBundleManifestDigest', 'conversionRef', 'conversionDigest',
  'targetSchemaRef', 'targetSchemaDigest', 'stateRootIdentityRef', 'stateRootIdentityDigest', 'stateLockIdentityRef',
  'stateLockIdentityDigest', 'retirementRef', 'retirementDigest', 'receiptDigest'] as const;

export function decodeRuntimeUpgradeReceipt(value: unknown): RuntimeUpgradeReceiptV1 {
  assertControlWireJson(value);
  const row = controlWireRecord(value, ['schemaVersion', 'format', ...receiptRefs, 'sourceOwnerEpoch',
    'sourceSchemaVersion', 'targetSchemaVersion', 'targetOwner', 'installation']);
  if (row.schemaVersion !== 1 || row.format !== 'cliq-runtime-upgrade-receipt-v1' || row.sourceSchemaVersion !== 7 || row.targetSchemaVersion !== 8) invalid();
  receiptRefs.forEach(key => controlWireRef(row[key])); controlWireInteger(row.sourceOwnerEpoch, 1);
  const installation = row.installation;
  if (!installation || typeof installation !== 'object' || Array.isArray(installation)) invalid();
  if (Reflect.get(installation, 'kind') === 'not_installed') controlWireRecord(installation, ['kind']);
  else {
    const v2 = Reflect.get(installation, 'kind') === 'held_installed_stage_v2';
    const source = controlWireRecord(installation, ['kind', 'stageName', 'stageIdentity', 'runtimeIdentity', 'targetBundleIdentity', 'originalActiveIdentity', 'originalBootstrapIdentity', 'stagedActiveIdentity', 'stagedBootstrapIdentity', 'sourceBundleDigest',
      'targetBundleDigest', 'originalActiveDigest', 'originalBootstrapDigest', 'originalKeeper',
      ...(v2 ? ['keeperObservationKind'] : [])], ['targetModelAuthorityRef']);
    if ((!v2 && source.kind !== 'held_installed_stage') || v2 && source.keeperObservationKind !== 'current_checked_original_keeper' ||
        typeof source.stageName !== 'string' || !/^\.upgrade-[0-9a-f]{32}$/u.test(source.stageName)) invalid();
    for (const key of ['stageIdentity', 'runtimeIdentity', 'targetBundleIdentity', 'originalActiveIdentity', 'originalBootstrapIdentity', 'stagedActiveIdentity', 'stagedBootstrapIdentity']) {
      const identity = controlWireRecord(source[key], ['deviceId', 'fileId', 'ownerUid', 'ownerGid', 'mode']);
      if (!/^(0|[1-9][0-9]*)$/u.test(controlWireText(identity.deviceId)) || !/^[1-9][0-9]*$/u.test(controlWireText(identity.fileId)) || identity.mode !== (key.includes('Active') ? 384 : key.includes('Bootstrap') ? 320 : 448)) invalid();
      controlWireInteger(identity.ownerUid, 0, 0xffffffff); controlWireInteger(identity.ownerGid, 0, 0xffffffff);
    }
    for (const key of ['sourceBundleDigest', 'targetBundleDigest', 'originalActiveDigest', 'originalBootstrapDigest']) controlWireRef(source[key]);
    if (Object.hasOwn(source, 'targetModelAuthorityRef')) controlWireRef(source.targetModelAuthorityRef);
    const keeper = controlWireRecord(source.originalKeeper, ['pid', 'processStartToken', 'locatorDigest', 'bootIdentityHex', 'observedAt', 'readyIdentity']);
    controlWireInteger(keeper.pid, 1, 2147483647); controlWireRef(keeper.locatorDigest);
    const ready = controlWireRecord(keeper.readyIdentity, ['deviceId', 'fileId', 'ownerUid', 'ownerGid', 'mode']);
    if (ready.mode !== 384 || !/^(0|[1-9][0-9]*)$/u.test(controlWireText(ready.deviceId)) || !/^[1-9][0-9]*$/u.test(controlWireText(ready.fileId))) invalid();
    controlWireInteger(ready.ownerUid, 0, 0xffffffff); controlWireInteger(ready.ownerGid, 0, 0xffffffff);
    // These names were born below one held runtime directory and are moved
    // only by its fixed rename sequence. Equal bytes cannot substitute a
    // different filesystem, owner or another registered object's inode.
    const identities = ['stageIdentity', 'runtimeIdentity', 'targetBundleIdentity', 'originalActiveIdentity',
      'originalBootstrapIdentity', 'stagedActiveIdentity', 'stagedBootstrapIdentity'].map(key =>
      source[key] as Record<string, unknown>);
    const runtime = source.runtimeIdentity as Record<string, unknown>;
    if ([...identities, ready].some(identity => identity.deviceId !== runtime.deviceId || identity.ownerUid !== runtime.ownerUid) ||
        new Set([...identities, ready].map(identity => identity.fileId)).size !== identities.length + 1) invalid();
    if (typeof keeper.processStartToken !== 'string' || !/^linux-proc-start-ticks:[1-9][0-9]*$/u.test(keeper.processStartToken) ||
        typeof keeper.bootIdentityHex !== 'string' || !/^[0-9a-f]{32}$/u.test(keeper.bootIdentityHex)) invalid();
    parseCanonicalTime(controlWireText(keeper.observedAt));
    if (source.sourceBundleDigest !== row.sourceRuntimeBundleRef || source.targetBundleDigest !== row.targetRuntimeBundleRef) invalid();
  }
  const owner = controlWireRecord(row.targetOwner, ['ownerEpoch', 'supervisorInstanceId', 'processIdentityRef', 'processIdentityDigest', 'instanceNonceDigest', 'acquiredAt']);
  if (controlWireInteger(owner.ownerEpoch, 2) !== Number(row.sourceOwnerEpoch) + 1) invalid();
  controlWireText(owner.supervisorInstanceId); ['processIdentityRef', 'processIdentityDigest', 'instanceNonceDigest'].forEach(key => controlWireRef(owner[key]));
  parseCanonicalTime(controlWireText(owner.acquiredAt));
  if (row.receiptDigest !== digestOmitting(row, 'receiptDigest') || canonicalJsonBytes(row).length > 1_048_576) invalid();
  return immutableSnapshot(row as RuntimeUpgradeReceiptV1);
}

export function decodeRuntimeUpgradeRetirement(value: unknown): RuntimeUpgradeRetirementV1 {
  assertControlWireJson(value);
  const row = controlWireRecord(value, ['schemaVersion', 'format', 'sourceOwnerEpoch', 'sourceOwnerRowDigest', 'sourceProcessIdentityRef',
    'sourceProcessIdentityDigest', 'sourceProcessObservation', 'resourceIndexRefs', 'totalRowCount',
    'sourceDataVersion', 'sourceTotalChanges', 'observedAt', 'retirementDigest']);
  if (row.schemaVersion !== 1 || row.format !== 'cliq-retired-runtime-cut-v1' || row.sourceProcessObservation !== 'absent_or_start_token_mismatch') invalid();
  for (const key of ['sourceOwnerRowDigest', 'sourceProcessIdentityRef', 'sourceProcessIdentityDigest', 'retirementDigest']) controlWireRef(row[key]);
  controlWireInteger(row.sourceOwnerEpoch, 1); controlWireInteger(row.sourceDataVersion); controlWireInteger(row.sourceTotalChanges);
  parseCanonicalTime(controlWireText(row.observedAt));
  const indexes = controlWireRecord(row.resourceIndexRefs, UPGRADE_RESOURCE_FAMILIES);
  for (const family of UPGRADE_RESOURCE_FAMILIES) controlWireRef(indexes[family]);
  if (new Set(Object.values(indexes)).size !== UPGRADE_RESOURCE_FAMILIES.length) invalid();
  controlWireInteger(row.totalRowCount, 0, UPGRADE_RESOURCE_FAMILIES.length * UPGRADE_RESOURCE_FAMILY_ROWS);
  if (row.retirementDigest !== digestOmitting(row, 'retirementDigest') || canonicalJsonBytes(row).length > 1_048_576) invalid();
  return immutableSnapshot(row as RuntimeUpgradeRetirementV1);
}

/** Retained evidence only: no process observation or new permission is minted.
 * Original immutable rows remain mandatory, not a matching path or same bytes. */
export async function readRuntimeUpgradeBoundary(driver: SqliteDriver, artifacts: ArtifactCatalog,
  prior: StateOwnerRecordV1, owner: StateOwnerRecordV1,
  acquisition: Extract<StateOwnerAcquisitionEvidenceV1, { kind: 'runtime_upgrade' }>,
  genesis: Extract<StateOwnerAcquisitionEvidenceV1, { kind: 'genesis' }>) {
  const receipt = decodeRuntimeUpgradeReceipt(await readCanonicalArtifact(artifacts, acquisition.upgradeReceiptRef));
  const source = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, prior.runtimeBundleRef);
  const target = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, owner.runtimeBundleRef);
  const conversion = await readSignedSchemaConversion(artifacts, source, target, artifacts.releaseTrustRoots());
  const conversionEntry = target.entries.find(entry => entry.entryId === 'schema_conversion')!;
  const retirement = decodeRuntimeUpgradeRetirement(await readUpgradeResourceRow(artifacts, receipt.retirementRef));
  if (prior.state !== 'terminal' || prior.terminalReason !== 'graceful_release' ||
      receipt.receiptDigest !== acquisition.upgradeReceiptDigest || receipt.sourceOwnerEpoch !== prior.ownerEpoch ||
      receipt.sourceOwnerRowDigest !== prior.rowDigest || receipt.sourceRuntimeBundleRef !== prior.runtimeBundleRef ||
      receipt.sourceRuntimeBundleManifestDigest !== prior.runtimeBundleManifestDigest ||
      receipt.sourceGenerationRef !== genesis.kernelGenerationIdentityRef || receipt.sourceGenerationDigest !== genesis.kernelGenerationIdentityDigest ||
      receipt.targetRuntimeBundleRef !== owner.runtimeBundleRef || receipt.targetRuntimeBundleManifestDigest !== owner.runtimeBundleManifestDigest ||
      receipt.conversionRef !== conversionEntry.digest || receipt.conversionDigest !== conversion.profileDigest ||
      receipt.targetSchemaRef !== conversion.targetSchemaRef || receipt.targetSchemaDigest !== conversion.targetSchemaDigest ||
      receipt.stateLockIdentityRef !== prior.stateLockIdentityRef || receipt.stateLockIdentityDigest !== prior.stateLockIdentityDigest ||
      receipt.stateLockIdentityRef !== owner.stateLockIdentityRef || receipt.stateLockIdentityDigest !== owner.stateLockIdentityDigest ||
      receipt.retirementDigest !== retirement.retirementDigest || retirement.sourceOwnerEpoch !== prior.ownerEpoch ||
      retirement.sourceOwnerRowDigest !== prior.rowDigest || retirement.sourceProcessIdentityRef !== prior.processIdentityRef ||
      retirement.sourceProcessIdentityDigest !== prior.processIdentityDigest || retirement.observedAt !== owner.acquiredAt) invalid();
  requireEqual(receipt.targetOwner, { ownerEpoch: owner.ownerEpoch, supervisorInstanceId: owner.supervisorInstanceId,
    processIdentityRef: owner.processIdentityRef, processIdentityDigest: owner.processIdentityDigest,
    instanceNonceDigest: owner.instanceNonceDigest, acquiredAt: owner.acquiredAt }, 'upgrade target owner');
  const resourceRefs = await readUpgradeResourceGraph(artifacts, { sourceOwnerEpoch: retirement.sourceOwnerEpoch,
    sourceOwnerRowDigest: retirement.sourceOwnerRowDigest }, retirement.resourceIndexRefs, retirement.totalRowCount);
  await readRuntimeUpgradeRetiredRows(driver, artifacts, resourceRefs);
  return { receipt, retirement, conversion, source, target };
}

/** Shared full row audit, before the producer samples death/time and during
 * retained reads. It never supplies an owner, physical proof or permit. */
export async function readRuntimeUpgradeRetiredRows(driver: SqliteDriver, artifacts: ArtifactCatalog, resourceRefs: UpgradeResourceRefs): Promise<void> {
  const runs = new Set<string>(), launches = new Set<string>(), generations = new Set<string>(), attempts = new Set<string>();
  for (const ref of resourceRefs.run_terminal) {
    const run = decodeWireRun(await readUpgradeResourceRow(artifacts, ref));
    if (!['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(run.status) ||
        run.activeWorkerLaunchId !== undefined || !isZeroBudget(run.budgetReserved) || runs.has(run.id)) invalid();
    requireEqual(readRun(driver, run.id), run, 'original retired upgrade Run');
    runs.add(run.id);
  }
  for (const ref of resourceRefs.worker_launch) {
    const row = decodeWorkerLaunch(await readUpgradeResourceRow(artifacts, ref));
    if (row.phase !== 'retired' || !runs.has(row.runId) || launches.has(row.launchId)) invalid();
    requireEqual(readWorkerLaunch(driver, row.launchId), row, 'original retired upgrade worker');
    launches.add(row.launchId);
  }
  for (const ref of resourceRefs.workspace_generation) {
    const row = decodeWorkspaceGenerationState(await readUpgradeResourceRow(artifacts, ref));
    if (row.phase !== 'retired' || !runs.has(row.runId) || generations.has(row.generationId)) invalid();
    requireEqual(readWorkspaceGeneration(driver, row.generationId), row, 'original retired upgrade generation');
    generations.add(row.generationId);
  }
  for (const ref of resourceRefs.source_inspection) {
    const row = decodeSourceInspectionAttempt(await readUpgradeResourceRow(artifacts, ref));
    if (row.phase !== 'retired' || attempts.has(row.inspectionId)) invalid();
    requireEqual(readSourceInspectionAttempt(driver, { principalId: row.principalId, method: row.method,
      admissionKey: row.admissionKey, admissionIntentDigest: row.admissionIntentDigest }), row, 'original retired upgrade source');
    attempts.add(row.inspectionId);
  }
}
