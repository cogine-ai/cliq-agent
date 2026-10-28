import assert from 'node:assert/strict';
import { test } from 'node:test';
import { digestOmitting } from '../kernel/identity.js';
import type { InstalledUpgradeSourceV1, RuntimeUpgradeReceiptV1 } from '../kernel/runtime-upgrade.js';
import { completeInstalledRuntimeUpgrade, readHeldInstalledUpgradeTransaction, stageInstalledRuntimeUpgrade,
  upgradeInstalledRuntime, type HeldInstalledRuntimeUpgrade, type HeldInstalledRuntime } from './installed-runtime.js';
import { decodeRuntimeUpgradeReceipt, decodeRuntimeUpgradeRetirement } from './runtime-upgrade-history.js';

const ref = 'a'.repeat(64), other = 'b'.repeat(64), now = '2026-10-27T00:00:00.000Z';
function dataReceipt(): RuntimeUpgradeReceiptV1 {
  // Decoder data only: this object is not registered, signed, installed or a
  // source of death/upgrade authority.
  const identity = (inode: number, mode = 0o700) => ({ deviceId: '7', fileId: String(inode), ownerUid: 501, ownerGid: 20, mode });
  const installation: InstalledUpgradeSourceV1 = { kind: 'held_installed_stage', stageName: `.upgrade-${'c'.repeat(32)}`,
    runtimeIdentity: identity(1), stageIdentity: identity(2), targetBundleIdentity: identity(3),
    originalActiveIdentity: identity(4, 0o600), originalBootstrapIdentity: identity(5, 0o500),
    stagedActiveIdentity: identity(6, 0o600), stagedBootstrapIdentity: identity(7, 0o500),
    sourceBundleDigest: ref, targetBundleDigest: other, originalActiveDigest: ref, originalBootstrapDigest: ref,
    originalKeeper: { pid: 7, processStartToken: 'linux-proc-start-ticks:10', locatorDigest: ref,
      bootIdentityHex: 'd'.repeat(32), observedAt: now, readyIdentity: identity(8, 0o600) } };
  const receipt: RuntimeUpgradeReceiptV1 = { schemaVersion: 1, format: 'cliq-runtime-upgrade-receipt-v1',
    sourceOwnerEpoch: 1, sourceOwnerRowDigest: ref, sourceRuntimeBundleRef: ref, sourceRuntimeBundleManifestDigest: ref,
    sourceGenerationRef: ref, sourceGenerationDigest: ref, targetRuntimeBundleRef: other, targetRuntimeBundleManifestDigest: other,
    conversionRef: ref, conversionDigest: ref, targetSchemaRef: ref, targetSchemaDigest: ref,
    sourceSchemaVersion: 7, targetSchemaVersion: 8, stateRootIdentityRef: ref, stateRootIdentityDigest: ref,
    stateLockIdentityRef: ref, stateLockIdentityDigest: ref, retirementRef: ref, retirementDigest: ref,
    installation, targetOwner: { ownerEpoch: 2, supervisorInstanceId: 'original-owner', processIdentityRef: ref,
      processIdentityDigest: ref, instanceNonceDigest: ref, acquiredAt: now }, receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest'); return receipt;
}

test('upgrade evidence has closed original identity, owner, version and byte contracts without minting a receipt brand', () => {
  const original = dataReceipt(); assert.deepEqual(decodeRuntimeUpgradeReceipt(original), original);
  const changes: Array<(row: RuntimeUpgradeReceiptV1) => void> = [
    row => { row.sourceSchemaVersion = 8 as 7; },
    row => { row.targetOwner.ownerEpoch = 3; },
    row => { row.installation = { kind: 'not_installed', authority: true } as { kind: 'not_installed' }; },
    row => { (row.installation as InstalledUpgradeSourceV1).stageName = '../package'; },
    row => { (row.installation as InstalledUpgradeSourceV1).stagedActiveIdentity.fileId = '4'; },
    row => { (row.installation as InstalledUpgradeSourceV1).targetBundleIdentity.deviceId = '9'; },
    row => { (row.installation as InstalledUpgradeSourceV1).originalKeeper.readyIdentity.ownerUid = 0; },
    row => { (row.installation as InstalledUpgradeSourceV1).originalKeeper.processStartToken = '10'; },
    row => { (row.installation as InstalledUpgradeSourceV1).targetBundleDigest = ref; },
    row => { delete (row.installation as Partial<InstalledUpgradeSourceV1>).originalBootstrapIdentity; },
    row => { Object.assign(row, { recoveryAllowed: true }); },
  ];
  for (const change of changes) {
    const row = structuredClone(original); change(row); row.receiptDigest = digestOmitting(row, 'receiptDigest');
    assert.throws(() => decodeRuntimeUpgradeReceipt(row));
  }
  const damaged = structuredClone(original); damaged.receiptDigest = other;
  assert.throws(() => decodeRuntimeUpgradeReceipt(damaged));
  let touched = false;
  const accessor = { ...original }; Object.defineProperty(accessor, 'installation', { enumerable: true, get() { touched = true; return original.installation; } });
  assert.throws(() => decodeRuntimeUpgradeReceipt(accessor));
  assert.throws(() => decodeRuntimeUpgradeReceipt(new Proxy(original, { ownKeys() { touched = true; return []; } })));
  assert.equal(touched, false);
});

test('current-checker V2 is a closed source while retained V1 keeps its exact original shape', () => {
  const legacy = dataReceipt(); assert.deepEqual(decodeRuntimeUpgradeReceipt(legacy), legacy);
  if (legacy.installation.kind === 'not_installed') throw new Error('decoder fixture only');
  const current = { ...legacy, installation: { ...legacy.installation, kind: 'held_installed_stage_v2' as const,
    keeperObservationKind: 'current_checked_original_keeper' as const } };
  current.receiptDigest = digestOmitting(current, 'receiptDigest');
  assert.deepEqual(decodeRuntimeUpgradeReceipt(current), current);
  const mutations = [
    { ...current.installation, keeperObservationKind: 'held_anchor' },
    { ...current.installation, kind: 'held_installed_stage' },
    { ...current.installation, kind: 'held_installed_stage_v3' },
    { ...current.installation, retainedKeeperName: 'caller-path' },
    { ...current.installation, withRoot: true },
  ];
  const missing: Record<string, unknown> = { ...current.installation }; delete missing.keeperObservationKind;
  for (const installation of [...mutations, missing]) {
    const changed = { ...current, installation }; changed.receiptDigest = digestOmitting(changed, 'receiptDigest');
    assert.throws(() => decodeRuntimeUpgradeReceipt(changed));
  }
});

test('retirement data binds four distinct bounded resource indexes and rejects claimed death shortcuts', () => {
  const row = { schemaVersion: 1, format: 'cliq-retired-runtime-cut-v1', sourceOwnerEpoch: 1, sourceOwnerRowDigest: ref,
    sourceProcessIdentityRef: ref, sourceProcessIdentityDigest: ref, sourceProcessObservation: 'absent_or_start_token_mismatch',
    resourceIndexRefs: { run_terminal: ref, worker_launch: other, workspace_generation: 'c'.repeat(64), source_inspection: 'd'.repeat(64) },
    totalRowCount: 2,
    sourceDataVersion: 1, sourceTotalChanges: 0, observedAt: now, retirementDigest: '' };
  row.retirementDigest = digestOmitting(row, 'retirementDigest');
  assert.deepEqual(decodeRuntimeUpgradeRetirement(row), row);
  for (const mutation of [
    { resourceIndexRefs: { ...row.resourceIndexRefs, worker_launch: ref } },
    { resourceIndexRefs: { ...row.resourceIndexRefs, foreign: ref } },
    { totalRowCount: 400_001 }, { runTerminalRowRefs: [ref] },
  ]) {
    const changed = { ...row, ...mutation }; changed.retirementDigest = digestOmitting(changed, 'retirementDigest');
    assert.throws(() => decodeRuntimeUpgradeRetirement(changed));
  }
  const changed = { ...row, sourceProcessObservation: 'unit_inactive' }; changed.retirementDigest = digestOmitting(changed, 'retirementDigest');
  assert.throws(() => decodeRuntimeUpgradeRetirement(changed));
});

test('foreign upgrade or installation objects are rejected before getters or proxy traps can run', async () => {
  let touched = false;
  const foreign = new Proxy({}, { get() { touched = true; throw new Error('foreign property'); }, ownKeys() { touched = true; return []; } });
  assert.throws(() => readHeldInstalledUpgradeTransaction(foreign as HeldInstalledRuntimeUpgrade), { code: 'ARTIFACT_MISMATCH' });
  await assert.rejects(completeInstalledRuntimeUpgrade(foreign as HeldInstalledRuntimeUpgrade), { code: 'ARTIFACT_MISMATCH' });
  await assert.rejects(stageInstalledRuntimeUpgrade(foreign as HeldInstalledRuntime, '/not-opened'), { code: 'ARTIFACT_MISMATCH' });
  await assert.rejects(upgradeInstalledRuntime(foreign as Parameters<typeof upgradeInstalledRuntime>[0], '/not-opened', '/not-opened'), { code: 'ARTIFACT_MISMATCH' });
  assert.equal(touched, false);
});
