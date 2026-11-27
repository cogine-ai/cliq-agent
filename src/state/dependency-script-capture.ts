import type { RetainedControlRootContext } from './control-channel.js';
// Complete retained capture data for dependency consent. No live source open,
// native capability, permission grant or admission is produced by this reader.
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { DependencyScriptConditionsV1 } from '../kernel/dependency.js';
import { assertArtifactRef } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { AuthorizationRuntime } from './authorization.js';
import { decodeSourceManifest } from './decoders.js';
import { readDependencyScriptIntentData } from './dependency-script-intent.js';
import { readDependencyScriptSourceConditions } from './dependency-script-source.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { KernelStorageError } from './errors.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { readAdmissionReplay, readControlRequest } from './rows.js';
import { readSourceInspectionAttempt, readSourceInspectionOriginalRequest } from './source-inspection.js';
import { readSourceInspectionErrorResponse, readSourceInspectionRetirement } from './source-inspection-owner.js';
import { readRetainedSourceInspectionTarget, readSourceInspectionTargetData } from './source-target.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'dependency consent differs from its complete original retired capture'); }

export async function readDependencyScriptCaptureData(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: RetainedControlRootContext,
  runtime: AuthorizationRuntime, input: { sourceInspectionId: string; principalId: string; sessionId: string;
    conditions: DependencyScriptConditionsV1 }, signal?: AbortSignal) {
  input = immutableSnapshot(input); const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  reads.assertReadActive();
  if (!/^[A-Za-z0-9_-]{43}$/u.test(input.sourceInspectionId)) invalid();
  const locator = driver.prepare(`SELECT principal_id,method,admission_key,admission_intent_digest FROM source_inspection_attempts
    WHERE inspection_id=?`).get<{ principal_id: string; method: string; admission_key: string; admission_intent_digest: string }>(input.sourceInspectionId);
  if (!locator || locator.principal_id !== input.principalId || locator.method !== 'run.submit') invalid();
  const key = { principalId: locator.principal_id, method: 'run.submit' as const,
    admissionKey: locator.admission_key, admissionIntentDigest: locator.admission_intent_digest };
  const selected = readSourceInspectionAttempt(driver, key);
  if (!selected || selected.inspectionId !== input.sourceInspectionId || selected.phase !== 'retired' || selected.method !== 'run.submit' ||
      selected.outcome.kind !== 'captured' || selected.cancelRequested) invalid();
  const row = selected, outcome = selected.outcome;
  if (outcome.kind !== 'captured') invalid();
  const originalIndex = readSourceInspectionOriginalRequest(driver, row.inspectionId);
  const raw = await readSourceInspectionTargetData(reads, row, originalIndex);
  const profile = decodeSandboxProfile(await readCanonicalArtifact(reads, raw.target.sandboxProfileRef));
  const { target, original } = await readRetainedSourceInspectionTarget(reads, row, originalIndex,
    { ...runtime, sandboxProfile: profile }, { driver, owner, signal });
  if (original.method !== 'run.submit' || original.sessionId !== input.sessionId || original.dependency.mode !== 'locked' ||
      !original.dependency.allowInstallScripts || target.runtimeBundleRef !== input.conditions.execution.runtimeBundleRef ||
      target.runtimeBundleManifestDigest !== input.conditions.execution.runtimeBundleManifestDigest) invalid();
  await readSourceInspectionRetirement(driver, reads, row, target);
  const source = decodeSourceManifest(await readCanonicalArtifact(reads, outcome.sourceManifestRef));
  if (source.role !== 'base' || source.manifestDigest !== outcome.sourceManifestDigest ||
      source.workspaceIdentityDigest !== row.workspaceIdentityDigest) invalid();
  const conditions = await readDependencyScriptSourceConditions(reads, {
    sourceManifestRef: outcome.sourceManifestRef, workspaceEntriesRef: source.entriesRef,
    ...(outcome.privateGitStateRef ? { privateGitStateRef: outcome.privateGitStateRef } : {}),
    workspaceIdentityDigest: row.workspaceIdentityDigest, resources: profile.resources,
    packageManifestDigest: input.conditions.packageManifestDigest, lockfileDigest: input.conditions.lockfileDigest,
    bindingGyp: input.conditions.bindingGyp, execution: input.conditions.execution });
  if (!same(conditions, input.conditions)) invalid();
  const control = readControlRequest(driver, input.principalId, 'run.submit', originalIndex.originalRequestId);
  const admission = readAdmissionReplay(driver, 'runs', input.principalId, 'run.submit', row.admissionKey);
  let intent: Awaited<ReturnType<typeof readSourceInspectionErrorResponse>> | undefined;
  let intentData: Awaited<ReturnType<typeof readDependencyScriptIntentData>> | undefined;
  if (row.admissionErrorResponseRef !== undefined) {
    assertArtifactRef(row.admissionErrorResponseRef);
    if (!control || admission || control.requestDigest !== originalIndex.originalRequestDigest ||
        control.responseRef !== row.admissionErrorResponseRef || control.committedAt !== row.retiredAt) invalid();
    if (!row.dependencyScriptIntentRef) invalid();
    intentData = await readDependencyScriptIntentData(driver, reads, owner, runtime, row.dependencyScriptIntentRef, row, signal);
    if (!same(intentData.intent.conditions, conditions)) invalid();
    intent = await readSourceInspectionErrorResponse(reads, row);
    if (intent.error.code !== 'AUTHORIZATION_REQUIRED' || !same(intent.error.requiredAuthorization, {
      kind: 'dependency_install_scripts', purpose: 'dependency_install_scripts', target: { sessionId: original.sessionId,
        sourceInspectionId: row.inspectionId, expectedWorkspaceIdentityDigest: row.workspaceIdentityDigest, conditions } })) invalid();
    const { channel } = await readHistoricalControlChannel(driver, reads, { principalId: input.principalId,
      channelIdentityRef: control.channelIdentityRef, channelIdentityDigest: control.channelIdentityDigest });
    if (channel.principalId !== input.principalId || channel.openedAt > row.retiredAt) invalid();
  }
  function assertUnchanged(connection: SqliteConnection | SqliteDriver) {
    reads.assertReadActive();
    if (!same(readSourceInspectionAttempt(connection, key), row) ||
        !same(readSourceInspectionOriginalRequest(connection, row.inspectionId), originalIndex) ||
        !same(readControlRequest(connection, input.principalId, 'run.submit', originalIndex.originalRequestId), control) ||
        !same(readAdmissionReplay(connection, 'runs', input.principalId, 'run.submit', row.admissionKey), admission)) invalid();
  }
  assertUnchanged(driver); reads.assertReadActive();
  return Object.freeze({ ...immutableSnapshot({ row, target, original, profile, source, conditions, intent, intentData, control, admission }), assertUnchanged });
}

/** Current public consumers retain the real active-owner gate independently
 * of the historical data reader above. */
export async function readDependencyScriptCapture(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, input: { sourceInspectionId: string; principalId: string; sessionId: string; conditions: DependencyScriptConditionsV1 }, signal?: AbortSignal) {
  assertActiveStateOwner(driver, owner);
  const data = await readDependencyScriptCaptureData(driver, artifacts, owner, runtime, input, signal);
  assertActiveStateOwner(driver, owner);
  return Object.freeze({ ...data, assertUnchanged(connection: SqliteConnection | SqliteDriver) {
    assertActiveStateOwner(connection, owner); data.assertUnchanged(connection);
  } });
}
export type DependencyScriptCaptureData = Awaited<ReturnType<typeof readDependencyScriptCapture>>;
