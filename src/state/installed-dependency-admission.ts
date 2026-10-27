import { canonicalSha256 } from '../kernel/canonical.js';
import { readCanonicalArtifact } from './agent-context.js';
import { decodeSourceManifest } from './decoders.js';
import { decodeDependencyPolicy } from '../kernel/dependency.js';
import type { NormalizedRunSubmitRequest } from '../kernel/control-submit.js';
import { identityHash } from '../kernel/identity.js';
import type { SourceInspectionAttemptV1 } from '../kernel/execution.js';
import type { PublishedArtifact, ArtifactCatalog } from './artifacts.js';
import { readDependencySubmissionConditions } from './dependency-submission.js';
import { prepareDependencyScriptAdmission, readPreparedDependencyScriptAdmission, consumePreparedDependencyScriptAdmission,
  type PreparedDependencyScriptAdmission } from './dependency-script-admission.js';
import { loadInstalledDependencyBroker, loadInstalledWorkerNative, withHeldInstalledRuntime, type HeldInstalledRuntime, type HeldCredentialAuthorityLock } from './installed-runtime.js';
import { installedSandboxProfile } from './installed-sandbox-profile.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { assertSqliteConnectionOwnedBy, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { assertControlWireJson } from '../kernel/control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import { runSubmitIntentDigest } from './source-target.js';
import { readRun, readSession, readSessionPrincipalId } from './rows.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import { requireEqual } from '../policy/runtime-authority.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { readEndpointAuthoritySource } from './store.js';
import { assertCurrentPublicDependencyEndpoint } from './dependency-endpoints.js';

const brand = Symbol('original installed dependency admission');
export type InstalledDependencyAdmission = Readonly<{ readonly [brand]: true }>;
type Held = { driver: SqliteDriver; owner: StateOwnerContext; request: NormalizedRunSubmitRequest; source: SourceInspectionAttemptV1;
  principalId: string; runId: string; policyRef: string; metadata: readonly PublishedArtifact[];
  scripts?: PreparedDependencyScriptAdmission; receiptRefs: readonly string[]; guestToolchain: { manifestRef: string; manifestDigest: string };
  bundle: RuntimeBundleManifest; registrations: readonly EndpointRegistrationV1[] };
const admissions = new WeakMap<object, Held>();

/** Complete source/policy data plus the existing grant preparation. This
 * creates no Run, network release, worker, Journal or new permission. */
export async function prepareInstalledDependencyAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, input: { request: NormalizedRunSubmitRequest; source: SourceInspectionAttemptV1;
    principalId: string; createdAt: string; deadlineAt: string }, signal?: AbortSignal) {
  assertControlWireJson(input); input = immutableSnapshot(input);
  const { request, source } = input;
  if (request.dependency.mode !== 'locked' || source.phase !== 'retired' || source.outcome.kind !== 'captured')
    throw new TypeError('dependency admission requires its original locked request and retired complete capture');
  const native = await loadInstalledWorkerNative(selected, signal);
  if (native.dependencyInterfaceVersion !== 1) throw new TypeError('installed worker lacks the fixed dependency recipe');
  await loadInstalledDependencyBroker(selected);
  const runtime = await withHeldInstalledRuntime(selected, async installed => {
    await installed.revalidate(signal);
    return { bundle: installed.bundle, releaseKeys: installed.releaseKeys, sandboxProfile: installedSandboxProfile(request.sandboxResources), selectedRuntime: selected };
  }, signal);
  const data = await readDependencySubmissionConditions(driver, artifacts, owner, runtime, { request,
    sourceManifestRef: source.outcome.sourceManifestRef,
    workspaceEntriesRef: decodeSourceManifest(await readCanonicalArtifact(artifacts, source.outcome.sourceManifestRef)).entriesRef,
    ...(source.outcome.privateGitStateRef ? { privateGitStateRef: source.outcome.privateGitStateRef } : {}) }, signal);
  const runId = identityHash('cliq-run-id-v1', input.principalId, 'run.submit', request.admissionKey);
  let scripts: PreparedDependencyScriptAdmission | undefined;
  let metadata: PublishedArtifact[] = [], receiptRefs: string[] = [];
  let policy = data.scriptlessPolicy;
  if (request.dependency.allowInstallScripts) {
    scripts = await prepareDependencyScriptAdmission(driver, artifacts, owner, runtime, { principalId: input.principalId, runId,
      request, sourceInspectionId: source.inspectionId, createdAt: input.createdAt, deadlineAt: input.deadlineAt,
      conditions: data.conditions, policy: data.scriptlessPolicy, plan: data.scriptlessPlan }, signal);
    const original = readPreparedDependencyScriptAdmission(owner, scripts);
    policy = decodeDependencyPolicy({ ...policy, installScriptsPolicy: 'exact_lockfile_grant', installScriptsGrantRef: original.artifact.ref });
    metadata.push(...original.metadata); receiptRefs.push(original.sourceConsumptionReceiptArtifact.ref);
  }
  const artifact = await artifacts.publishCanonical(policy, 'cliq-dependency-policy-v1'); metadata.push(artifact);
  const token: InstalledDependencyAdmission = Object.freeze({ [brand]: true as const });
  admissions.set(token, { driver, owner, request, source, principalId: input.principalId, runId, policyRef: artifact.ref, metadata, scripts, receiptRefs,
    guestToolchain: { manifestRef: data.toolchain.manifestRef, manifestDigest: data.toolchain.manifest.manifestDigest },
    bundle: runtime.bundle, registrations: data.registryRecords.map(value => value.registration) });
  return token;
}
export function assertInstalledDependencyAdmissionAuthority(driver: SqliteDriver, owner: StateOwnerContext,
  token: InstalledDependencyAdmission, authority: HeldCredentialAuthorityLock): void {
  const held = admissions.get(token);
  if (!held || held.driver !== driver || held.owner !== owner) throw new TypeError('dependency admission requires its original owner');
  assertActiveStateOwner(driver, owner); authority.assertHeld();
  for (const original of held.registrations) {
    const source = readEndpointAuthoritySource(authority, original.endpointRegistrationId);
    if (!source) throw new TypeError('dependency admission registry is no longer registered');
    requireEqual(source.record.registration, original, 'dependency admission current complete original registry');
    assertCurrentPublicDependencyEndpoint(source.record, held.principalId, held.bundle);
  }
  authority.assertHeld();
}
export function readInstalledDependencyAdmission(driver: SqliteDriver, owner: StateOwnerContext, token: InstalledDependencyAdmission) {
  const held = admissions.get(token);
  if (!held || held.driver !== driver || held.owner !== owner) throw new TypeError('dependency admission requires its original preparation');
  assertActiveStateOwner(driver, owner);
  return Object.freeze({ policyRef: held.policyRef, metadata: held.metadata, receiptRefs: held.receiptRefs, guestToolchain: held.guestToolchain });
}
export function consumeInstalledDependencyAdmission(connection: SqliteConnection, driver: SqliteDriver, owner: StateOwnerContext,
  token: InstalledDependencyAdmission, input: { runId: string; admissionIntentDigest: string; sourceInspectionId: string }, at: string) {
  const held = admissions.get(token);
  if (!held || held.driver !== driver || held.owner !== owner) throw new TypeError('dependency admission has another original owner');
  assertSqliteConnectionOwnedBy(driver, connection);
  assertActiveStateOwner(connection, owner);
  const intent = runSubmitIntentDigest(held.principalId, held.request);
  requireEqual(input, { runId: held.runId, admissionIntentDigest: intent, sourceInspectionId: held.source.inspectionId }, 'dependency exact original admission identity');
  requireEqual(readSourceInspectionAttempt(connection, { principalId: held.principalId, admissionKey: held.request.admissionKey,
    admissionIntentDigest: intent }), held.source, 'dependency original retired source cut');
  if (readSessionPrincipalId(connection, held.request.sessionId) !== held.principalId ||
      readSession(connection, held.request.sessionId).contextRevision !== held.request.expectedContextRevision ||
      connection.prepare('SELECT id FROM runs WHERE id=?').get(held.runId))
    throw new TypeError('dependency admission Session or original Run cut changed');
  if (held.scripts) consumePreparedDependencyScriptAdmission(connection, owner, held.scripts, input, at);
}
