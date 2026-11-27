// Admission-only script consent. Preparation returns an opaque internal token;
// the original Run transaction alone registers the receipt and consumes it.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { AuthorizationConsumptionReceiptV1, AuthorizationGrantV1 } from '../kernel/authorization.js';
import { decodeEndpointRegistration } from '../kernel/credential-authority.js';
import type { NormalizedRunSubmitRequest } from '../kernel/control-submit.js';
import { decodeDependencyAcquisitionPlan, decodeDependencyPolicy, decodeDependencyScriptConditions,
  decodeDependencyInstallScriptsTemplate, dependencyRegistryTargetsDigest, DEPENDENCY_LIMITS,
  type DependencyAcquisitionPlan, type DependencyPolicy, type DependencyScriptConditionsV1,
  type DependencyInstallScriptsAuthorizationTemplateV1 } from '../kernel/dependency.js';
import { addCanonicalDuration, digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { readCanonicalArtifact } from './agent-context.js';
import { authorizationGrantCore, decodeAuthorizationConsumptionReceipt, VerifierAuthorizationError } from './authorization-artifacts.js';
import { readDependencyScriptsAuthorizationHistory, type AuthorizationRuntime } from './authorization.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { readTimeFence } from './canonical-time.js';
import { readDependencyScriptCapture, type DependencyScriptCaptureData } from './dependency-script-capture.js';
import { readCandidateDependencyPlan } from './dependency-plan.js';
import { sameDependencyScriptInputs } from './dependency-script-source.js';
import { KernelStorageError } from './errors.js';
import { consumeOrRevokeAuthorization, readAuthorizationCreationControl, readAuthorizationGrant } from './repositories/authorization-grants.js';
import { readSession, readSessionPrincipalId } from './rows.js';
import { runSubmitIntentDigest } from './source-target.js';
import { assertSqliteConnectionOwnedBy, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type AdmissionInput = {
  principalId: string; runId: string; request: NormalizedRunSubmitRequest; sourceInspectionId: string;
  createdAt: string; deadlineAt: string; conditions: DependencyScriptConditionsV1;
  policy: DependencyPolicy; plan: DependencyAcquisitionPlan;
};
declare const admissionBrand: unique symbol;
export type PreparedDependencyScriptAdmission = Readonly<{ [admissionBrand]: true }>;
type Binding = { driver: SqliteDriver; reads: ArtifactCatalog; owner: StateOwnerContext; input: AdmissionInput; capture: DependencyScriptCaptureData;
  prior: AuthorizationGrantV1; next: Extract<AuthorizationGrantV1, { state: 'consumed' }>;
  receipt: AuthorizationConsumptionReceiptV1; receiptArtifact: PublishedArtifact;
  template: DependencyInstallScriptsAuthorizationTemplateV1; templateArtifact: PublishedArtifact; creationCommittedAt: string };
const preparedAdmissions = new WeakMap<PreparedDependencyScriptAdmission, Binding>();
const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
function refused(): never { throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED'); }
function held(owner: StateOwnerContext, token: PreparedDependencyScriptAdmission): Binding {
  const value = preparedAdmissions.get(token); if (!value || value.owner !== owner) throw new TypeError('dependency consent has no genuine original preparation');
  return value;
}

export async function prepareDependencyScriptAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  runtime: AuthorizationRuntime, input: AdmissionInput, signal?: AbortSignal): Promise<PreparedDependencyScriptAdmission> {
  decodeDependencyScriptConditions(input.conditions); decodeDependencyPolicy(input.policy); decodeDependencyAcquisitionPlan(input.plan);
  input = immutableSnapshot(input); const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  signal?.throwIfAborted(); const active = assertActiveStateOwner(driver, owner);
  const { request, policy, plan, conditions } = input;
  parseCanonicalTime(input.createdAt); parseCanonicalTime(input.deadlineAt);
  if (request.dependency.mode !== 'locked' || !request.dependency.allowInstallScripts || !request.dependency.installScriptsGrantId ||
      input.runId !== identityHash('cliq-run-id-v1', input.principalId, 'run.submit', request.admissionKey) ||
      input.deadlineAt !== addCanonicalDuration(input.createdAt, request.budgets.wallTimeMs) || input.createdAt < active.acquiredAt ||
      active.runtimeBundleRef !== canonicalSha256(runtime.bundle) || active.runtimeBundleManifestDigest !== runtime.bundle.manifestDigest ||
      policy.mode !== 'locked_node' || policy.installScriptsPolicy !== 'deny' || policy.installScriptsGrantRef !== undefined ||
      plan.allowInstallScripts || plan.adapter !== 'npm-ci-v1' || !same(policy.allowedAdapters, ['npm-ci-v1']) ||
      !same(policy.registryEndpoints, plan.registryEndpoints) || !same(policy.credentialGrantRefs, plan.credentialGrantRefs) ||
      policy.maxPackages !== plan.maxPackages || policy.maxDownloadBytes !== plan.maxDownloadBytes ||
      policy.maxPackages !== (request.dependency.maxPackages ?? DEPENDENCY_LIMITS.defaultPackages) ||
      policy.maxDownloadBytes !== (request.dependency.maxDownloadBytes ?? DEPENDENCY_LIMITS.defaultDownloadBytes) ||
      dependencyRegistryTargetsDigest(policy) !== conditions.execution.registryTargetsDigest ||
      plan.guestToolchainManifestRef !== conditions.execution.guestToolchainManifestRef ||
      plan.lockfileDigest !== conditions.lockfileDigest || plan.packageManifest.contentDigest !== conditions.packageManifestDigest ||
      !same(plan.bindingGyp.kind === 'absent' ? { kind: 'absent' } : { kind: 'present', contentDigest: plan.bindingGyp.contentDigest }, conditions.bindingGyp)) refused();
  const capture = await readDependencyScriptCapture(driver, reads, owner, runtime, {
    sourceInspectionId: input.sourceInspectionId, principalId: input.principalId, sessionId: request.sessionId, conditions }, signal);
  if (capture.intent || capture.admission || !same(capture.original, request) || input.createdAt < capture.row.retiredAt ||
      capture.target.workspaceIdentityDigest !== capture.row.workspaceIdentityDigest) refused();
  const registrations = await reads.mapReads(policy.registryEndpoints, async endpoint => {
    const registration = decodeEndpointRegistration(await readCanonicalArtifact(reads, endpoint.endpointRegistrationRef));
    if (registration.ownerPrincipalId !== input.principalId || !registration.purposes.includes('dependency_registry') ||
        registration.endpointIdentityDigest !== endpoint.endpointIdentityDigest || registration.tlsPolicyDigest !== endpoint.tlsPolicyDigest) refused();
    return registration;
  });
  if (!same([...request.dependency.registryEndpointIds].sort(), registrations.map(value => value.endpointRegistrationId).sort())) refused();
  const rebuilt = await readCandidateDependencyPlan(reads, { sourceRef: capture.row.outcome.kind === 'captured'
      ? capture.row.outcome.sourceManifestRef : refused(), policy, registryEndpoints: registrations,
    guestToolchainManifestRef: plan.guestToolchainManifestRef, maxSingleFileBytes: request.sandboxResources.maxSingleFileBytes });
  if (!same(rebuilt.plan, plan)) refused();
  const prior = readAuthorizationGrant(driver, request.dependency.installScriptsGrantId);
  if (!prior || prior.state !== 'active' || prior.ownerPrincipalId !== input.principalId || prior.target.kind !== 'dependency_install_scripts' ||
      prior.target.workspaceIdentityDigest !== capture.row.workspaceIdentityDigest || !sameDependencyScriptInputs(prior.target.conditions, conditions)) refused();
  const history = await readDependencyScriptsAuthorizationHistory(driver, reads, owner, prior, runtime.releaseKeys, signal);
  if (input.createdAt < history.committedAt || input.createdAt >= prior.expiresAt) refused();
  const intent = runSubmitIntentDigest(input.principalId, request);
  const receipt: AuthorizationConsumptionReceiptV1 = { schemaVersion: 1, grantId: prior.grantId, ownerPrincipalId: input.principalId,
    targetDigest: prior.targetDigest, consumer: { kind: 'run_admission', runId: input.runId, admissionIntentDigest: intent },
    consumedAt: input.createdAt, receiptDigest: '' };
  receipt.receiptDigest = digestOmitting(receipt, 'receiptDigest'); decodeAuthorizationConsumptionReceipt(receipt);
  const template: DependencyInstallScriptsAuthorizationTemplateV1 = { schemaVersion: 1, format: 'cliq-dependency-install-scripts-authorization-v1',
    runId: input.runId, ownerPrincipalId: input.principalId, workspaceIdentityDigest: capture.row.workspaceIdentityDigest,
    provenance: { kind: 'run_admission', sourceAuthorizationGrantId: prior.grantId, sourceConsumptionReceiptRef: canonicalSha256(receipt) },
    scriptConditions: conditions, guestToolchainManifestRef: plan.guestToolchainManifestRef, allowedAdapters: [...policy.allowedAdapters],
    lockfilePath: plan.lockfilePath, lockfileRef: plan.lockfileRef, lockfileDigest: plan.lockfileDigest,
    packageManifestRef: plan.packageManifest.contentRef, packageManifestDigest: plan.packageManifest.contentDigest, bindingGyp: plan.bindingGyp,
    registryTargetsDigest: conditions.execution.registryTargetsDigest, maxCandidateGenerations: request.budgets.repairAttempts + 1,
    maxDispatchedAttemptsPerPlan: 1, expiresAt: input.deadlineAt, templateDigest: '' };
  template.templateDigest = digestOmitting(template, 'templateDigest'); decodeDependencyInstallScriptsTemplate(template);
  const [receiptArtifact, templateArtifact] = await reads.publishCanonicalPair([
    { value: receipt, schemaKind: 'cliq-authorization-consumption-receipt-v1' }, { value: template, schemaKind: template.format } ]);
  if (receiptArtifact.ref !== canonicalSha256(receipt) || templateArtifact.ref !== canonicalSha256(template) ||
      !same(await readCanonicalArtifact(reads, receiptArtifact.ref), receipt) || !same(await readCanonicalArtifact(reads, templateArtifact.ref), template))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'dependency admission publications differ from their original complete bytes');
  const next: Extract<AuthorizationGrantV1, { state: 'consumed' }> = { ...authorizationGrantCore(prior), rowVersion: 2,
    grantCoreDigest: prior.grantCoreDigest, state: 'consumed', useCount: 1, consumptionReceiptRef: receiptArtifact.ref,
    consumedAt: input.createdAt, rowDigest: '' }; next.rowDigest = digestOmitting(next, 'rowDigest');
  signal?.throwIfAborted(); capture.assertUnchanged(driver);
  const token = Object.freeze({}) as PreparedDependencyScriptAdmission;
  preparedAdmissions.set(token, { driver, reads, owner, input, capture, prior: immutableSnapshot(prior), next: immutableSnapshot(next),
    receipt: immutableSnapshot(receipt), receiptArtifact, template: immutableSnapshot(template), templateArtifact, creationCommittedAt: history.committedAt });
  return token;
}

export function readPreparedDependencyScriptAdmission(owner: StateOwnerContext, token: PreparedDependencyScriptAdmission) {
  const value = held(owner, token); value.reads.assertReadActive(); assertActiveStateOwner(value.driver, owner);
  return immutableSnapshot({ template: value.template, artifact: value.templateArtifact,
    sourceConsumptionReceipt: value.receipt, sourceConsumptionReceiptArtifact: value.receiptArtifact,
    metadata: [value.receiptArtifact, value.templateArtifact] });
}

/** Called before INSERT Run in the one original admission SQL transaction.
 * Rollback leaves the original active grant and this same preparation usable. */
export function consumePreparedDependencyScriptAdmission(connection: SqliteConnection, owner: StateOwnerContext,
  token: PreparedDependencyScriptAdmission, actual: { runId: string; admissionIntentDigest: string; sourceInspectionId: string }, freshC: string): void {
  const value = held(owner, token), { input, prior, capture } = value;
  assertSqliteConnectionOwnedBy(value.driver, connection); value.reads.assertReadActive();
  assertActiveStateOwner(connection, owner); capture.assertUnchanged(connection); const fence = readTimeFence(connection);
  if (!same(actual, { runId: input.runId, admissionIntentDigest: runSubmitIntentDigest(input.principalId, input.request),
      sourceInspectionId: input.sourceInspectionId }) || !same(readAuthorizationGrant(connection, prior.grantId), prior) ||
      readSessionPrincipalId(connection, input.request.sessionId) !== input.principalId ||
      readSession(connection, input.request.sessionId).workspaceIdentityRef !== capture.target.workspaceIdentityRef ||
      readSession(connection, input.request.sessionId).contextRevision !== input.request.expectedContextRevision ||
      !fence || fence.state !== 'healthy' || fence.stateOwnerEpoch !== owner.ownerEpoch || fence.lastAcceptedAt !== freshC ||
      freshC < input.createdAt || freshC >= input.deadlineAt || freshC >= prior.expiresAt ||
      readAuthorizationCreationControl(connection, prior).committedAt !== value.creationCommittedAt) refused();
  for (const metadata of [value.receiptArtifact, value.templateArtifact]) insertArtifactMetadata(connection, metadata, freshC);
  consumeOrRevokeAuthorization(connection, prior, value.next);
}
