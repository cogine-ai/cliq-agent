// Original root admission data shared by child/history readers. This never
// acquires an owner, replays a control mutation or grants current execution.
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { DependencyRequest, VerifierRequest } from '../kernel/control-submit.js';
import { decodeDependencyPolicy, decodeDependencyInstallScriptsTemplate, DEPENDENCY_LIMITS, type DependencyPolicy,
  type DependencyInstallScriptsAuthorizationTemplateV1 } from '../kernel/dependency.js';
import { mergeBudgets } from '../kernel/control-submit.js';
import { addCanonicalDuration, digestOmitting, identityHash } from '../kernel/identity.js';
import type { Run, RunSpec, Session } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeAuthorizationConsumptionReceipt } from './authorization-artifacts.js';
import { readHistoricalControlChannel } from './control-channel.js';
import { decodeAdmittedContext, decodeContextManifest, decodeRunObjective, decodeRunSpec,
  decodeSourceManifest, decodeUnverifiedConsent, decodeWorkspaceIdentity, decodeWorkspaceState } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import { readCheckpoint, readControlRequest, readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from './rows.js';
import { readFrozenSessionContextCut } from './session-context.js';
import { normalizeRunSubmitRequest, runSubmitIntentDigest } from './source-target.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { decodeVerifierSpec } from './verifier-artifacts.js';

const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
function invalid(): never { throw new KernelStorageError('RECOVERY_REQUIRED', 'root Run differs from its complete original immutable admission'); }
const immutableRun = (run: Run) => ({ id: run.id, sessionId: run.sessionId, parentRunId: run.parentRunId ?? null,
  specRef: run.specRef, createdAt: run.createdAt, deadlineAt: run.deadlineAt });
const sessionOrigin = (session: Session) => ({ id: session.id, workspaceIdentityRef: session.workspaceIdentityRef,
  parentSessionId: session.parentSessionId ?? null, forkedThroughItemSeq: session.forkedThroughItemSeq ?? null, createdAt: session.createdAt });

export async function readRootRunAdmissionOrigin(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string,
  options: { signal?: AbortSignal } = {}) {
  const reads = options.signal ? artifacts.withReadSignal(options.signal) : artifacts;
  reads.assertReadActive();
  const select = (connection: SqliteConnection | SqliteDriver) => connection.prepare(`SELECT principal_id,admission_method,admission_key,
    admission_intent_digest,admitted_request_digest,admission_request_id FROM runs WHERE id=?`).get<{
      principal_id: string; admission_method: string; admission_key: string; admission_intent_digest: string;
      admitted_request_digest: string; admission_request_id: string | null }>(runId);
  const captured = driver.readSnapshot(connection => {
    const run = readRun(connection, runId), admission = select(connection);
    if (run.parentRunId || !admission || admission.admission_method !== 'run.submit' || !admission.admission_request_id ||
        readSessionPrincipalId(connection, run.sessionId) !== admission.principal_id) invalid();
    const control = readControlRequest(connection, admission.principal_id, 'run.submit', admission.admission_request_id);
    if (!control || control.committedAt !== run.createdAt ||
        run.id !== identityHash('cliq-run-id-v1', admission.principal_id, 'run.submit', admission.admission_key)) invalid();
    return { run, admission, control, session: readSession(connection, run.sessionId),
      initialCheckpoint: readCheckpoint(connection, identityHash('cliq-checkpoint-id-v1', run.id, 'initial', 0)) };
  });
  const { run, admission, control, session, initialCheckpoint } = captured, principalId = admission.principal_id;
  const spec = decodeRunSpec(await readCanonicalArtifact(reads, run.specRef));
  if (spec.operation !== 'agent' || !exactKeys(spec, ['schemaVersion', 'operation', 'objectiveRef', 'admittedContextRef',
    'baseWorkspaceManifestRef', 'sourceProjectionRef', 'assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef',
    'credentialGrantRefs', 'budgets', ...(spec.dependencyPolicyRef === undefined ? [] : ['dependencyPolicyRef']), ...(spec.unverifiedConsentRef === undefined ? [] : ['unverifiedConsentRef'])])) invalid();
  const requestCore = await readCanonicalArtifact<Record<string, unknown>>(reads, control.requestDigest);
  let verifierRequests: VerifierRequest[], admissionIntentDigest: string, objectiveText: unknown, expectedContextRevision: unknown,
    allowUnverified: unknown, workspacePath: unknown, dependencyRequest: DependencyRequest | undefined;
  if (Object.hasOwn(requestCore, 'verifiers')) {
    const normalized = normalizeRunSubmitRequest({ ...requestCore, requestDigest: control.requestDigest }), request = normalized.request;
    if (request.requestId !== admission.admission_request_id || request.admissionKey !== admission.admission_key || request.sessionId !== run.sessionId ||
        !same(request.budgets, spec.budgets)) invalid();
    verifierRequests = request.verifiers; admissionIntentDigest = runSubmitIntentDigest(principalId, request);
    objectiveText = request.objective; expectedContextRevision = request.expectedContextRevision;
    allowUnverified = request.allowUnverified; workspacePath = request.workspacePath; dependencyRequest = request.dependency;
  } else {
    if (!exactKeys(requestCore, ['protocolVersion', 'requestId', 'method', 'admissionKey', 'sessionId', 'expectedContextRevision', 'workspacePath',
      'objective', 'assemblyRef', 'policyRef', 'sandboxProfileRef', 'verifierSpecRef', 'credentialGrantRefs', 'budgets', 'allowUnverified',
      'sourceProjectionRef', 'frozenIgnoreRulesRef', 'baseWorkspaceManifestRef',
      ...(Object.hasOwn(requestCore, 'verifierRequests') ? ['verifierRequests'] : [])]) || requestCore.protocolVersion !== 1 ||
        requestCore.method !== 'run.submit' || requestCore.requestId !== admission.admission_request_id ||
        requestCore.admissionKey !== admission.admission_key || requestCore.sessionId !== run.sessionId ||
        requestCore.verifierSpecRef !== spec.verifierSpecRef || requestCore.assemblyRef !== spec.assemblyRef ||
        requestCore.policyRef !== spec.policyRef || requestCore.sandboxProfileRef !== spec.sandboxProfileRef ||
        requestCore.sourceProjectionRef !== spec.sourceProjectionRef || requestCore.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef ||
        !same(mergeBudgets(requestCore.budgets as RunSpec['budgets']), spec.budgets) ||
        !same(requestCore.credentialGrantRefs, spec.credentialGrantRefs)) invalid();
    const { protocolVersion: _protocol, requestId: _requestId, admissionKey: _key, ...intent } = requestCore;
    admissionIntentDigest = canonicalSha256({ principalId, method: 'run.submit', request: intent });
    verifierRequests = Object.hasOwn(requestCore, 'verifierRequests') ? requestCore.verifierRequests as VerifierRequest[] : [];
    objectiveText = requestCore.objective; expectedContextRevision = requestCore.expectedContextRevision;
    allowUnverified = requestCore.allowUnverified; workspacePath = requestCore.workspacePath;
  }
  if (!Array.isArray(verifierRequests) || verifierRequests.length > 32 || admissionIntentDigest !== admission.admission_intent_digest ||
      run.deadlineAt !== addCanonicalDuration(run.createdAt, spec.budgets.wallTimeMs)) invalid();
  const objective = decodeRunObjective(await readCanonicalArtifact(reads, spec.objectiveRef));
  const admittedContext = decodeAdmittedContext(await readCanonicalArtifact(reads, spec.admittedContextRef));
  if (objective.utf8 !== objectiveText || !exactKeys(admittedContext, ['schemaVersion', 'format', 'sessionId', 'sessionContextRevision',
    'throughSessionItemSeq', 'sessionProjectionRef', 'parentContextRefs', 'additionalArtifactRefs', 'contextDigest']) ||
      admittedContext.sessionId !== run.sessionId || admittedContext.sessionContextRevision !== expectedContextRevision ||
      admittedContext.parentContextRefs.length || admittedContext.additionalArtifactRefs.length) invalid();
  // This temporary read bound is not a reconstructed mutable Session row.
  // Original frozen revision/ref/range come from the admitted artifact; SQL
  // contributes only immutable Session lineage. Every source item must have
  // existed by this Run's actual original admission time.
  await readFrozenSessionContextCut(driver, reads, principalId, { ...session, contextRevision: admittedContext.sessionContextRevision,
    latestItemSeq: admittedContext.throughSessionItemSeq, contextProjectionRef: admittedContext.sessionProjectionRef, updatedAt: run.createdAt });
  const { channel } = await readHistoricalControlChannel(driver, reads, { principalId,
    channelIdentityRef: control.channelIdentityRef, channelIdentityDigest: control.channelIdentityDigest });
  if (channel.openedAt > run.createdAt) invalid();
  const verifierSpec = decodeVerifierSpec(await readCanonicalArtifact(reads, spec.verifierSpecRef));
  if (verifierSpec.verifiers.length !== verifierRequests.length) invalid();
  if (verifierSpec.verifiers.some(entry => entry.gate === 'required')) {
    if (allowUnverified !== false || spec.unverifiedConsentRef !== undefined) invalid();
  } else {
    if (allowUnverified !== true || !spec.unverifiedConsentRef) invalid();
    const consent = decodeUnverifiedConsent(await readCanonicalArtifact(reads, spec.unverifiedConsentRef));
    const { unverifiedConsentRef: _consent, ...specCore } = spec;
    if (!exactKeys(consent, ['schemaVersion', 'kind', 'principalId', 'client', 'channelIdentityRef', 'channelIdentityDigest',
      'admissionIntentDigest', 'runSpecCoreDigest', 'allowUnverified', 'createdAt', 'consentDigest']) ||
        consent.principalId !== principalId || consent.admissionIntentDigest !== admissionIntentDigest || consent.createdAt !== run.createdAt ||
        consent.runSpecCoreDigest !== canonicalSha256(specCore) || consent.channelIdentityRef !== control.channelIdentityRef ||
        consent.channelIdentityDigest !== control.channelIdentityDigest || consent.client !== channel.client) invalid();
  }
  const initialRun: Run = { id: run.id, sessionId: run.sessionId, specRef: run.specRef, status: 'queued', nextStep: 'agent',
    frontierRef: canonicalSha256({ schemaVersion: 1, kind: 'agent', phase: 'model_turn',
      turnId: identityHash('cliq-turn-id-v1', run.id, 'initial'), contextItemSeq: 0, cause: 'initial' }), revision: 1,
    leaseEpoch: 0, latestCheckpointId: initialCheckpoint.id, budgetReserved: ZERO_BUDGET, budgetConsumed: ZERO_BUDGET,
    repairCount: 0, cancelRequested: false, createdAt: run.createdAt, deadlineAt: run.deadlineAt, updatedAt: run.createdAt };
  const initialResponse = await readCanonicalArtifact(reads, control.responseRef);
  if (!same(initialResponse, { protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: {
    schemaVersion: 1, operation: 'agent', run: initialRun, latestRunItemSeq: 0 } } }) || initialCheckpoint.reason !== 'initial' ||
      initialCheckpoint.runId !== run.id || initialCheckpoint.createdAt !== run.createdAt || initialCheckpoint.basedOnRunRevision !== 0 ||
      initialCheckpoint.runItemSeq !== 0 || initialCheckpoint.journalSeq !== 0) invalid();
  if (!same(await readCanonicalArtifact(reads, initialRun.frontierRef!), { schemaVersion: 1, kind: 'agent', phase: 'model_turn',
    turnId: identityHash('cliq-turn-id-v1', run.id, 'initial'), contextItemSeq: 0, cause: 'initial' })) invalid();
  const initialContext = decodeContextManifest(await readCanonicalArtifact(reads, initialCheckpoint.contextManifestRef));
  const expectedContext = { schemaVersion: 1 as const, format: 'cliq-context-manifest-v1' as const, runId: run.id, throughItemSeq: 0,
    admittedContextRef: spec.admittedContextRef, segments: [], assemblyRef: spec.assemblyRef, projectionDigest: '' };
  expectedContext.projectionDigest = digestOmitting(expectedContext, 'projectionDigest');
  if (!same(initialContext, expectedContext)) invalid();
  const state = decodeWorkspaceState(await readCanonicalArtifact(reads, initialCheckpoint.workspaceStateRef));
  const source = decodeSourceManifest(await readCanonicalArtifact(reads, spec.baseWorkspaceManifestRef));
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, session.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== principalId || workspace.canonicalRootPath !== workspacePath ||
      source.workspaceIdentityDigest !== workspace.identityDigest || source.role !== 'base' || source.sourceProjectionRef !== spec.sourceProjectionRef ||
      source.git?.repositoryIdentityDigest !== workspace.repositoryIdentityDigest ||
      state.runId !== run.id || state.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef || state.entriesRef !== source.entriesRef ||
      state.sourceProjectionDigest !== source.sourceProjectionDigest || state.invalidatedEphemeralPaths.length ||
      initialContext.runId !== run.id || initialContext.throughItemSeq !== 0 || initialContext.assemblyRef !== spec.assemblyRef ||
      initialContext.admittedContextRef !== spec.admittedContextRef || initialContext.segments.length ||
      !Object.hasOwn(requestCore, 'verifiers') && requestCore.frozenIgnoreRulesRef !== source.frozenIgnoreRulesRef) invalid();
  let dependencyPolicy: DependencyPolicy | undefined, dependencyTemplate: DependencyInstallScriptsAuthorizationTemplateV1 | undefined;
  const authorizationReceiptRefs: string[] = [];
  if (spec.dependencyPolicyRef !== undefined) {
    if (dependencyRequest?.mode !== 'locked') invalid();
    dependencyPolicy = decodeDependencyPolicy(await readCanonicalArtifact(reads, spec.dependencyPolicyRef));
    if (dependencyPolicy.mode !== 'locked_node' || !same(dependencyPolicy.allowedAdapters, ['npm-ci-v1']) ||
        dependencyPolicy.credentialGrantRefs.length || dependencyRequest.credentialGrantIds.length ||
        dependencyPolicy.maxPackages !== (dependencyRequest.maxPackages ?? DEPENDENCY_LIMITS.defaultPackages) ||
        dependencyPolicy.maxDownloadBytes !== (dependencyRequest.maxDownloadBytes ?? DEPENDENCY_LIMITS.defaultDownloadBytes) ||
        dependencyRequest.allowInstallScripts !== (dependencyPolicy.installScriptsPolicy === 'exact_lockfile_grant')) invalid();
    if (dependencyPolicy.installScriptsPolicy === 'exact_lockfile_grant') {
      dependencyTemplate = decodeDependencyInstallScriptsTemplate(await readCanonicalArtifact(reads, dependencyPolicy.installScriptsGrantRef!));
      if (dependencyTemplate.provenance.kind !== 'run_admission' || dependencyTemplate.runId !== run.id ||
          dependencyTemplate.ownerPrincipalId !== principalId || dependencyTemplate.workspaceIdentityDigest !== workspace.identityDigest ||
          dependencyTemplate.provenance.sourceAuthorizationGrantId !== dependencyRequest.installScriptsGrantId ||
          dependencyTemplate.expiresAt !== run.deadlineAt || dependencyTemplate.maxCandidateGenerations !== spec.budgets.repairAttempts + 1 ||
          dependencyTemplate.scriptConditions.source.sourceManifestRef !== spec.baseWorkspaceManifestRef ||
          dependencyTemplate.scriptConditions.source.sourceManifestDigest !== source.manifestDigest ||
          dependencyTemplate.scriptConditions.source.workspaceEntriesRef !== state.entriesRef ||
          dependencyTemplate.scriptConditions.source.workspaceTreeDigest !== source.treeDigest) invalid();
    } else if (dependencyRequest.installScriptsGrantId !== undefined) invalid();
  } else if (dependencyRequest?.mode === 'locked') invalid();
  for (const request of verifierRequests) {
    const grant = readAuthorizationGrant(driver, request.identityReadGrantId);
    if (!grant || grant.ownerPrincipalId !== principalId || grant.state !== 'consumed') invalid();
    const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(reads, grant.consumptionReceiptRef));
    if (receipt.grantId !== grant.grantId || receipt.ownerPrincipalId !== principalId || receipt.targetDigest !== grant.targetDigest ||
        receipt.consumedAt !== run.createdAt || !same(receipt.consumer, { kind: 'run_admission', runId, admissionIntentDigest })) invalid();
    authorizationReceiptRefs.push(grant.consumptionReceiptRef);
  }
  if (dependencyTemplate) {
    if (dependencyTemplate.provenance.kind !== 'run_admission') invalid();
    const grant = readAuthorizationGrant(driver, dependencyTemplate.provenance.sourceAuthorizationGrantId);
    if (!grant || grant.ownerPrincipalId !== principalId || grant.state !== 'consumed' || grant.target.kind !== 'dependency_install_scripts' ||
        grant.consumptionReceiptRef !== dependencyTemplate.provenance.sourceConsumptionReceiptRef) invalid();
    const receipt = decodeAuthorizationConsumptionReceipt(await readCanonicalArtifact(reads, grant.consumptionReceiptRef));
    if (receipt.grantId !== grant.grantId || receipt.ownerPrincipalId !== principalId || receipt.targetDigest !== grant.targetDigest ||
        receipt.consumedAt !== run.createdAt || !same(receipt.consumer, { kind: 'run_admission', runId, admissionIntentDigest })) invalid();
    authorizationReceiptRefs.push(grant.consumptionReceiptRef);
  }
  const admittedDigest = canonicalSha256({ admissionIntentDigest, objectiveRef: spec.objectiveRef, admittedContextRef: spec.admittedContextRef,
    runSpecRef: run.specRef, workspaceIdentityDigest: source.workspaceIdentityDigest, repositoryIdentityDigest: source.git?.repositoryIdentityDigest ?? null,
    sourceProjectionRef: spec.sourceProjectionRef, frozenIgnoreRulesRef: source.frozenIgnoreRulesRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
    workspaceStateRef: initialCheckpoint.workspaceStateRef, assemblyRef: spec.assemblyRef, policyRef: spec.policyRef, sandboxProfileRef: spec.sandboxProfileRef,
    verifierSpecRef: spec.verifierSpecRef, unverifiedConsentRef: spec.unverifiedConsentRef ?? null, credentialGrantRefs: spec.credentialGrantRefs,
    ...(spec.dependencyPolicyRef === undefined ? {} : { dependencyPolicyRef: spec.dependencyPolicyRef }),
    ...(authorizationReceiptRefs.length ? { authorizationReceiptRefs } : {}) });
  if (admission.admitted_request_digest !== admittedDigest) invalid();
  function assertUnchanged(connection: SqliteConnection | SqliteDriver) {
    if (!same(select(connection), admission) || !same(immutableRun(readRun(connection, runId)), immutableRun(run)) ||
        !same(sessionOrigin(readSession(connection, run.sessionId)), sessionOrigin(session)) ||
        readSessionPrincipalId(connection, run.sessionId) !== principalId ||
        !same(readControlRequest(connection, principalId, 'run.submit', admission.admission_request_id!), control) ||
        !same(readCheckpoint(connection, initialCheckpoint.id), initialCheckpoint)) invalid();
  }
  reads.assertReadActive(); assertUnchanged(driver);
  return Object.freeze({ ...immutableSnapshot({ run, spec, admission, principalId, control, requestCore, verifierRequests,
    admissionIntentDigest, allowUnverified, objective, admittedContext, verifierSpec, initialCheckpoint, initialRun, initialResponse, channel,
    authorizationReceiptRefs, ...(dependencyPolicy ? { dependencyPolicy } : {}), ...(dependencyTemplate ? { dependencyTemplate } : {}) }), assertUnchanged });
}
export type RootRunAdmissionOrigin = Awaited<ReturnType<typeof readRootRunAdmissionOrigin>>;
