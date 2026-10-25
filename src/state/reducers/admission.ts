import { canonicalSha256 } from '../../kernel/canonical.js';
import { immutableSnapshot } from '../../model/immutable.js';
import { decodeRetainedRunAssembly } from '../../model/run-assembly.js';
import { exactKeys } from '../../policy/runtime-authority.js';
import {
  addCanonicalDuration,
  assertAdmissionKey,
  assertArtifactRef,
  assertRequestId,
  digestOmitting,
  identityHash,
  normalizeAbsolutePath,
  normalizeBoundedText
} from '../../kernel/identity.js';
import type {
  AdmittedContextManifest,
  ContextManifest,
  ControlApplicationResponseV1,
  ControlResultV1,
  DirectUnverifiedConsentV1,
  Run,
  RunEvent,
  RunFrontier,
  RunObjectiveV1,
  RunSnapshotV1,
  RunSpec,
  WorkspaceIdentityV1
} from '../../kernel/types.js';
import type { ArtifactCatalog, PublishedArtifact } from '../artifacts.js';
import { insertArtifactMetadata } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from '../canonical-time.js';
import { assertCurrentControlFrame, readRetainedControlChannelClosure, validateControlChannelClosure, type AuthenticatedControlIdentity } from '../control-channel.js';
import {
  decodeAdmittedContext,
  decodeContextManifest,
  decodeFrozenIgnoreRules,
  decodeRunObjective,
  decodeRunSpec,
  decodeSessionProjection,
  decodeSourceManifest,
  decodeSourceProjection,
  decodeUnverifiedConsent,
  decodeVerifierSpec,
  decodeWorkspaceEntries,
  decodeWorkspaceIdentity,
  decodeWorkspaceState
} from '../decoders.js';
import { KernelStorageError } from '../errors.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { readInstalledRunAdmission, recheckInstalledRunWorkspace, type AssembledInstalledRun } from '../installed-run.js';
import { assertInstalledRunAdmissionCapacity } from '../installed-run-capacity.js';
import { normalizeRunSubmitRequest, runSubmitIntentDigest } from '../source-target.js';
import { readSourceInspectionAttempt, readSourceInspectionOriginalRequest } from '../source-inspection.js';
import { readSourceInspectionErrorResponse, readSourceInspectionRetirement } from '../source-inspection-owner.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';
import {
  DEFAULT_RUN_BUDGETS,
  insertControlRequest,
  insertRunEvent,
  mergeBudgets,
  readAdmissionReplay,
  readControlRequest,
  readCheckpoint,
  readRun,
  readSession,
  readSessionPrincipalId,
  ZERO_BUDGET
} from '../rows.js';
import type { SqliteDriver } from '../sqlite-driver.js';
import { recaptureLiveWorkspaceIdentity } from '../workspace-identity.js';
import type { SourceInspectionTargetV1 } from '../../kernel/execution.js';
import type { VerifierRequest } from '../../kernel/control-submit.js';
import type { AuthorizationRuntime } from '../authorization.js';
import { assertVerifierRequestData, prepareVerifierSpec, prepareVerifierConsumption, validateVerifierRunAdmission } from '../verifier-admission.js';
import { VerifierAuthorizationError } from '../authorization-artifacts.js';

export type AdmitRunInput = {
  principalId: string;
  requestId: string;
  admissionKey: string;
  channelIdentityRef: string;
  channelIdentityDigest: string;
  sessionId: string;
  expectedContextRevision: number;
  workspacePath: string;
  objective: string;
  assemblyRef: string;
  policyRef: string;
  sandboxProfileRef: string;
  verifierSpecRef: string;
  verifierRequests?: VerifierRequest[];
  credentialGrantRefs?: string[];
  budgets?: Partial<typeof DEFAULT_RUN_BUDGETS>;
  allowUnverified: boolean;
  sourceProjectionRef: string;
  frozenIgnoreRulesRef: string;
  baseWorkspaceManifestRef: string;
};

type RunSubmitResponse = {
  protocolVersion: 1;
  ok: true;
  result: Extract<ControlResultV1, { method: 'run.submit' }>;
};

export type AdmitRunResult = {
  replayed: boolean;
  run: Run;
  response: RunSubmitResponse;
};

function admitIntent(
  input: AdmitRunInput,
  workspacePath: string,
  objective: string,
  budgets: typeof DEFAULT_RUN_BUDGETS
): string {
  return canonicalSha256({
    principalId: input.principalId,
    method: 'run.submit',
    request: {
      method: 'run.submit',
      sessionId: input.sessionId,
      expectedContextRevision: input.expectedContextRevision,
      workspacePath,
      objective,
      assemblyRef: input.assemblyRef,
      policyRef: input.policyRef,
      sandboxProfileRef: input.sandboxProfileRef,
      verifierSpecRef: input.verifierSpecRef,
      ...(input.verifierRequests?.length ? { verifierRequests: input.verifierRequests } : {}),
      credentialGrantRefs: input.credentialGrantRefs ?? [],
      budgets,
      allowUnverified: input.allowUnverified,
      sourceProjectionRef: input.sourceProjectionRef,
      frozenIgnoreRulesRef: input.frozenIgnoreRulesRef,
      baseWorkspaceManifestRef: input.baseWorkspaceManifestRef
    }
  });
}

function admitRequestCore(
  input: AdmitRunInput,
  workspacePath: string,
  objective: string,
  budgets: typeof DEFAULT_RUN_BUDGETS
): object {
  return {
    protocolVersion: 1,
    requestId: input.requestId,
    method: 'run.submit',
    admissionKey: input.admissionKey,
    sessionId: input.sessionId,
    expectedContextRevision: input.expectedContextRevision,
    workspacePath,
    objective,
    assemblyRef: input.assemblyRef,
    policyRef: input.policyRef,
    sandboxProfileRef: input.sandboxProfileRef,
    verifierSpecRef: input.verifierSpecRef,
    ...(input.verifierRequests?.length ? { verifierRequests: input.verifierRequests } : {}),
    credentialGrantRefs: input.credentialGrantRefs ?? [],
    budgets,
    allowUnverified: input.allowUnverified,
    sourceProjectionRef: input.sourceProjectionRef,
    frozenIgnoreRulesRef: input.frozenIgnoreRulesRef,
    baseWorkspaceManifestRef: input.baseWorkspaceManifestRef
  };
}

function admitRequestDigest(input: AdmitRunInput, workspacePath: string, objective: string, budgets: typeof DEFAULT_RUN_BUDGETS): string {
  return canonicalSha256(admitRequestCore(input, workspacePath, objective, budgets));
}

async function readPublishedResponse(
  artifacts: ArtifactCatalog,
  responseRef: string
): Promise<RunSubmitResponse> {
  const response = await readCanonicalArtifact<ControlApplicationResponseV1>(artifacts, responseRef);
  if (response.ok && response.result.method === 'run.submit') {
    return { protocolVersion: 1, ok: true, result: response.result };
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'run.submit replay did not return a success snapshot');
}

async function replayAdmitRun(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: AdmitRunInput,
  admissionIntentDigest: string,
  requestDigest: string
): Promise<AdmitRunResult | undefined> {
  const existingControl = readControlRequest(driver, input.principalId, 'run.submit', input.requestId);
  if (existingControl !== undefined) {
    if (existingControl.requestDigest !== requestDigest) {
      throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.submit requestId was reused with different bytes');
    }
    const response = await readPublishedResponse(artifacts, existingControl.responseRef);
    return { replayed: true, run: response.result.snapshot.run, response };
  }

  const existingAdmission = readAdmissionReplay(driver, 'runs', input.principalId, 'run.submit', input.admissionKey);
  if (existingAdmission !== undefined) {
    if (existingAdmission.admissionIntentDigest !== admissionIntentDigest) {
      throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'run.submit admissionKey was reused with a different intent');
    }
    if (existingAdmission.admissionRequestId === null) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Run admission has no original control request');
    }
    const originalRequestId = existingAdmission.admissionRequestId;
    const original = readControlRequest(driver, input.principalId, 'run.submit', originalRequestId);
    if (!original || original.requestDigest !== admitRequestDigest({ ...input, requestId: originalRequestId },
      input.workspacePath, input.objective, input.budgets as typeof DEFAULT_RUN_BUDGETS)) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Run admission original control request does not match');
    }
    const response = await readPublishedResponse(artifacts, original.responseRef);
    const run = response.result.snapshot.run;
    if (run.id !== existingAdmission.id) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'Run admission original response names another Run');
    }
    const channel = await validateControlChannelClosure(artifacts, owner, input);
    let fenceOutcome: TimeFenceAdvance | undefined;
    driver.transaction(connection => {
      const control = readControlRequest(connection, input.principalId, 'run.submit', input.requestId);
      if (control !== undefined) {
        if (control.requestDigest !== requestDigest || control.responseRef !== original.responseRef) {
          throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.submit requestId was reused with different bytes');
        }
        return;
      }
      const current = readAdmissionReplay(connection, 'runs', input.principalId, 'run.submit', input.admissionKey);
      const currentOriginal = readControlRequest(connection, input.principalId, 'run.submit', originalRequestId);
      if (!current || !currentOriginal || canonicalSha256(current) !== canonicalSha256(existingAdmission) ||
          canonicalSha256(currentOriginal) !== canonicalSha256(original)) {
        throw new KernelStorageError('RECOVERY_REQUIRED', 'Run admission original response link changed');
      }
      assertActiveStateOwner(connection, owner);
      const now = sampleCanonicalNow();
      fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now);
      if (fenceOutcome !== 'healthy') return;
      for (const artifact of channel.metadata) insertArtifactMetadata(connection, artifact, now);
      insertControlRequest(connection, { principalId: input.principalId, method: 'run.submit', requestId: input.requestId,
        channelIdentityRef: input.channelIdentityRef, channelIdentityDigest: input.channelIdentityDigest, requestDigest,
        responseRef: original.responseRef, committedAt: now });
    });
    if (fenceOutcome !== undefined && fenceOutcome !== 'healthy') {
      throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; admission replay binding is paused');
    }
    return { replayed: true, run, response };
  }
  return undefined;
}

/** Original public request bytes are retained at their existing wire digest.
 * This is inert provenance, not a second operation/authority ledger. Replays
 * never recapture source, choose new assemblies or refresh model authority. */
export async function replayInstalledRunAdmission(
  driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  supplied: ReturnType<typeof normalizeRunSubmitRequest>, identity: AuthenticatedControlIdentity, runtime?: AuthorizationRuntime, signal?: AbortSignal
): Promise<AdmitRunResult | undefined> {
  signal?.throwIfAborted();
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  assertCurrentControlFrame(owner, identity);
  const normalized = normalizeRunSubmitRequest(supplied.originalRequest), request = normalized.request;
  const { principalId } = identity, requestDigest = normalized.originalRequestDigest;
  const intent = runSubmitIntentDigest(principalId, request);
  const channel = await validateControlChannelClosure(reads, owner, identity);
  assertActiveStateOwner(driver, owner);
  const control = readControlRequest(driver, principalId, 'run.submit', request.requestId);
  if (control && control.requestDigest !== requestDigest)
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.submit requestId was reused with different bytes');
  const admission = readAdmissionReplay(driver, 'runs', principalId, 'run.submit', request.admissionKey);
  if (!admission) {
    if (control) {
      const source = readSourceInspectionAttempt(driver, { principalId, admissionKey: request.admissionKey, admissionIntentDigest: intent });
      if (!source || source.phase !== 'retired' || source.outcome.kind === 'captured' || source.outcome.errorResponseRef !== control.responseRef)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run replay has neither admission nor its original source refusal');
      await readSourceInspectionErrorResponse(reads, source);
    }
    return undefined;
  }
  if (admission.admissionIntentDigest !== intent)
    throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'run.submit admissionKey was reused with a different intent');
  if (!admission.admissionRequestId) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run admission has no original request');
  const originalControl = readControlRequest(driver, principalId, 'run.submit', admission.admissionRequestId);
  if (!originalControl || (control && control.responseRef !== originalControl.responseRef))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run original response link is missing or inconsistent');
  const originalCore = await readCanonicalArtifact<object>(reads, originalControl.requestDigest);
  const original = normalizeRunSubmitRequest({ ...originalCore, requestDigest: originalControl.requestDigest });
  if (original.request.requestId !== admission.admissionRequestId || original.request.admissionKey !== request.admissionKey ||
      runSubmitIntentDigest(principalId, original.request) !== intent)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run original public request does not bind its admission');

  const source = readSourceInspectionAttempt(driver, { principalId, admissionKey: request.admissionKey, admissionIntentDigest: intent });
  if (!source || source.phase !== 'retired' || source.outcome.kind !== 'captured')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run original source is not captured and retired');
  const target = await readCanonicalArtifact<SourceInspectionTargetV1>(reads, source.targetRef);
  const sourceOriginal = normalizeRunSubmitRequest(await readCanonicalArtifact(reads, target.originalRequestRef));
  const sourceIndex = readSourceInspectionOriginalRequest(driver, source.inspectionId);
  if (!exactKeys(target, ['schemaVersion', 'format', 'principalId', 'method', 'admissionKey', 'admissionIntentDigest',
      'originalRequestRef', 'originalRequestDigest', 'sessionId', 'expectedContextRevision', 'workspaceIdentityRef', 'workspaceIdentityDigest',
      'sourceReadGrantRefs', 'runtimeBundleRef', 'runtimeBundleManifestDigest', 'sandboxProfileRef', 'sandboxProfileDigest', 'targetDigest']) ||
      target.schemaVersion !== 1 || target.format !== 'cliq-source-inspection-target-v1' || target.method !== 'run.submit' ||
      target.workspaceIdentityDigest !== source.workspaceIdentityDigest || target.sessionId !== request.sessionId ||
      target.expectedContextRevision !== request.expectedContextRevision || !Array.isArray(target.sourceReadGrantRefs) || target.sourceReadGrantRefs.length !== 0 ||
      target.targetDigest !== source.targetDigest || target.targetDigest !== digestOmitting(target, 'targetDigest') ||
      target.principalId !== principalId || target.admissionKey !== request.admissionKey || target.admissionIntentDigest !== intent ||
      target.originalRequestDigest !== sourceOriginal.originalRequestDigest || sourceIndex.originalRequestId !== sourceOriginal.request.requestId ||
      sourceIndex.originalRequestDigest !== sourceOriginal.originalRequestDigest || runSubmitIntentDigest(principalId, sourceOriginal.request) !== intent)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run source original request closure changed');
  await readSourceInspectionRetirement(driver, reads, source, target);

  const response = await readPublishedResponse(reads, originalControl.responseRef), run = response.result.snapshot.run;
  const actual = readRun(driver, admission.id), spec = decodeRunSpec(await readCanonicalArtifact(reads, actual.specRef));
  const checkpoint = readCheckpoint(driver, identityHash('cliq-checkpoint-id-v1', actual.id, 'initial', 0));
  const expectedFrontier: RunFrontier = { schemaVersion: 1, kind: 'agent', phase: 'model_turn',
    turnId: identityHash('cliq-turn-id-v1', actual.id, 'initial'), contextItemSeq: 0, cause: 'initial' };
  const expectedRun: Run = { id: actual.id, sessionId: actual.sessionId, specRef: actual.specRef, status: 'queued', nextStep: 'agent',
    frontierRef: canonicalSha256(expectedFrontier), revision: 1, leaseEpoch: 0, latestCheckpointId: checkpoint.id,
    budgetReserved: ZERO_BUDGET, budgetConsumed: ZERO_BUDGET, repairCount: 0, cancelRequested: false,
    createdAt: actual.createdAt, deadlineAt: actual.deadlineAt, updatedAt: actual.createdAt };
  const expectedResponse: RunSubmitResponse = { protocolVersion: 1, ok: true,
    result: { method: 'run.submit', snapshot: { schemaVersion: 1, operation: 'agent', run: expectedRun, latestRunItemSeq: 0 } } };
  if (actual.id !== identityHash('cliq-run-id-v1', principalId, 'run.submit', request.admissionKey) || actual.sessionId !== request.sessionId ||
      actual.deadlineAt !== addCanonicalDuration(actual.createdAt, request.budgets.wallTimeMs) ||
      canonicalSha256(expectedResponse) !== originalControl.responseRef || canonicalSha256(response) !== originalControl.responseRef ||
      checkpoint.runId !== actual.id || checkpoint.basedOnRunRevision !== 0 || checkpoint.runItemSeq !== 0 || checkpoint.journalSeq !== 0 ||
      checkpoint.reason !== 'initial' || checkpoint.createdAt !== actual.createdAt ||
      spec.operation !== 'agent' || canonicalSha256(spec.budgets) !== canonicalSha256(request.budgets) ||
      spec.baseWorkspaceManifestRef !== source.outcome.sourceManifestRef)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run original response, budget or initial checkpoint closure changed');
  const objective = decodeRunObjective(await readCanonicalArtifact(reads, spec.objectiveRef));
  const context = decodeAdmittedContext(await readCanonicalArtifact(reads, spec.admittedContextRef));
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(reads, target.workspaceIdentityRef));
  const manifest = decodeSourceManifest(await readCanonicalArtifact(reads, spec.baseWorkspaceManifestRef));
  const frozenIgnore = decodeFrozenIgnoreRules(await readCanonicalArtifact(reads, manifest.frozenIgnoreRulesRef));
  const projection = decodeSourceProjection(await readCanonicalArtifact(reads, spec.sourceProjectionRef));
  const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(reads, spec.assemblyRef));
  const state = decodeWorkspaceState(await readCanonicalArtifact(reads, checkpoint.workspaceStateRef));
  const initialContext = decodeContextManifest(await readCanonicalArtifact(reads, checkpoint.contextManifestRef));
  if (objective.utf8 !== request.objective || context.sessionId !== request.sessionId ||
      context.sessionContextRevision !== request.expectedContextRevision || workspace.kind !== 'live' || workspace.ownerPrincipalId !== principalId ||
      workspace.canonicalRootPath !== request.workspacePath || workspace.identityDigest !== target.workspaceIdentityDigest ||
      manifest.manifestDigest !== source.outcome.sourceManifestDigest || manifest.workspaceIdentityDigest !== workspace.identityDigest ||
      manifest.role !== 'base' || manifest.sourceProjectionRef !== spec.sourceProjectionRef || manifest.sourceProjectionDigest !== projection.projectionDigest ||
      manifest.frozenIgnoreRulesDigest !== frozenIgnore.rulesDigest || projection.frozenIgnoreRulesRef !== manifest.frozenIgnoreRulesRef ||
      projection.frozenIgnoreRulesDigest !== frozenIgnore.rulesDigest || assembly.createdAt !== actual.createdAt ||
      assembly.runtime.runtimeBundleRef !== target.runtimeBundleRef || assembly.runtime.runtimeBundleManifestDigest !== target.runtimeBundleManifestDigest ||
      state.runId !== actual.id || state.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef ||
      state.entriesRef !== manifest.entriesRef || state.sourceProjectionDigest !== manifest.sourceProjectionDigest || state.invalidatedEphemeralPaths.length !== 0 ||
      initialContext.runId !== actual.id || initialContext.throughItemSeq !== 0 || initialContext.assemblyRef !== spec.assemblyRef ||
      initialContext.admittedContextRef !== spec.admittedContextRef || initialContext.segments.length !== 0)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run frozen objective/context/source closure changed');
  const { channel: initialChannel } = await readRetainedControlChannelClosure(reads, owner, { principalId,
    channelIdentityRef: originalControl.channelIdentityRef, channelIdentityDigest: originalControl.channelIdentityDigest });
  const verifierSpec = decodeVerifierSpec(await readCanonicalArtifact(reads, spec.verifierSpecRef));
  if (verifierSpec.verifiers.some(entry => entry.gate === 'required')) {
    if (request.allowUnverified || spec.unverifiedConsentRef !== undefined) throw new TypeError('required verifier admission cannot carry unverified consent');
  } else {
    const consent = decodeUnverifiedConsent(await readCanonicalArtifact(reads, spec.unverifiedConsentRef!));
    const { unverifiedConsentRef: _consent, ...specCore } = spec;
    if (initialChannel.channelIdentityDigest !== originalControl.channelIdentityDigest || initialChannel.principalId !== principalId ||
        consent.principalId !== principalId || consent.admissionIntentDigest !== intent || consent.createdAt !== actual.createdAt ||
        consent.channelIdentityRef !== originalControl.channelIdentityRef || consent.channelIdentityDigest !== originalControl.channelIdentityDigest ||
        canonicalSha256(consent.client) !== canonicalSha256(initialChannel.client) || consent.runSpecCoreDigest !== canonicalSha256(specCore) || !request.allowUnverified)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run original direct consent closure changed');
  }
  let verifierHistory: Awaited<ReturnType<typeof validateVerifierRunAdmission>> | undefined;
  if (verifierSpec.verifiers.length) {
    if (!runtime) throw new TypeError('verifier replay has no trusted retained release keys');
    verifierHistory = await validateVerifierRunAdmission(driver, reads, owner, runtime, actual.id, signal);
  }
  const admittedRequestDigest = canonicalSha256({ admissionIntentDigest: intent, objectiveRef: spec.objectiveRef,
    admittedContextRef: spec.admittedContextRef, runSpecRef: actual.specRef, workspaceIdentityDigest: workspace.identityDigest,
    repositoryIdentityDigest: workspace.repositoryIdentityDigest ?? null, sourceProjectionRef: spec.sourceProjectionRef,
    frozenIgnoreRulesRef: manifest.frozenIgnoreRulesRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
    workspaceStateRef: checkpoint.workspaceStateRef, assemblyRef: spec.assemblyRef, policyRef: spec.policyRef,
    sandboxProfileRef: spec.sandboxProfileRef, verifierSpecRef: spec.verifierSpecRef, unverifiedConsentRef: spec.unverifiedConsentRef ?? null,
    credentialGrantRefs: spec.credentialGrantRefs,
    ...(verifierHistory ? { authorizationReceiptRefs: verifierHistory.authorizationReceiptRefs } : {}) });
  const frozen = driver.prepare('SELECT admitted_request_digest FROM runs WHERE id = ?').get<{ admitted_request_digest: string }>(actual.id);
  if (frozen?.admitted_request_digest !== admittedRequestDigest)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run final admitted closure no longer rehashes');

  if (!control) {
    const { requestDigest: _digest, ...core } = normalized.originalRequest as Record<string, unknown>;
    signal?.throwIfAborted();
    const requestArtifact = await artifacts.publishCanonical(core, 'cliq-run-submit-request-core-v1');
    signal?.throwIfAborted();
    if (requestArtifact.ref !== requestDigest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed replay public core digest changed');
    let fenceOutcome: TimeFenceAdvance | undefined;
    driver.transaction(connection => {
      const raced = readControlRequest(connection, principalId, 'run.submit', request.requestId);
      if (raced) {
        if (raced.requestDigest !== requestDigest || raced.responseRef !== originalControl.responseRef)
          throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.submit requestId was reused with different bytes');
        return;
      }
      if (canonicalSha256(readAdmissionReplay(connection, 'runs', principalId, 'run.submit', request.admissionKey)) !== canonicalSha256(admission) ||
          canonicalSha256(readControlRequest(connection, principalId, 'run.submit', admission.admissionRequestId!)) !== canonicalSha256(originalControl) ||
          connection.prepare('SELECT admitted_request_digest FROM runs WHERE id = ?').get<{ admitted_request_digest: string }>(actual.id)?.admitted_request_digest !== admittedRequestDigest)
        throw new KernelStorageError('RECOVERY_REQUIRED', 'installed Run replay retained cut changed');
      assertCurrentControlFrame(owner, identity); assertActiveStateOwner(connection, owner); const now = sampleCanonicalNow();
      fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, now); if (fenceOutcome !== 'healthy') return;
      for (const artifact of [...channel.metadata, requestArtifact]) insertArtifactMetadata(connection, artifact, now);
      insertControlRequest(connection, { ...identity, method: 'run.submit', requestId: request.requestId, requestDigest,
        responseRef: originalControl.responseRef, committedAt: now });
    });
    if (fenceOutcome && fenceOutcome !== 'healthy') throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; installed admission replay is paused');
  }
  assertCurrentControlFrame(owner, identity); assertActiveStateOwner(driver, owner);
  return { replayed: true, run, response };
}

type InstalledAdmission = Readonly<{ prepared: AssembledInstalledRun; identity: AuthenticatedControlIdentity;
  data: ReturnType<typeof readInstalledRunAdmission> }>;

/** Public-id production path. The private WeakMap friend, not caller refs or
 * an arbitrary digest override, binds the exact authenticated original frame. */
export async function admitInstalledRun(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  prepared: AssembledInstalledRun, identity: AuthenticatedControlIdentity, runtime?: AuthorizationRuntime, signal?: AbortSignal): Promise<AdmitRunResult> {
  const data = readInstalledRunAdmission(prepared, driver, owner, identity);
  assertCurrentControlFrame(owner, identity);
  return admitRunInternal(driver, artifacts, owner, data.input, { prepared, identity, data }, runtime, signal);
}

export function admitRun(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext, input: AdmitRunInput,
  runtime?: AuthorizationRuntime, signal?: AbortSignal): Promise<AdmitRunResult> {
  return admitRunInternal(driver, artifacts, owner, input, undefined, runtime, signal);
}

async function admitRunInternal(
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  owner: StateOwnerContext,
  input: AdmitRunInput,
  installed?: InstalledAdmission,
  runtime?: AuthorizationRuntime,
  signal?: AbortSignal
): Promise<AdmitRunResult> {
  signal?.throwIfAborted();
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const verifierInput = Object.getOwnPropertyDescriptor(input, 'verifierRequests');
  if (verifierInput) {
    if (!verifierInput.enumerable || !Object.hasOwn(verifierInput, 'value')) throw new TypeError('verifier requests must be plain data');
    assertVerifierRequestData(verifierInput.value);
  }
  assertRequestId(input.requestId);
  assertAdmissionKey(input.admissionKey);
  for (const ref of [
    input.channelIdentityRef,
    input.assemblyRef,
    input.policyRef,
    input.sandboxProfileRef,
    input.verifierSpecRef,
    input.sourceProjectionRef,
    input.frozenIgnoreRulesRef,
    input.baseWorkspaceManifestRef,
    ...(input.credentialGrantRefs ?? [])
  ]) {
    assertArtifactRef(ref);
  }

  const workspacePath = normalizeAbsolutePath(input.workspacePath);
  const objectiveText = normalizeBoundedText(input.objective, 1, 262_144);
  const budgets = mergeBudgets(input.budgets);
  input = immutableSnapshot({ ...input, workspacePath, objective: objectiveText, budgets });
  const admissionIntentDigest = installed ? runSubmitIntentDigest(input.principalId, installed.data.normalized.request) :
    admitIntent(input, workspacePath, objectiveText, budgets);
  const requestDigest = installed?.data.normalized.originalRequestDigest ?? admitRequestDigest(input, workspacePath, objectiveText, budgets);
  const replay = () => installed ? replayInstalledRunAdmission(driver, artifacts, owner, installed.data.normalized, installed.identity, runtime, signal) :
    replayAdmitRun(driver, reads, owner, input, admissionIntentDigest, requestDigest);

  const replayed = await replay();
  if (replayed !== undefined) {
    if (input.verifierRequests?.length) {
      if (!runtime) throw new TypeError('verifier replay has no retained runtime roots');
      await validateVerifierRunAdmission(driver, reads, owner, runtime, replayed.run.id, signal);
    }
    return replayed;
  }

  const channelClosure = await validateControlChannelClosure(reads, owner, input);
  const channel = channelClosure.channel;

  const session = readSession(driver, input.sessionId);
  if (readSessionPrincipalId(driver, input.sessionId) !== input.principalId) {
    throw new KernelStorageError('INVALID_REQUEST', 'session does not belong to the calling principal');
  }
  if (session.contextRevision !== input.expectedContextRevision) {
    throw new KernelStorageError('INVALID_REQUEST', 'session context revision does not match the admitted cursor');
  }
  const workspaceIdentity = decodeWorkspaceIdentity(
    await reads.readCanonical(session.workspaceIdentityRef)
  ) as Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  if (workspaceIdentity.kind !== 'live') {
    throw new KernelStorageError('INVALID_REQUEST', 'only live Sessions may admit a Run');
  }
  if (workspaceIdentity.ownerPrincipalId !== input.principalId) {
    throw new KernelStorageError('INVALID_REQUEST', 'workspace identity is not owned by the calling principal');
  }
  if (installed) recheckInstalledRunWorkspace(installed.prepared, driver, owner, installed.identity);
  else await recaptureLiveWorkspaceIdentity(workspaceIdentity, workspacePath);

  const projection = decodeSessionProjection(await reads.readCanonical(session.contextProjectionRef));
  if (
    projection.sessionId !== session.id ||
    projection.contextRevision !== session.contextRevision ||
    projection.throughItemSeq !== session.latestItemSeq
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'session projection does not match the Session row');
  }

  const frozenIgnore = decodeFrozenIgnoreRules(await reads.readCanonical(input.frozenIgnoreRulesRef));
  const sourceProjection = decodeSourceProjection(await reads.readCanonical(input.sourceProjectionRef));
  if (
    sourceProjection.frozenIgnoreRulesRef !== input.frozenIgnoreRulesRef ||
    sourceProjection.frozenIgnoreRulesDigest !== frozenIgnore.rulesDigest
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'source projection is not bound to the frozen ignore rules');
  }
  const sourceManifest = decodeSourceManifest(await reads.readCanonical(input.baseWorkspaceManifestRef));
  if (
    sourceManifest.role !== 'base' ||
    sourceManifest.sourceProjectionRef !== input.sourceProjectionRef ||
    sourceManifest.sourceProjectionDigest !== sourceProjection.projectionDigest ||
    sourceManifest.frozenIgnoreRulesRef !== input.frozenIgnoreRulesRef ||
    sourceManifest.frozenIgnoreRulesDigest !== frozenIgnore.rulesDigest ||
    sourceManifest.workspaceIdentityDigest !== workspaceIdentity.identityDigest
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'base SourceManifest is not bound to the admitted Session workspace');
  }
  decodeWorkspaceEntries(await reads.readCanonical(sourceManifest.entriesRef));
  if ((sourceManifest.git === undefined) !== (workspaceIdentity.repositoryIdentityDigest === undefined)) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest git identity does not match the live workspace');
  }
  if (
    sourceManifest.git !== undefined &&
    sourceManifest.git.repositoryIdentityDigest !== workspaceIdentity.repositoryIdentityDigest
  ) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'SourceManifest repository digest does not match the live workspace');
  }

  const verifierSpec = decodeVerifierSpec(await reads.readCanonical(input.verifierSpecRef));
  const requiredVerifiers = verifierSpec.verifiers.filter((entry) => entry.gate === 'required');
  if (requiredVerifiers.length > 0 && input.allowUnverified) {
    throw new KernelStorageError('INVALID_REQUEST', 'allowUnverified is forbidden when a required verifier exists');
  }
  if (requiredVerifiers.length === 0 && !input.allowUnverified) {
    throw new KernelStorageError('INVALID_REQUEST', 'an empty required verifier set needs allowUnverified=true');
  }
  const verifierRequests = installed?.data.normalized.request.verifiers ?? input.verifierRequests ?? [];
  let verifierPreparation: Awaited<ReturnType<typeof prepareVerifierSpec>> | undefined;
  if (verifierSpec.verifiers.length || verifierRequests.length) {
    if (!runtime || !verifierRequests.length) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    const policy = await readCanonicalArtifact<{ mode: string }>(reads, input.policyRef);
    verifierPreparation = await prepareVerifierSpec(driver, reads, owner, runtime, { principalId: input.principalId,
      requests: verifierRequests, policyMode: policy.mode, assembly: decodeRetainedRunAssembly(await readCanonicalArtifact(reads, input.assemblyRef)),
      sourceProjectionRef: input.sourceProjectionRef, sandboxProfileRef: input.sandboxProfileRef }, undefined, signal);
    if (verifierPreparation.specRef !== input.verifierSpecRef) throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier spec differs from the authorized public command and environment');
  }

  await reads.readBytes(input.assemblyRef);
  await reads.readBytes(input.policyRef);
  await reads.readBytes(input.sandboxProfileRef);

  const referencedMetadata = await reads.mapReads([
    [input.assemblyRef, 'cliq-run-assembly-v1'],
    [input.policyRef, 'cliq-run-policy-v1'],
    [input.sandboxProfileRef, 'cliq-sandbox-profile-v1'],
    [input.verifierSpecRef, 'cliq-verifier-spec-v1'],
    [input.sourceProjectionRef, 'cliq-source-projection-v1'],
    [input.frozenIgnoreRulesRef, 'cliq-frozen-ignore-rules-v1'],
    [input.baseWorkspaceManifestRef, 'cliq-source-manifest-v1'],
    [sourceManifest.entriesRef, 'cliq-workspace-entries-v1'],
    ...(input.credentialGrantRefs ?? []).map((ref) => [ref, 'cliq-endpoint-credential-grant-binding-v1'] as const)
  ] as const, ([ref, schemaKind]) => reads.describe(ref, 'application/json', schemaKind));

  const now = installed?.data.admittedAt ?? sampleCanonicalNow();
  const runId = identityHash('cliq-run-id-v1', input.principalId, 'run.submit', input.admissionKey);
  const verifierConsumption = verifierPreparation && await prepareVerifierConsumption(artifacts, verifierPreparation,
    { runId, admissionIntentDigest, admittedAt: now }, signal);
  // Revocation stops the next independent publication, never an already
  // started write/fsync/cleanup. A storage or retirement failure keeps priority.
  const publish = async (value: unknown, schemaKind: string): Promise<PublishedArtifact> => {
    signal?.throwIfAborted();
    const artifact = await artifacts.publishCanonical(value, schemaKind);
    signal?.throwIfAborted();
    return artifact;
  };
  const checkpointId = identityHash('cliq-checkpoint-id-v1', runId, 'initial', 0);
  const turnId = identityHash('cliq-turn-id-v1', runId, 'initial');

  const objective: RunObjectiveV1 = {
    schemaVersion: 1,
    format: 'cliq-run-objective-v1',
    utf8: objectiveText,
    byteCount: Buffer.byteLength(objectiveText, 'utf8'),
    objectiveDigest: ''
  };
  objective.objectiveDigest = digestOmitting(objective, 'objectiveDigest');
  const published: PublishedArtifact[] = [...channelClosure.metadata, ...referencedMetadata];
  if (verifierPreparation && verifierConsumption) published.push(...verifierPreparation.metadata, ...verifierConsumption.metadata);
  if (installed) {
    const { requestDigest: _digest, ...core } = installed.data.normalized.originalRequest as Record<string, unknown>;
    const requestArtifact = await publish(core, 'cliq-run-submit-request-core-v1');
    if (requestArtifact.ref !== requestDigest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed original public core digest changed');
    published.push(requestArtifact);
  } else if (verifierPreparation) {
    const requestArtifact = await publish(admitRequestCore(input, workspacePath, objectiveText, budgets), 'cliq-run-submit-internal-request-core-v1');
    if (requestArtifact.ref !== requestDigest) throw new TypeError('internal verifier admission request identity changed');
    published.push(requestArtifact);
  }
  const objectiveArtifact = await publish(objective, 'cliq-run-objective-v1');
  published.push(objectiveArtifact);
  decodeRunObjective(objective);

  const admittedContext: AdmittedContextManifest = {
    schemaVersion: 1,
    format: 'cliq-admitted-context-v1',
    sessionId: session.id,
    sessionContextRevision: session.contextRevision,
    throughSessionItemSeq: session.latestItemSeq,
    sessionProjectionRef: session.contextProjectionRef,
    parentContextRefs: [],
    additionalArtifactRefs: [],
    contextDigest: ''
  };
  admittedContext.contextDigest = digestOmitting(admittedContext, 'contextDigest');
  const admittedContextArtifact = await publish(admittedContext, 'cliq-admitted-context-v1');
  published.push(admittedContextArtifact);
  decodeAdmittedContext(admittedContext);

  const workspaceState = {
    schemaVersion: 1 as const,
    format: 'cliq-workspace-state-v1' as const,
    runId,
    baseWorkspaceManifestRef: input.baseWorkspaceManifestRef,
    entriesRef: sourceManifest.entriesRef,
    invalidatedEphemeralPaths: [] as string[],
    sourceProjectionDigest: sourceProjection.projectionDigest,
    stateDigest: ''
  };
  workspaceState.stateDigest = digestOmitting(workspaceState, 'stateDigest');
  const workspaceStateArtifact = await publish(workspaceState, 'cliq-workspace-state-v1');
  published.push(workspaceStateArtifact);
  decodeWorkspaceState(workspaceState);

  const runSpecCore: RunSpec = {
    schemaVersion: 1,
    operation: 'agent',
    objectiveRef: objectiveArtifact.ref,
    admittedContextRef: admittedContextArtifact.ref,
    baseWorkspaceManifestRef: input.baseWorkspaceManifestRef,
    sourceProjectionRef: input.sourceProjectionRef,
    assemblyRef: input.assemblyRef,
    policyRef: input.policyRef,
    sandboxProfileRef: input.sandboxProfileRef,
    verifierSpecRef: input.verifierSpecRef,
    credentialGrantRefs: input.credentialGrantRefs ?? [],
    budgets
  };
  const runSpecCoreDigest = canonicalSha256(runSpecCore);
  let runSpec = runSpecCore;
  if (requiredVerifiers.length === 0) {
    const consent: DirectUnverifiedConsentV1 = {
      schemaVersion: 1,
      kind: 'direct_unverified_consent',
      principalId: input.principalId,
      client: channel.client,
      channelIdentityRef: input.channelIdentityRef,
      channelIdentityDigest: input.channelIdentityDigest,
      admissionIntentDigest,
      runSpecCoreDigest,
      allowUnverified: true,
      createdAt: now,
      consentDigest: ''
    };
    consent.consentDigest = digestOmitting(consent, 'consentDigest');
    const consentArtifact = await publish(consent, 'cliq-direct-unverified-consent-v1');
    published.push(consentArtifact);
    decodeUnverifiedConsent(consent);
    runSpec = { ...runSpecCore, unverifiedConsentRef: consentArtifact.ref };
  }
  const specArtifact = await publish(runSpec, 'cliq-run-spec-v1');
  published.push(specArtifact);
  decodeRunSpec(runSpec);

  const contextManifest: ContextManifest = {
    schemaVersion: 1,
    format: 'cliq-context-manifest-v1',
    runId,
    throughItemSeq: 0,
    admittedContextRef: admittedContextArtifact.ref,
    segments: [],
    assemblyRef: input.assemblyRef,
    projectionDigest: ''
  };
  contextManifest.projectionDigest = digestOmitting(contextManifest, 'projectionDigest');
  const contextManifestArtifact = await publish(contextManifest, 'cliq-context-manifest-v1');
  published.push(contextManifestArtifact);
  decodeContextManifest(contextManifest);

  const frontier: Extract<RunFrontier, { kind: 'agent' }> = {
    schemaVersion: 1,
    kind: 'agent',
    phase: 'model_turn',
    turnId,
    contextItemSeq: 0,
    cause: 'initial'
  };
  const frontierArtifact = await publish(frontier, 'cliq-run-frontier-v1');
  published.push(frontierArtifact);

  const deadlineAt = installed?.data.deadlineAt ?? addCanonicalDuration(now, budgets.wallTimeMs);
  if (deadlineAt !== addCanonicalDuration(now, budgets.wallTimeMs))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed Run interval does not preserve the complete requested duration');
  const run: Run = {
    id: runId,
    sessionId: session.id,
    specRef: specArtifact.ref,
    status: 'queued',
    nextStep: 'agent',
    frontierRef: frontierArtifact.ref,
    revision: 1,
    leaseEpoch: 0,
    latestCheckpointId: checkpointId,
    budgetReserved: ZERO_BUDGET,
    budgetConsumed: ZERO_BUDGET,
    repairCount: 0,
    cancelRequested: false,
    createdAt: now,
    deadlineAt,
    updatedAt: now
  };
  const snapshot: RunSnapshotV1 = {
    schemaVersion: 1,
    operation: 'agent',
    run,
    latestRunItemSeq: 0
  };
  const event: Extract<RunEvent, { kind: 'state_changed' }> = {
    schemaVersion: 1,
    kind: 'state_changed',
    runId,
    eventSeq: 1,
    runRevision: 1,
    status: 'queued',
    nextStep: 'agent',
    frontierRef: frontierArtifact.ref,
    latestRunItemSeq: 0,
    occurredAt: now
  };
  const response: RunSubmitResponse = {
    protocolVersion: 1,
    ok: true,
    result: { method: 'run.submit', snapshot }
  };
  const responseArtifact = await publish(response, 'cliq-control-response-v1');
  published.push(responseArtifact);

  const admittedRequestDigest = canonicalSha256({
    admissionIntentDigest,
    objectiveRef: objectiveArtifact.ref,
    admittedContextRef: admittedContextArtifact.ref,
    runSpecRef: specArtifact.ref,
    workspaceIdentityDigest: workspaceIdentity.identityDigest,
    repositoryIdentityDigest: workspaceIdentity.repositoryIdentityDigest ?? null,
    sourceProjectionRef: input.sourceProjectionRef,
    frozenIgnoreRulesRef: input.frozenIgnoreRulesRef,
    baseWorkspaceManifestRef: input.baseWorkspaceManifestRef,
    workspaceStateRef: workspaceStateArtifact.ref,
    assemblyRef: input.assemblyRef,
    policyRef: input.policyRef,
    sandboxProfileRef: input.sandboxProfileRef,
    verifierSpecRef: input.verifierSpecRef,
    unverifiedConsentRef: runSpec.unverifiedConsentRef ?? null,
    credentialGrantRefs: runSpec.credentialGrantRefs,
    ...(verifierConsumption ? { authorizationReceiptRefs: verifierConsumption.refs } : {})
  });

  let committed = false;
  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    signal?.throwIfAborted();
    const control = readControlRequest(connection, input.principalId, 'run.submit', input.requestId);
    if (control !== undefined) {
      if (control.requestDigest !== requestDigest) {
        throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.submit requestId was reused with different bytes');
      }
      return;
    }
    const admission = readAdmissionReplay(connection, 'runs', input.principalId, 'run.submit', input.admissionKey);
    if (admission !== undefined) {
      if (admission.admissionIntentDigest !== admissionIntentDigest) {
        throw new KernelStorageError(
          'ADMISSION_KEY_CONFLICT',
          'run.submit admissionKey was reused with a different intent'
        );
      }
      return;
    }

    const lockedSession = readSession(connection, input.sessionId);
    if (readSessionPrincipalId(connection, input.sessionId) !== input.principalId) {
      throw new KernelStorageError('INVALID_REQUEST', 'session does not belong to the calling principal');
    }
    if (lockedSession.contextRevision !== input.expectedContextRevision) {
      throw new KernelStorageError('INVALID_REQUEST', 'session context revision changed before admission committed');
    }

    assertActiveStateOwner(connection, owner);
    const freshNow = sampleCanonicalNow();
    fenceOutcome = advanceTimeFence(connection, owner.ownerEpoch, freshNow);
    if (fenceOutcome !== 'healthy') return;
    if (installed) {
      assertCurrentControlFrame(owner, installed.identity);
      recheckInstalledRunWorkspace(installed.prepared, driver, owner, installed.identity, connection);
      if (freshNow < now || freshNow >= deadlineAt)
        throw new KernelStorageError('INVALID_REQUEST', 'installed admission interval is not current at its final time fence');
      assertInstalledRunAdmissionCapacity(connection);
    }
    for (const artifact of published) insertArtifactMetadata(connection, artifact, now);
    verifierConsumption?.commit(connection, freshNow);

    connection
      .prepare(
        `INSERT INTO checkpoints (
           id, schema_version, run_id, based_on_run_revision, run_item_seq,
           context_manifest_ref, journal_seq, workspace_state_ref, created_at, reason
         ) VALUES (?, 1, ?, 0, 0, ?, 0, ?, ?, 'initial')`
      )
      .run(checkpointId, runId, contextManifestArtifact.ref, workspaceStateArtifact.ref, now);
    connection
      .prepare(
        `INSERT INTO runs (
           id, session_id, parent_run_id, spec_ref, status, next_step, frontier_ref,
           waiting_reason, waiting_on_ref, revision, lease_epoch, active_worker_launch_id,
           latest_checkpoint_id, budget_reserved_json, budget_consumed_json, repair_count,
           result_ref, terminal_reason, terminal_detail_ref, stop_intent_ref, cancel_requested,
           created_at, deadline_at, updated_at, principal_id, admission_method, admission_key,
           admission_intent_digest, admitted_request_digest, admission_request_id
         ) VALUES (?, ?, NULL, ?, 'queued', 'agent', ?, NULL, NULL, 1, 0, NULL, ?, ?, ?, 0,
                   NULL, NULL, NULL, NULL, 0, ?, ?, ?, ?, 'run.submit', ?, ?, ?, ?)`
      )
      .run(
        runId,
        session.id,
        specArtifact.ref,
        frontierArtifact.ref,
        checkpointId,
        JSON.stringify(ZERO_BUDGET),
        JSON.stringify(ZERO_BUDGET),
        now,
        deadlineAt,
        now,
        input.principalId,
        input.admissionKey,
        admissionIntentDigest,
        admittedRequestDigest,
        input.requestId
      );
    insertRunEvent(connection, event);
    insertControlRequest(connection, {
      principalId: input.principalId,
      method: 'run.submit',
      requestId: input.requestId,
      channelIdentityRef: input.channelIdentityRef,
      channelIdentityDigest: input.channelIdentityDigest,
      requestDigest,
      responseRef: responseArtifact.ref,
      committedAt: now
    });
    committed = true;
  });

  if (fenceOutcome === 'clock_regressed') {
    throw new KernelStorageError('INVALID_REQUEST', 'canonical clock has regressed; admission is paused');
  }
  if (fenceOutcome === 'still_regressed') {
    throw new KernelStorageError('INVALID_REQUEST', 'canonical clock is still in clock_regressed');
  }
  if (committed) return { replayed: false, run, response };
  const raced = await replay();
  if (raced !== undefined) return raced;
  throw new KernelStorageError('RECOVERY_REQUIRED', 'run.submit transaction committed no Run');
}
