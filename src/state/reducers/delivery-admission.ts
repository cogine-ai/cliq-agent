import { canonicalSha256 } from '../../kernel/canonical.js';
import { normalizeRunApplyRequest, runApplyIntentDigest } from '../../kernel/control-apply.js';
import { decodeInstalledControlEnvelope } from '../../kernel/control-wire.js';
import type { SourceInspectionAttemptV1, SourceInspectionTarget } from '../../kernel/execution.js';
import { addCanonicalDuration, digestOmitting, identityHash } from '../../kernel/identity.js';
import type { AdmittedContextManifest, ContextManifest, ControlResultV1, Run, RunEvent, RunFrontier, RunSpec,
  Session, WorkspaceStateManifest } from '../../kernel/types.js';
import { immutableSnapshot } from '../../model/immutable.js';
import { readCanonicalArtifact } from '../agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from '../artifacts.js';
import { advanceTimeFence, sampleCanonicalNow } from '../canonical-time.js';
import { assertCurrentControlFrame, readHistoricalControlChannel, validateControlChannelClosure,
  type AuthenticatedControlIdentity } from '../control-channel.js';
import { decodeAdmittedContext, decodeContextManifest, decodeRunSpec, decodeSessionProjection, decodeSourceManifest, decodeWorkspaceIdentity,
  decodeWorkspaceState } from '../decoders.js';
import { assertVerifiedDeliverySource, readRetainedVerifiedDeliverySource, readVerifiedDeliverySource,
  type VerifiedDeliverySource } from '../delivery-source-authority.js';
import { KernelStorageError, ResourceRetirementError, stateOperation } from '../errors.js';
import { decodeSandboxProfile } from '../execution-closure.js';
import { assertInstalledRunAdmissionCapacity } from '../installed-run-capacity.js';
import { loadInstalledWorkerNative, withHeldInstalledRuntime, type HeldInstalledRuntime } from '../installed-runtime.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, type NativeStateOwner } from '../native-owner.js';
import { readCandidateSource } from '../result-source.js';
import { insertControlRequest, insertRunEvent, readAdmissionReplay, readCheckpoint, readControlRequest,
  readRun, readSession, readSessionPrincipalId, ZERO_BUDGET } from '../rows.js';
import { readSourceInspectionAttempt, readSourceInspectionOriginalRequest } from '../source-inspection.js';
import { readDeliveryCaptureTopology, readSourceInspectionRetirement } from '../source-inspection-owner.js';
import { readSourceInspectionTargetData, resolveDeliverySourceCapture } from '../source-target.js';
import { readRetainedSourceInspectionTarget } from '../source-target.js';
import { decodeRepositoryIdentity } from '../repository-identity.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from '../state-owner.js';

type Normalized = ReturnType<typeof normalizeRunApplyRequest>;
type Capture = Extract<SourceInspectionAttemptV1, { phase: 'retired'; method: 'run.apply' }>;
type ApplyResponse = { protocolVersion: 1; ok: true; result: Extract<ControlResultV1, { method: 'run.apply' }> };
export type AdmitDeliveryResult = { replayed: boolean; run: Run; response: ApplyResponse };
export type PreparedInstalledDelivery = Readonly<{ kind: 'prepared_installed_delivery' }>;
type Binding = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; identity: AuthenticatedControlIdentity;
  native: NativeStateOwner; normalized: Normalized; source: VerifiedDeliverySource; capture: Capture;
  workspace: Extract<import('../../kernel/types.js').WorkspaceIdentityV1, { kind: 'live' }>;
  repository?: import('../../kernel/types.js').RepositoryIdentity;
  target: SourceInspectionTarget; session: Session; run: Run; spec: RunSpec; workspaceState: WorkspaceStateManifest;
  contextManifest: ContextManifest; response: ApplyResponse; responseRef: string; admittedRequestDigest: string;
  metadata: PublishedArtifact[]; signal?: AbortSignal;
};
const preparedDeliveries = new WeakMap<PreparedInstalledDelivery, Binding>();
const same = (left: unknown, right: unknown) => canonicalSha256(left) === canonicalSha256(right);
function invalid(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function assertApplyCapture(value: SourceInspectionAttemptV1 | undefined): asserts value is Capture {
  if (!value || value.phase !== 'retired' || value.method !== 'run.apply' || value.outcome.kind !== 'captured')
    invalid('delivery requires its original successful retired apply capture');
}
function key(principalId: string, request: Normalized['request']) {
  return { principalId, method: 'run.apply' as const, admissionKey: request.admissionKey,
    admissionIntentDigest: runApplyIntentDigest(principalId, request) };
}
function inherited(spec: RunSpec, source: VerifiedDeliverySource['spec']): void {
  for (const name of ['objectiveRef', 'assemblyRef', 'verifierSpecRef', 'sourceProjectionRef', 'policyRef', 'sandboxProfileRef', 'dependencyPolicyRef'] as const)
    if (spec[name] !== source[name]) invalid('delivery changed an inherited immutable source identity');
  if (spec.operation !== 'delivery' || spec.unverifiedConsentRef !== undefined || spec.credentialGrantRefs.length ||
      spec.budgets.modelTokens !== 0 || spec.budgets.costMicros !== 0 || spec.budgets.repairAttempts !== 0 ||
      spec.budgets.childDepth !== 0 || spec.budgets.childConcurrency !== 0)
    invalid('delivery acquired agentic or credential authority');
}
function admittedDigest(input: { intent: string; sourceRunId: string; sourceRunResultRef: string; spec: RunSpec; specRef: string;
  workspaceIdentityRef: string; workspaceIdentityDigest: string; workspaceStateRef: string; capture: Capture }) {
  const { spec, capture } = input;
  if (capture.outcome.kind !== 'captured') invalid('delivery has no successful original capture');
  return canonicalSha256({ admissionIntentDigest: input.intent, sourceRunId: input.sourceRunId, sourceRunResultRef: input.sourceRunResultRef,
    objectiveRef: spec.objectiveRef, admittedContextRef: spec.admittedContextRef, runSpecRef: input.specRef,
    workspaceIdentityRef: input.workspaceIdentityRef, workspaceIdentityDigest: input.workspaceIdentityDigest,
    sourceProjectionRef: spec.sourceProjectionRef, baseWorkspaceManifestRef: spec.baseWorkspaceManifestRef,
    workspaceStateRef: input.workspaceStateRef, assemblyRef: spec.assemblyRef, policyRef: spec.policyRef,
    sandboxProfileRef: spec.sandboxProfileRef, verifierSpecRef: spec.verifierSpecRef, dependencyPolicyRef: spec.dependencyPolicyRef ?? null,
    credentialGrantRefs: spec.credentialGrantRefs, sourceInspectionId: capture.inspectionId, sourceInspectionTargetRef: capture.targetRef,
    sourceInspectionRetirementRef: capture.retirementEvidenceRef, captureTopologyRef: capture.outcome.captureTopologyRef,
    captureTopologyDigest: capture.outcome.captureTopologyDigest });
}
function initialRun(run: Pick<Run, 'id' | 'sessionId' | 'createdAt' | 'deadlineAt'>, specRef: string, frontierRef: string, checkpointId: string): Run {
  return { id: run.id, sessionId: run.sessionId, specRef, status: 'queued', nextStep: 'delivery', frontierRef, revision: 1, leaseEpoch: 0,
    latestCheckpointId: checkpointId, budgetReserved: ZERO_BUDGET, budgetConsumed: ZERO_BUDGET, repairCount: 0, cancelRequested: false,
    createdAt: run.createdAt, deadlineAt: run.deadlineAt, updatedAt: run.createdAt };
}
function assertSourceCut(connection: SqliteConnection | SqliteDriver, source: VerifiedDeliverySource, principalId: string): void {
  if (!same(readRun(connection, source.run.id), source.run) || readSessionPrincipalId(connection, source.run.sessionId) !== principalId ||
      readSession(connection, source.run.sessionId).workspaceIdentityRef !== source.session.workspaceIdentityRef)
    invalid('delivery source terminal result or original Session identity changed');
}
function held(prepared: PreparedInstalledDelivery, driver: SqliteDriver, owner: StateOwnerContext,
  identity: AuthenticatedControlIdentity): Binding {
  const value = preparedDeliveries.get(prepared);
  if (!value || value.driver !== driver || value.owner !== owner || !same(value.identity, identity))
    throw new TypeError('a genuine same-owner prepared delivery is required');
  value.signal?.throwIfAborted(); return value;
}

/** Data preparation after the existing capture owner has fully joined. It
 * publishes A's complete W_A before any Run or physical generation exists. */
export async function prepareInstalledDelivery(input: {
  driver: SqliteDriver; artifacts: ArtifactCatalog; owner: StateOwnerContext; selected: HeldInstalledRuntime;
  request: unknown; identity: AuthenticatedControlIdentity; source: VerifiedDeliverySource; capture: SourceInspectionAttemptV1;
}, signal?: AbortSignal): Promise<PreparedInstalledDelivery> {
  const source = assertVerifiedDeliverySource(input.driver, input.owner, input.source);
  const normalized = normalizeRunApplyRequest(input.request), identity = immutableSnapshot(input.identity);
  const { driver, artifacts, owner, selected } = input;
  const capture = immutableSnapshot(input.capture);
  const selection = await resolveDeliverySourceCapture(driver, artifacts, owner, normalized.request, identity.principalId, source, signal);
  const channel = await validateControlChannelClosure(artifacts, owner, identity);
  signal?.throwIfAborted(); assertActiveStateOwner(driver, owner);
  const retained = readSourceInspectionAttempt(driver, key(identity.principalId, normalized.request));
  assertApplyCapture(capture);
  if (!retained || !same(retained, capture)) invalid('delivery requires the exact committed retired apply capture');
  if (source.run.updatedAt > capture.createdAt) invalid('delivery captured its workspace before the source was verified');
  const native = await loadInstalledWorkerNative(selected, signal);
  if (native.verifierInterfaceVersion !== 1) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed verifier capability is unavailable');
  const retainedTarget = await readSourceInspectionTargetData(artifacts, capture, readSourceInspectionOriginalRequest(driver, capture.inspectionId));
  const target = retainedTarget.target;
  const profile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, source.spec.sandboxProfileRef));
  if (retainedTarget.original.method !== 'run.apply' || runApplyIntentDigest(identity.principalId, retainedTarget.original) !==
      key(identity.principalId, normalized.request).admissionIntentDigest || target.sandboxProfileRef !== source.spec.sandboxProfileRef ||
      target.sandboxProfileDigest !== profile.profileDigest || !profile.allowedOwners.includes('source_inspection'))
    invalid('delivery target changed its original request or inherited sandbox profile');
  const stateOwnerNative = await withHeldInstalledRuntime(selected, async installed => {
    await installed.revalidate(signal);
    if (installed.bundleDigest !== source.assembly.runtime.runtimeBundleRef || installed.bundleDigest !== target.runtimeBundleRef ||
        installed.bundle.manifestDigest !== source.assembly.runtime.runtimeBundleManifestDigest)
      invalid('delivery requires its unchanged signed installed source runtime');
    await readRetainedSourceInspectionTarget(artifacts, capture, readSourceInspectionOriginalRequest(driver, capture.inspectionId),
      { bundle: installed.bundle, releaseKeys: installed.releaseKeys, sandboxProfile: profile }, { driver, owner, signal });
    const native = await installed.loadStateOwner(signal); await installed.revalidate(signal); return native;
  }, signal);
  await readSourceInspectionRetirement(driver, artifacts, capture, target);
  await readDeliveryCaptureTopology(artifacts, capture, target);
  const session = readSession(driver, source.run.sessionId);
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== identity.principalId || workspace.identityDigest !== target.workspaceIdentityDigest)
    invalid('delivery requires its unchanged live Session workspace identity');
  const repository = workspace.repositoryIdentityRef ? decodeRepositoryIdentity(await readCanonicalArtifact(artifacts, workspace.repositoryIdentityRef)) : undefined;
  const sessionProjection = decodeSessionProjection(await readCanonicalArtifact(artifacts, session.contextProjectionRef));
  if (sessionProjection.sessionId !== session.id || sessionProjection.contextRevision !== session.contextRevision ||
      sessionProjection.throughItemSeq !== session.latestItemSeq) invalid('delivery Session projection differs from its captured cursor');
  if (target.sessionId !== session.id || target.expectedContextRevision !== session.contextRevision ||
      target.workspaceIdentityRef !== session.workspaceIdentityRef || target.workspaceIdentityRef !== source.session.workspaceIdentityRef ||
      !same(selection.sandboxResources, profile.resources)) invalid('delivery capture no longer owns its original Session cut');
  const base = decodeSourceManifest(await readCanonicalArtifact(artifacts, capture.outcome.sourceManifestRef));
  if (base.role !== 'base' || base.manifestDigest !== capture.outcome.sourceManifestDigest ||
      base.sourceProjectionRef !== source.spec.sourceProjectionRef || base.workspaceIdentityDigest !== target.workspaceIdentityDigest ||
      !!base.git !== !!capture.outcome.privateGitStateRef || !!base.git !== !!repository ||
      base.git && base.git.repositoryIdentityDigest !== repository?.repositoryIdentityDigest)
    invalid('delivery A differs from its retained capture and inherited projection');
  const runId = identityHash('cliq-run-id-v1', identity.principalId, 'run.apply', normalized.request.admissionKey);
  const workspaceState: WorkspaceStateManifest = { schemaVersion: 1, format: 'cliq-workspace-state-v1', runId,
    baseWorkspaceManifestRef: capture.outcome.sourceManifestRef, entriesRef: base.entriesRef, invalidatedEphemeralPaths: [],
    ...(capture.outcome.privateGitStateRef ? { privateGitStateRef: capture.outcome.privateGitStateRef } : {}),
    sourceProjectionDigest: base.sourceProjectionDigest, stateDigest: '' };
  workspaceState.stateDigest = digestOmitting(workspaceState, 'stateDigest'); decodeWorkspaceState(workspaceState);
  const stateArtifact = await artifacts.publishCanonical(workspaceState, workspaceState.format);
  const admittedContext: AdmittedContextManifest = { schemaVersion: 1, format: 'cliq-admitted-context-v1', sessionId: session.id,
    sessionContextRevision: session.contextRevision, throughSessionItemSeq: session.latestItemSeq,
    sessionProjectionRef: session.contextProjectionRef, parentContextRefs: [], additionalArtifactRefs: [], contextDigest: '' };
  admittedContext.contextDigest = digestOmitting(admittedContext, 'contextDigest'); decodeAdmittedContext(admittedContext);
  const context = await artifacts.publishCanonical(admittedContext, admittedContext.format);
  const spec: RunSpec = { schemaVersion: 1, operation: 'delivery', objectiveRef: source.spec.objectiveRef, admittedContextRef: context.ref,
    baseWorkspaceManifestRef: capture.outcome.sourceManifestRef, sourceProjectionRef: source.spec.sourceProjectionRef,
    assemblyRef: source.spec.assemblyRef, policyRef: source.spec.policyRef, sandboxProfileRef: source.spec.sandboxProfileRef,
    verifierSpecRef: source.spec.verifierSpecRef, ...(source.spec.dependencyPolicyRef ? { dependencyPolicyRef: source.spec.dependencyPolicyRef } : {}),
    credentialGrantRefs: [], budgets: { ...normalized.request.budgets, modelTokens: 0, costMicros: 0, repairAttempts: 0, childDepth: 0, childConcurrency: 0 } };
  inherited(spec, source.spec); decodeRunSpec(spec);
  // The production projection reader exhausts/rehashes every actual file and
  // validates W_A against A. No generation, Node process or proof is minted.
  const recoveryImage = await readCandidateSource(artifacts, spec, stateArtifact.ref, signal);
  if (recoveryImage.diff.operations.length || recoveryImage.source.entriesRef !== base.entriesRef)
    invalid('delivery recovery image does not exactly reproduce admitted A');
  const specArtifact = await artifacts.publishCanonical(spec, 'cliq-run-spec-v1');
  const contextManifest: ContextManifest = { schemaVersion: 1, format: 'cliq-context-manifest-v1', runId, throughItemSeq: 0,
    admittedContextRef: context.ref, segments: [], assemblyRef: spec.assemblyRef, projectionDigest: '' };
  contextManifest.projectionDigest = digestOmitting(contextManifest, 'projectionDigest'); decodeContextManifest(contextManifest);
  const manifest = await artifacts.publishCanonical(contextManifest, contextManifest.format);
  const frontier: Extract<RunFrontier, { kind: 'delivery'; phase: 'merge' }> = { schemaVersion: 1, kind: 'delivery',
    sourceRunResultRef: normalized.request.expectedRunResultRef, phase: 'merge', capturedWorkspaceRef: spec.baseWorkspaceManifestRef };
  const frontierArtifact = await artifacts.publishCanonical(frontier, 'cliq-run-frontier-v1');
  const now = sampleCanonicalNow(), checkpointId = identityHash('cliq-checkpoint-id-v1', runId, 'initial', 0);
  const run = initialRun({ id: runId, sessionId: session.id, createdAt: now,
    deadlineAt: addCanonicalDuration(now, normalized.request.budgets.wallTimeMs) }, specArtifact.ref, frontierArtifact.ref, checkpointId);
  const response: ApplyResponse = { protocolVersion: 1, ok: true, result: { method: 'run.apply',
    snapshot: { schemaVersion: 1, operation: 'delivery', run, latestRunItemSeq: 0 } } };
  const responseArtifact = await artifacts.publishCanonical(response, 'cliq-control-response-v1');
  const { requestDigest: _digest, ...core } = normalized.originalRequest as Record<string, unknown>;
  const requestCore = await artifacts.publishCanonical(core, 'cliq-run-apply-request-core-v1');
  if (requestCore.ref !== normalized.originalRequestDigest) invalid('delivery original public request bytes changed');
  const admittedRequestDigest = admittedDigest({ intent: key(identity.principalId, normalized.request).admissionIntentDigest,
    sourceRunId: source.run.id, sourceRunResultRef: normalized.request.expectedRunResultRef, spec, specRef: specArtifact.ref,
    workspaceIdentityRef: target.workspaceIdentityRef, workspaceIdentityDigest: target.workspaceIdentityDigest,
    workspaceStateRef: stateArtifact.ref, capture });
  // Revalidate the complete source after the potentially long new capture and
  // data publication, never only its transient selection brand.
  const currentSource = await readVerifiedDeliverySource(driver, artifacts, owner, { principalId: identity.principalId,
    sourceRunId: source.run.id, expectedRunResultRef: normalized.request.expectedRunResultRef, signal });
  if (!same(currentSource.run, source.run) || !same(currentSource.spec, source.spec)) invalid('delivery original source closure changed');
  const metadata = [...channel.metadata, stateArtifact, context, specArtifact, manifest, frontierArtifact, responseArtifact, requestCore,
    ...recoveryImage.metadata.filter(entry => entry.ref !== recoveryImage.sourceRef && entry.ref !== recoveryImage.diffRef)];
  const prepared: PreparedInstalledDelivery = Object.freeze({ kind: 'prepared_installed_delivery' });
  preparedDeliveries.set(prepared, { driver, artifacts, owner, identity, native: stateOwnerNative, normalized, source,
    capture, target, workspace: immutableSnapshot(workspace), ...(repository ? { repository } : {}),
    session: immutableSnapshot(session), run: immutableSnapshot(run), spec: immutableSnapshot(spec),
    workspaceState: immutableSnapshot(workspaceState), contextManifest: immutableSnapshot(contextManifest), response: immutableSnapshot(response),
    responseRef: responseArtifact.ref, admittedRequestDigest, metadata, signal });
  return prepared;
}

/** The sole delivery admission transaction. Preparing above created only CAS
 * data: physical resource ownership starts later on the existing spine. */
export async function admitInstalledDelivery(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  prepared: PreparedInstalledDelivery, identity: AuthenticatedControlIdentity, signal?: AbortSignal): Promise<AdmitDeliveryResult> {
  const value = held(prepared, driver, owner, identity), { run, normalized, source, session, capture } = value;
  signal?.throwIfAborted(); assertCurrentControlFrame(owner, identity);
  const replay = await replayInstalledDeliveryAdmission(driver, artifacts, owner, normalized, identity, signal);
  if (replay) return replay;
  await validateControlChannelClosure(artifacts, owner, identity);
  let committed = false, regressed = false;
  driver.transaction(connection => {
    signal?.throwIfAborted(); value.signal?.throwIfAborted(); assertCurrentControlFrame(owner, identity); assertActiveStateOwner(connection, owner);
    const existing = readAdmissionReplay(connection, 'runs', identity.principalId, 'run.apply', normalized.request.admissionKey);
    const control = readControlRequest(connection, identity.principalId, 'run.apply', normalized.request.requestId);
    if (existing || control) return;
    assertSourceCut(connection, source, identity.principalId);
    const current = readSession(connection, session.id);
    if (!same(current, session) || !same(readSourceInspectionAttempt(connection, key(identity.principalId, normalized.request)), capture))
      invalid('delivery admission lost its exact original Session or capture cut');
    const root = value.native.openWorkspaceRoot(value.workspace.canonicalRootPath); let failure: unknown;
    try {
      assertHeldWorkspaceRoot(root);
      if (!same(root.identity, value.workspace.rootIdentity) || heldWorkspaceRootPath(root) !== value.workspace.canonicalRootPath ||
          (root.repositoryDirectory === undefined) !== (value.repository === undefined) ||
          value.repository && !same(root.repositoryDirectory, value.repository.gitDirectoryIdentity))
        invalid('delivery real workspace root changed after its original descriptor capture');
      root.assertHeld();
    } catch (error) { failure = error; throw error; }
    finally {
      try { root.close(); }
      catch (error) { throw new ResourceRetirementError('delivery root recheck did not retire', failure === undefined ? error : new AggregateError([failure, error])); }
    }
    const now = sampleCanonicalNow();
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy') { regressed = true; return; }
    if (now < run.createdAt || now >= run.deadlineAt) invalid('delivery admission interval is no longer current');
    assertInstalledRunAdmissionCapacity(connection);
    for (const entry of value.metadata) insertArtifactMetadata(connection, entry, run.createdAt);
    connection.prepare(`INSERT INTO checkpoints (id,schema_version,run_id,based_on_run_revision,run_item_seq,context_manifest_ref,
      journal_seq,workspace_state_ref,created_at,reason) VALUES (?,1,?,0,0,?,0,?,?,'initial')`).run(run.latestCheckpointId, run.id,
        canonicalSha256(value.contextManifest), canonicalSha256(value.workspaceState), run.createdAt);
    connection.prepare(`INSERT INTO runs (id,session_id,parent_run_id,spec_ref,status,next_step,frontier_ref,waiting_reason,waiting_on_ref,
      revision,lease_epoch,active_worker_launch_id,latest_checkpoint_id,budget_reserved_json,budget_consumed_json,repair_count,result_ref,
      terminal_reason,terminal_detail_ref,stop_intent_ref,cancel_requested,created_at,deadline_at,updated_at,principal_id,admission_method,
      admission_key,admission_intent_digest,admitted_request_digest,admission_request_id)
      VALUES (?,?,NULL,?,'queued','delivery',?,NULL,NULL,1,0,NULL,?,?,?,0,NULL,NULL,NULL,NULL,0,?,?,?,?, 'run.apply',?,?,?,?)`).run(run.id,
        run.sessionId, run.specRef, run.frontierRef!, run.latestCheckpointId, JSON.stringify(ZERO_BUDGET), JSON.stringify(ZERO_BUDGET),
        run.createdAt, run.deadlineAt, run.createdAt, identity.principalId, normalized.request.admissionKey,
        key(identity.principalId, normalized.request).admissionIntentDigest, value.admittedRequestDigest, normalized.request.requestId);
    const event: Extract<RunEvent, { kind: 'state_changed' }> = { schemaVersion: 1, kind: 'state_changed', runId: run.id, eventSeq: 1,
      runRevision: 1, status: 'queued', nextStep: 'delivery', frontierRef: run.frontierRef!, latestRunItemSeq: 0, occurredAt: run.createdAt };
    insertRunEvent(connection, event);
    insertControlRequest(connection, { principalId: identity.principalId, method: 'run.apply', requestId: normalized.request.requestId,
      requestDigest: normalized.originalRequestDigest, channelIdentityRef: identity.channelIdentityRef,
      channelIdentityDigest: identity.channelIdentityDigest, responseRef: value.responseRef, committedAt: run.createdAt });
    committed = true;
  });
  if (regressed) throw new KernelStorageError('INVALID_REQUEST', 'canonical time is regressed; delivery admission is paused');
  if (committed) return { replayed: false, run, response: value.response };
  const raced = await replayInstalledDeliveryAdmission(driver, artifacts, owner, normalized, identity, signal);
  if (raced) return raced;
  throw new KernelStorageError('RECOVERY_REQUIRED', 'delivery transaction committed no Run');
}

/** One retained consumer for delivery continuation, replay and verifier
 * admission. It reads immutable provenance, never opens today's workspace. */
export const readDeliveryRunAdmission = stateOperation('RECOVERY_REQUIRED', async function readDeliveryRunAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, runId: string,
  options: { signal?: AbortSignal } = {}) {
  const { signal } = options; signal?.throwIfAborted();
  const run = readRun(driver, runId), spec = decodeRunSpec(await readCanonicalArtifact(artifacts, run.specRef));
  const admission = driver.prepare(`SELECT principal_id,admission_method,admission_key,admission_intent_digest,admitted_request_digest,
    admission_request_id FROM runs WHERE id=?`).get<{ principal_id: string; admission_method: string; admission_key: string;
      admission_intent_digest: string; admitted_request_digest: string; admission_request_id: string }>(runId);
  if (!admission || admission.admission_method !== 'run.apply' || spec.operation !== 'delivery' || !admission.admission_request_id)
    invalid('delivery has no original admission identity');
  const original = readControlRequest(driver, admission.principal_id, 'run.apply', admission.admission_request_id);
  if (!original || original.committedAt !== run.createdAt) invalid('delivery has no original committed response');
  const core = await readCanonicalArtifact<Record<string, unknown>>(artifacts, original.requestDigest);
  const normalized = normalizeRunApplyRequest({ ...core, requestDigest: original.requestDigest }), request = normalized.request;
  const intent = runApplyIntentDigest(admission.principal_id, request);
  if (request.requestId !== admission.admission_request_id || request.admissionKey !== admission.admission_key ||
      intent !== admission.admission_intent_digest || run.id !== identityHash('cliq-run-id-v1', admission.principal_id, 'run.apply', request.admissionKey))
    invalid('delivery original request no longer reproduces its Run identity');
  if (request.sourceRunId === run.id) invalid('delivery cannot select its own result as an original source');
  if (request.verifierExecutionGrantIds.length)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'retained delivery verifier template admission is not implemented');
  const channel = await readHistoricalControlChannel(driver, artifacts, { principalId: admission.principal_id,
    channelIdentityRef: original.channelIdentityRef, channelIdentityDigest: original.channelIdentityDigest });
  if (channel.channel.openedAt > run.createdAt) invalid('delivery admission precedes its original channel');
  const inspection = readSourceInspectionAttempt(driver, key(admission.principal_id, request));
  assertApplyCapture(inspection);
  const retainedTarget = await readSourceInspectionTargetData(artifacts, inspection, readSourceInspectionOriginalRequest(driver, inspection.inspectionId));
  const target = retainedTarget.target;
  if (retainedTarget.original.method !== 'run.apply' || runApplyIntentDigest(admission.principal_id, retainedTarget.original) !== intent)
    invalid('delivery target original request differs from its admitted intent');
  const originalSourceRun = readRun(driver, request.sourceRunId);
  if (originalSourceRun.updatedAt > inspection.createdAt || inspection.retiredAt > run.createdAt)
    invalid('delivery capture precedes its verified source or follows its own admission');
  const source = await readRetainedVerifiedDeliverySource(driver, artifacts, { principalId: admission.principal_id,
    sourceRunId: request.sourceRunId, expectedRunResultRef: request.expectedRunResultRef, signal });
  inherited(spec, source.spec);
  if (run.id === source.run.id || source.run.updatedAt > inspection.createdAt || inspection.retiredAt > run.createdAt ||
      run.sessionId !== source.run.sessionId || target.workspaceIdentityRef !== source.session.workspaceIdentityRef ||
      spec.baseWorkspaceManifestRef !== inspection.outcome.sourceManifestRef || target.sessionId !== run.sessionId ||
      spec.budgets.wallTimeMs !== request.budgets.wallTimeMs || spec.budgets.toolCalls !== request.budgets.toolCalls ||
      run.deadlineAt !== addCanonicalDuration(run.createdAt, request.budgets.wallTimeMs)) invalid('delivery changed its inherited source or original budget');
  const bundle = await readCanonicalArtifact<import('../../policy/runtime-authority.js').RuntimeBundleManifest>(artifacts, source.assembly.runtime.runtimeBundleRef);
  // Signature roots are already verified by the full source recovery reader;
  // retained target closure is revalidated by capture/replay composition.
  const profile = decodeSandboxProfile(await readCanonicalArtifact(artifacts, spec.sandboxProfileRef));
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, target.workspaceIdentityRef));
  if (target.runtimeBundleRef !== canonicalSha256(bundle) || target.runtimeBundleManifestDigest !== bundle.manifestDigest ||
      target.sandboxProfileRef !== spec.sandboxProfileRef || target.sandboxProfileDigest !== profile.profileDigest ||
      !profile.allowedOwners.includes('source_inspection') || workspace.kind !== 'live' ||
      workspace.ownerPrincipalId !== admission.principal_id || workspace.identityDigest !== target.workspaceIdentityDigest)
    invalid('delivery target changed its original runtime/profile/workspace');
  await readSourceInspectionRetirement(driver, artifacts, inspection, target);
  await readDeliveryCaptureTopology(artifacts, inspection, target);
  const checkpoint = readCheckpoint(driver, identityHash('cliq-checkpoint-id-v1', runId, 'initial', 0));
  const workspaceState = decodeWorkspaceState(await readCanonicalArtifact(artifacts, checkpoint.workspaceStateRef));
  const context = decodeAdmittedContext(await readCanonicalArtifact(artifacts, spec.admittedContextRef));
  const sessionProjection = decodeSessionProjection(await readCanonicalArtifact(artifacts, context.sessionProjectionRef));
  const contextManifest = decodeContextManifest(await readCanonicalArtifact(artifacts, checkpoint.contextManifestRef));
  if (checkpoint.runId !== runId || checkpoint.reason !== 'initial' || checkpoint.basedOnRunRevision !== 0 || checkpoint.runItemSeq !== 0 ||
      checkpoint.journalSeq !== 0 || checkpoint.createdAt !== run.createdAt || workspaceState.runId !== runId ||
      workspaceState.baseWorkspaceManifestRef !== spec.baseWorkspaceManifestRef || context.sessionId !== run.sessionId ||
      context.sessionContextRevision !== target.expectedContextRevision || context.parentContextRefs.length || context.additionalArtifactRefs.length ||
      sessionProjection.sessionId !== run.sessionId || sessionProjection.contextRevision !== context.sessionContextRevision ||
      sessionProjection.throughItemSeq !== context.throughSessionItemSeq || contextManifest.runId !== runId || contextManifest.throughItemSeq !== 0 ||
      contextManifest.admittedContextRef !== spec.admittedContextRef || contextManifest.assemblyRef !== spec.assemblyRef || contextManifest.segments.length)
    invalid('delivery initial recovery image/context differs from its committed snapshot');
  const recovered = await readCandidateSource(artifacts, spec, checkpoint.workspaceStateRef, signal);
  if (inspection.outcome.kind !== 'captured' || recovered.diff.operations.length || workspaceState.invalidatedEphemeralPaths.length ||
      workspaceState.privateGitStateRef !== inspection.outcome.privateGitStateRef)
    invalid('delivery W_A is not its exact complete captured source');
  const digest = admittedDigest({ intent, sourceRunId: source.run.id, sourceRunResultRef: request.expectedRunResultRef, spec, specRef: run.specRef,
    workspaceIdentityRef: target.workspaceIdentityRef, workspaceIdentityDigest: target.workspaceIdentityDigest,
    workspaceStateRef: checkpoint.workspaceStateRef, capture: inspection });
  if (digest !== admission.admitted_request_digest) invalid('delivery resolved admission digest changed');
  const frontier: Extract<RunFrontier, { kind: 'delivery'; phase: 'merge' }> = { schemaVersion: 1, kind: 'delivery', phase: 'merge',
    sourceRunResultRef: request.expectedRunResultRef, capturedWorkspaceRef: spec.baseWorkspaceManifestRef };
  const expected: ApplyResponse = { protocolVersion: 1, ok: true, result: { method: 'run.apply', snapshot: { schemaVersion: 1,
    operation: 'delivery', run: initialRun(run, run.specRef, canonicalSha256(frontier), checkpoint.id), latestRunItemSeq: 0 } } };
  if (!same(await readCanonicalArtifact(artifacts, original.responseRef), expected)) invalid('delivery original response changed');
  signal?.throwIfAborted();
  if (!same(readRun(driver, runId), run) || !same(readRun(driver, source.run.id), source.run) ||
      readSessionPrincipalId(driver, run.sessionId) !== admission.principal_id || readSession(driver, run.sessionId).workspaceIdentityRef !== target.workspaceIdentityRef)
    invalid('delivery Run or original source/Session changed during retained admission validation');
  return immutableSnapshot({ run, spec, source, request, original, inspection, target, initialCheckpoint: checkpoint, workspaceState, admittedRequestDigest: digest });
});

/** Lookup precedes any Session/source/capture read. A fresh request may bind
 * only the original immutable response, never recapture or refresh authority. */
export async function replayInstalledDeliveryAdmission(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  supplied: Normalized, identity: AuthenticatedControlIdentity, signal?: AbortSignal): Promise<AdmitDeliveryResult | undefined> {
  const normalized = normalizeRunApplyRequest(supplied.originalRequest), request = normalized.request;
  signal?.throwIfAborted(); assertCurrentControlFrame(owner, identity);
  const channel = await validateControlChannelClosure(artifacts, owner, identity); assertActiveStateOwner(driver, owner);
  const control = readControlRequest(driver, identity.principalId, 'run.apply', request.requestId);
  if (control && control.requestDigest !== normalized.originalRequestDigest)
    throw new KernelStorageError('REQUEST_ID_CONFLICT', 'run.apply request id belongs to different original bytes');
  const admission = readAdmissionReplay(driver, 'runs', identity.principalId, 'run.apply', request.admissionKey);
  if (!admission) return undefined;
  const intent = runApplyIntentDigest(identity.principalId, request);
  if (admission.admissionIntentDigest !== intent) throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'run.apply key belongs to another intent');
  if (!admission.admissionRequestId) invalid('delivery admission has no original request');
  const original = readControlRequest(driver, identity.principalId, 'run.apply', admission.admissionRequestId);
  if (!original || control && control.responseRef !== original.responseRef) invalid('delivery replay substitutes its original response');
  await readDeliveryRunAdmission(driver, artifacts, admission.id, { signal });
  const response = decodeInstalledControlEnvelope(await readCanonicalArtifact(artifacts, original.responseRef), 'run.apply');
  if (!response.ok || response.result.method !== 'run.apply') invalid('delivery replay has no admitted snapshot');
  if (!control) driver.transaction(connection => {
    signal?.throwIfAborted(); assertCurrentControlFrame(owner, identity); assertActiveStateOwner(connection, owner);
    if (!same(readAdmissionReplay(connection, 'runs', identity.principalId, 'run.apply', request.admissionKey), admission) ||
        !same(readControlRequest(connection, identity.principalId, 'run.apply', admission.admissionRequestId!), original))
      invalid('delivery replay identity changed before binding');
    const raced = readControlRequest(connection, identity.principalId, 'run.apply', request.requestId);
    if (raced) {
      if (raced.requestDigest !== normalized.originalRequestDigest || raced.responseRef !== original.responseRef)
        throw new KernelStorageError('REQUEST_ID_CONFLICT', 'delivery replay raced different bytes');
      return;
    }
    const now = sampleCanonicalNow();
    if (advanceTimeFence(connection, owner.ownerEpoch, now) !== 'healthy')
      throw new KernelStorageError('INVALID_REQUEST', 'canonical time is regressed; delivery replay is paused');
    for (const entry of channel.metadata) insertArtifactMetadata(connection, entry, now);
    insertControlRequest(connection, { principalId: identity.principalId, method: 'run.apply', requestId: request.requestId,
      requestDigest: normalized.originalRequestDigest, channelIdentityRef: identity.channelIdentityRef,
      channelIdentityDigest: identity.channelIdentityDigest, responseRef: original.responseRef, committedAt: now });
  });
  return { replayed: true, run: response.result.snapshot.run, response };
}
