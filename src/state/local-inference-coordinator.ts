import { setTimeout as sleep } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import { decodeInstalledControlEnvelope, type InstalledControlResponseFor } from '../kernel/control-wire.js';
import { addCanonicalDuration, digestOmitting, parseCanonicalTime } from '../kernel/identity.js';
import { decodeLocalInferenceFailure, decodeLocalModelRegistration, localInferenceCycleId, localInferenceLaunchId, LOCAL_INFERENCE_PARTICIPANTS,
  LOCAL_INFERENCE_RETRY_MS, localInferenceFailureSources, type LocalInferenceActivationCycleV1, type LocalInferenceActivationFailureV1,
  type LocalInferenceActivationParticipantV1, type LocalInferenceServiceLaunchV1, type LocalModelRegistrationV1 } from '../kernel/local-inference.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import { insertArtifactMetadata, type ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { assertCurrentControlFrame, readHistoricalControlChannel, validateControlChannelClosure,
  type AuthenticatedControlIdentity, type LocalInferenceAdmissionFrame } from './control-channel.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import type { AssembledInstalledRun } from './installed-run.js';
import { InstalledRunCapacityError } from './installed-run-capacity.js';
import { readLocalInferenceFailureClosure } from './local-inference-frontier.js';
import { withHeldInstalledRuntime, type HeldCredentialAuthorityLock, type HeldInstalledRuntime } from './installed-runtime.js';
import { appendLocalInferenceParticipant, commitLocalInferenceCut, findLocalInferenceSubmission, localCycleData,
  readLocalInferenceCurrent, readLocalInferenceCycle, readLocalInferenceLaunch, readUnclosedLocalInference } from './local-inference-rows.js';
import type { InstalledLocalInferenceServices, LocalInferenceAttemptResult } from './local-inference-service.js';
import { withExistingLocalModelRegistry, type LocalModelRegistry } from './local-model-registry.js';
import type { AdmitRunResult, PreparedLocalRunAdmission } from './reducers/admission.js';
import { insertControlRequest, readAdmissionReplay, readControlRequest, readRun, readSession, readSessionPrincipalId } from './rows.js';
import type { normalizeRunSubmitRequest } from './source-target.js';
import { runSubmitIntentDigest } from './source-target.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type Cycle = LocalInferenceActivationCycleV1;
type StartingCycle = Extract<Cycle, { phase: 'starting_launch' }>;
type Launch = LocalInferenceServiceLaunchV1;
type Registration = Extract<LocalModelRegistrationV1, { state: 'active' }>;
type Submission = Extract<LocalInferenceActivationParticipantV1, { kind: 'run_submission' }>;
type Frontier = Extract<LocalInferenceActivationParticipantV1, { kind: 'run_model_frontier' }>;
type Normalized = ReturnType<typeof normalizeRunSubmitRequest>;
type SubmitRefusal = Extract<InstalledControlResponseFor<'run.submit'>, { ok: false }>;
type LiveSubmission = Readonly<{ identity: AuthenticatedControlIdentity; frame: LocalInferenceAdmissionFrame;
  replay(): Promise<AdmitRunResult | undefined>;
  prepare(registration: Registration): Promise<Readonly<{ assembled: AssembledInstalledRun; cut: PreparedLocalRunAdmission;
    assertCredentials?: (token: HeldCredentialAuthorityLock) => void }>> }>;
type Success = Readonly<{ result: AdmitRunResult; responseRef: string }>;
type FinishedSubmission = Readonly<{ participant: Submission;
  prepared?: Awaited<ReturnType<LiveSubmission['prepare']>>; refusal?: PublishedArtifact }>;
type FrontierFinalizer = (connection: SqliteConnection, now: string) => void;
type PrepareFrontierFailure = (cycle: Cycle, participant: Frontier, failureDetailRef: string) => Promise<FrontierFinalizer>;

function mismatch(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }
const pending = (cycle: Cycle): cycle is Extract<Cycle, { phase: 'starting_launch' | 'retry_wait' }> =>
  cycle.phase === 'starting_launch' || cycle.phase === 'retry_wait';
const currentRegistration = (cycle: Cycle, registration: Registration) =>
  cycle.ownerPrincipalId === registration.ownerPrincipalId && cycle.serviceId === registration.serviceId &&
  cycle.serviceSpecRef === registration.expectedServiceSpecRef && cycle.serviceSpecDigest === registration.serviceSpec.serviceSpecDigest &&
  cycle.localModelRegistrationRef === canonicalSha256(registration) && cycle.localModelRegistrationDigest === registration.registrationDigest;

function nextStarting(cycle: Extract<Cycle, { phase: 'retry_wait' }>): StartingCycle {
  const { retryNotBeforeAt: _retryAt, ...before } = cycle;
  const launchId = localInferenceLaunchId(cycle.activationCycleId, 2);
  const next = localCycleData({ ...before, phase: 'starting_launch', activationAttempt: 2,
    launchIds: [...cycle.launchIds, launchId], currentLaunchId: launchId, rowVersion: cycle.rowVersion + 1 });
  if (next.phase !== 'starting_launch') mismatch('local inference second attempt decoder differs');
  return next;
}

function refusal(code: 'ARTIFACT_MISMATCH' | 'UNSUPPORTED_PLATFORM' | 'NOT_FOUND' | 'ADMISSION_KEY_CONFLICT', messageCode: string): SubmitRefusal {
  return { protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1, code, retryable: false, messageCode } };
}
const originalFrameLost = refusal('ARTIFACT_MISMATCH', 'run.original_local_activation_frame_ended');
const originalModelChanged = refusal('NOT_FOUND', 'run.local_model_registration_changed');
const invalidAdmission: SubmitRefusal = { protocolVersion: 1, ok: false, method: 'run.submit',
  error: { schemaVersion: 1, code: 'INVALID_REQUEST', retryable: false, messageCode: 'control.invalid_request',
    issues: [{ path: 'request', issueCode: 'invalid_request' }] } };
const capacityRefusal: SubmitRefusal = { protocolVersion: 1, ok: false, method: 'run.submit',
  error: { schemaVersion: 1, code: 'RESOURCE_EXHAUSTED', retryable: true, messageCode: 'run.queue_capacity',
    resourceKind: 'run_queue', retryAfterMs: 1000 } };
const activationCapacityRefusal: SubmitRefusal = { protocolVersion: 1, ok: false, method: 'run.submit',
  error: { schemaVersion: 1, code: 'RESOURCE_EXHAUSTED', retryable: true, messageCode: 'run.local_inference_activation_capacity',
    resourceKind: 'local_inference_activation_cycle', retryAfterMs: 1000 } };
function admissionRefusal(error: unknown): SubmitRefusal | undefined {
  if (error instanceof InstalledRunCapacityError) return capacityRefusal;
  if (!(error instanceof KernelStorageError)) return undefined;
  if (error.code === 'INVALID_REQUEST') return invalidAdmission;
  if (error.code === 'ADMISSION_KEY_CONFLICT' || error.code === 'UNSUPPORTED_PLATFORM' || error.code === 'NOT_FOUND')
    return refusal(error.code, 'control.mutation_refused');
  return undefined;
}

/** The one original Store owns these actual activation promises and frame
 * pins. Durable participant identity, attempts, outcomes and Run writes are
 * exclusively the existing cycle, launch, Run and control-request rows. */
export class InstalledLocalInferenceCoordinator {
  private readonly tasks = new Map<string, Promise<void>>();
  private readonly frames = new Map<string, LiveSubmission>();
  private readonly stop = new AbortController();
  private retirementFailure?: ResourceRetirementError;
  private exclusiveSealed = false;
  private activationDraining = false;

  constructor(private readonly driver: SqliteDriver, private readonly artifacts: ArtifactCatalog,
    private readonly owner: StateOwnerContext, private readonly installed: HeldInstalledRuntime,
    readonly services: InstalledLocalInferenceServices, private readonly prepareFrontierFailure: PrepareFrontierFailure,
    private readonly admitted: (runId: string, assembled: AssembledInstalledRun) => void) {}

  private withRegistry<T>(operation: (registry: LocalModelRegistry | undefined) => Promise<T>, signal = this.stop.signal): Promise<T> {
    return withHeldInstalledRuntime(this.installed, installed => withExistingLocalModelRegistry(installed, operation, signal), signal);
  }

  private assertSession(connection: SqliteConnection, normalized: Normalized, principalId: string): void {
    const request = normalized.request, session = readSession(connection, request.sessionId);
    if (readSessionPrincipalId(connection, session.id) !== principalId || session.contextRevision !== request.expectedContextRevision)
      throw new KernelStorageError('INVALID_REQUEST', 'local inference participant has a stale original Session cut');
  }

  /** Retained request replay is read-only. A current frame never replaces
   * the origin of an already joined request or creates another cycle. */
  async replay(normalized: Normalized, identity: AuthenticatedControlIdentity): Promise<SubmitRefusal | undefined> {
    const cycle = findLocalInferenceSubmission(this.driver, identity.principalId, normalized.request.requestId, normalized.originalRequestDigest);
    if (!cycle) return undefined;
    if (pending(cycle)) await (this.tasks.get(cycle.activationCycleId) ?? this.schedule(cycle));
    const response = await this.readResponse(cycle.activationCycleId, normalized, identity);
    return response.ok ? undefined : response;
  }

  async submit(normalized: Normalized, live: LiveSubmission): Promise<AdmitRunResult | { response: SubmitRefusal }> {
    this.assertAccepting();
    const { request, originalRequest, originalRequestDigest } = normalized, { identity, frame } = live;
    if (request.model.provider !== 'ollama') throw new TypeError('local activation requires its exact Ollama request');
    const signal = this.stop.signal;
    const intent = runSubmitIntentDigest(identity.principalId, request);
    const model = request.model.model;
    const { requestDigest: _digest, ...core } = originalRequest as Record<string, unknown>;
    const selected = await this.withRegistry(async registry => {
      this.assertAccepting();
      assertCurrentControlFrame(this.owner, identity, frame);
      const original = findLocalInferenceSubmission(this.driver, identity.principalId, request.requestId, originalRequestDigest);
      if (original) return { cycle: original };
      const registration = (await registry?.select(model))?.active;
      if (!registry || !registration || registration.ownerPrincipalId !== identity.principalId)
        throw new KernelStorageError('NOT_FOUND', 'local model has no current original signed registration');
      const state = readLocalInferenceCurrent(this.driver, identity.principalId, registration.serviceId);
      if (state.latest?.phase === 'active' && state.launch?.phase === 'active' && currentRegistration(state.latest, registration))
        return { registration };
      if (state.latest && pending(state.latest) && state.latest.participants.length >= LOCAL_INFERENCE_PARTICIPANTS)
        return { response: activationCapacityRefusal };
      const [requestArtifact, channel] = await Promise.all([
        this.artifacts.publishCanonical(core, 'cliq-run-submit-request-core-v1'),
        validateControlChannelClosure(this.artifacts.withReadSignal(signal), this.owner, identity, frame)
      ]);
      if (requestArtifact.ref !== originalRequestDigest) mismatch('local inference original request changed during durable publication');
      const modelMetadata = state.latest && pending(state.latest) ? [] : await registry.retainForRun(registration, this.artifacts);
      const joinedAt = sampleCanonicalNow();
      const participant: Submission = { kind: 'run_submission', requestId: request.requestId, requestDigest: originalRequestDigest,
        runSubmitRequestRef: requestArtifact.ref, channelIdentityRef: identity.channelIdentityRef, channelIdentityDigest: identity.channelIdentityDigest,
        admissionKey: request.admissionKey, admissionIntentDigest: intent, joinedAt };
      const cycle = this.join(registration, participant, [requestArtifact, ...channel.metadata, ...modelMetadata], (connection) => {
        registry.assertHeld(); assertCurrentControlFrame(this.owner, identity, frame); this.assertSession(connection, normalized, identity.principalId);
        if (readControlRequest(connection, identity.principalId, 'run.submit', request.requestId))
          mismatch('local activation participant already has a response outside its cycle');
      });
      this.frames.set(this.frameKey(cycle.activationCycleId, request.requestId), live);
      return { cycle };
    });
    if (selected.response) return { response: selected.response };
    if (selected.registration) {
      const prepared = await live.prepare(selected.registration);
      const original = selected.registration;
      const outcome = await this.withRegistry(async registry => {
        const current = (await registry?.select(model))?.active;
        if (!registry || !current || canonicalSha256(current) !== canonicalSha256(original)) return { kind: 'model_changed' as const };
        const commit = async (credential?: HeldCredentialAuthorityLock) => {
          this.assertAccepting(); registry.assertHeld();
          if (readControlRequest(this.driver, identity.principalId, 'run.submit', request.requestId) ||
              readAdmissionReplay(this.driver, 'runs', identity.principalId, 'run.submit', request.admissionKey))
            return { kind: 'replay' as const };
          if (prepared.assertCredentials) {
            if (!credential) mismatch('local Run lost its original dependency credential scope');
            prepared.assertCredentials(credential);
          }
          let success: Success | undefined;
          commitLocalInferenceCut(this.driver, this.owner, { assert: (connection, now) => {
            this.assertAccepting(); registry.assertHeld(); credential?.assertHeld();
            success = prepared.cut.commit(connection, now);
          } });
          if (success) return { kind: 'admitted' as const, success };
          mismatch('warm local admission committed no original outcome');
        };
        return prepared.assertCredentials ? registry.withAdmissionCredentials(commit) : commit();
      });
      if (outcome.kind === 'model_changed') return { response: originalModelChanged };
      if (outcome.kind === 'replay') {
        const retained = await live.replay();
        if (!retained) mismatch('raced local admission has no original installed replay');
        return retained;
      }
      this.admitted(outcome.success.result.run.id, prepared.assembled);
      return outcome.success.result;
    }
    const cycle = selected.cycle;
    if (!cycle) mismatch('local activation selected no original cycle');
    if (pending(cycle)) await (this.tasks.get(cycle.activationCycleId) ?? this.schedule(cycle));
    const response = await this.readResponse(cycle.activationCycleId, normalized, identity, frame);
    if (!response.ok) return { response };
    return { replayed: false, run: readRun(this.driver, response.result.snapshot.run.id), response };
  }

  /** Called only after the original Store has quiesced the Run on its exact
   * frontier. Its frozen registration is independent of today's model head. */
  joinFrontier(registration: Registration, participant: Frontier, assert: (connection: SqliteConnection) => void): Promise<void> {
    const cycle = this.join(registration, participant, [], assert);
    return this.tasks.get(cycle.activationCycleId) ?? this.schedule(cycle);
  }

  private join(registration: Registration, participant: LocalInferenceActivationParticipantV1, metadata: readonly PublishedArtifact[],
    assert: (connection: SqliteConnection) => void): Cycle {
    this.assertAccepting();
    const current = readLocalInferenceCurrent(this.driver, registration.ownerPrincipalId, registration.serviceId);
    const original = current.latest && pending(current.latest) ? current.latest : undefined;
    let next: Cycle;
    if (original) {
      if (!currentRegistration(original, registration)) mismatch('local inference request differs from the current original activation');
      next = appendLocalInferenceParticipant(original, participant);
      if (next === original) return original;
    } else {
      if (current.launch) mismatch('local inference activation cannot overtake an unretired service');
      const base = { schemaVersion: 1, ownerPrincipalId: registration.ownerPrincipalId, serviceId: registration.serviceId,
        localModelRegistrationRef: canonicalSha256(registration), localModelRegistrationDigest: registration.registrationDigest,
        serviceSpecRef: registration.expectedServiceSpecRef, serviceSpecDigest: registration.serviceSpec.serviceSpecDigest,
        cycleOrdinal: (current.latest?.cycleOrdinal ?? 0) + 1, participants: [participant], rowVersion: 1, createdAt: participant.joinedAt };
      const activationCycleId = localInferenceCycleId(base), currentLaunchId = localInferenceLaunchId(activationCycleId, 1);
      next = localCycleData({ ...base, activationCycleId, phase: 'starting_launch', activationAttempt: 1,
        launchIds: [currentLaunchId], currentLaunchId });
    }
    commitLocalInferenceCut(this.driver, this.owner, { cycle: { ...(original ? { previous: original } : {}), next }, metadata, assert });
    return next;
  }

  private schedule(cycle: Cycle): Promise<void> {
    this.stop.signal.throwIfAborted();
    const task = this.drive(cycle.activationCycleId);
    this.tasks.set(cycle.activationCycleId, task);
    void task.then(() => undefined, error => {
      if (error instanceof ResourceRetirementError) this.retirementFailure ??= error;
    }).finally(() => {
      this.tasks.delete(cycle.activationCycleId);
      for (const participant of this.current(cycle.activationCycleId).participants)
        if (participant.kind === 'run_submission') this.frames.delete(this.frameKey(cycle.activationCycleId, participant.requestId));
    }).catch(() => {});
    return task;
  }

  private current(cycleId: string): Cycle {
    const cycle = readLocalInferenceCycle(this.driver, cycleId);
    if (!cycle) mismatch('local inference original cycle disappeared');
    return cycle;
  }

  private async readRegistration(cycle: Cycle): Promise<Registration> {
    const value = decodeLocalModelRegistration(await readCanonicalArtifact(this.artifacts.withReadSignal(this.stop.signal), cycle.localModelRegistrationRef));
    if (value.state !== 'active' || !currentRegistration(cycle, value)) mismatch('local inference cycle lost its original frozen registration');
    return value;
  }

  private async drive(cycleId: string): Promise<void> {
    const signal = this.stop.signal, registration = await this.readRegistration(this.current(cycleId));
    for (;;) {
      signal.throwIfAborted();
      let cycle = this.current(cycleId);
      if (!pending(cycle)) return;
      if (cycle.phase === 'retry_wait') {
        const remaining = parseCanonicalTime(cycle.retryNotBeforeAt) - Date.now();
        if (remaining > 0) { await sleep(remaining, undefined, { signal }); continue; }
        const next = nextStarting(cycle);
        commitLocalInferenceCut(this.driver, this.owner, { cycle: { previous: cycle, next } });
        cycle = next;
      }
      const old = readLocalInferenceLaunch(this.driver, cycle.currentLaunchId);
      let attempt: LocalInferenceAttemptResult | undefined;
      if (old?.phase === 'active' && this.services.ownsActive(registration, old.launchId))
        attempt = await this.finishOrRetireActive(cycleId, registration, old);
      else if (old && old.phase !== 'retired') {
        const retired = this.activationDraining ? await this.services.retireActivationForDrain(old.launchId) : undefined;
        attempt = retired ? { kind: 'failed', reason: 'activation_cancelled_for_migration', retired } :
          { kind: 'failed', reason: 'containment_unprovable' };
      } else if (old) attempt = { kind: 'failed', reason: this.activationDraining ? 'activation_cancelled_for_migration' : 'sandbox_launch_failed', retired: old };
      else attempt = await this.services.attempt({ cycle, registration });
      signal.throwIfAborted();
      if (attempt?.kind === 'active') attempt = await this.finishOrRetireActive(cycleId, registration, attempt.launch);
      if (!attempt) return;
      cycle = this.current(cycleId);
      if (cycle.phase !== 'starting_launch') mismatch('local inference lost its original failed attempt');
      if (cycle.activationAttempt === 1 && attempt.retired) {
        const { currentLaunchId: _launch, ...before } = cycle;
        const next = localCycleData({ ...before, phase: 'retry_wait',
          retryNotBeforeAt: addCanonicalDuration(attempt.retired.retiredAt, LOCAL_INFERENCE_RETRY_MS), rowVersion: cycle.rowVersion + 1 });
        commitLocalInferenceCut(this.driver, this.owner, { cycle: { previous: cycle, next } });
        continue;
      }
      await this.finishFailure(cycleId, attempt.reason);
      return;
    }
  }

  private async finishOrRetireActive(cycleId: string, registration: Registration, launch: Extract<Launch, { phase: 'active' }>):
    Promise<Extract<LocalInferenceAttemptResult, { kind: 'failed' }> | undefined> {
    if (!this.activationDraining && await this.finishActive(cycleId, registration, launch)) return undefined;
    const retired = await this.services.retireActivationForDrain(launch.launchId);
    return retired ? { kind: 'failed', reason: 'activation_cancelled_for_migration', retired } : { kind: 'failed', reason: 'containment_unprovable' };
  }

  private async readParticipant(cycle: Cycle, participant: Submission): Promise<void> {
    if (participant.runSubmitRequestRef !== participant.requestDigest) mismatch('original local participant request reference differs');
    const core = await readCanonicalArtifact<object>(this.artifacts, participant.runSubmitRequestRef);
    const { normalizeRunSubmitRequest } = await import('./source-target.js');
    const normalized = normalizeRunSubmitRequest({ ...core, requestDigest: participant.requestDigest });
    const request = normalized.request;
    const registration = await this.readRegistration(cycle);
    if (request.requestId !== participant.requestId || request.admissionKey !== participant.admissionKey ||
        runSubmitIntentDigest(cycle.ownerPrincipalId, request) !== participant.admissionIntentDigest ||
        request.model.provider !== 'ollama' || request.model.model !== registration.model)
      mismatch('local participant differs from the original complete Run request');
    await readHistoricalControlChannel(this.driver, this.artifacts, { principalId: cycle.ownerPrincipalId,
      channelIdentityRef: participant.channelIdentityRef, channelIdentityDigest: participant.channelIdentityDigest });
  }

  private frameKey(cycleId: string, requestId: string): string { return cycleId + '/' + requestId; }

  private async prepareSubmission(cycle: Cycle, participant: Submission, registration: Registration): Promise<FinishedSubmission> {
    await this.readParticipant(cycle, participant);
    const live = this.frames.get(this.frameKey(cycle.activationCycleId, participant.requestId));
    if (live) {
      let current = true;
      try { assertCurrentControlFrame(this.owner, live.identity, live.frame); }
      catch (error) {
        if (!(error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH')) throw error;
        current = false;
      }
      if (current) {
        try { return { participant, prepared: await live.prepare(registration) }; }
        catch (error) {
          const response = admissionRefusal(error);
          if (!response) throw error;
          return { participant, refusal: await this.publishResponse(response) };
        }
      }
    }
    return { participant, refusal: await this.publishResponse(originalFrameLost) };
  }

  private publishResponse(response: SubmitRefusal): Promise<PublishedArtifact> {
    return this.artifacts.publishCanonical(response, 'cliq-control-response-v1');
  }

  private writeResponse(connection: SqliteConnection, cycle: Cycle, participant: Submission, response: PublishedArtifact, now: string): void {
    if (readControlRequest(connection, cycle.ownerPrincipalId, 'run.submit', participant.requestId))
      mismatch('local inference participant response is already committed');
    insertArtifactMetadata(connection, response, now);
    insertControlRequest(connection, { principalId: cycle.ownerPrincipalId, method: 'run.submit', requestId: participant.requestId,
      requestDigest: participant.requestDigest, channelIdentityRef: participant.channelIdentityRef,
      channelIdentityDigest: participant.channelIdentityDigest, responseRef: response.ref, committedAt: now });
  }

  private async finishActive(cycleId: string, registration: Registration, launch: Extract<Launch, { phase: 'active' }>): Promise<boolean> {
    const [modelChanged, frameLost, invalid, capacity, conflict] = await Promise.all([
      this.publishResponse(originalModelChanged), this.publishResponse(originalFrameLost), this.publishResponse(invalidAdmission),
      this.publishResponse(capacityRefusal), this.publishResponse(refusal('ADMISSION_KEY_CONFLICT', 'control.mutation_refused'))
    ]);
    for (;;) {
      if (this.activationDraining) return false;
      const cycle = this.current(cycleId);
      if (cycle.phase !== 'starting_launch' || cycle.currentLaunchId !== launch.launchId) mismatch('active service differs from the original cycle');
      const prepared = new Map<string, FinishedSubmission>();
      for (const participant of cycle.participants) {
        if (this.activationDraining) return false;
        if (participant.kind === 'run_submission') {
          try { prepared.set(participant.requestId, await this.prepareSubmission(cycle, participant, registration)); }
          catch (error) {
            if (this.activationDraining && (error instanceof KernelStorageError && error.code === 'LEASE_FENCED' ||
                error instanceof DOMException && error.name === 'AbortError')) return false;
            throw error;
          }
        }
      }
      const committed = await this.withRegistry(async registry => {
        if (this.activationDraining) return false;
        const current = (await registry?.select(registration.model))?.active;
        if (this.current(cycleId).cycleDigest !== cycle.cycleDigest) return false;
        const originalModel = registry && current && canonicalSha256(current) === canonicalSha256(registration);
        const credentialChecks = [...prepared.values()].flatMap(item => item.prepared?.assertCredentials ? [item.prepared.assertCredentials] : []);
        const commit = async (credential?: HeldCredentialAuthorityLock) => {
          if (this.activationDraining || this.current(cycleId).cycleDigest !== cycle.cycleDigest) return false;
          if (originalModel && credentialChecks.length) {
            if (!credential) mismatch('local activation lost its original dependency credential scope');
            for (const check of credentialChecks) check(credential);
          }
          const next = localCycleData({ ...cycle, phase: 'active', finishedAt: sampleCanonicalNow(),
            boundaryEvidenceRef: launch.boundaryEvidenceRef, rowVersion: cycle.rowVersion + 1 });
          const admitted = new Map<string, Success>();
          const material = new Map<string, AssembledInstalledRun>();
          commitLocalInferenceCut(this.driver, this.owner, { cycle: { previous: cycle, next }, finalizeParticipants: (connection, now) => {
            for (const participant of cycle.participants) {
              if (participant.kind !== 'run_submission') continue;
              const item = prepared.get(participant.requestId);
              if (!item) mismatch('active cycle omitted an original submission participant');
              if (item.refusal) { this.writeResponse(connection, cycle, participant, item.refusal, now); continue; }
              if (!registry || !originalModel) { this.writeResponse(connection, cycle, participant, modelChanged, now); continue; }
              const live = this.frames.get(this.frameKey(cycleId, participant.requestId));
              if (!item.prepared || !live) mismatch('active cycle lost its owned admission preparation');
              try { assertCurrentControlFrame(this.owner, live.identity, live.frame); }
              catch (error) {
                if (!(error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH')) throw error;
                this.writeResponse(connection, cycle, participant, frameLost, now); continue;
              }
              try { registry.assertHeld(); credential?.assertHeld(); item.prepared.cut.assertCurrent(connection, now); }
              catch (error) {
                const response = admissionRefusal(error);
                if (!response) throw error;
                const value = response.error.code === 'RESOURCE_EXHAUSTED' ? capacity :
                  response.error.code === 'ADMISSION_KEY_CONFLICT' ? conflict : invalid;
                this.writeResponse(connection, cycle, participant, value, now); continue;
              }
              const result = item.prepared.cut.commit(connection, now, admitted.get(participant.admissionKey));
              admitted.set(participant.admissionKey, result);
              if (!result.result.replayed) material.set(result.result.run.id, item.prepared.assembled);
            }
          } });
          for (const [runId, assembled] of material) this.admitted(runId, assembled);
          return true;
        };
        return registry && originalModel && credentialChecks.length ? registry.withAdmissionCredentials(commit) : commit();
      });
      if (committed) return true;
    }
  }

  private async finishFailure(cycleId: string, reason: LocalInferenceActivationFailureV1['reason']): Promise<void> {
    for (;;) {
      const cycle = this.current(cycleId);
      if (cycle.phase !== 'starting_launch') mismatch('terminal local inference failure lacks its exact original attempt');
      const launch = readLocalInferenceLaunch(this.driver, cycle.currentLaunchId);
      if (!launch) mismatch('terminal local inference failure lacks a real original launch reservation');
      const launches = cycle.launchIds.map(id => {
        const attempt = readLocalInferenceLaunch(this.driver, id);
        if (!attempt) mismatch('local inference failure lost an original launch');
        return attempt;
      });
      const evidenceRefs = launches.map(attempt => attempt.phase === 'retired' ? attempt.retirementEvidenceRef : attempt.nativeInputRef);
      const failure = { schemaVersion: 1, activationCycleId: cycleId, ownerPrincipalId: cycle.ownerPrincipalId,
        serviceId: cycle.serviceId, serviceSpecRef: cycle.serviceSpecRef, serviceSpecDigest: cycle.serviceSpecDigest,
        finalAttempt: cycle.activationAttempt, reason, launchIds: cycle.launchIds, evidenceRefs,
        observedAt: sampleCanonicalNow(), failureDigest: '' };
      const data = decodeLocalInferenceFailure({ ...failure, failureDigest: digestOmitting(failure, 'failureDigest') });
      localInferenceFailureSources(cycle, data, launches);
      const detail = await this.artifacts.publishCanonical(data, 'cliq-local-inference-activation-failure-v1');
      const response = await this.publishResponse({ protocolVersion: 1, ok: false, method: 'run.submit', error: { schemaVersion: 1,
        code: 'RECOVERY_REQUIRED', retryable: false, recoveryKind: 'local_inference_service',
        messageCode: 'run.local_inference_unavailable', detailRef: detail.ref } });
      const frontiers: FrontierFinalizer[] = [];
      for (const participant of cycle.participants) {
        if (participant.kind === 'run_submission') await this.readParticipant(cycle, participant);
        else frontiers.push(await this.prepareFrontierFailure(cycle, participant, detail.ref));
      }
      if (this.current(cycleId).cycleDigest !== cycle.cycleDigest) continue;
      const { currentLaunchId: _current, ...before } = cycle;
      const next = localCycleData({ ...before, phase: 'failed', finishedAt: sampleCanonicalNow(),
        failureDetailRef: detail.ref, rowVersion: cycle.rowVersion + 1 });
      commitLocalInferenceCut(this.driver, this.owner, { cycle: { previous: cycle, next }, metadata: [detail],
        finalizeParticipants: (connection, now) => {
          for (const participant of cycle.participants)
            if (participant.kind === 'run_submission') this.writeResponse(connection, cycle, participant, response, now);
          for (const commit of frontiers) commit(connection, now);
        } });
      return;
    }
  }

  private async readResponse(cycleId: string, normalized: Normalized, identity: AuthenticatedControlIdentity,
    frame?: LocalInferenceAdmissionFrame): Promise<InstalledControlResponseFor<'run.submit'>> {
    const cycle = this.current(cycleId), participant = cycle.participants.find((value): value is Submission =>
      value.kind === 'run_submission' && value.requestId === normalized.request.requestId);
    if (pending(cycle) || !participant || cycle.ownerPrincipalId !== identity.principalId || participant.requestDigest !== normalized.originalRequestDigest)
      mismatch('local inference participant has no exact terminal response');
    const row = readControlRequest(this.driver, cycle.ownerPrincipalId, 'run.submit', participant.requestId);
    if (!row || row.requestDigest !== participant.requestDigest || row.channelIdentityRef !== participant.channelIdentityRef ||
        row.channelIdentityDigest !== participant.channelIdentityDigest) mismatch('terminal local inference response lost its original request or channel');
    await this.readParticipant(cycle, participant);
    const response = decodeInstalledControlEnvelope(await readCanonicalArtifact(this.artifacts, row.responseRef), 'run.submit');
    if (cycle.phase === 'failed') {
      if (response.ok || response.error.code !== 'RECOVERY_REQUIRED' || response.error.detailRef !== cycle.failureDetailRef)
        mismatch('failed local inference response differs from its original cycle evidence');
      await readLocalInferenceFailureClosure(this.driver, this.artifacts, cycle, cycle.failureDetailRef);
    }
    assertActiveStateOwner(this.driver, this.owner);
    assertCurrentControlFrame(this.owner, identity, frame);
    requireEqual(readControlRequest(this.driver, cycle.ownerPrincipalId, 'run.submit', participant.requestId), row, 'original local inference response');
    return response;
  }

  async start(): Promise<void> {
    const open = readUnclosedLocalInference(this.driver);
    for (const launch of open.launches) {
      const cycle = this.current(launch.activationCycleId);
      await this.services.recover(launch, cycle);
    }
    for (const cycle of open.cycles) this.schedule(this.current(cycle.activationCycleId));
  }

  private assertAccepting(): void {
    this.stop.signal.throwIfAborted();
    if (this.exclusiveSealed) throw new KernelStorageError('LEASE_FENCED', 'local inference is fenced for installed exclusion');
  }

  /** Fence new participants without cancelling an already accepted cycle.
   * EX entry independently checks its original durable cycle inventory. */
  sealForExclusive(): void { this.assertAccepting(); this.exclusiveSealed = true; }
  restoreAfterExclusiveRefusal(): void {
    this.stop.signal.throwIfAborted();
    if (this.activationDraining) throw new TypeError('local activation drain must fully retire before ordinary work can resume');
    this.exclusiveSealed = false;
  }

  async drainForExclusive(): Promise<void> {
    if (!this.exclusiveSealed || this.activationDraining) throw new TypeError('local activation drain requires its original exclusive fence');
    const original = readUnclosedLocalInference(this.driver);
    if (!original.cycles.length) return;
    this.activationDraining = true; this.services.beginActivationDrain();
    const results = await Promise.allSettled(original.cycles.map(cycle =>
      this.tasks.get(cycle.activationCycleId) ?? this.schedule(cycle)));
    const failed = results.find(result => result.status === 'rejected');
    const current = readUnclosedLocalInference(this.driver);
    if (failed?.status === 'rejected' || current.cycles.length ||
        current.launches.some(launch => original.cycles.some(cycle => launch.activationCycleId === cycle.activationCycleId)))
      throw new ResourceRetirementError('installed exclusion cannot prove every original local activation retired',
        failed?.status === 'rejected' ? failed.reason : undefined);
  }

  beginClose(): void { this.stop.abort(); this.services.beginClose(); }
  async close(): Promise<void> {
    this.beginClose();
    const results = await Promise.allSettled([...this.tasks.values(), this.services.close()]);
    for (const result of results)
      if (result.status === 'rejected' && result.reason instanceof ResourceRetirementError) this.retirementFailure ??= result.reason;
    if (this.retirementFailure) throw this.retirementFailure;
  }
}
