import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { ProcessContainmentDeathEvidenceV1, ProcessContainmentNoSpawnEvidenceV1 } from '../kernel/execution.js';
import { addCanonicalDuration, digestOmitting, encodeCanonicalTime, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeLocalModelRegistration } from '../kernel/local-inference.js';
import type { LocalInferenceNativeObservation } from '../kernel/local-inference-native-input.js';
import { decodeLocalInferenceLaunch, type LocalInferenceActivationCycleV1, type LocalInferenceActivationFailureV1,
  type LocalInferenceServiceLaunchV1, type LocalModelRegistrationV1 } from '../kernel/local-inference.js';
import { cleanupInstalledRetainedLocalInference, InstalledLocalInferenceBusyError, openInstalledLocalInferenceController,
  type InstalledLocalInferenceController } from '../sandbox/linux-worker.js';
import { requireEqual, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';
import { retainInstalledLocalInferenceRuntime, type HeldInstalledAnchor, type HeldInstalledRuntime } from './installed-runtime.js';
import { observeLocalInferenceBoundary, observeLocalInferenceContainment, originalLocalContainment, probeLocalInferenceHealth, publishLocalInferenceLaunch,
  readRetainedLocalInferenceLaunch } from './local-inference-launch.js';
import { commitLocalInferenceCut, readLocalInferenceCurrent, readLocalInferenceCycle, readLocalInferenceLaunch } from './local-inference-rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { supervisorInspectorIdentity } from './supervisor-inspector.js';

type Cycle = LocalInferenceActivationCycleV1;
type StartingCycle = Extract<Cycle, { phase: 'starting_launch' }>;
type Launch = LocalInferenceServiceLaunchV1;
type ActiveLaunch = Extract<Launch, { phase: 'active' }>;
type RetiredLaunch = Extract<Launch, { phase: 'retired' }>;
type LaunchRecipe = Awaited<ReturnType<typeof publishLocalInferenceLaunch>>;
type Containment = ReturnType<typeof originalLocalContainment>;
type Boundary = Awaited<ReturnType<typeof observeLocalInferenceBoundary>>;
type Reason = LocalInferenceActivationFailureV1['reason'];
export type InstalledLocalInferenceObservation = Readonly<{
  boundary: Boundary; controller: InstalledLocalInferenceController; assertCurrent(connection?: SqliteConnection): void;
}>;
const liveObservations = new WeakMap<InstalledLocalInferenceObservation, {
  driver: SqliteDriver; owner: StateOwnerContext; registration: LocalModelRegistrationV1; launch: ActiveLaunch;
}>();
export function readInstalledLocalInferenceObservation(observation: InstalledLocalInferenceObservation, driver: SqliteDriver,
  owner: StateOwnerContext): Readonly<{ registration: LocalModelRegistrationV1; launch: ActiveLaunch }> {
  const held = liveObservations.get(observation);
  if (!held || held.driver !== driver || held.owner !== owner)
    mismatch('local inference observation has no original installed StateOwner and service');
  observation.assertCurrent();
  return { registration: held.registration, launch: held.launch };
}

type OwnedService = {
  controller: InstalledLocalInferenceController;
  registration: LocalModelRegistrationV1;
  recipe?: LaunchRecipe;
  containment?: Containment;
  stopping?: Promise<RetiredLaunch | undefined>;
  active?: ActiveLaunch;
  activationAbort?: AbortController;
  reservationReady?: true;
  modelProducer?: object;
};
type AttemptInput = Readonly<{
  cycle: StartingCycle; registration: LocalModelRegistrationV1;
}>;
export type LocalInferenceAttemptResult =
  | Readonly<{ kind: 'active'; launch: ActiveLaunch; boundary: Boundary }>
  | Readonly<{ kind: 'failed'; reason: Reason; retired?: RetiredLaunch }>;

function mismatch(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

/** Owns actual installed service attempts for one original Store. Cycles and
 * launches stay in the same SQLite authority and native ownership lasts until
 * the real close and exact retirement transaction have both completed. */
export class InstalledLocalInferenceServices {
  private readonly owners = new Map<string, OwnedService>();
  private readonly tasks = new Map<string, Promise<LocalInferenceAttemptResult>>();
  private readonly stopSignal = new AbortController();
  private closing?: Promise<void>;
  private retirementFailure?: ResourceRetirementError;
  private activationDraining = false;

  constructor(private readonly driver: SqliteDriver, private readonly artifacts: ArtifactCatalog,
    private readonly owner: StateOwnerContext, private readonly selected: HeldInstalledRuntime,
    private readonly anchor: HeldInstalledAnchor) {}

  attempt(input: AttemptInput): Promise<LocalInferenceAttemptResult> {
    if (this.stopSignal.signal.aborted) return Promise.reject(new KernelStorageError('RECOVERY_REQUIRED', 'local inference producer is closing'));
    if (this.tasks.has(input.cycle.currentLaunchId) || this.owners.has(input.cycle.currentLaunchId))
      return Promise.reject(new KernelStorageError('RECOVERY_REQUIRED', 'original local inference attempt already has a physical owner'));
    const pending = this.produce(input);
    this.tasks.set(input.cycle.currentLaunchId, pending);
    void pending.then(() => undefined, error => {
      if (error instanceof ResourceRetirementError) this.retirementFailure ??= error;
    }).finally(() => this.tasks.delete(input.cycle.currentLaunchId));
    return pending;
  }

  private async produce(input: AttemptInput): Promise<LocalInferenceAttemptResult> {
    const { cycle, registration } = input, activationAbort = new AbortController();
    const signal = AbortSignal.any([this.stopSignal.signal, activationAbort.signal]);
    const lock = this.owner.filesystem;
    const owner = assertActiveStateOwner(this.driver, this.owner);
    const runtime = await retainInstalledLocalInferenceRuntime(this.selected, registration.serviceSpec.runtimeBundleRef, signal);
    const controller = await openInstalledLocalInferenceController(this.selected, this.anchor, lock, signal);
    const scope: OwnedService = { controller, registration, activationAbort };
    this.owners.set(cycle.currentLaunchId, scope);
    let reserved = false, stage: Reason = 'sandbox_launch_failed';
    try {
      const recipe = await publishLocalInferenceLaunch(this.artifacts, { registration, bundle: this.selected.bundle, cycle,
        attempt: cycle.activationAttempt, supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch,
        createdAt: sampleCanonicalNow(), nativeNonce: randomBytes(32).toString('hex'), activationNonce: randomBytes(32).toString('hex'), controller, lock });
      scope.recipe = recipe; signal.throwIfAborted();
      commitLocalInferenceCut(this.driver, this.owner, { launch: { next: recipe.launch }, metadata: [...runtime, ...recipe.metadata],
        assert(connection) {
          const current = readLocalInferenceCycle(connection, cycle.activationCycleId);
          if (!current || current.phase !== 'starting_launch' || current.currentLaunchId !== cycle.currentLaunchId ||
              current.activationAttempt !== cycle.activationAttempt || current.localModelRegistrationRef !== cycle.localModelRegistrationRef ||
              current.localModelRegistrationDigest !== cycle.localModelRegistrationDigest)
            mismatch('original local inference attempt was fenced before native reservation');
        } });
      reserved = true;
      await controller.reserve(recipe.launch.nativeInputRef);
      scope.reservationReady = true;
      if (this.activationDraining) {
        const retired = await this.stop(cycle.currentLaunchId);
        return retired ? { kind: 'failed', reason: 'activation_cancelled_for_migration', retired }
          : { kind: 'failed', reason: 'containment_unprovable' };
      }
      await controller.prepare();
      const observed = await controller.createBlocked();
      const containment = originalLocalContainment(recipe, observed);
      scope.containment = containment;
      const containmentArtifact = await this.artifacts.publishCanonical(containment, 'cliq-process-containment-v1');
      const blocked = decodeLocalInferenceLaunch({ ...recipe.launch, phase: 'preactivated', rowVersion: recipe.launch.rowVersion + 1,
        processContainmentRef: containmentArtifact.ref });
      commitLocalInferenceCut(this.driver, this.owner, { launch: { previous: recipe.launch, next: blocked }, metadata: [containmentArtifact] });
      await controller.releaseEngine();
      stage = 'health_mismatch';
      await probeLocalInferenceHealth(this.selected, controller, registration, recipe.runtimeProfile.engineVersion, blocked.activationDeadlineAt, signal);
      stage = 'sandbox_launch_failed';
      const boundary = await observeLocalInferenceBoundary(this.artifacts, controller, registration, blocked, containment,
        assertActiveStateOwner(this.driver, this.owner));
      const active = decodeLocalInferenceLaunch({ ...blocked, phase: 'active', rowVersion: blocked.rowVersion + 1, leaseVersion: 1,
        leaseExpiresAt: boundary.boundary.validThrough, boundaryEvidenceRef: boundary.boundaryRef });
      if (active.phase !== 'active') mismatch('local inference active row decoder differs');
      commitLocalInferenceCut(this.driver, this.owner, { launch: { previous: blocked, next: active }, metadata: boundary.metadata,
        assert(_connection, now) {
          signal.throwIfAborted();
          if (boundary.boundary.observedAt > now || now >= boundary.boundary.validThrough) mismatch('local inference activation boundary expired before commit');
        } });
      await controller.publishActive();
      scope.active = active;
      scope.activationAbort = undefined;
      return { kind: 'active', launch: active, boundary };
    } catch (error) {
      if (!reserved) {
        try { await controller.close(); }
        catch (close) { throw new ResourceRetirementError('unreserved original local inference controller did not retire', new AggregateError([error, close])); }
        this.owners.delete(cycle.currentLaunchId);
        throw error;
      }
      const launch = scope.recipe?.launch;
      const reason = this.activationDraining ? 'activation_cancelled_for_migration' :
        launch && sampleCanonicalNow() >= launch.activationDeadlineAt ? 'activation_timeout' : stage;
      try {
        const retired = await this.stop(cycle.currentLaunchId);
        return retired ? { kind: 'failed', reason, retired } : { kind: 'failed', reason: 'containment_unprovable' };
      } catch (retirement) {
        this.retirementFailure ??= retirement instanceof ResourceRetirementError ? retirement :
          new ResourceRetirementError('original local inference retirement could not commit', retirement);
        return { kind: 'failed', reason: 'containment_unprovable' };
      }
    }
  }

  /** Migration allows the original reservation to finish, then revokes any
   * preparer or engine through its existing actual cancel-and-join path.
   * A later mandatory attempt reserves only to prove no spawn. */
  beginActivationDrain(): void {
    this.activationDraining = true;
    for (const scope of this.owners.values())
      if (scope.reservationReady) scope.activationAbort?.abort();
  }

  retireActivationForDrain(launchId: string): Promise<RetiredLaunch | undefined> {
    if (!this.activationDraining) throw new TypeError('local inference activation retirement lacks its original drain');
    return this.stop(launchId);
  }

  private stop(launchId: string): Promise<RetiredLaunch | undefined> {
    const scope = this.owners.get(launchId);
    if (!scope) return Promise.resolve(undefined);
    return scope.stopping ??= this.retire(launchId, scope);
  }

  private async retire(launchId: string, scope: OwnedService): Promise<RetiredLaunch | undefined> {
    let previous = readLocalInferenceLaunch(this.driver, launchId);
    if (previous?.phase === 'active') {
      try { previous = this.revoke(previous); }
      catch (error) {
        try { await scope.controller.close(); }
        catch (close) { throw new ResourceRetirementError('original local inference revocation and join failed', new AggregateError([error, close])); }
        throw error;
      }
    }
    await scope.controller.close();
    if (!previous) { this.owners.delete(launchId); return undefined; }
    if (previous.phase === 'retired') { this.owners.delete(launchId); return previous; }
    const observed = scope.controller.retirement(), recipe = scope.recipe;
    if (!observed || !recipe || !observed.allReaped || observed.populated || observed.remainingDescendants) return undefined;
    const retired = await this.completeRetirement(previous, observed, recipe, scope.containment);
    if (retired) this.owners.delete(launchId);
    return retired;
  }

  private revoke(previous: ActiveLaunch): Launch {
    const { leaseExpiresAt: _lease, ...data } = previous;
    const revoking = decodeLocalInferenceLaunch({ ...data, phase: 'revoking', rowVersion: previous.rowVersion + 1,
      quiesceId: identityHash('cliq-local-inference-quiesce-v1', previous.launchId, previous.rowVersion) });
    commitLocalInferenceCut(this.driver, this.owner, { launch: { previous, next: revoking } });
    return revoking;
  }

  private async completeRetirement(previous: Launch, observed: LocalInferenceNativeObservation,
    recipe: Pick<LaunchRecipe, 'plan' | 'spec'>, containment?: Containment,
    assertSource?: (connection: SqliteConnection) => void): Promise<RetiredLaunch | undefined> {
    if (!observed.allReaped || observed.populated || observed.remainingDescendants) return undefined;
    const launchId = previous.launchId;
    const current = assertActiveStateOwner(this.driver, this.owner), inspector = supervisorInspectorIdentity(current);
    const at = encodeCanonicalTime(observed.observedAtMs);
    const common = { schemaVersion: 1 as const, planRef: previous.containmentPlanRef, sandboxLaunchSpecRef: previous.sandboxLaunchSpecRef,
      sandboxLaunchSpecDigest: recipe.spec.launchSpecDigest, owner: recipe.plan.owner, launchNonceDigest: recipe.plan.launchNonceDigest,
      inspectorSupervisorInstanceId: inspector.supervisorInstanceId, inspectorIdentityRef: canonicalSha256(inspector),
      inspectorIdentityDigest: inspector.identityDigest, observedAt: at, evidenceDigest: '' };
    const plan = recipe.plan.backend;
    let proof: ProcessContainmentDeathEvidenceV1 | ProcessContainmentNoSpawnEvidenceV1;
    let fields: Record<string, unknown>;
    if (previous.phase === 'reserved') {
      // A known monitor without its original namespace-init identity cannot
      // be re-labeled as never-created even after a successful process join.
      if (observed.monitor && !observed.namespaceInit) return undefined;
      proof = { ...common, kind: 'containment_plan_quiescent', backend: { kind: 'linux', cgroupPath: plan.cgroupPath,
        cgroupObservation: observed.cgroupFileId === '0' ? { kind: 'absent' } :
          { kind: 'empty', cgroupId: observed.cgroupFileId, populated: 0 },
        pidNamespaceObservation: observed.namespaceInit ? { kind: 'dead_reaped', pidNamespaceReservationId: plan.pidNamespaceReservationId,
          namespaceInitStartToken: observed.namespaceInit.processStartToken } : { kind: 'never_created', pidNamespaceReservationId: plan.pidNamespaceReservationId },
        subreaperStartToken: plan.subreaperStartToken, matchingLaunchNonceProcessCount: 0 } };
      fields = { retirementKind: 'no_spawn' };
    } else {
      if (!containment || !observed.namespaceInit || !['preactivated', 'revoking'].includes(previous.phase) ||
          containment.backend.cgroupId !== observed.cgroupFileId || containment.backend.pidNamespaceId !== observed.pidNamespaceId ||
          containment.backend.namespaceInitStartToken !== observed.namespaceInit.processStartToken ||
          !('processContainmentRef' in previous) || previous.processContainmentRef !== canonicalSha256(containment)) return undefined;
      proof = { ...common, kind: 'containment_all_descendants_dead', containmentRef: previous.processContainmentRef,
        backend: { ...containment.backend, cgroupPopulated: 0, namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 } };
      fields = { retirementKind: 'death', quiesceId: previous.phase === 'revoking' ? previous.quiesceId :
        identityHash('cliq-local-inference-quiesce-v1', launchId, previous.rowVersion) };
    }
    proof.evidenceDigest = digestOmitting(proof, 'evidenceDigest');
    const metadata = await this.artifacts.publishCanonicalPair([{ value: inspector, schemaKind: inspector.format },
      { value: proof, schemaKind: proof.kind === 'containment_plan_quiescent' ? 'cliq-process-containment-no-spawn-evidence-v1' : 'cliq-process-containment-death-evidence-v1' }]);
    const retired = decodeLocalInferenceLaunch({ ...previous, ...fields, phase: 'retired', rowVersion: previous.rowVersion + 1,
      retiredAt: at, retirementEvidenceRef: metadata[1].ref });
    if (retired.phase !== 'retired') mismatch('local inference retirement row decoder differs');
    commitLocalInferenceCut(this.driver, this.owner, { launch: { previous, next: retired }, metadata, assert(connection, now) {
      assertSource?.(connection);
      if (at > now || now >= addCanonicalDuration(at, 5000)) mismatch('local inference retirement observation is no longer fresh');
    } });
    return retired;
  }

  /** Startup never adopts the old model process. Current source verification
   * follows the original cycle, bundle and StateOwner history before the
   * cleanup-only native owner can observe or touch the born containment. */
  async recover(previous: Launch, cycle: Cycle): Promise<RetiredLaunch | undefined> {
    if (previous.phase === 'retired') return previous;
    const signal = this.stopSignal.signal, lock = this.owner.filesystem;
    signal.throwIfAborted();
    const registration = decodeLocalModelRegistration(await readCanonicalArtifact(this.artifacts, cycle.localModelRegistrationRef));
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(this.artifacts, registration.serviceSpec.runtimeBundleRef);
    const recipe = await readRetainedLocalInferenceLaunch(this.artifacts, previous, cycle, registration, bundle);
    const originalEpoch = recipe.original.data.binding.stateOwnerEpoch;
    if (originalEpoch >= this.owner.ownerEpoch) mismatch('retained local inference cleanup requires a strictly newer StateOwner');
    const history = await readRetainedStateOwnerHistory(this.driver, this.artifacts, originalEpoch);
    const original = history.entries.at(-1);
    if (!original || original.owner.ownerEpoch !== originalEpoch || original.owner.state !== 'terminal' ||
        original.owner.supervisorInstanceId !== previous.supervisorInstanceId ||
        original.owner.runtimeBundleRef !== registration.serviceSpec.runtimeBundleRef || history.rootIdentity.identityDigest !== this.owner.stateRootIdentityDigest)
      mismatch('retained local inference launch does not belong to its exact earlier Supervisor');
    history.assertUnchanged(this.driver);
    requireEqual(readLocalInferenceLaunch(this.driver, previous.launchId), previous, 'retained local inference exact startup launch');
    if (previous.phase === 'active') previous = this.revoke(previous);
    const observed = await cleanupInstalledRetainedLocalInference(this.selected, this.anchor, lock, recipe.bytes, original.process, signal);
    if (!observed) return undefined;
    let containment: Containment | undefined;
    if ('processContainmentRef' in previous) {
      const originalContainment = await readCanonicalArtifact<Containment>(this.artifacts, previous.processContainmentRef);
      parseCanonicalTime(originalContainment.createdAt);
      if (!observed.namespaceInit || originalContainment.createdAt < previous.createdAt || originalContainment.createdAt >= previous.activationDeadlineAt)
        mismatch('retained local inference containment lacks its exact original namespace and creation interval');
      const expected: Containment = { schemaVersion: 1, owner: recipe.plan.owner, planRef: previous.containmentPlanRef,
        sandboxLaunchSpecRef: previous.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: recipe.spec.launchSpecDigest,
        filesystemBinding: recipe.plan.filesystemBinding, launchNonceDigest: recipe.plan.launchNonceDigest,
        backend: { kind: 'linux', cgroupPath: recipe.plan.backend.cgroupPath, cgroupId: observed.cgroupFileId,
          pidNamespaceReservationId: recipe.plan.backend.pidNamespaceReservationId, pidNamespaceId: observed.pidNamespaceId,
          namespaceInitStartToken: observed.namespaceInit.processStartToken, subreaperStartToken: recipe.plan.backend.subreaperStartToken },
        createdAt: originalContainment.createdAt };
      requireEqual(originalContainment, expected, 'retained local inference exact native containment');
      containment = expected;
    }
    return this.completeRetirement(previous, observed, recipe, containment, connection => history.assertUnchanged(connection));
  }

  observeRegistration(registration: LocalModelRegistrationV1, purpose: 'admission' | 'model' = 'admission'): Promise<InstalledLocalInferenceObservation> {
    const { latest, launch } = readLocalInferenceCurrent(this.driver, registration.ownerPrincipalId, registration.serviceId);
    const scope = launch && this.owners.get(launch.launchId);
    if (!scope || !launch || launch.phase !== 'active' || canonicalSha256(scope.registration) !== canonicalSha256(registration) ||
        purpose === 'model' && (latest?.phase !== 'active' || !scope.modelProducer))
      return Promise.reject(new KernelStorageError('RECOVERY_REQUIRED', 'local inference registration has no fresh original service'));
    return this.observe(launch, purpose === 'model' ? scope.modelProducer : undefined);
  }

  ownsActive(registration: LocalModelRegistrationV1, launchId?: string): boolean {
    const { latest, launch } = readLocalInferenceCurrent(this.driver, registration.ownerPrincipalId, registration.serviceId);
    const scope = launch && this.owners.get(launch.launchId);
    const cycleAllows = launchId === undefined ? latest?.phase === 'active' :
      latest?.phase === 'starting_launch' && launchId === latest.currentLaunchId;
    return !!(cycleAllows && scope?.active && !scope.stopping && launch?.phase === 'active' &&
      sampleCanonicalNow() < launch.leaseExpiresAt && canonicalSha256(scope.registration) === canonicalSha256(registration));
  }

  /** This is scheduling custody for the service's one native connector.
   * It grants no broker peer, release or lease and is held before a Run
   * opens a worker or prepares an invocation. */
  tryOwnModelProducer(registration: LocalModelRegistrationV1): Readonly<{ close(): void }> | undefined {
    if (!this.ownsActive(registration) || this.stopSignal.signal.aborted || this.activationDraining) return undefined;
    const { launch } = readLocalInferenceCurrent(this.driver, registration.ownerPrincipalId, registration.serviceId);
    const scope = launch && this.owners.get(launch.launchId);
    if (!scope || scope.modelProducer) return undefined;
    const booking = Object.freeze({ close() {
      if (this !== booking || scope.modelProducer !== booking) throw new TypeError('model scheduling booking is closed or foreign');
      scope.modelProducer = undefined;
    } });
    scope.modelProducer = booking;
    return booking;
  }

  private async observe(launch: ActiveLaunch, modelProducer?: object): Promise<InstalledLocalInferenceObservation> {
    const scope = this.owners.get(launch.launchId), signal = this.stopSignal.signal;
    if (!scope?.active || !scope.containment || scope.stopping) mismatch('active local inference lacks its original live native owner');
    let validThrough = launch.leaseExpiresAt;
    const assertCurrent = (connection: SqliteConnection = this.driver) => {
      signal.throwIfAborted();
      assertActiveStateOwner(connection, this.owner);
      const current = readLocalInferenceLaunch(connection, launch.launchId), now = sampleCanonicalNow();
      if (!current || current.phase !== 'active' || now >= current.leaseExpiresAt || now >= validThrough || scope.stopping ||
          current.leaseVersion < launch.leaseVersion || current.leaseExpiresAt < launch.leaseExpiresAt)
        mismatch('local inference service lease or observation is not live');
      if (modelProducer && (scope.modelProducer !== modelProducer ||
          readLocalInferenceCycle(connection, launch.activationCycleId)?.phase !== 'active'))
        mismatch('local inference model producer lacks its original completed activation');
      const { leaseVersion: _currentLease, leaseExpiresAt: _currentTime, ...retained } = current;
      const { leaseVersion: _originalLease, leaseExpiresAt: _originalTime, ...original } = launch;
      requireEqual(retained, original, 'original active local inference launch apart from its advancing lease');
    };
    let boundary: Boundary;
    for (;;) {
      assertCurrent();
      try {
        boundary = await observeLocalInferenceBoundary(this.artifacts, scope.controller, scope.registration, launch, scope.containment,
          assertActiveStateOwner(this.driver, this.owner));
        break;
      } catch (error) {
        if (!(error instanceof InstalledLocalInferenceBusyError)) throw error;
        // Wait for the fixed controller command slot. The original lease and
        // observation bounds above never move because the slot was occupied.
        await delay(5, undefined, { signal });
      }
    }
    validThrough = boundary.boundary.validThrough;
    assertCurrent();
    const observation: InstalledLocalInferenceObservation = Object.freeze({ boundary, controller: scope.controller, assertCurrent });
    liveObservations.set(observation, { driver: this.driver, owner: this.owner, registration: scope.registration, launch });
    return observation;
  }

  /** Reuse the original StateOwner maintenance task. Heartbeat commits only
   * the two lease fields after a real fresh containment observation. */
  async maintain(): Promise<void> {
    if (this.stopSignal.signal.aborted) return;
    for (const [id, scope] of this.owners) {
      if (!scope.active || !scope.containment || scope.stopping) continue;
      const launch = readLocalInferenceLaunch(this.driver, id), now = sampleCanonicalNow();
      if (!launch || launch.phase !== 'active') mismatch('owned local inference service lost its exact active row');
      if (now >= launch.leaseExpiresAt) {
        if (!await this.stop(id)) throw new ResourceRetirementError('expired local inference service lacks complete retirement', undefined);
        continue;
      }
      if (parseCanonicalTime(launch.leaseExpiresAt) - parseCanonicalTime(now) > 2500) continue;
      const owner = assertActiveStateOwner(this.driver, this.owner);
      try {
        const fresh = await observeLocalInferenceContainment(scope.controller, launch, scope.containment, owner);
        if (fresh.validThrough <= launch.leaseExpiresAt) continue;
        const next = decodeLocalInferenceLaunch({ ...launch, leaseVersion: launch.leaseVersion + 1, leaseExpiresAt: fresh.validThrough });
        commitLocalInferenceCut(this.driver, this.owner, { launch: { previous: launch, next }, assert(_connection, at) {
          if (at < fresh.at || at >= fresh.validThrough) mismatch('local inference heartbeat observation expired before commit');
        } });
      } catch (error) {
        if (error instanceof InstalledLocalInferenceBusyError) continue;
        const retired = await this.stop(id);
        if (!retired) throw new ResourceRetirementError('local inference service lost its original lease without complete retirement', error);
      }
    }
  }

  beginClose(): void { this.stopSignal.abort(); }
  close(): Promise<void> {
    this.beginClose();
    return this.closing ??= (async () => {
      const jobs = await Promise.allSettled([...this.tasks.values()]);
      const joins = [...this.owners.keys()].map(id => this.stop(id).then(result => {
        if (!result && this.owners.has(id)) throw new ResourceRetirementError('local inference launch has no exact physical retirement evidence', undefined);
      }));
      await joinResourceOperations(joins);
      const failed = jobs.find(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError);
      if (failed?.status === 'rejected') throw failed.reason;
      if (this.retirementFailure) throw this.retirementFailure;
    })();
  }
}
