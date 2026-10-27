import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { decodeDependencyClaimEvidence, type DependencyClaimEvidenceV1 } from '../kernel/dependency-claim.js';
import { decodeDependencyPackageFetchObservation } from '../kernel/dependency-fetch.js';
import { decodePackageCacheManifest, type PackageCacheEntryV1, type PackageCacheFetchAttemptV1 } from '../kernel/dependency.js';
import { decodeEndpointRegistration, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import { digestOmitting, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { InvocationJournalEntry, Run } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { requireEqual, type ReleaseTrustKey } from '../policy/runtime-authority.js';
import { assertNativeDependencyInvocation, captureNativeDependencyResult, type LinuxBlockedDependency,
  type NativeDependencyResult, type NativeDependencyResultAcknowledgement } from '../sandbox/linux-worker.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { advanceTimeFence, sampleCanonicalNow, type TimeFenceAdvance } from './canonical-time.js';
import type { DependencyBrokerBinding, NativeDependencyClosed, NativeDependencyFailureObservation, NativeDependencyGetOutcome,
  NativeDependencyPackage, NativeDependencySettlementFence, NativeDependencyTransport } from './dependency-broker-native.js';
import { assertCurrentPublicDependencyEndpoint, readInstalledDependencyEndpoints } from './dependency-endpoints.js';
import { publishDependencyPackageData } from './dependency-package-publication.js';
import { planDependencyTransport } from './dependency-transport-plan.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { readDependencyLaunchClosure, readDependencyPreparedLaunchData, type DependencyLaunchClosure,
  type DependencyLaunchClosureInput } from './execution-closure.js';
import { assertInstalledDependencySettlement, assertInstalledDependencyTransportConfiguration, loadInstalledDependencyBroker,
  withCredentialAuthorityLock, withHeldInstalledRuntime, type HeldInstalledRuntime } from './installed-runtime.js';
import { assertLiveDispatchState, claimValidatedInvocation, requireHealthyFence, settleValidatedInvocation, type ClaimInvocationDispatchInput } from './reducers/invocation.js';
import { readInvocationAttempt } from './repositories/journal.js';
import { readRun } from './rows.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import { readEndpointAuthoritySource } from './store.js';
import { retainDependencyCapturePublication } from './dependency-capture.js';
import { isJoinedCasPublicationFailure } from './cas.js';
import { decodeDependencyAcquisitionClosure, type DependencyAcquisitionClosureV1, decodeDependencyBrokerDispatchClosure,
  type DependencyBrokerDispatchClosureV1 } from '../kernel/dependency-acquisition.js';
import { supervisorInspectorIdentity, readSupervisorInspector } from './supervisor-inspector.js';

const ownerBrand = Symbol('original dependency invocation owner');
/** One original native broker and Journal, including its blocked npm scope.
 * Neither the public fields nor a retained artifact can reproduce this owner. */
export type DependencyInvocationOwner = Readonly<{ readonly [ownerBrand]: true; runId: string; opId: string; attempt: number }>;
type Prepared = Awaited<ReturnType<typeof readDependencyPreparedLaunchData>>;
type Observation = Readonly<{ value: unknown; artifact?: PublishedArtifact; attempt: PackageCacheFetchAttemptV1 }>;
type PackageProgress = { attempt: 1 | 2 | 3; observations: Observation[];
  outcome?: NativeDependencyGetOutcome; failure?: NativeDependencyFailureObservation;
  package?: NativeDependencyPackage; blob?: PublishedArtifact; packageClosed?: boolean; packageCloseFailure?: { error: unknown } };
type Held = {
  driver: SqliteDriver; artifacts: ArtifactCatalog; reads: ArtifactCatalog; owner: StateOwnerContext; selected: HeldInstalledRuntime;
  input: DependencyLaunchClosureInput; keys: readonly ReleaseTrustKey[]; signal?: AbortSignal; abortListener?: () => void; data: Prepared;
  endpoints: readonly EndpointRegistrationV1[]; configurationBytes: Buffer; maxPackageBytes: number; transport: NativeDependencyTransport;
  evidence: DependencyClaimEvidenceV1; evidenceArtifact: PublishedArtifact; retained: boolean; revoked: boolean;
  claim?: InvocationJournalEntry; binding?: DependencyBrokerBinding; bindingBytes?: Buffer; bound: boolean; closure?: DependencyLaunchClosure;
  process?: LinuxBlockedDependency; result?: NativeDependencyResult; processReleased: boolean;
  processInputsStaged?: boolean; stagingProcessInputs?: Promise<void>;
  capture?: ReturnType<typeof retainDependencyCapturePublication>;
  capturePublication?: Awaited<ReturnType<ReturnType<typeof retainDependencyCapturePublication>['publish']>>;
  ackCommitted?: string; acknowledged?: NativeDependencyResultAcknowledgement; pendingAcknowledgement?: Promise<NativeDependencyResultAcknowledgement>;
  pendingClaim?: Promise<InvocationJournalEntry>; pendingPackages?: Promise<PackageCachePublication>;
  index: number; progress?: PackageProgress; entries: PackageCacheEntryV1[]; metadata: PublishedArtifact[]; transferred: number;
  cache?: PackageCachePublication; cacheManifest?: ReturnType<typeof decodePackageCacheManifest>; packageInputsSealed: boolean;
  inputSealing?: Promise<void>; settlement?: NativeDependencySettlementFence;
  ioClosing?: Promise<NativeDependencyClosed>;
  acquisitionClosing?: Promise<void>; acquisitionClosure?: DependencyAcquisitionClosureV1;
  acquisitionPublication?: { evidence: DependencyAcquisitionClosureV1; artifact: PublishedArtifact; metadata: PublishedArtifact[] };
  unknownClosing?: Promise<void>; unknownPublication?: { evidence: DependencyBrokerDispatchClosureV1; artifact: PublishedArtifact; metadata: PublishedArtifact[] };
  closePending?: Promise<NativeDependencyClosed>; closed?: NativeDependencyClosed; retirementFailure?: ResourceRetirementError;
};
type PackageCachePublication = Readonly<{ manifest: ReturnType<typeof decodePackageCacheManifest>; artifact: PublishedArtifact;
  metadata: readonly PublishedArtifact[] }>;
const owners = new WeakMap<object, Held>();
// Strong retention is physical custody, not a second dispatch ledger. It is
// removed only after this exact native owner and retained fence really join.
const liveOwners = new Set<Held>();
const openingOwners = new Set<{ driver: SqliteDriver; owner: StateOwnerContext; runId: string; transport: NativeDependencyTransport }>();
function invalid(message: string): never { throw new KernelStorageError('STATE_TRANSITION_INVALID', message); }
function heldOwner(driver: SqliteDriver, owner: StateOwnerContext, token: unknown, retiring = false): Held {
  const held = token !== null && typeof token === 'object' ? owners.get(token) : undefined;
  if (!held || held.driver !== driver || held.owner !== owner) throw new TypeError('dependency requires its exact original invocation owner');
  if (held.retirementFailure && !retiring) throw held.retirementFailure;
  return held;
}
/** Pure registry assertion, independent of live authorization or SQL phase. */
export function assertDependencyBrokerQuiescence(driver: SqliteDriver, owner: StateOwnerContext, runId: string): void {
  if ([...openingOwners].some(held => held.driver === driver && held.owner === owner && held.runId === runId))
    throw new ResourceRetirementError('generation retains an original dependency native owner', undefined);
  for (const held of liveOwners) if (held.driver === driver && held.owner === owner && held.data.run.id === runId) {
    if (!held.unknownPublication || !held.closed || !held.settlement || !held.retained || held.retirementFailure)
      throw new ResourceRetirementError('generation retains an unfenced original dependency native owner', undefined);
    assertInstalledDependencySettlement(held.selected, held.settlement, bindingOf(held));
    const rows = readInvocationAttempt(driver, runId, held.data.prepared.opId, held.data.prepared.attempt);
    if (rows.length !== 3 || rows.at(-1)?.phase !== 'unknown')
      throw new ResourceRetirementError('dependency broker quiescence lost its exact charged UNKNOWN', undefined);
  }
}
function live(held: Held, connection: SqliteConnection = held.driver, now = sampleCanonicalNow()): Run {
  if (held.revoked || held.closed || held.closePending) throw new KernelStorageError('LEASE_FENCED', 'dependency owner is permanently revoked');
  held.signal?.throwIfAborted();
  const current = readRun(connection, held.data.run.id);
  const observed = assertLiveDispatchState(connection, held.owner, current.id, current.revision, held.data.run.leaseEpoch, now);
  if (observed.run.specRef !== held.data.run.specRef || observed.run.frontierRef !== held.data.run.frontierRef ||
      observed.run.latestCheckpointId !== held.data.run.latestCheckpointId || observed.run.activeWorkerLaunchId !== held.data.launch.launchId ||
      observed.generation.generationRef !== held.data.launch.workspaceGenerationRef ||
      now >= held.data.grant.expiresAt) throw new KernelStorageError('LEASE_FENCED', 'dependency release lost its original source, lease or consent');
  return observed.run;
}
async function frozenEndpoints(held: Pick<Held, 'reads' | 'data'>): Promise<EndpointRegistrationV1[]> {
  return held.reads.mapReads(held.data.dependencyPlan.registryEndpoints, async target => {
    const endpoint = decodeEndpointRegistration(await readCanonicalArtifact(held.reads, target.endpointRegistrationRef));
    if (canonicalSha256(endpoint) !== target.endpointRegistrationRef || endpoint.endpointIdentityDigest !== target.endpointIdentityDigest ||
        endpoint.tlsPolicyDigest !== target.tlsPolicyDigest) invalid('dependency substitutes its original complete registry target');
    return endpoint;
  });
}
/** The private owner alone supplies the fixed native action. The original
 * credential scope remains held through that actual CONNECT/GET release,
 * so revocation cannot race a previously returned data snapshot. */
async function releaseWithEndpoints<T>(held: Held, phase: 'prepared' | 'claimed', action: () => T | Promise<T>): Promise<T> {
  live(held);
  const data = phase === 'prepared' ? await readDependencyPreparedLaunchData(held.driver, held.reads, held.owner, held.input, held.keys, held.signal)
    : await readDependencyLaunchClosure(held.driver, held.reads, held.owner, held.input, held.keys, held.signal);
  requireEqual(data.request, held.data.request, 'dependency original complete request');
  requireEqual(data.grant, held.data.grant, 'dependency original complete grant');
  requireEqual(data.spec, held.data.spec, 'dependency original complete sandbox recipe');
  return withHeldInstalledRuntime(held.selected, async installed => {
    await installed.revalidate(held.signal); live(held);
    requireEqual(installed.bundle, held.data.bundle, 'dependency original selected signed bundle');
    return withCredentialAuthorityLock(held.selected, async token => {
      token.assertHeld(); live(held);
      for (const endpoint of held.endpoints) {
        const source = readEndpointAuthoritySource(token, endpoint.endpointRegistrationId);
        if (!source) invalid('dependency registry no longer has its original registered authority');
        assertCurrentPublicDependencyEndpoint(source.record, held.data.grant.principalId, installed.bundle);
        requireEqual(source.record.registration, endpoint, 'dependency current complete original registry registration');
      }
      token.assertHeld(); live(held);
      if ('assertUnchanged' in data) data.assertUnchanged(held.driver);
      assertInstalledDependencyTransportConfiguration(held.selected, held.transport, held.configurationBytes);
      let operation: T | Promise<T> | undefined, started = false;
      if (phase === 'claimed') {
        let fence: TimeFenceAdvance | undefined;
        held.driver.transaction(connection => {
          const at = sampleCanonicalNow();
          assertActiveStateOwner(connection, held.owner);
          fence = advanceTimeFence(connection, held.owner.ownerEpoch, at); if (fence !== 'healthy') return;
          const run = live(held, connection, at);
          requireEqual(run, data.run, 'dependency freshly read release Run cut');
          requireEqual(readInvocationAttempt(connection, run.id, held.data.prepared.opId, held.data.prepared.attempt),
            [held.data.prepared, held.claim], 'dependency unique original live claim');
          token.assertHeld(); assertInstalledDependencyTransportConfiguration(held.selected, held.transport, held.configurationBytes);
          // The fixed native start is synchronous; its real async work is
          // joined outside SQLite while the credential scope stays held.
          started = true; operation = action();
        });
        requireHealthyFence(fence);
      } else { started = true; operation = action(); }
      if (!started) invalid('dependency release did not pass its original canonical time fence');
      const result = await operation as T;
      token.assertHeld(); held.reads.assertReadActive(); return result;
    });
  }, held.signal);
}
function bindingOf(held: Held): DependencyBrokerBinding {
  if (!held.claim || !held.binding || !held.bindingBytes || !held.bound) invalid('dependency has no original permanently bound broker claim');
  return held.binding;
}

/** No GET or npm release occurs in this factory. It holds the genuine native
 * configuration and one dispatch fence before the original SQL claim. */
export async function prepareDependencyInvocationOwner(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  selected: HeldInstalledRuntime, input: DependencyLaunchClosureInput, releaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal): Promise<DependencyInvocationOwner> {
  const reads = signal ? artifacts.withReadSignal(signal) : artifacts;
  const data = await readDependencyPreparedLaunchData(driver, reads, owner, input, releaseKeys, signal);
  const endpoints = await frozenEndpoints({ reads, data });
  const sources = await readInstalledDependencyEndpoints(driver, reads, owner, selected,
    { principalId: data.grant.principalId, endpointIds: endpoints.map(endpoint => endpoint.endpointRegistrationId) }, signal);
  for (const endpoint of endpoints) {
    const source = sources.find(value => value.record.registration.endpointRegistrationId === endpoint.endpointRegistrationId);
    requireEqual(source?.record.registration, endpoint, 'dependency native configuration original registered endpoint');
  }
  const trustRef = endpoints[0]!.tls.trustStoreRef;
  const trust = sources[0]!.objects.find(object => object.artifactRef === trustRef)?.bytes;
  if (!trust || trust.length < 1 || trust.length > 16_777_216 || sha256Bytes(trust) !== trustRef) invalid('dependency original signed CA bytes are missing');
  const native = await loadInstalledDependencyBroker(selected);
  const now = sampleCanonicalNow(), remaining = Math.min(parseCanonicalTime(data.run.deadlineAt), parseCanonicalTime(data.grant.expiresAt)) - parseCanonicalTime(now);
  const planned = planDependencyTransport({ plan: data.dependencyPlan, packages: data.packageData.packages, endpoints,
    sandboxLaunchSpecRef: input.sandboxLaunchSpecRef, resources: data.spec.resources, runRemainingMs: remaining,
    storage: { maximumOwnerDataBytes: native.maximumOwnerDataBytes, descriptorPageStorageBytes: native.descriptorPageStorageBytes,
      fixedOwnerStorageBytes: native.fixedOwnerStorageBytes } });
  let transport: NativeDependencyTransport | undefined, retained = false;
  let held: Held | undefined;
  let abortListener: (() => void) | undefined;
  let opening: { driver: SqliteDriver; owner: StateOwnerContext; runId: string; transport: NativeDependencyTransport } | undefined;
  try {
    transport = native.prepareDependencyTransport(planned.configurationBytes, trust);
    opening = { driver, owner, runId: data.run.id, transport }; openingOwners.add(opening);
    const originalTransport = transport;
    abortListener = () => {
      if (held) held.revoked = true;
      // Revoke and join native I/O immediately, including an unsealed ready
      // task. Keep the original dispatch/settlement fence and known bytes for
      // their sole completion/cleanup owner; cancellation never acknowledges.
      void originalTransport.close().catch(() => {});
    };
    signal?.addEventListener('abort', abortListener, { once: true });
    if (signal?.aborted) abortListener();
    // Observe before any synchronous page registration can reject.
    const ready = transport.ready; void ready.catch(() => {});
    for (const page of planned.pages) transport.registerPackagePage(page);
    transport.sealPackagePlan(); await ready;
    assertInstalledDependencyTransportConfiguration(selected, transport, planned.configurationBytes);
    transport.retainDispatchFence(); retained = true;
    const core = { schemaVersion: 1 as const, format: 'cliq-dependency-claim-evidence-v1' as const, runId: data.run.id,
      opId: data.prepared.opId, attempt: data.prepared.attempt, dispatchId: input.dispatchId, sourceCheckpointId: input.sourceCheckpointId,
      workerLaunchId: data.launch.launchId, leaseEpoch: data.run.leaseEpoch, stateOwnerEpoch: owner.ownerEpoch,
      supervisorInstanceId: owner.supervisorInstanceId, dependencyPlanRef: data.request.dependencyPlanRef,
      dependencyPlanDigest: data.dependencyPlan.planDigest, requestRef: data.prepared.requestRef, requestDigest: data.request.requestDigest,
      targetRef: data.request.targetRef, targetDigest: data.target.targetDigest, grantRef: data.prepared.grantRef!,
      sandboxLaunchSpecRef: input.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: data.spec.launchSpecDigest,
      brokerFenceTokenDigest: transport.brokerFenceTokenDigest, createdAt: data.spec.createdAt, evidenceDigest: '' };
    core.evidenceDigest = digestOmitting(core, 'evidenceDigest'); const evidence = decodeDependencyClaimEvidence(core);
    const evidenceArtifact = await reads.publishCanonical(evidence, evidence.format);
    if (evidenceArtifact.ref !== canonicalSha256(evidence)) invalid('dependency original claim evidence publication differs');
    held = { driver, artifacts, reads, owner, selected, input: immutableSnapshot(input), keys: immutableSnapshot(releaseKeys), signal, abortListener, data,
      endpoints: immutableSnapshot(endpoints), configurationBytes: Buffer.from(planned.configurationBytes), maxPackageBytes: planned.maxPackageBytes,
      transport, evidence, evidenceArtifact, retained, revoked: false, bound: false, processReleased: false, index: 0, entries: [], metadata: [], transferred: 0,
      packageInputsSealed: false };
    const token = Object.freeze({ [ownerBrand]: true as const, runId: data.run.id, opId: data.prepared.opId, attempt: data.prepared.attempt });
    owners.set(token, held); liveOwners.add(held); openingOwners.delete(opening);
    await releaseWithEndpoints(held, 'prepared', () => {});
    return token;
  } catch (error) {
    if (held) held.revoked = true;
    if (transport) {
      try {
        await transport.close(); if (retained) transport.releaseDispatchFence();
        if (held) liveOwners.delete(held); if (opening) openingOwners.delete(opening);
        if (abortListener) signal?.removeEventListener('abort', abortListener);
      }
      catch (cause) {
        if (held) held.retirementFailure = new ResourceRetirementError('dependency original preparation resources did not join', new AggregateError([error, cause]));
        throw held?.retirementFailure ?? new ResourceRetirementError('dependency original preparation resources did not join', new AggregateError([error, cause]));
      }
    }
    throw error;
  }
}

/** Internal typed claim friend: a locator or callback cannot provide it. */
export function assertDependencyClaimForInvocation(driver: SqliteDriver, owner: StateOwnerContext, token: unknown, input: ClaimInvocationDispatchInput) {
  const held = heldOwner(driver, owner, token); live(held);
  if (held.claim || input.runId !== held.data.run.id || input.opId !== held.data.prepared.opId || input.attempt !== held.data.prepared.attempt ||
      input.expectedRunRevision !== held.data.run.revision || input.leaseEpoch !== held.data.run.leaseEpoch || input.dispatchId !== held.input.dispatchId ||
      input.sandboxLaunchSpecRef !== undefined || input.brokerFenceTokenDigest !== held.transport.brokerFenceTokenDigest)
    throw new TypeError('dependency claim requires its exact original unclaimed native owner');
  assertInstalledDependencyTransportConfiguration(held.selected, held.transport, held.configurationBytes);
  return { metadata: [held.evidenceArtifact], evidenceRef: held.evidenceArtifact.ref, evidenceDigest: held.evidence.evidenceDigest,
    validate(connection: SqliteConnection, run: Run, prepared: InvocationJournalEntry, now: string) {
      live(held, connection, now); held.data.assertUnchanged(connection);
      requireEqual(run, held.data.run, 'dependency original prepared Run'); requireEqual(prepared, held.data.prepared, 'dependency original preparation');
      requireEqual(readInvocationAttempt(connection, run.id, prepared.opId, prepared.attempt), [held.data.prepared], 'dependency unique preparation');
      if (now < held.data.spec.createdAt || now >= held.data.grant.expiresAt) invalid('dependency permanent claim is outside its original grant');
      assertInstalledDependencyTransportConfiguration(held.selected, held.transport, held.configurationBytes);
    } };
}
export function claimDependencyInvocation(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner): Promise<InvocationJournalEntry> {
  const held = heldOwner(driver, owner, token);
  if (held.claim) { bindingOf(held); return Promise.resolve(immutableSnapshot(held.claim)); }
  if (held.pendingClaim) return held.pendingClaim;
  const pending = releaseWithEndpoints(held, 'prepared', async () => {
    const claim = await claimValidatedInvocation(driver, held.artifacts, owner, { runId: held.data.run.id, opId: held.data.prepared.opId,
      attempt: held.data.prepared.attempt, expectedRunRevision: held.data.run.revision, leaseEpoch: held.data.run.leaseEpoch,
      dispatchId: held.input.dispatchId, brokerFenceTokenDigest: held.transport.brokerFenceTokenDigest }, undefined, undefined, token);
    held.claim = immutableSnapshot(claim);
    held.binding = immutableSnapshot({ runId: claim.runId, opId: claim.opId, attempt: claim.attempt, dispatchId: claim.dispatchId!,
      dispatchJournalSeq: claim.seq, requestRef: claim.requestRef, requestDigest: held.data.request.requestDigest,
      targetRef: held.data.request.targetRef, targetDigest: held.data.target.targetDigest, grantRef: claim.grantRef!,
      supervisorInstanceId: owner.supervisorInstanceId, stateOwnerEpoch: owner.ownerEpoch, leaseEpoch: claim.leaseEpoch,
      brokerFenceTokenDigest: claim.brokerFenceTokenDigest! });
    held.bindingBytes = canonicalJsonBytes(held.binding);
    // If this original bind fails, the permanent claim is still retained. It
    // cannot create another owner, claim, dispatch or reset its deadline.
    try { held.transport.bindInvocation(held.bindingBytes); held.bound = true; }
    catch (error) { held.revoked = true; throw error; }
    return immutableSnapshot(claim);
  }).finally(() => { if (held.pendingClaim === pending) held.pendingClaim = undefined; });
  held.pendingClaim = pending; return pending;
}

async function publishObservation(held: Held, progress: PackageProgress): Promise<void> {
  const observation = progress.observations.at(-1)!;
  if (observation.artifact) return;
  const artifact = await held.reads.publishCanonical(decodeDependencyPackageFetchObservation(observation.value), 'cliq-dependency-package-fetch-observation-v1');
  if (artifact.ref !== observation.attempt.observationDigest) invalid('dependency GET observation publication differs');
  (observation as { artifact?: PublishedArtifact }).artifact = artifact; held.metadata.push(artifact);
}
function retainObservation(held: Held, progress: PackageProgress, observation: NativeDependencyGetOutcome | NativeDependencyFailureObservation) {
  const failed = 'brokerCode' in observation;
  const value = immutableSnapshot({ schemaVersion: 1, format: 'cliq-dependency-package-fetch-observation-v1',
    runId: held.data.run.id, opId: held.data.prepared.opId, invocationAttempt: held.data.prepared.attempt,
    dispatchId: held.input.dispatchId, brokerFenceTokenDigest: held.transport.brokerFenceTokenDigest,
    ...(failed ? { kind: 'transport_failed', ...observation } : { kind: observation.kind, packageIndex: held.index, attempt: progress.attempt,
      status: observation.status, receivedBytes: observation.receivedBytes, eof: observation.eof }), observedAt: sampleCanonicalNow() });
  if (observation.packageIndex !== held.index || observation.attempt !== progress.attempt ||
      !Number.isSafeInteger(observation.receivedBytes) || observation.receivedBytes < 0 || observation.receivedBytes > held.maxPackageBytes ||
      held.transferred + observation.receivedBytes > held.data.dependencyPlan.maxDownloadBytes)
    invalid('dependency GET observation exceeds its exact original index, attempt or transfer bound');
  held.transferred += observation.receivedBytes;
  const attempt: PackageCacheFetchAttemptV1 = { attempt: progress.attempt,
    outcome: failed ? 'transport_failed' : observation.kind === 'complete' ? 'completed' : observation.kind,
    receivedBytes: observation.receivedBytes, observationDigest: canonicalSha256(value),
    ...(!failed && observation.kind === 'http_error' ? { httpStatus: observation.status } : {}) };
  progress.observations.push({ value, attempt });
}
/** CAS retry reopens the same opaque package reader. It never issues another
 * GET or treats metadata publication as package retirement. */
export function acquireDependencyPackages(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner): Promise<PackageCachePublication> {
  const held = heldOwner(driver, owner, token); bindingOf(held);
  if (held.cache) return Promise.resolve(held.cache);
  if (held.pendingPackages) return held.pendingPackages;
  const pending = (async () => {
    while (held.index < held.data.packageData.packages.length) {
      const descriptor = held.data.packageData.packages[held.index]!;
      const progress = held.progress ??= { attempt: 1, observations: [] };
      if (!progress.outcome && !progress.failure) {
        try {
          await releaseWithEndpoints(held, 'claimed', () => held.transport.connect(held.bindingBytes!, held.index, progress.attempt));
          progress.outcome = await releaseWithEndpoints(held, 'claimed', () => held.transport.releaseGet(held.bindingBytes!, held.index, progress.attempt));
          retainObservation(held, progress, progress.outcome);
          if (progress.outcome.kind === 'complete') progress.package = progress.outcome.package;
        } catch (error) {
          let failure: NativeDependencyFailureObservation;
          try { failure = held.transport.observeFailure(error); } catch { held.revoked = true; throw error; }
          progress.failure = failure; retainObservation(held, progress, failure);
          if (!failure.retryableTransport || !failure.ioJoined || failure.brokerCode !== 'transport_interrupted') { held.revoked = true; throw error; }
        }
      }
      await publishObservation(held, progress);
      if (!progress.package) {
        if (progress.attempt === 3) { held.revoked = true; invalid('dependency exhausted its original three package GET attempts'); }
        held.progress = { attempt: (progress.attempt + 1) as 2 | 3, observations: progress.observations }; continue;
      }
      progress.blob ??= await publishDependencyPackageData(held.reads, progress.package, descriptor, held.maxPackageBytes, held.signal);
      if (progress.packageCloseFailure) throw progress.packageCloseFailure.error;
      if (!progress.packageClosed) {
        try { progress.package.close(); progress.packageClosed = true; }
        catch (error) { held.revoked = true; progress.packageCloseFailure = { error }; throw error; }
      }
      held.metadata.push(progress.blob);
      held.entries.push({ ...descriptor, blobRef: progress.blob.ref, blobDigest: progress.blob.ref, blobBytes: progress.blob.byteLength,
        fetchAttempts: progress.observations.map(observation => observation.attempt) });
      held.index++; held.progress = undefined;
    }
    if (!held.packageInputsSealed) {
      held.inputSealing ??= releaseWithEndpoints(held, 'claimed', () => held.transport.sealPackageInputs(held.bindingBytes!))
        .then(() => { held.packageInputsSealed = true; }, error => { held.revoked = true; throw error; });
      await held.inputSealing;
    }
    const core = { schemaVersion: 1 as const, format: 'cliq-package-cache-manifest-v1' as const, runId: held.data.run.id,
      resultSourceRef: held.data.request.resultSourceRef, dependencyPlanRef: held.data.request.dependencyPlanRef,
      lockfileRef: held.data.dependencyPlan.lockfileRef, lockfileDigest: held.data.dependencyPlan.lockfileDigest,
      entries: held.entries, packageCount: held.entries.length, totalTransferredBytes: held.transferred, createdAt: sampleCanonicalNow(), manifestDigest: '' };
    core.manifestDigest = digestOmitting(core, 'manifestDigest');
    const manifest = held.cacheManifest ??= immutableSnapshot(decodePackageCacheManifest(core));
    const artifact = await held.reads.publishCanonical(manifest, manifest.format);
    const cache = immutableSnapshot({ manifest, artifact, metadata: [...held.metadata, artifact] });
    held.cache = cache; return cache;
  })().catch(error => {
    if (!isJoinedCasPublicationFailure(error)) held.revoked = true;
    if (error instanceof ResourceRetirementError) { held.revoked = true; held.retirementFailure ??= error; }
    throw error;
  }).finally(() => { if (held.pendingPackages === pending) held.pendingPackages = undefined; });
  held.pendingPackages = pending; return pending;
}
/** Supplies only the same genuine claimed scope inputs to its original loaded
 * Worker. Native acquire_worker still permits exactly one actual scope. */
export async function readDependencyProcessInputs(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token); const binding = bindingOf(held); live(held);
  if (!held.cache || !held.packageInputsSealed || held.process) invalid('dependency process has no complete original package inputs or is already created');
  const current = await readDependencyLaunchClosure(driver, held.reads, owner, held.input, held.keys, held.signal);
  if (held.closure) {
    requireEqual(current.spec, held.closure.spec, 'dependency original blocked process recipe');
    requireEqual(current.claim, held.closure.claim, 'dependency original blocked process permanent claim');
  } else held.closure = current;
  return Object.freeze({ closure: held.closure, transport: held.transport, binding });
}
export function registerDependencyProcess(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner, process: LinuxBlockedDependency): void {
  const held = heldOwner(driver, owner, token);
  if (!held.closure || held.process) invalid('dependency has no unique original blocked process');
  assertNativeDependencyInvocation(held.closure, held.transport, bindingOf(held), process); held.process = process;
}
/** Replays the already verified original package CAS bytes into this one
 * blocked scope. Native metadata/SHA/EOF and writer joins precede RELEASE. */
export function stageDependencyProcessInputs(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner): Promise<void> {
  const held = heldOwner(driver, owner, token); bindingOf(held);
  if (held.processInputsStaged) return Promise.resolve();
  if (held.stagingProcessInputs) return held.stagingProcessInputs;
  if (!held.process || !held.closure || !held.cache || held.processReleased) invalid('dependency staging lost its original blocked scope');
  const process = held.process;
  const work = (async () => {
    for (const entry of held.cache!.manifest.entries) {
      let count = 0;
      for await (const bytes of held.reads.readChunks(entry.blobRef, entry.blobBytes)) {
        live(held); assertNativeDependencyInvocation(held.closure!, held.transport, bindingOf(held), process);
        count += bytes.length;
        if (count > entry.blobBytes) invalid('dependency staged package exceeds its original sealed size');
        for (let offset = 0; offset < bytes.length; offset += 65_536)
          await process.stagePackageChunk(bytes.subarray(offset, Math.min(bytes.length, offset + 65_536)));
      }
      if (count !== entry.blobBytes) invalid('dependency staged package did not read its complete original EOF');
    }
    live(held); await process.sealPackageInputs(); held.processInputsStaged = true;
  })().catch(error => { held.revoked = true; throw error; });
  held.stagingProcessInputs = work; return work;
}
export async function releaseDependencyProcess(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner): Promise<void> {
  const held = heldOwner(driver, owner, token); bindingOf(held);
  if (!held.process || !held.processInputsStaged || held.processReleased) invalid('dependency process is absent, unsealed or already permanently released');
  await releaseWithEndpoints(held, 'claimed', () => { held.processReleased = true; held.transport.releaseProcess(held.bindingBytes!); });
}
/** Preserve the genuine result and its private byte snapshot before any
 * await. This native mutex is for the sole SQL settlement, never a release. */
export function retainDependencyResultForSettlement(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner,
  result: NativeDependencyResult) {
  const held = heldOwner(driver, owner, token);
  if (!held.closure || !held.process || !held.processReleased) invalid('dependency result has no original released scope');
  assertNativeDependencyInvocation(held.closure, held.transport, bindingOf(held), held.process, result);
  if (held.result && held.result !== result) invalid('dependency changed its original known result');
  const snapshot = captureNativeDependencyResult(result); held.result = result;
  held.capture ??= retainDependencyCapturePublication(held.artifacts, assertActiveStateOwner(driver, owner), held.data.prepared,
    held.claim!, held.evidenceArtifact.ref, held.data.spec, result);
  held.settlement ??= held.transport.acquireSettlementFence(held.bindingBytes!);
  assertInstalledDependencySettlement(held.selected, held.settlement, held.binding!);
  if (!held.settlement.processClaimed || !held.settlement.processJoined || !held.settlement.processResultAvailable)
    invalid('dependency settlement lacks the original process result and actual whole-domain join');
  return Object.freeze({ result: snapshot, cache: held.cache!, claim: immutableSnapshot(held.claim!), fence: held.settlement });
}
/** The native owner supplies the original publisher; callers supply no byte
 * buffers, success flags, capture refs or acknowledgement callbacks. */
export async function publishDependencyResultCapture(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token);
  if (!held.result || !held.capture || !held.settlement) invalid('dependency capture has no original joined result owner');
  held.capturePublication ??= await held.capture.publish(); return held.capturePublication;
}
export function assertDependencySettlementForInvocation(driver: SqliteDriver, owner: StateOwnerContext,
  token: DependencyInvocationOwner, connection: SqliteConnection) {
  const held = heldOwner(driver, owner, token); const binding = bindingOf(held);
  if (!held.settlement || !held.result || !held.cache || !held.closure || !held.process || !held.capturePublication)
    invalid('dependency has no genuine original joined settlement and full durable capture');
  assertActiveStateOwner(connection, owner); assertInstalledDependencySettlement(held.selected, held.settlement, binding);
  assertNativeDependencyInvocation(held.closure, held.transport, binding, held.process, held.result);
  requireEqual(readInvocationAttempt(connection, binding.runId, binding.opId, binding.attempt), [held.data.prepared, held.claim], 'dependency unchanged pending original claim');
  return Object.freeze({ prepared: held.data.prepared, claim: held.claim!, cache: held.cache, capture: held.capturePublication, result: held.result,
    validateSnapshot(current: SqliteConnection, run: Run) {
      assertActiveStateOwner(current, owner); assertInstalledDependencySettlement(held.selected, held.settlement!, binding);
      if (run.id !== binding.runId || run.specRef !== held.data.run.specRef || run.leaseEpoch !== binding.leaseEpoch ||
          run.activeWorkerLaunchId !== held.data.launch.launchId) invalid('dependency settlement changed its original Run and parent');
      requireEqual(readInvocationAttempt(current, binding.runId, binding.opId, binding.attempt), [held.data.prepared, held.claim], 'dependency pending permanent claim');
    } });
}
/** Original private locators only. Returning these retained data does not
 * transfer the native owner, its mutex, result custody or release authority. */
export function readDependencySettlementInput(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token);
  assertDependencySettlementForInvocation(driver, owner, token, driver);
  return Object.freeze({ input: immutableSnapshot(held.input), request: held.data.request, target: held.data.target,
    spec: held.data.spec, grant: held.data.grant, keys: held.keys });
}
/** The genuine broker must affirm it never acquired a process peer. A failed
 * CREATE, staging or execution release remains UNKNOWN, even after close. */
export async function retainDependencyAcquisitionFailure(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token); bindingOf(held);
  if (held.process || held.processReleased || held.result || held.capture || held.closure)
    invalid('dependency process custody cannot become an acquisition-only failure');
  held.acquisitionClosing ??= (async () => {
    const closed = await revokeDependencyInvocationIO(driver, owner, token);
    held.settlement ??= held.transport.acquireSettlementFence(held.bindingBytes!);
    assertInstalledDependencySettlement(held.selected, held.settlement, held.binding!);
    if (closed.processClaimed || closed.processJoined || closed.processResultAcknowledged || closed.processResultCustodyRetired ||
        closed.processResultCustodyOrigin !== 'none' || !closed.dispatchFenceRetained ||
        held.settlement.processClaimed || held.settlement.processJoined || held.settlement.processResultAvailable ||
        held.settlement.networkStarted !== closed.networkStarted || held.settlement.requestStarted !== closed.requestStarted)
      invalid('dependency acquisition has no genuine worker-never-acquired closure');
    const inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner));
    const evidence: DependencyAcquisitionClosureV1 = { schemaVersion: 1, format: 'cliq-dependency-acquisition-closure-v1',
      runId: token.runId, opId: token.opId, attempt: token.attempt, claimEvidenceRef: held.evidenceArtifact.ref,
      dispatchId: held.claim!.dispatchId!, dispatchJournalSeq: held.claim!.seq, brokerFenceTokenDigest: held.binding!.brokerFenceTokenDigest,
      inspectorIdentityRef: canonicalSha256(inspector), inspectorIdentityDigest: inspector.identityDigest, observedAt: sampleCanonicalNow(),
      closure: { kind: 'dependency_transport_closed', tokenRevoked: true, networkStarted: closed.networkStarted, requestStarted: closed.requestStarted,
        connectionCount: closed.connectionCount, requestCount: closed.requestCount, transferredBytes: closed.transferredBytes,
        processClaimed: false, processJoined: false, processResultAvailable: false, processResultAcknowledged: false,
        processResultCustodyRetired: false, processResultCustodyOrigin: 'none', fenceAction: 'original_token_revoked_io_joined_worker_never_acquired' }, evidenceDigest: '' };
    evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); held.acquisitionClosure = decodeDependencyAcquisitionClosure(evidence);
  })();
  await held.acquisitionClosing;
}
export function hasDependencyProcessCustody(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner): boolean {
  const held = heldOwner(driver, owner, token, true);
  return held.closure !== undefined || held.process !== undefined || held.processReleased || held.result !== undefined;
}
/** Retain the same original irreversible native fence through UNKNOWN and
 * terminal quarantine. Parent death does not close the Supervisor GET owner. */
export async function retainDependencyUnknownBrokerFence(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token); bindingOf(held);
  held.unknownClosing ??= (async () => {
    const closed = await revokeDependencyInvocationIO(driver, owner, token);
    held.settlement ??= held.transport.acquireSettlementFence(held.bindingBytes!);
    assertInstalledDependencySettlement(held.selected, held.settlement, held.binding!);
    if (!closed.dispatchFenceRetained || held.settlement.processClaimed !== closed.processClaimed ||
        held.settlement.processJoined !== closed.processJoined || held.settlement.networkStarted !== closed.networkStarted ||
        held.settlement.requestStarted !== closed.requestStarted) invalid('dependency UNKNOWN lost its original broker fence or joined I/O');
  })();
  await held.unknownClosing;
  if (held.unknownPublication) return held.unknownPublication;
  const closed = held.closed!, inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner));
  const { networkStarted, requestStarted, connectionCount, requestCount, transferredBytes, processClaimed, processJoined,
    processResultAcknowledged, processResultCustodyRetired, processResultCustodyOrigin } = closed;
  const evidence: DependencyBrokerDispatchClosureV1 = { schemaVersion: 1, format: 'cliq-dependency-broker-dispatch-closure-v1',
    runId: token.runId, opId: token.opId, attempt: token.attempt, dispatchId: held.claim!.dispatchId!, claimJournalSeq: held.claim!.seq,
    claimEvidenceRef: held.evidenceArtifact.ref, brokerFenceTokenDigest: held.binding!.brokerFenceTokenDigest,
    inspectorIdentityRef: canonicalSha256(inspector), inspectorIdentityDigest: inspector.identityDigest, observedAt: sampleCanonicalNow(),
    io: { networkStarted, requestStarted, connectionCount, requestCount, transferredBytes, processClaimed, processJoined,
      processResultAcknowledged, processResultCustodyRetired, processResultCustodyOrigin },
    fenceAction: 'original_matching_token_revoked_all_io_joined_native_mutex_held', evidenceDigest: '' };
  evidence.evidenceDigest = digestOmitting(evidence, 'evidenceDigest'); decodeDependencyBrokerDispatchClosure(evidence);
  const published = await held.artifacts.publishCanonicalPair([{ value: inspector, schemaKind: inspector.format }, { value: evidence, schemaKind: evidence.format }]);
  return held.unknownPublication = { evidence, artifact: published[1], metadata: [...published] };
}
/** Current same-process producer only. Successors require the original
 * positive StateOwner process-death closure instead of this native registry. */
export function assertDependencyUnknownBrokerFence(driver: SqliteDriver, owner: StateOwnerContext, runId: string,
  opId: string, attempt: number, closureRef: string): void {
  const matching = [...liveOwners].filter(held => held.driver === driver && held.owner === owner && held.data.run.id === runId &&
    held.data.prepared.opId === opId && held.data.prepared.attempt === attempt);
  if (matching.length !== 1 || matching[0]!.unknownPublication?.artifact.ref !== closureRef)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'dependency UNKNOWN has no continuously retained original broker fence');
  assertDependencyBrokerQuiescence(driver, owner, runId);
}
export async function markDependencyInvocationUnknown(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token);
  const publication = await retainDependencyUnknownBrokerFence(driver, owner, token), binding = bindingOf(held);
  const value = { schemaVersion: 1, format: 'cliq-dependency-ambiguity-v1', runId: token.runId, opId: token.opId,
    attempt: token.attempt, dispatchId: binding.dispatchId, claimJournalSeq: binding.dispatchJournalSeq,
    requestRef: binding.requestRef, target: held.claim!.target, grantRef: binding.grantRef,
    brokerFenceTokenDigest: binding.brokerFenceTokenDigest, brokerDispatchClosureRef: publication.artifact.ref,
    reason: 'original_owner_joined_without_process_result' };
  const artifact = await held.artifacts.publishCanonical(value, value.format);
  const original = readInvocationAttempt(driver, token.runId, token.opId, token.attempt), last = original.at(-1);
  if (original.length === 3 && last?.phase === 'unknown' && last.evidenceRef === artifact.ref && last.evidenceDigest === artifact.ref)
    return readRun(driver, token.runId);
  requireEqual(original, [held.data.prepared, held.claim], 'dependency UNKNOWN original pending claim');
  const result = await settleValidatedInvocation(driver, held.artifacts, owner, { runId: token.runId, opId: token.opId,
    attempt: token.attempt, expectedRunRevision: readRun(driver, token.runId).revision }, {
    phase: 'unknown', evidenceRef: artifact.ref, evidenceDigest: artifact.ref }, async () => ({
      metadata: [...publication.metadata, artifact], validate(connection, run) {
        assertActiveStateOwner(connection, owner); assertInstalledDependencySettlement(held.selected, held.settlement!, binding);
        requireEqual(readInvocationAttempt(connection, token.runId, token.opId, token.attempt), original, 'dependency UNKNOWN sole original claim');
        if (run.specRef !== held.data.run.specRef || run.leaseEpoch !== binding.leaseEpoch || run.activeWorkerLaunchId !== held.data.launch.launchId)
          invalid('dependency UNKNOWN changed its original Run or physical parent');
      }
    }));
  return result.run;
}
export async function publishDependencyAcquisitionFailure(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token);
  await retainDependencyAcquisitionFailure(driver, owner, token);
  if (held.acquisitionPublication) return held.acquisitionPublication;
  const evidence = held.acquisitionClosure!, inspector = supervisorInspectorIdentity(assertActiveStateOwner(driver, owner));
  if (canonicalSha256(inspector) !== evidence.inspectorIdentityRef) invalid('dependency acquisition changed its original inspector');
  const published = await held.artifacts.publishCanonicalPair([{ value: inspector, schemaKind: inspector.format }, { value: evidence, schemaKind: evidence.format }]);
  await readSupervisorInspector(held.artifacts, assertActiveStateOwner(driver, owner), held.data.assembly,
    { inspectorIdentityRef: published[0].ref, inspectorIdentityDigest: inspector.identityDigest, observedAt: evidence.observedAt });
  return held.acquisitionPublication = { evidence, artifact: published[1], metadata: [...held.metadata, ...published] };
}
export function assertDependencyAcquisitionFailure(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner, connection: SqliteConnection) {
  const held = heldOwner(driver, owner, token), binding = bindingOf(held);
  if (!held.acquisitionPublication || !held.settlement || !held.closed || held.process || held.processReleased || held.result)
    invalid('dependency acquisition failure has no genuine joined original owner');
  const validateSnapshot = (current: SqliteConnection, run: Run) => {
    assertActiveStateOwner(current, owner); assertInstalledDependencySettlement(held.selected, held.settlement!, binding);
    if (run.id !== binding.runId || run.specRef !== held.data.run.specRef || run.leaseEpoch !== binding.leaseEpoch ||
        run.activeWorkerLaunchId !== held.data.launch.launchId) invalid('dependency acquisition failure changed its original parent');
    requireEqual(readInvocationAttempt(current, binding.runId, binding.opId, binding.attempt), [held.data.prepared, held.claim], 'dependency acquisition pending original claim');
  };
  validateSnapshot(connection, readRun(connection, token.runId));
  return { prepared: held.data.prepared, claim: held.claim!, publication: held.acquisitionPublication,
    input: immutableSnapshot(held.input), request: held.data.request, target: held.data.target, keys: held.keys, validateSnapshot };
}
/** Lease maintenance borrows the same genuine claimed owner. It cannot
 * release, revive a cancelled native token or extend the outer deadline. */
export function assertDependencyLeaseMaintenance(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner): void {
  const held = heldOwner(driver, owner, token); bindingOf(held); live(held);
  assertInstalledDependencyTransportConfiguration(held.selected, held.transport, held.configurationBytes);
}
/** Immediate authority reduction and actual I/O join; dispatch/settlement
 * custody stays with its sole result owner until durable settlement/ACK. */
export function revokeDependencyInvocationIO(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token, true); held.revoked = true;
  return held.ioClosing ??= held.transport.close().then(receipt => { held.closed = receipt; return receipt; }, cause => {
    throw held.retirementFailure = new ResourceRetirementError('dependency original I/O did not actually join', cause);
  });
}
/** The caller supplies no committed flag: inspect the actual unique Journal
 * terminal row before relinquishing the mutex and permitting output ACK. */
export async function acknowledgeDependencyInvocation(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner) {
  const held = heldOwner(driver, owner, token); const binding = bindingOf(held);
  const rows = readInvocationAttempt(driver, binding.runId, binding.opId, binding.attempt), terminal = rows.at(-1);
  if (rows.length !== 3 || terminal?.phase !== 'completed' && terminal?.phase !== 'failed' || !terminal.budgetSettlementRef ||
      terminal.dispatchId !== held.claim!.dispatchId || terminal.requestRef !== held.claim!.requestRef)
    invalid('dependency data ACK requires its original unique durable settlement');
  const committed = canonicalSha256(terminal);
  if (held.ackCommitted && held.ackCommitted !== committed) invalid('dependency ACK changed its exact original committed terminal row');
  if (held.acknowledged) return held.acknowledged;
  if (held.pendingAcknowledgement) return held.pendingAcknowledgement;
  const capture = held.capturePublication;
  if (!held.result || !held.process || !capture || !held.settlement && !held.ackCommitted ||
      (terminal.phase === 'completed' ? terminal.resultRef !== capture.artifact.ref :
        terminal.evidenceRef !== capture.artifact.ref || terminal.evidenceDigest !== capture.capture.captureDigest))
    invalid('dependency data ACK has no exact durable original output graph');
  for (const artifact of capture.metadata) {
    const row = driver.prepare('SELECT byte_length FROM artifacts WHERE ref=?').get<{ byte_length: unknown }>(artifact.ref);
    if (!row || Number(row.byte_length) !== artifact.byteLength) invalid('dependency data ACK lacks a registered original capture member');
  }
  if (!held.ackCommitted) {
    try { held.settlement!.close(); held.settlement = undefined; held.ackCommitted = committed; }
    catch (cause) { throw held.retirementFailure = new ResourceRetirementError('dependency settlement mutex did not actually retire after commit', cause); }
  }
  const producer = held.process, result = held.result;
  const pending = (async () => {
    const { acknowledgeNativeDependencyResult } = await import('../sandbox/linux-worker.js');
    const observed = await acknowledgeNativeDependencyResult(producer, result);
    held.acknowledged = observed; held.result = undefined; held.process = undefined;
    held.capture?.releasePublishedData(); held.capture = undefined;
    return observed;
  })().finally(() => { if (held.pendingAcknowledgement === pending) held.pendingAcknowledgement = undefined; });
  held.pendingAcknowledgement = pending; return pending;
}
/** Revocation/actual closure is distinct from result settlement and ACK. */
export function closeDependencyInvocationOwner(driver: SqliteDriver, owner: StateOwnerContext, token: DependencyInvocationOwner): Promise<NativeDependencyClosed> {
  const held = heldOwner(driver, owner, token, true); held.revoked = true;
  if (held.closePending) return held.closePending;
  const pending = (async () => {
    try {
      held.settlement?.close(); held.settlement = undefined;
      const receipt = await revokeDependencyInvocationIO(driver, owner, token); held.closed = receipt;
      if (held.retirementFailure) throw held.retirementFailure;
      if (held.retained) { held.transport.releaseDispatchFence(); held.retained = false; }
      if (held.abortListener) held.signal?.removeEventListener('abort', held.abortListener);
      liveOwners.delete(held); return immutableSnapshot(receipt);
    } catch (cause) { throw held.retirementFailure = new ResourceRetirementError('dependency original native owner did not actually join', cause); }
  })();
  held.closePending = pending; return pending;
}
