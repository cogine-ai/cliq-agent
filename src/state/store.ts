import type { Stats } from 'node:fs';
import { lstat, mkdir, readFile, readdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';

import {
  KERNEL_CAS_DIRECTORY,
  KERNEL_DATABASE_FILENAME,
  KERNEL_SQLITE_APPLICATION_ID,
  KERNEL_STATE_SCHEMA_VERSION
} from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import {
  digestOmitting,
  identityHash,
  normalizeAbsolutePath,
  parseCanonicalTime,
  sha256Bytes,
  unsignedDecimalId
} from '../kernel/identity.js';
import type {
  KernelGenerationIdentityV1,
  LocalControlChannelIdentityV1,
  LocalPrincipalIdentityV1,
  PlatformProcessIdentityV1,
  RecoveryClosureV1,
  Run,
  Session,
  StateLockIdentityV1,
  StateOwnerAcquisitionEvidenceV1,
  StateOwnerRecordV1,
  StateOwnerTransitionEvidenceV1,
  StateRootIdentityV1
} from '../kernel/types.js';
import { ArtifactCatalog, type PublishedArtifact } from './artifacts.js';
import {
  insertGenesisTimeFence,
  readTimeFence,
  recoverRegressedTimeFence,
  sampleCanonicalNow,
  transferTimeFenceOwner,
  type TimeFenceAdvance
} from './canonical-time.js';
import { ContentAddressedStore } from './cas.js';
import { openLocalControlListener, type AuthenticatedControlIdentity, type LocalControlConnection, type LocalControlListener } from './control-channel.js';
import { readControl, type ReadControlRequest } from './control-read.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertStateOwnerLock, loadNativeStateOwner, stateRootIdentityFromDescriptor, type HeldStateOwnerLock, type NativeStateOwner } from './native-owner.js';
import {
  decodePlatformProcessIdentity,
  decodeStateLockIdentity,
  decodeStateOwnerAcquisitionEvidence,
  decodeStateOwnerTransitionEvidence,
  decodeStateRootIdentity
} from './decoders.js';
import { admitRun, type AdmitRunInput, type AdmitRunResult } from './reducers/admission.js';
import { loadAgentRun, type LoadAgentRunInput } from './reducers/agent.js';
import {
  abandonUnknownInvocation,
  claimInvocationDispatch,
  completeInvocation,
  failClaimedInvocationWithoutRelease,
  failInvocationBeforeDispatch,
  markInvocationUnknown,
  prepareInvocation,
  type ClaimInvocationDispatchInput,
  type PrepareInvocationInput,
  type SettleInvocationInput
} from './reducers/invocation.js';
import { createSession, type CreateSessionInput, type CreateSessionResult } from './reducers/session.js';
import {
  activateWorkerLease,
  beginGenerationCheckpoint,
  beginGenerationRevocation,
  recordWorkerPreactivated,
  renewWorkerLease,
  reserveWorkerLaunch,
  sealWorkerGeneration,
  type ActivateWorkerLeaseInput,
  type BeginGenerationCheckpointInput,
  type BeginGenerationRevocationInput,
  type RecordWorkerPreactivatedInput,
  type RenewWorkerLeaseInput,
  type ReserveWorkerLaunchInput,
  type SealWorkerGenerationInput
} from './reducers/worker-launch.js';
import {
  recordWorkspaceGenerationPreactivated,
  registerWorkspaceGeneration,
  type RecordWorkspaceGenerationPreactivatedInput,
  type RegisterWorkspaceGenerationInput
} from './reducers/workspace-transition.js';
import { readRecoveryClosure } from './recovery-closure.js';
import { beginWorkerRecovery, beginWorkerRecoveryProbe, closeWorkerRecoveryProbe, type BeginWorkerRecoveryInput } from './reducers/worker-recovery.js';
import { readRun, readSession } from './rows.js';
import { applyKernelSchema, KERNEL_SCHEMA_SQL, readSchemaUserVersion } from './schema.js';
import { openSqliteDriver, type SqliteConnection, type SqliteDriver } from './sqlite-driver.js';
import {
  assertActiveStateOwner,
  assertContiguousStateOwnerHistory,
  contextFromStateOwner,
  gracefullyReleaseStateOwner,
  readActiveStateOwner,
  readLatestStateOwner,
  readStateOwner,
  insertStateOwnerArtifacts,
  terminalStateOwnerRecord,
  type StateOwnerContext
} from './state-owner.js';
import { hostPlatform } from './workspace-identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { loadRunExecution, type LoadRunExecutionInput, type RunExecutionInstallation } from './run-execution.js';
import { retireAbandonedPreactivations } from './preactivation-retirement.js';
import { verifyRuntimeBundle, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import type { SandboxProfileV1, SourceInspectionAttemptV1 } from '../kernel/execution.js';
import { normalizeRunSubmitRequest, runSubmitIntentDigest } from './source-target.js';
import { validateControlChannelClosure } from './control-channel.js';

/** Trusted Supervisor bootstrap input, never loaded from Run/workspace configuration. Required again on signed-owner reopen. */
export type StateStoreRuntimeAuthority = { bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[];
  execution?: RunExecutionInstallation;
  sourceInspection?: { controlledHome: string; sandboxProfile: SandboxProfileV1 } };

export type CaptureSubmittedSourceInput = Readonly<{ request: unknown; identity: AuthenticatedControlIdentity }>;
type SourceInspectionTask = { abort: AbortController; promise: Promise<SourceInspectionAttemptV1> };

export type {
  LoadAgentRunInput,
  ActivateWorkerLeaseInput,
  AdmitRunInput,
  AdmitRunResult,
  BeginGenerationCheckpointInput,
  BeginGenerationRevocationInput,
  BeginWorkerRecoveryInput,
  ClaimInvocationDispatchInput,
  CreateSessionInput,
  CreateSessionResult,
  PrepareInvocationInput,
  RecordWorkerPreactivatedInput,
  RecordWorkspaceGenerationPreactivatedInput,
  RegisterWorkspaceGenerationInput,
  RenewWorkerLeaseInput,
  ReserveWorkerLaunchInput,
  SealWorkerGenerationInput,
  SettleInvocationInput
};

const AUTHORITY_TABLES = [
  'canonical_time_fence',
  'state_owners',
  'artifacts',
  'sessions',
  'items',
  'runs',
  'checkpoints',
  'run_journal',
  'run_events',
  'worker_launches',
  'workspace_generations',
  'local_inference_activation_cycles',
  'local_inference_launches',
  'control_requests',
  'list_read_cuts',
  'list_read_cut_entries',
  'child_allocations',
  'authorization_grants',
  'source_inspection_attempts',
  'mcp_registrations',
  'admin_operations'
] as const;

function assertFreshAuthorityDatabaseEmpty(connection: SqliteConnection | SqliteDriver): void {
  for (const table of AUTHORITY_TABLES) {
    const row = connection
      .prepare(`SELECT count(*) AS count FROM ${table}`)
      .get<{ count: unknown }>();
    if (Number(row?.count ?? 0) !== 0) {
      throw new KernelStorageError(
        'RECOVERY_REQUIRED',
        `refusing fresh_empty genesis over non-empty authority table ${table}`
      );
    }
  }
}

function requireEffectiveUid(): number {
  if (typeof process.geteuid !== 'function') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'state store requires a POSIX effective uid');
  }
  return process.geteuid();
}

let currentProcessBasePromise:
  | Promise<{ processStartToken: string; executableImageDigest: string }>
  | undefined;

async function currentProcessBase(native: NativeStateOwner): Promise<{
  processStartToken: string;
  executableImageDigest: string;
}> {
  currentProcessBasePromise ??= (async () => {
    const executableImageDigest = sha256Bytes(await readFile(process.execPath));
    return {
      processStartToken: native.processStartToken(),
      executableImageDigest
    };
  })();
  return currentProcessBasePromise;
}

async function currentProcessIdentity(native: NativeStateOwner, observedAt: string): Promise<PlatformProcessIdentityV1> {
  const base = await currentProcessBase(native);
  const identity: PlatformProcessIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-platform-process-identity-v1',
    platform: hostPlatform(),
    pid: process.pid,
    processStartToken: base.processStartToken,
    ownerUid: requireEffectiveUid(),
    executableImageDigest: base.executableImageDigest,
    observedAt,
    identityDigest: ''
  };
  identity.identityDigest = digestOmitting(identity, 'identityDigest');
  return identity;
}

async function assertPrivateStateRoot(stateRoot: string): Promise<void> {
  let normalized: string;
  try {
    normalized = normalizeAbsolutePath(stateRoot);
  } catch {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must be a normalized absolute path');
  }
  if (normalized !== stateRoot) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must be a normalized absolute path');
  }
  const info = await lstat(stateRoot);
  if (info.isSymbolicLink()) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must not be a symbolic link');
  }
  if (!info.isDirectory()) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must be a directory');
  }
  if (info.uid !== requireEffectiveUid()) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root must be owned by the effective uid');
  }
  if ((info.mode & 0o7777) !== 0o700) {
    throw new KernelStorageError('INVALID_REQUEST', 'state root mode must be exactly 0700');
  }
}

async function ensurePrivateDirectory(directory: string, allowCreate: boolean): Promise<void> {
  let existing: Stats;
  try {
    existing = await lstat(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    if (!allowCreate) {
      throw new KernelStorageError(
        'RECOVERY_REQUIRED',
        `${directory} is missing from an existing StateOwner generation`
      );
    }
    await mkdir(directory, { mode: 0o700 });
    existing = await lstat(directory);
  }
  if (existing.isSymbolicLink() || !existing.isDirectory()) {
    throw new KernelStorageError('INVALID_REQUEST', `${directory} must be a 0700 directory`);
  }
  if (existing.uid !== requireEffectiveUid()) {
    throw new KernelStorageError('INVALID_REQUEST', `${directory} must be owned by the effective uid`);
  }
  const info = await lstat(directory);
  if (
    info.isSymbolicLink() ||
    !info.isDirectory() ||
    info.uid !== requireEffectiveUid() ||
    (info.mode & 0o7777) !== 0o700
  ) {
    throw new KernelStorageError('INVALID_REQUEST', `${directory} must be a 0700 directory`);
  }
}

async function stateOwnerFilesystemFromArtifacts(
  stateRoot: string,
  artifacts: ArtifactCatalog,
  owner: StateOwnerRecordV1,
  heldLock: HeldStateOwnerLock
): Promise<{
  lockIdentity: StateLockIdentityV1;
  filesystem: StateOwnerContext['filesystem'];
}> {
  const lockIdentity = decodeStateLockIdentity(
    await artifacts.readCanonical(owner.stateLockIdentityRef)
  );
  if (lockIdentity.identityDigest !== owner.stateLockIdentityDigest) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner lock identity does not rehash');
  }
  const rootIdentity = decodeStateRootIdentity(
    await artifacts.readCanonical(lockIdentity.stateRootIdentityRef)
  );
  if (
    rootIdentity.identityDigest !== lockIdentity.stateRootIdentityDigest ||
    rootIdentity.canonicalAbsolutePath !== stateRoot ||
    rootIdentity.ownerUid !== requireEffectiveUid() ||
    rootIdentity.platform !== hostPlatform() ||
    lockIdentity.ownerUid !== requireEffectiveUid()
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner root identity does not rehash');
  }
  assertStateOwnerLock(heldLock);
  if (
    heldLock.root.deviceId !== rootIdentity.deviceId ||
    heldLock.root.fileId !== rootIdentity.directoryFileId ||
    heldLock.lock.deviceId !== lockIdentity.deviceId ||
    heldLock.lock.fileId !== lockIdentity.fileId
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner filesystem identity changed during open');
  }
  return {
    lockIdentity,
    filesystem: heldLock
  };
}

async function stateOwnerContextFromArtifacts(
  stateRoot: string,
  artifacts: ArtifactCatalog,
  owner: Extract<StateOwnerRecordV1, { state: 'active' }>,
  heldLock: HeldStateOwnerLock
): Promise<StateOwnerContext> {
  const { lockIdentity, filesystem } = await stateOwnerFilesystemFromArtifacts(
    stateRoot,
    artifacts,
    owner,
    heldLock
  );
  await readStateOwnerProcess(artifacts, owner);
  return contextFromStateOwner(
    owner,
    filesystem,
    { ref: lockIdentity.stateRootIdentityRef, digest: lockIdentity.stateRootIdentityDigest }
  );
}

async function readStateOwnerProcess(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1): Promise<PlatformProcessIdentityV1> {
  const processIdentity = decodePlatformProcessIdentity(
    await artifacts.readCanonical(owner.processIdentityRef)
  );
  const acquisition = decodeStateOwnerAcquisitionEvidence(
    await artifacts.readCanonical(owner.acquisitionEvidenceRef)
  );
  if (
    processIdentity.identityDigest !== owner.processIdentityDigest ||
    processIdentity.executableImageDigest !== owner.supervisorExecutableDigest ||
    processIdentity.ownerUid !== requireEffectiveUid() ||
    processIdentity.platform !== hostPlatform() ||
    processIdentity.observedAt !== owner.acquiredAt ||
    acquisition.evidenceDigest !== owner.acquisitionEvidenceDigest ||
    acquisition.ownerEpoch !== owner.ownerEpoch ||
    acquisition.supervisorInstanceId !== owner.supervisorInstanceId ||
    acquisition.runtimeBundleRef !== owner.runtimeBundleRef ||
    acquisition.runtimeBundleManifestDigest !== owner.runtimeBundleManifestDigest ||
    acquisition.processIdentityRef !== owner.processIdentityRef ||
    acquisition.processIdentityDigest !== owner.processIdentityDigest ||
    acquisition.stateLockIdentityRef !== owner.stateLockIdentityRef ||
    acquisition.stateLockIdentityDigest !== owner.stateLockIdentityDigest ||
    acquisition.instanceNonceDigest !== owner.instanceNonceDigest ||
    acquisition.acquiredAt !== owner.acquiredAt ||
    (owner.ownerEpoch === 1
      ? acquisition.kind !== 'genesis'
      : acquisition.kind === 'genesis' || acquisition.priorOwnerEpoch !== owner.ownerEpoch - 1)
  ) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner process/acquisition closure does not match');
  }
  return processIdentity;
}

// Failed opening has no Store for a caller to close. Keep uncertain resources
// strongly owned until actual process death; skipping close alone would let
// the native finalizer release the flock after GC. This is resource retention,
// not another durable lifecycle or a permission to retry the failed opening.
const unretiredStateStoreOpenings = new Set<Readonly<{
  lock: HeldStateOwnerLock; driver: SqliteDriver | undefined; failure: ResourceRetirementError;
}>>();
// A rejected close can outlive the caller too. GC is not a successful join;
// release this strong owner only after the exact close actually succeeds.
const unretiredStateStoreClosings = new Set<StateStore>();

export class StateStore {
  private closed = false;
  private released = false;
  private closeRequested = false;
  private closing: Promise<void> | undefined;
  private readonly controlListeners = new Set<LocalControlListener>();
  // Reserve the Run through validation and join that opening during shutdown.
  // This protects resources; SQLite remains the sole lifecycle authority.
  private readonly executions = new Map<string, Promise<Awaited<ReturnType<typeof loadRunExecution>>>>();
  private readonly sourceInspectionTasks = new Set<SourceInspectionTask>();
  private readonly sourceInspections = new Map<string, { intent: string; task: SourceInspectionTask }>();

  private constructor(
    readonly stateRoot: string,
    private readonly driver: SqliteDriver,
    readonly artifacts: ArtifactCatalog,
    private readonly owner: StateOwnerContext,
    private readonly runtimeAuthority?: StateStoreRuntimeAuthority
  ) {}

  get ownerEpoch(): number {
    return this.owner.ownerEpoch;
  }

  get stateRootIdentity(): { ref: string; digest: string } {
    return {
      ref: this.owner.stateRootIdentityRef,
      digest: this.owner.stateRootIdentityDigest
    };
  }

  /** Internal authenticated transport, not an installed public protocol server. */
  openLocalControl(onConnection: (connection: LocalControlConnection) => void, onError: (error: Error) => void): LocalControlListener {
    if (this.closed || this.closing || this.released) throw new KernelStorageError('RECOVERY_REQUIRED', 'StateStore is closing or closed');
    assertActiveStateOwner(this.driver, this.owner);
    const nativeListener = openLocalControlListener(this.artifacts, this.owner, onConnection, onError);
    const listener: LocalControlListener = Object.freeze({ close: () => {
      const closing = nativeListener.close();
      void closing.then(() => this.controlListeners.delete(listener), () => {});
      return closing;
    } });
    this.controlListeners.add(listener);
    return listener;
  }

  static async open(stateRoot: string, runtimeAuthority?: StateStoreRuntimeAuthority): Promise<StateStore> {
    runtimeAuthority = runtimeAuthority === undefined ? undefined : immutableSnapshot(runtimeAuthority);
    if (process.platform !== 'darwin' && process.platform !== 'linux') {
      throw new KernelStorageError('UNSUPPORTED_PLATFORM', `state store is unsupported on ${process.platform}`);
    }
    if (runtimeAuthority) {
      verifyRuntimeBundle(runtimeAuthority.bundle, runtimeAuthority.releaseKeys);
    }
    const native = await loadNativeStateOwner(runtimeAuthority?.bundle);
    if (runtimeAuthority) {
      const supervisor = runtimeAuthority.bundle.entries.find((entry) => entry.role === 'supervisor')!;
      if (supervisor.digest !== (await currentProcessBase(native)).executableImageDigest ||
          runtimeAuthority.bundle.stateSchemaRange.min > KERNEL_STATE_SCHEMA_VERSION ||
          runtimeAuthority.bundle.stateSchemaRange.max < KERNEL_STATE_SCHEMA_VERSION) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'signed Supervisor does not match this process or state schema');
      }
    }
    await assertPrivateStateRoot(stateRoot);
    const casRoot = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
    const databasePath = path.join(stateRoot, KERNEL_DATABASE_FILENAME);
    const databaseExists = await lstat(databasePath).then(() => true, (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return false;
      throw error;
    });
    let heldLock: HeldStateOwnerLock;
    try {
      // An existing database must never silently recreate a missing lock inode.
      heldLock = Object.freeze(native.acquireLock(stateRoot, !databaseExists));
    } catch (error) {
      throw new KernelStorageError('RECOVERY_REQUIRED', error instanceof Error ? error.message : 'StateOwner OS lock acquisition failed');
    }
    let driver: SqliteDriver | undefined;
    try {
      assertStateOwnerLock(heldLock);
      driver = openSqliteDriver(databasePath);
      const preflightSchemaVersion = readSchemaUserVersion(driver);
      if (preflightSchemaVersion === 1) {
        const priorOwners = driver
          .prepare('SELECT count(*) AS count FROM state_owners')
          .get<{ count: unknown }>();
        if (Number(priorOwners?.count ?? 0) !== 0) {
          throw new KernelStorageError(
            'RECOVERY_REQUIRED',
            'schema-v1 authority requires the explicit WP01 generation migration path'
          );
        }
      }
      applyKernelSchema(driver);
      const ownerHistory = driver
        .prepare('SELECT count(*) AS count FROM state_owners')
        .get<{ count: unknown }>();
      const allowLayoutCreation = Number(ownerHistory?.count ?? 0) === 0;
      await ensurePrivateDirectory(casRoot, allowLayoutCreation);
      const artifacts = new ArtifactCatalog(new ContentAddressedStore(casRoot));
      const owner = await acquireOrBootstrapStateOwner(stateRoot, driver, artifacts, native, heldLock, runtimeAuthority?.bundle);
      const ownerContext = await stateOwnerContextFromArtifacts(stateRoot, artifacts, owner, heldLock);
      // Close abandoned capture resources before publishing the successor
      // Store. Retained reservations replace neither source nor client: only
      // actual authenticated replay later binds the immutable error response.
      const { retireAbandonedSourceInspections } = await import('./source-inspection-owner.js');
      await retireAbandonedSourceInspections(driver, artifacts, ownerContext,
        runtimeAuthority?.sourceInspection && { bundle: runtimeAuthority.bundle,
          releaseKeys: runtimeAuthority.releaseKeys, sandboxProfile: runtimeAuthority.sourceInspection.sandboxProfile });
      await retireAbandonedPreactivations(driver, artifacts, ownerContext,
        runtimeAuthority?.execution && { ...runtimeAuthority.execution,
          runtimeAuthority: { bundle: runtimeAuthority.bundle, releaseKeys: runtimeAuthority.releaseKeys } });
      return new StateStore(stateRoot, driver, artifacts, ownerContext, runtimeAuthority);
    } catch (error) {
      let failure = error;
      if (!(error instanceof ResourceRetirementError)) {
        try {
          // A failed SQLite close must retain the flock, rather than free the
          // native owner while database resource retirement is unproven.
          driver?.close();
          heldLock.close();
        } catch (cause) {
          failure = new ResourceRetirementError('StateStore opening resources did not retire',
            new AggregateError([error, cause]));
        }
      }
      if (failure instanceof ResourceRetirementError)
        unretiredStateStoreOpenings.add(Object.freeze({ lock: heldLock, driver, failure }));
      throw failure;
    }
  }

  createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
    return createSession(this.driver, this.artifacts, this.owner, input);
  }

  admitRun(input: AdmitRunInput): Promise<AdmitRunResult> {
    return admitRun(this.driver, this.artifacts, this.owner, input);
  }

  registerWorkspaceGeneration(input: RegisterWorkspaceGenerationInput) {
    return registerWorkspaceGeneration(this.driver, this.artifacts, this.owner, input);
  }

  recordWorkspaceGenerationPreactivated(input: RecordWorkspaceGenerationPreactivatedInput) {
    return recordWorkspaceGenerationPreactivated(this.driver, this.artifacts, this.owner, input);
  }

  reserveWorkerLaunch(input: ReserveWorkerLaunchInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return reserveWorkerLaunch(this.driver, this.artifacts, this.owner, input);
  }

  recordWorkerPreactivated(input: RecordWorkerPreactivatedInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return recordWorkerPreactivated(this.driver, this.artifacts, this.owner, input);
  }

  activateWorkerLease(input: ActivateWorkerLeaseInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    return activateWorkerLease(this.driver, this.owner, input);
  }

  renewWorkerLease(input: RenewWorkerLeaseInput) {
    return renewWorkerLease(this.driver, this.owner, input);
  }

  beginGenerationRevocation(input: BeginGenerationRevocationInput) {
    return beginGenerationRevocation(this.driver, this.owner, input);
  }

  beginGenerationCheckpoint(input: BeginGenerationCheckpointInput) {
    return beginGenerationCheckpoint(this.driver, this.owner, input);
  }

  sealWorkerGeneration(input: SealWorkerGenerationInput) {
    return sealWorkerGeneration(this.driver, this.artifacts, this.owner, input);
  }

  prepareInvocation(input: PrepareInvocationInput) {
    return prepareInvocation(this.driver, this.artifacts, this.owner, input);
  }

  loadAgentRun(input: LoadAgentRunInput) {
    return loadAgentRun(this.driver, this.artifacts, this.owner, input);
  }

  async loadRunExecution(input: LoadRunExecutionInput) {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    const runId = input.runId;
    if (this.executions.has(runId)) throw new KernelStorageError('REVISION_CONFLICT', 'Run already has an execution resource owner');
    const opening = loadRunExecution(this.driver, this.artifacts, this.owner, this.runtimeAuthority, input,
      () => this.closed || this.closeRequested || this.released);
    this.executions.set(runId, opening);
    let scope: Awaited<typeof opening> | undefined;
    try {
      scope = await opening;
      if (this.closed || this.closeRequested || this.released) {
        await scope.close();
        throw new KernelStorageError('LEASE_FENCED', 'StateStore closed while loading execution');
      }
      return scope.execution;
    } catch (error) {
      // A failed factory whose cleanup completed releases its reservation.
      // A resolved scope or unjoined opening must remain owned across close
      // retries, even when the original load caller receives an error.
      if (!scope && !(error instanceof ResourceRetirementError) && this.executions.get(runId) === opening) {
        this.executions.delete(runId);
      }
      throw error;
    }
  }

  /** Internal source producer, not a public wire method or accepted Run.
   * The whole factory, including validation/replay reads, is Store-owned before
   * its first asynchronous action; shutdown cancels and joins every operation. */
  async captureSubmittedSource(input: CaptureSubmittedSourceInput): Promise<SourceInspectionAttemptV1> {
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    input = immutableSnapshot(input);
    if (!input || Object.keys(input).length !== 2 || !Object.hasOwn(input, 'request') || !Object.hasOwn(input, 'identity')) {
      throw new KernelStorageError('INVALID_REQUEST', 'source capture requires one inline request and authenticated identity');
    }
    const normalized = normalizeRunSubmitRequest(input.request);
    const key = identityHash('cliq-source-inspection-task-v1', input.identity.principalId, normalized.request.admissionKey);
    const intent = runSubmitIntentDigest(input.identity.principalId, normalized.request);
    const existing = this.sourceInspections.get(key);
    const abort = new AbortController();
    const promise = Promise.resolve().then(async () => {
      abort.signal.throwIfAborted();
      await validateControlChannelClosure(this.artifacts, this.owner, input.identity);
      abort.signal.throwIfAborted();
      assertActiveStateOwner(this.driver, this.owner);
      const { captureSubmittedSource, assertSourceInspectionRequestId } = await import('./source-inspection-owner.js');
      assertSourceInspectionRequestId(this.driver, input.identity.principalId, normalized.request,
        existing && identityHash('cliq-source-inspection-v1', input.identity.principalId, 'run.submit', normalized.request.admissionKey, intent));
      if (existing) {
        if (existing.intent !== intent) throw new KernelStorageError('ADMISSION_KEY_CONFLICT', 'source key belongs to a different original intent');
        // Join one physical task, then bind this authenticated follower through
        // the ordinary retained replay path. A failed resource join propagates
        // as-is; it must never become a new capture of live source bytes.
        await existing.task.promise;
      }
      const bootstrap = this.runtimeAuthority;
      if (!bootstrap?.sourceInspection) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'trusted source inspection installation is not configured');
      abort.signal.throwIfAborted();
      return captureSubmittedSource(this.driver, this.artifacts, this.owner,
        { bundle: bootstrap.bundle, releaseKeys: bootstrap.releaseKeys, ...bootstrap.sourceInspection }, input, abort.signal);
    });
    const task: SourceInspectionTask = { abort, promise };
    this.sourceInspectionTasks.add(task);
    if (!existing) this.sourceInspections.set(key, { intent, task });
    const settled = (error?: unknown) => {
      // A rejected resource join is retained across close retries. Ordinary
      // validation failures own nothing once their complete task has ended.
      if (!(error instanceof ResourceRetirementError)) {
        if (this.sourceInspections.get(key)?.task === task) this.sourceInspections.delete(key);
        this.sourceInspectionTasks.delete(task);
      }
    };
    void promise.then(() => settled(), settled);
    return promise;
  }

  claimInvocationDispatch(input: ClaimInvocationDispatchInput) {
    return claimInvocationDispatch(this.driver, this.artifacts, this.owner, input);
  }

  completeInvocation(
    input: SettleInvocationInput & {
      resultRef?: string;
      receiptRef?: string;
      consumed: import('../kernel/types.js').BudgetUsage;
    }
  ) {
    return completeInvocation(this.driver, this.artifacts, this.owner, input);
  }

  failInvocationBeforeDispatch(input: SettleInvocationInput & { errorRef: string }) {
    return failInvocationBeforeDispatch(this.driver, this.artifacts, this.owner, input);
  }

  failClaimedInvocationWithoutRelease(
    input: SettleInvocationInput & { errorRef: string; evidenceRef: string; evidenceDigest: string }
  ) {
    return failClaimedInvocationWithoutRelease(this.driver, this.artifacts, this.owner, input);
  }

  markInvocationUnknown(
    input: SettleInvocationInput & { evidenceRef: string; evidenceDigest: string }
  ) {
    return markInvocationUnknown(this.driver, this.artifacts, this.owner, input);
  }

  abandonUnknownInvocation(input: {
    runId: string;
    opId: string;
    attempt: number;
    attestationRef: string;
  }) {
    return abandonUnknownInvocation(this.driver, this.artifacts, this.owner, input);
  }

  getSession(sessionId: string): Session {
    return readSession(this.driver, sessionId);
  }

  /** Canonical bounded queries shared by clients; identity comes from the control channel, never the request. */
  readControl(request: ReadControlRequest, identity: AuthenticatedControlIdentity) {
    return readControl(this.driver, this.artifacts, this.owner, request, identity);
  }

  getRun(runId: string): Run {
    return readRun(this.driver, runId);
  }

  readRecoveryClosure(runId: string): Promise<RecoveryClosureV1> {
    return readRecoveryClosure(this.driver, this.artifacts, runId);
  }

  beginWorkerRecovery(input: BeginWorkerRecoveryInput): Promise<Run> {
    return beginWorkerRecovery(this.driver, this.artifacts, this.owner, input);
  }

  beginWorkerRecoveryProbe(input: { runId: string; expectedRunRevision: number }) {
    if (this.closed || this.closeRequested || this.released) {
      return Promise.reject(new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed'));
    }
    return beginWorkerRecoveryProbe(this.driver, this.artifacts, this.owner, input);
  }

  async closeWorkerRecoveryProbe(input: { runId: string; expectedRunRevision: number }) {
    input = immutableSnapshot(input);
    if (this.closed || this.closeRequested || this.released) throw new KernelStorageError('LEASE_FENCED', 'StateStore is closing or closed');
    const opening = this.executions.get(input.runId);
    if (opening) return (await opening).closeWorkerRecoveryProbe(input);
    return closeWorkerRecoveryProbe(this.driver, this.artifacts, this.owner, input);
  }

  recoverCanonicalTime(): TimeFenceAdvance {
    let outcome!: TimeFenceAdvance;
    this.driver.transaction((connection) => {
      assertActiveStateOwner(connection, this.owner);
      outcome = recoverRegressedTimeFence(connection, this.owner.ownerEpoch);
    });
    return outcome;
  }

  close(): Promise<void> {
    if (this.closed) return Promise.resolve();
    if (this.closing !== undefined) return this.closing;
    // The gate is synchronous: existing execution references cannot dispatch
    // while listeners/opening resources are being joined.
    this.closeRequested = true;
    for (const task of this.sourceInspectionTasks) task.abort.abort();
    const attempt = (async () => {
      const results = await Promise.allSettled([
        ...[...this.controlListeners].map(listener => listener.close()),
        ...[...this.sourceInspectionTasks].map(async task => {
          try { await task.promise; }
          catch (error) { if (error instanceof ResourceRetirementError) throw error; }
        }),
        ...[...this.executions.entries()].map(async ([runId, opening]) => {
          let scope: Awaited<typeof opening> | undefined;
          try { scope = await opening; await scope.close(); }
          catch (error) {
            if (scope || error instanceof ResourceRetirementError) throw error;
            // Ordinary failed validation owns no outstanding resources; it
            // must not make an otherwise successful Store shutdown fail.
            if (this.executions.get(runId) === opening) this.executions.delete(runId);
          }
        })
      ]);
      const failure = results.find(result => result.status === 'rejected');
      if (failure?.status === 'rejected') throw failure.reason;
      this.executions.clear();
      if (!this.released) {
        await retireAbandonedPreactivations(this.driver, this.artifacts, this.owner,
          this.runtimeAuthority?.execution && { ...this.runtimeAuthority.execution,
            runtimeAuthority: { bundle: this.runtimeAuthority.bundle, releaseKeys: this.runtimeAuthority.releaseKeys } });
        await gracefullyReleaseStateOwner(this.driver, this.artifacts, this.owner);
        this.released = true;
      }
      this.driver.close();
      this.owner.filesystem.close();
      this.closed = true;
      unretiredStateStoreClosings.delete(this);
    })();
    this.closing = attempt.catch((error: unknown) => {
      unretiredStateStoreClosings.add(this);
      this.closing = undefined;
      // Failed close retains the owner and permits its exact recovery path;
      // it never makes a retired execution resource reusable.
      this.closeRequested = false;
      throw error;
    });
    return this.closing;
  }
}

export async function openStateStore(stateRoot: string, runtimeAuthority?: StateStoreRuntimeAuthority): Promise<StateStore> {
  return StateStore.open(stateRoot, runtimeAuthority);
}

async function acquireOrBootstrapStateOwner(
  stateRoot: string,
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  native: NativeStateOwner,
  heldLock: HeldStateOwnerLock,
  runtimeBundle?: RuntimeBundleManifest
): Promise<Extract<StateOwnerRecordV1, { state: 'active' }>> {
  assertContiguousStateOwnerHistory(driver);
  const existingOwner = readActiveStateOwner(driver);
  const fence = readTimeFence(driver);
  const latestOwner = readLatestStateOwner(driver);
  if (latestOwner !== undefined) {
    if (fence === undefined || fence.stateOwnerEpoch !== latestOwner.ownerEpoch) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner history and time fence do not match');
    }
    if (existingOwner !== undefined && existingOwner.rowDigest !== latestOwner.rowDigest) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'active state owner is not the latest owner');
    }
    if (latestOwner.state === 'terminal' && latestOwner.terminalReason !== 'graceful_release') {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'latest state owner is not cleanly acquirable');
    }
    const retainedRuntime = await artifacts.readCanonical<{ format?: string }>(latestOwner.runtimeBundleRef);
    const supervisor = runtimeBundle?.entries.find((entry) => entry.role === 'supervisor');
    if (runtimeBundle ? canonicalSha256(runtimeBundle) !== latestOwner.runtimeBundleRef ||
        runtimeBundle.manifestDigest !== latestOwner.runtimeBundleManifestDigest ||
        supervisor?.entryId !== latestOwner.supervisorEntryId || supervisor.version !== latestOwner.supervisorEntryVersion ||
        supervisor.digest !== latestOwner.supervisorExecutableDigest :
        retainedRuntime.format !== 'cliq-kernel-schema-manifest-v1') {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'reopen requires the same signed Supervisor authority; runtime upgrades need their own transition');
    }
    return acquireSuccessorStateOwner(stateRoot, driver, artifacts, latestOwner, native, heldLock);
  }
  if (fence !== undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence exists without state owner history');
  }
  assertFreshAuthorityDatabaseEmpty(driver);

  const casRoot = path.join(stateRoot, KERNEL_CAS_DIRECTORY);
  const existingCasEntries = await readdir(casRoot);
  if (existingCasEntries.length !== 0) {
    throw new KernelStorageError(
      'RECOVERY_REQUIRED',
      'refusing fresh_empty genesis over a non-empty CAS namespace'
    );
  }

  const now = sampleCanonicalNow();
  const platform = hostPlatform();
  const uid = requireEffectiveUid();
  const casInfo = await lstat(casRoot, { bigint: true });
  assertStateOwnerLock(heldLock);

  const stateRootIdentity = stateRootIdentityFromDescriptor(stateRoot, heldLock.root);
  const stateRootArtifact = await artifacts.publishCanonical(stateRootIdentity, 'cliq-state-root-identity-v1');

  const processIdentity = await currentProcessIdentity(native, now);
  const processArtifact = await artifacts.publishCanonical(processIdentity, 'cliq-platform-process-identity-v1');

  const lockIdentity: StateLockIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-state-lock-identity-v1',
    stateRootIdentityRef: stateRootArtifact.ref,
    stateRootIdentityDigest: stateRootIdentity.identityDigest,
    canonicalRootRelativePath: 'runtime/state-owner.lock',
    deviceId: heldLock.lock.deviceId,
    fileId: heldLock.lock.fileId,
    ownerUid: heldLock.lock.ownerUid,
    mode: 384,
    linkCount: 1,
    identityDigest: ''
  };
  lockIdentity.identityDigest = digestOmitting(lockIdentity, 'identityDigest');
  const lockArtifact = await artifacts.publishCanonical(lockIdentity, 'cliq-state-lock-identity-v1');

  const schemaDigest = sha256Bytes(Buffer.from(KERNEL_SCHEMA_SQL, 'utf8'));
  const schemaManifest = {
    schemaVersion: 1,
    format: 'cliq-kernel-schema-manifest-v1',
    applicationId: KERNEL_SQLITE_APPLICATION_ID,
    userVersion: KERNEL_STATE_SCHEMA_VERSION,
    schemaDigest,
    manifestDigest: ''
  };
  schemaManifest.manifestDigest = digestOmitting(schemaManifest, 'manifestDigest');
  const schemaArtifact = await artifacts.publishCanonical(schemaManifest, 'cliq-kernel-schema-manifest-v1');
  const runtimeArtifact = runtimeBundle ? await artifacts.publishCanonical(runtimeBundle, 'cliq-runtime-bundle-v1') : schemaArtifact;
  const supervisor = runtimeBundle?.entries.find((entry) => entry.role === 'supervisor');

  const emptyDatabase = {
    schemaVersion: 1,
    format: 'cliq-kernel-empty-database-v1',
    applicationId: KERNEL_SQLITE_APPLICATION_ID,
    userVersion: readSchemaUserVersion(driver),
    contentDigest: canonicalSha256({
      applicationId: KERNEL_SQLITE_APPLICATION_ID,
      userVersion: KERNEL_STATE_SCHEMA_VERSION,
      tables: AUTHORITY_TABLES.length
    })
  };
  const databaseArtifact = await artifacts.publishCanonical(emptyDatabase, 'cliq-kernel-empty-database-v1');

  const casNamespace = {
    schemaVersion: 1,
    format: 'cliq-cas-namespace-manifest-v1',
    snapshotBoundary: 'generation_birth',
    namespaceId: identityHash('cliq-cas-namespace-v1', stateRootIdentity.identityDigest, 'cas'),
    stateRootIdentityRef: stateRootArtifact.ref,
    stateRootIdentityDigest: stateRootIdentity.identityDigest,
    canonicalRootRelativePath: KERNEL_CAS_DIRECTORY,
    ownerUid: uid,
    deviceId: unsignedDecimalId(casInfo.dev),
    directoryFileId: unsignedDecimalId(casInfo.ino),
    mode: 448,
    entries: [] as Array<{ artifactRef: string; byteCount: number }>,
    objectCount: 0,
    totalBytes: 0,
    rootDigest: canonicalSha256([]),
    manifestDigest: ''
  };
  casNamespace.manifestDigest = digestOmitting(casNamespace, 'manifestDigest');
  const casArtifact = await artifacts.publishCanonical(casNamespace, 'cliq-cas-namespace-manifest-v1');

  const generation: KernelGenerationIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-kernel-generation-identity-v1',
    generationId: identityHash('cliq-kernel-generation-v1', stateRootIdentity.identityDigest, 'fresh_empty'),
    stateRootIdentityRef: stateRootArtifact.ref,
    stateRootIdentityDigest: stateRootIdentity.identityDigest,
    databaseImageRef: databaseArtifact.ref,
    databaseImageDigest: databaseArtifact.ref,
    databaseIdentityDigest: databaseArtifact.ref,
    databaseContentDigest: emptyDatabase.contentDigest,
    casNamespaceManifestRef: casArtifact.ref,
    casNamespaceManifestDigest: casNamespace.manifestDigest,
    casNamespaceId: casNamespace.namespaceId,
    casRootDigest: casNamespace.rootDigest,
    stateSchemaVersion: 1,
    generationDigest: '',
    origin: 'fresh_empty',
    pristineSchemaManifestRef: schemaArtifact.ref,
    pristineSchemaManifestDigest: schemaManifest.manifestDigest,
    pristineSchemaDigest: schemaDigest
  };
  generation.generationDigest = digestOmitting(generation, 'generationDigest');
  const generationArtifact = await artifacts.publishCanonical(generation, 'cliq-kernel-generation-identity-v1');

  const supervisorInstanceId = identityHash('cliq-supervisor-instance-v1', processIdentity.identityDigest, now);
  const instanceNonceDigest = sha256Bytes(randomBytes(32));
  const acquisition: StateOwnerAcquisitionEvidenceV1 = {
    schemaVersion: 1,
    format: 'cliq-state-owner-acquisition-evidence-v1',
    ownerEpoch: 1,
    supervisorInstanceId,
    runtimeBundleRef: runtimeArtifact.ref,
    runtimeBundleManifestDigest: runtimeBundle?.manifestDigest ?? schemaManifest.manifestDigest,
    processIdentityRef: processArtifact.ref,
    processIdentityDigest: processIdentity.identityDigest,
    stateLockIdentityRef: lockArtifact.ref,
    stateLockIdentityDigest: lockIdentity.identityDigest,
    instanceNonceDigest,
    acquiredAt: now,
    evidenceDigest: '',
    kind: 'genesis',
    kernelGenerationIdentityRef: generationArtifact.ref,
    kernelGenerationIdentityDigest: generation.generationDigest,
    ownerTableObservation: 'empty'
  };
  acquisition.evidenceDigest = digestOmitting(acquisition, 'evidenceDigest');
  const acquisitionArtifact = await artifacts.publishCanonical(
    acquisition,
    'cliq-state-owner-acquisition-evidence-v1'
  );

  const owner: Extract<StateOwnerRecordV1, { state: 'active' }> = {
    schemaVersion: 1,
    ownerEpoch: 1,
    supervisorInstanceId,
    runtimeBundleRef: runtimeArtifact.ref,
    runtimeBundleManifestDigest: runtimeBundle?.manifestDigest ?? schemaManifest.manifestDigest,
    supervisorEntryId: supervisor?.entryId ?? 'state-store',
    supervisorEntryVersion: supervisor?.version ?? 'm2',
    supervisorExecutableDigest: processIdentity.executableImageDigest,
    processIdentityRef: processArtifact.ref,
    processIdentityDigest: processIdentity.identityDigest,
    stateLockIdentityRef: lockArtifact.ref,
    stateLockIdentityDigest: lockIdentity.identityDigest,
    acquisitionEvidenceRef: acquisitionArtifact.ref,
    acquisitionEvidenceDigest: acquisition.evidenceDigest,
    instanceNonceDigest,
    acquiredAt: now,
    rowDigest: '',
    state: 'active',
    rowVersion: 1
  };
  owner.rowDigest = digestOmitting(owner, 'rowDigest');

  driver.transaction((connection) => {
    assertStateOwnerLock(heldLock);
    assertFreshAuthorityDatabaseEmpty(connection);
    insertStateOwnerArtifacts(
      connection,
      [
        stateRootArtifact,
        processArtifact,
        lockArtifact,
        schemaArtifact,
        ...(runtimeBundle ? [runtimeArtifact] : []),
        databaseArtifact,
        casArtifact,
        generationArtifact,
        acquisitionArtifact
      ],
      now
    );
    insertGenesisTimeFence(connection, 1, now);
    connection
      .prepare(
        `INSERT INTO state_owners (owner_epoch, supervisor_instance_id, record_json, state, row_digest)
         VALUES (1, ?, ?, 'active', ?)`
      )
      .run(supervisorInstanceId, JSON.stringify(owner), owner.rowDigest);
  });
  return owner;
}

async function readStateOwnerTransition(
  artifacts: ArtifactCatalog,
  prior: Extract<StateOwnerRecordV1, { state: 'terminal' }>,
  successor?: StateOwnerRecordV1
): Promise<StateOwnerTransitionEvidenceV1> {
  const transition = decodeStateOwnerTransitionEvidence(await artifacts.readCanonical(prior.transitionEvidenceRef));
  if (transition.kind !== prior.terminalReason || transition.evidenceDigest !== prior.transitionEvidenceDigest ||
      transition.priorOwnerEpoch !== prior.ownerEpoch || transition.priorSupervisorInstanceId !== prior.supervisorInstanceId ||
      transition.priorProcessIdentityRef !== prior.processIdentityRef || transition.priorProcessIdentityDigest !== prior.processIdentityDigest ||
      transition.stateLockIdentityRef !== prior.stateLockIdentityRef || transition.stateLockIdentityDigest !== prior.stateLockIdentityDigest ||
      (transition.kind === 'graceful_release'
        ? transition.releasingProcessIdentityRef !== prior.processIdentityRef || transition.releasingProcessIdentityDigest !== prior.processIdentityDigest
        : !successor || transition.successorOwnerEpoch !== successor.ownerEpoch ||
          transition.successorSupervisorInstanceId !== successor.supervisorInstanceId ||
          transition.successorRuntimeBundleRef !== successor.runtimeBundleRef ||
          transition.successorRuntimeBundleManifestDigest !== successor.runtimeBundleManifestDigest ||
          transition.successorProcessIdentityRef !== successor.processIdentityRef ||
          transition.successorProcessIdentityDigest !== successor.processIdentityDigest ||
          transition.successorInstanceNonceDigest !== successor.instanceNonceDigest || transition.observedAt !== successor.acquiredAt)) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner transition evidence does not match its prior/successor');
  }
  return transition;
}

async function validateOwnerPredecessor(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerRecordV1): Promise<void> {
  const acquisition = decodeStateOwnerAcquisitionEvidence(await artifacts.readCanonical(owner.acquisitionEvidenceRef));
  if (acquisition.kind === 'genesis') return;
  const prior = readStateOwner(driver, acquisition.priorOwnerEpoch);
  if (!prior || prior.state !== 'terminal' || prior.rowDigest !== acquisition.priorTerminalRowDigest ||
      prior.terminalReason !== acquisition.priorTerminalReason || prior.transitionEvidenceRef !== acquisition.priorTransitionEvidenceRef ||
      prior.transitionEvidenceDigest !== acquisition.priorTransitionEvidenceDigest ||
      prior.stateLockIdentityRef !== owner.stateLockIdentityRef || prior.stateLockIdentityDigest !== owner.stateLockIdentityDigest) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner acquisition does not match its retained predecessor');
  }
  await readStateOwnerTransition(artifacts, prior, owner);
}

function assertPriorProcessDead(heldLock: HeldStateOwnerLock, identity: PlatformProcessIdentityV1): void {
  try { heldLock.assertPriorProcessDead(identity.pid, identity.processStartToken); }
  catch (error) {
    throw new KernelStorageError('RECOVERY_REQUIRED', error instanceof Error ? error.message : 'prior StateOwner process death is unproven');
  }
}

async function acquireSuccessorStateOwner(
  stateRoot: string,
  driver: SqliteDriver,
  artifacts: ArtifactCatalog,
  prior: StateOwnerRecordV1,
  native: NativeStateOwner,
  heldLock: HeldStateOwnerLock
): Promise<Extract<StateOwnerRecordV1, { state: 'active' }>> {
  await stateOwnerFilesystemFromArtifacts(stateRoot, artifacts, prior, heldLock);
  const priorProcess = await readStateOwnerProcess(artifacts, prior);
  await validateOwnerPredecessor(driver, artifacts, prior);
  if (prior.state === 'terminal') await readStateOwnerTransition(artifacts, prior);

  const currentFence = readTimeFence(driver);
  if (currentFence === undefined || currentFence.stateOwnerEpoch !== prior.ownerEpoch) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'canonical time fence does not match prior owner history');
  }
  const acquiredAt = sampleCanonicalNow();
  if (prior.state === 'active') assertPriorProcessDead(heldLock, priorProcess);
  const artifactCreatedAt = acquiredAt >= currentFence.lastAcceptedAt
    ? acquiredAt
    : currentFence.lastAcceptedAt;
  const processIdentity = await currentProcessIdentity(native, acquiredAt);
  const processArtifact = await artifacts.publishCanonical(
    processIdentity,
    'cliq-platform-process-identity-v1'
  );
  const ownerEpoch = prior.ownerEpoch + 1;
  const supervisorInstanceId = identityHash(
    'cliq-supervisor-instance-v1',
    processIdentity.identityDigest,
    acquiredAt,
    String(ownerEpoch)
  );
  const instanceNonceDigest = sha256Bytes(randomBytes(32));
  let terminal: Extract<StateOwnerRecordV1, { state: 'terminal' }>;
  let transitionArtifact: PublishedArtifact | undefined;
  if (prior.state === 'active') {
    const transition: StateOwnerTransitionEvidenceV1 = {
      schemaVersion: 1, format: 'cliq-state-owner-transition-evidence-v1',
      priorOwnerEpoch: prior.ownerEpoch, priorSupervisorInstanceId: prior.supervisorInstanceId,
      priorProcessIdentityRef: prior.processIdentityRef, priorProcessIdentityDigest: prior.processIdentityDigest,
      stateLockIdentityRef: prior.stateLockIdentityRef, stateLockIdentityDigest: prior.stateLockIdentityDigest,
      observedAt: acquiredAt, evidenceDigest: '', kind: 'superseded_after_owner_death',
      priorProcessObservation: 'absent_or_start_token_mismatch', successorOwnerEpoch: ownerEpoch,
      successorSupervisorInstanceId: supervisorInstanceId, successorRuntimeBundleRef: prior.runtimeBundleRef,
      successorRuntimeBundleManifestDigest: prior.runtimeBundleManifestDigest,
      successorProcessIdentityRef: processArtifact.ref, successorProcessIdentityDigest: processIdentity.identityDigest,
      successorInstanceNonceDigest: instanceNonceDigest
    };
    transition.evidenceDigest = digestOmitting(transition, 'evidenceDigest');
    transitionArtifact = await artifacts.publishCanonical(transition, 'cliq-state-owner-transition-evidence-v1');
    terminal = terminalStateOwnerRecord(prior, transition, transitionArtifact.ref, artifactCreatedAt);
  } else {
    terminal = prior;
  }
  const acquisition: StateOwnerAcquisitionEvidenceV1 = {
    schemaVersion: 1,
    format: 'cliq-state-owner-acquisition-evidence-v1',
    ownerEpoch,
    supervisorInstanceId,
    runtimeBundleRef: prior.runtimeBundleRef,
    runtimeBundleManifestDigest: prior.runtimeBundleManifestDigest,
    processIdentityRef: processArtifact.ref,
    processIdentityDigest: processIdentity.identityDigest,
    stateLockIdentityRef: prior.stateLockIdentityRef,
    stateLockIdentityDigest: prior.stateLockIdentityDigest,
    instanceNonceDigest,
    acquiredAt,
    evidenceDigest: '',
    ...(prior.state === 'active'
      ? { kind: 'takeover_after_owner_death' as const, priorTerminalReason: 'superseded_after_owner_death' as const }
      : { kind: 'acquire_after_graceful_release' as const, priorTerminalReason: 'graceful_release' as const }),
    priorOwnerEpoch: prior.ownerEpoch,
    priorTerminalRowDigest: terminal.rowDigest,
    priorTransitionEvidenceRef: terminal.transitionEvidenceRef,
    priorTransitionEvidenceDigest: terminal.transitionEvidenceDigest
  };
  acquisition.evidenceDigest = digestOmitting(acquisition, 'evidenceDigest');
  const acquisitionArtifact = await artifacts.publishCanonical(
    acquisition,
    'cliq-state-owner-acquisition-evidence-v1'
  );
  const owner: Extract<StateOwnerRecordV1, { state: 'active' }> = {
    schemaVersion: 1,
    ownerEpoch,
    supervisorInstanceId,
    runtimeBundleRef: prior.runtimeBundleRef,
    runtimeBundleManifestDigest: prior.runtimeBundleManifestDigest,
    supervisorEntryId: prior.supervisorEntryId,
    supervisorEntryVersion: prior.supervisorEntryVersion,
    supervisorExecutableDigest: processIdentity.executableImageDigest,
    processIdentityRef: processArtifact.ref,
    processIdentityDigest: processIdentity.identityDigest,
    stateLockIdentityRef: prior.stateLockIdentityRef,
    stateLockIdentityDigest: prior.stateLockIdentityDigest,
    acquisitionEvidenceRef: acquisitionArtifact.ref,
    acquisitionEvidenceDigest: acquisition.evidenceDigest,
    instanceNonceDigest,
    acquiredAt,
    rowDigest: '',
    state: 'active',
    rowVersion: 1
  };
  owner.rowDigest = digestOmitting(owner, 'rowDigest');

  let fenceOutcome: TimeFenceAdvance | undefined;
  driver.transaction((connection) => {
    assertStateOwnerLock(heldLock);
    assertContiguousStateOwnerHistory(connection);
    const active = readActiveStateOwner(connection);
    if (prior.state === 'active' ? active?.rowDigest !== prior.rowDigest : active !== undefined) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'another state owner acquired authority');
    }
    const lockedPrior = readLatestStateOwner(connection);
    if (
      lockedPrior === undefined ||
      lockedPrior.state !== prior.state ||
      lockedPrior.ownerEpoch !== prior.ownerEpoch ||
      lockedPrior.rowDigest !== prior.rowDigest
    ) {
      throw new KernelStorageError('RECOVERY_REQUIRED', 'prior state owner changed during acquisition');
    }
    const committedAt = sampleCanonicalNow();
    if (prior.state === 'active') {
      const age = parseCanonicalTime(committedAt) - parseCanonicalTime(acquiredAt);
      if (age < 0 || age > 5000) throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner death observation is outside the five-second commit window');
      assertPriorProcessDead(heldLock, priorProcess);
    }
    fenceOutcome = transferTimeFenceOwner(connection, prior.ownerEpoch, ownerEpoch, committedAt);
    insertStateOwnerArtifacts(connection, [processArtifact, ...(transitionArtifact ? [transitionArtifact] : []), acquisitionArtifact], artifactCreatedAt);
    if (prior.state === 'active') {
      const changed = connection.prepare(`UPDATE state_owners SET record_json = ?, state = 'terminal', row_digest = ?
        WHERE owner_epoch = ? AND state = 'active' AND row_digest = ?`)
        .run(JSON.stringify(terminal), terminal.rowDigest, BigInt(prior.ownerEpoch), prior.rowDigest);
      if (changed.changes !== 1n) throw new KernelStorageError('RECOVERY_REQUIRED', 'prior state owner changed during takeover');
    }
    connection
      .prepare(
        `INSERT INTO state_owners (
           owner_epoch, supervisor_instance_id, record_json, state, row_digest
         ) VALUES (?, ?, ?, 'active', ?)`
      )
      .run(BigInt(ownerEpoch), supervisorInstanceId, JSON.stringify(owner), owner.rowDigest);
  });
  if (fenceOutcome === undefined) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'state owner acquisition did not transfer the time fence');
  }
  return owner;
}

export async function publishInProcessChannel(
  store: StateStore,
  client: LocalControlChannelIdentityV1['client'] = 'cli'
): Promise<{ principalId: string; channelIdentityRef: string; channelIdentityDigest: string }> {
  const now = sampleCanonicalNow();
  const processIdentity = await currentProcessIdentity(await loadNativeStateOwner(), now);
  const processArtifact = await store.artifacts.publishCanonical(
    processIdentity,
    'cliq-platform-process-identity-v1'
  );
  const principal: LocalPrincipalIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-local-principal-identity-v1',
    stateRootIdentityRef: store.stateRootIdentity.ref,
    stateRootIdentityDigest: store.stateRootIdentity.digest,
    platform: hostPlatform(),
    effectiveUid: requireEffectiveUid(),
    principalId: identityHash('cliq-local-principal-v1', store.stateRootIdentity.digest,
      processIdentity.platform, processIdentity.ownerUid),
    identityDigest: ''
  };
  principal.identityDigest = digestOmitting(principal, 'identityDigest');
  const principalArtifact = await store.artifacts.publishCanonical(
    principal,
    'cliq-local-principal-identity-v1'
  );
  const channel: LocalControlChannelIdentityV1 = {
    schemaVersion: 1,
    format: 'cliq-local-control-channel-identity-v1',
    principalIdentityRef: principalArtifact.ref,
    principalIdentityDigest: principal.identityDigest,
    principalId: principal.principalId,
    client,
    transport: {
      kind: 'in_process',
      processIdentityRef: processArtifact.ref,
      processIdentityDigest: processIdentity.identityDigest
    },
    openedAt: now,
    channelNonceDigest: sha256Bytes(randomBytes(32)),
    channelIdentityDigest: ''
  };
  channel.channelIdentityDigest = digestOmitting(channel, 'channelIdentityDigest');
  const channelArtifact = await store.artifacts.publishCanonical(channel, 'cliq-local-control-channel-identity-v1');
  return { principalId: principal.principalId, channelIdentityRef: channelArtifact.ref,
    channelIdentityDigest: channel.channelIdentityDigest };
}
