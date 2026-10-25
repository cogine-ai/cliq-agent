import { randomBytes } from 'node:crypto';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { ProcessContainment, SourceInspectionAttemptV1 } from '../kernel/execution.js';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { openInstalledSourceGitInspection, readSourceGitConstructionRetirement, readSourceGitRetirement, readSourceGitNativeLifecycle,
  type InstalledSourceGitInspection } from '../sandbox/source-git-native.js';
import type { NativeSourceGitRetirementObservation } from '../sandbox/linux-worker.js';
import type { ArtifactCatalog, PublishedArtifact } from './artifacts.js';
import { insertArtifactMetadata } from './artifacts.js';
import { advanceTimeFence, readTimeFence } from './canonical-time.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { readRetainedVerifierToolchain, guestToolchainRoots } from './guest-toolchain.js';
import type { HeldInstalledAnchor, HeldInstalledRuntime } from './installed-runtime.js';
import { withHeldInstalledRuntime } from './installed-runtime.js';
import { openHeldSourceGitInput, type HeldSourceGitInput, type HeldSourceInspectionStaging } from './native-owner.js';
import { readAuthorizationGrant } from './repositories/authorization-grants.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import { readSourceGitInputIntent } from './source-git-input.js';
import { publishSourceGitLaunch } from './source-git-launch.js';
import { publishInstalledSourceGitResult } from './source-git-result.js';
import { sourceGitConsentData } from './source-git-consent.js';
import { assertVerifiedSourceInspectionTargetCut, readVerifiedSourceInspectionTarget,
  recheckVerifiedSourceInspectionTarget, type SourceInspectionBootstrap, type VerifiedSourceInspectionTarget } from './source-target.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';

type Unretired = Exclude<SourceInspectionAttemptV1, { phase: 'retired' }>;
type Capturing = Extract<Unretired, { phase: 'capturing' }>;
type Prepared = Extract<Unretired, { phase: 'prepared' }>;
type Active = Extract<Unretired, { phase: 'active' }>;
export type InstalledSourceGitCapture = Readonly<{
  run(): Promise<Awaited<ReturnType<typeof publishInstalledSourceGitResult>>>;
  close(): Promise<void>;
}>;
type Binding = { owner: StateOwnerContext; row: Unretired; input?: HeldSourceGitInput;
  observation?: NativeSourceGitRetirementObservation; lifecycle?: Buffer; joined: boolean; attempted: boolean };
const captures = new WeakMap<InstalledSourceGitCapture, Binding>();
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

/** Current program-owned cut only, never an accepted source or Run. The
 * original caller must join this task before retiring staging or directories. */
export function readInstalledSourceGitCapture(owner: StateOwnerContext, capture: InstalledSourceGitCapture) {
  const held = captures.get(capture);
  if (!held || held.owner !== owner) return invalid('source capture belongs to another owning program task');
  owner.filesystem.assertHeld();
  if (!held.joined) return invalid('source capture has not joined every original producer and consumer');
  if (held.attempted && (!held.input || !held.observation || !held.lifecycle)) return invalid('source capture retains an uncertain native birth');
  const facts = immutableSnapshot({ row: held.row, nativeAttempted: held.attempted,
    ...(held.input && held.observation ? { nativeBirthIdentity: held.input.identity.birthIdentity, observation: held.observation } : {}) });
  return Object.freeze({ ...facts, ...(held.lifecycle ? { nativeLifecycle: Buffer.from(held.lifecycle) } : {}) });
}

/** Resource-free registration before the first native source borrow. It owns
 * the only reserve/blocked/capture/continue/result/retirement sequence and
 * cannot be replayed as a replacement scope after a failure. */
export function createInstalledSourceGitCapture(driver: SqliteDriver, artifacts: ArtifactCatalog, owner: StateOwnerContext,
  bootstrap: SourceInspectionBootstrap, context: { row: Capturing; target: VerifiedSourceInspectionTarget;
    staging: HeldSourceInspectionStaging; installed: HeldInstalledRuntime; anchor: HeldInstalledAnchor; signal: AbortSignal }): InstalledSourceGitCapture {
  const { target, staging, installed, anchor } = context;
  const cancellation = new AbortController(), signal = AbortSignal.any([context.signal, cancellation.signal]);
  const held = readVerifiedSourceInspectionTarget(owner, target);
  if (held.target.schemaVersion !== 2 || !held.inspectionConsent || !context.row.inputRef || !context.row.inputDigest)
    return invalid('Git capture requires its first committed exact input and inspection consent');
  const original = held.target, consent = sourceGitConsentData(owner, held.inspectionConsent);
  const key = { principalId: context.row.principalId, method: context.row.method,
    admissionKey: context.row.admissionKey, admissionIntentDigest: context.row.admissionIntentDigest };
  const state: Binding = { owner, row: context.row, joined: false, attempted: false };
  const reads = artifacts.withReadSignal(signal);
  let scope: InstalledSourceGitInspection | undefined, pending: Promise<Awaited<ReturnType<typeof publishInstalledSourceGitResult>>> | undefined;
  let closing: Promise<void> | undefined, closed = false;
  const cut = (action: (connection: SqliteConnection, now: string) => void) => {
    let clockRejected = false;
    driver.transaction(connection => {
      signal.throwIfAborted(); assertVerifiedSourceInspectionTargetCut(connection, owner, target);
      const current = readSourceInspectionAttempt(connection, key);
      if (!current || current.rowDigest !== state.row.rowDigest || current.phase === 'retired' || current.cancelRequested || current.retirementHandoffRef)
        return invalid('Git source no longer owns its exact unretired capture cut');
      if (advanceTimeFence(connection, owner.ownerEpoch) !== 'healthy') { clockRejected = true; return; }
      const now = readTimeFence(connection)!.lastAcceptedAt;
      if (now >= current.deadlineAt || now >= consent.expiresAt) throw new KernelStorageError('BUDGET_EXHAUSTED', 'source capture deadline elapsed');
      for (const item of [{ grantId: original.inspectionGrantId, receiptRef: original.inspectionReceiptRef }, ...original.ignoreReadConsents]) {
        const grant = readAuthorizationGrant(connection, item.grantId);
        if (!grant || grant.state !== 'consumed' || grant.consumptionReceiptRef !== item.receiptRef ||
            grant.ownerPrincipalId !== current.principalId || now >= grant.expiresAt)
          return invalid('source capture lost its same-attempt consumed inspection or ignore consent');
      }
      action(connection, now);
    });
    // Persist the sticky regression in this original transaction. Throwing
    // inside it would roll that observation back and silently auto-heal later.
    if (clockRejected) return invalid('Git source requires healthy canonical time');
  };
  const transition = (value: Prepared | Active, metadata: readonly PublishedArtifact[]) => {
    let committed: Prepared | Active | undefined;
    cut((connection, now) => {
      const next = { ...value, rowVersion: state.row.rowVersion + 1, updatedAt: now, rowDigest: '' };
      next.rowDigest = digestOmitting(next, 'rowDigest');
      for (const artifact of metadata) insertArtifactMetadata(connection, artifact, now);
      const updated = connection.prepare(`UPDATE source_inspection_attempts SET phase=?,row_version=?,row_json=?
        WHERE inspection_id=? AND phase=? AND row_version=? AND row_json=?`).run(next.phase, next.rowVersion,
        canonicalJsonBytes(next).toString(), state.row.inspectionId, state.row.phase, state.row.rowVersion, canonicalJsonBytes(state.row).toString());
      if (updated.changes !== 1n) return invalid('source capture lost its original phase CAS');
      committed = immutableSnapshot(next);
    });
    // A COMMIT failure cannot lend an uncommitted phase to the next release.
    if (!committed) return invalid('source phase did not commit');
    state.row = committed;
  };
  const refresh = async () => {
    signal.throwIfAborted(); await recheckVerifiedSourceInspectionTarget(owner, target);
    await withHeldInstalledRuntime(installed, async runtime => {
      await runtime.revalidate(signal);
      if (runtime.bundleDigest !== original.runtimeBundleRef) return invalid('source capture installation changed');
    }, signal);
    signal.throwIfAborted(); assertActiveStateOwner(driver, owner);
  };
  const closeScope = async () => {
    const failures: unknown[] = [];
    if (state.attempted && !state.input) throw new ResourceRetirementError('source input construction retains uncertain native birth',
      new Error('native input construction was requested without a complete returned owner'));
    if (state.input) {
      try {
        const receipt = scope ? await scope.stop() : readSourceGitConstructionRetirement(state.input);
        if (receipt) {
          state.observation = readSourceGitRetirement(receipt, state.input);
          state.lifecycle = readSourceGitNativeLifecycle(receipt, state.input);
        }
        else if (state.attempted) return invalid('source construction lacks its original actual retirement receipt');
      } catch (error) { failures.push(error); }
      try { state.input.close(); } catch (error) { failures.push(error); }
    }
    if (failures.length) throw failures.find(error => error instanceof ResourceRetirementError) ??
      new ResourceRetirementError('source capture scope did not completely join', new AggregateError(failures));
  };
  const api: InstalledSourceGitCapture = Object.freeze({
    run() {
      if (closed || pending) return Promise.reject(new KernelStorageError('STATE_TRANSITION_INVALID', 'source capture is single-use'));
      return pending = (async () => {
        const input = await readSourceGitInputIntent(reads, context.row.inputRef!, signal);
        if (canonicalSha256(input) !== context.row.inputRef || input.inputDigest !== context.row.inputDigest ||
            input.targetRef !== context.row.targetRef || input.targetDigest !== context.row.targetDigest ||
            input.inspectionId !== context.row.inspectionId || input.inspectionGrantId !== original.inspectionGrantId ||
            input.inspectionReceiptRef !== original.inspectionReceiptRef || input.inspectionReceiptDigest !== original.inspectionReceiptDigest ||
            input.repositoryIdentityDigest !== held.workspace.repositoryIdentityDigest ||
            canonicalSha256(input.resources) !== canonicalSha256(bootstrap.sandboxProfile.resources)) return invalid('source input differs from its first owning transaction');
        const roots = guestToolchainRoots(bootstrap.bundle);
        if (roots.length !== 1) return invalid('source capture has no unique signed guest toolchain');
        const toolchain = await readRetainedVerifierToolchain(reads, { ...bootstrap, guestToolchainManifestRef: roots[0]!.artifactRef, signal });
        await refresh(); cut(() => {});
        // Set before the call: a throw after allocation is uncertainty, never
        // evidence that native source construction was not attempted.
        state.attempted = true;
        state.input = openHeldSourceGitInput(owner.filesystem, held.workspaceRoot, staging,
          { targetRef: state.row.targetRef, inputIntentRef: context.row.inputRef! });
        const exclude = consent.ignoreReadScopes.find(item => item.canonicalRootRelativePath === '.git/info/exclude');
        const excludeGrant = exclude && original.ignoreReadConsents.find(item =>
          readAuthorizationGrant(driver, item.grantId)?.targetDigest === canonicalSha256(exclude));
        const excludeRow = excludeGrant && readAuthorizationGrant(driver, excludeGrant.grantId);
        if (exclude && !excludeRow) return invalid('source exclude has no exact original consumed rule grant');
        const launchNonceDigest = sha256Bytes(randomBytes(32));
        scope = await openInstalledSourceGitInspection(installed, anchor, state.input, toolchain,
          { ...input.resources, launchNonceDigest, repositoryIdentityDigest: input.repositoryIdentityDigest,
            excludeGrantDigest: excludeRow?.grantCoreDigest ?? null }, { signal });
        const reservation = await scope.reservation();
        const launch = await publishSourceGitLaunch(artifacts, { ...bootstrap, row: context.row,
          target: original, input, reservation, toolchain }, launchNonceDigest, signal);
        await refresh(); transition({ ...state.row, phase: 'prepared', inputRef: launch.inputRef,
          inputDigest: input.inputDigest, plan: launch.plan } as Prepared, launch.metadata);
        cut(() => scope!.createBlocked(launch.plan.containmentPlanRef, launch.plan.sandboxLaunchSpecRef, launch.plan.sandboxLaunchSpecDigest));
        const actual = await scope.ready();
        const containment: ProcessContainment = { schemaVersion: 1, planRef: launch.plan.containmentPlanRef,
          sandboxLaunchSpecRef: launch.plan.sandboxLaunchSpecRef, sandboxLaunchSpecDigest: launch.plan.sandboxLaunchSpecDigest,
          owner: launch.spec.owner, filesystemBinding: launch.containmentPlan.filesystemBinding, launchNonceDigest,
          backend: { kind: 'linux', pidNamespaceReservationId: reservation.pidNamespaceReservationId,
            pidNamespaceId: actual.pidNamespaceId, cgroupPath: reservation.cgroupPath, cgroupId: actual.cgroupId,
            namespaceInitStartToken: actual.namespaceInitStartToken, subreaperStartToken: reservation.subreaperStartToken },
          createdAt: new Date(actual.observedAtMs).toISOString() };
        const physical = await artifacts.publishCanonical(containment, 'cliq-process-containment-v1');
        await refresh(); transition({ ...state.row, phase: 'active', processContainmentRef: physical.ref } as Active, [physical]);
        cut(() => scope!.releaseCapture()); await scope.sealed();
        await refresh(); cut(() => scope!.continueFixedGit());
        const result = await scope.result();
        return await publishInstalledSourceGitResult(artifacts, state.input, result, {
          repositoryIdentityDigest: input.repositoryIdentityDigest, resources: input.resources,
          exclude: exclude ? { grantCoreDigest: excludeRow!.grantCoreDigest,
            ...(exclude.expectedDigest === undefined ? {} : { expectedDigest: exclude.expectedDigest }) } : null }, signal);
      })();
    },
    close() {
      if (closing) return closing;
      closed = true;
      cancellation.abort(new KernelStorageError('LEASE_FENCED', 'source capture owner is closing'));
      return closing = (async () => {
        // The caller's owned signal already revokes productive work. Join the
        // actual running publisher/readers before removing its charged scope.
        const result = pending ? await Promise.allSettled([pending]) : [];
        await closeScope();
        const failed = result.find(item => item.status === 'rejected' && item.reason instanceof ResourceRetirementError);
        if (failed?.status === 'rejected') throw failed.reason;
        state.joined = true;
      })();
    },
  });
  captures.set(api, state); return api;
}
