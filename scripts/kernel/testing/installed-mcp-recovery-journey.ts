// The real signed installation, authenticated v1 UDS and retained CAS only.
// No native factory, StateOwner, fabricated claim, process pause or clock seam.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chown, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeAdminProbeClosureEvidence, decodeMcpRegistrationReceipt, decodeMcpHttpCapture } from '../../../src/kernel/mcp.js';
import { decodeMcpRetryDispatchClosure, decodeMcpHttpRetryClaimIdentity } from '../../../src/kernel/mcp-retry.js';
import { decodeMcpInvocationWait, decodeMcpRecoveryProbeEvidence, decodeMcpReconciledEffectResult,
  decodeMcpStatusProbePreparation } from '../../../src/kernel/mcp-status.js';
import { decodeMcpRecoveryPredicate, evaluateMcpRecoveryPredicates } from '../../../src/kernel/mcp-recovery.js';
import { decodeMcpServerLaunchFailure } from '../../../src/kernel/mcp-server-authorization.js';
import { decodeMcpStdioCapture } from '../../../src/kernel/mcp-stdio.js';
import { decodeRetryUnknownCancelledResult } from '../../../src/kernel/retry-unknown.js';
import { decodeAgentStop } from '../../../src/runtime/stop.js';
import { decodeBudgetSettlement } from '../../../src/state/decoders.js';
import { decodeMcpStatusRetirement, decodeMcpStatusProbeWrapper, decodeMcpStatusProbeClosure } from '../../../src/state/mcp-status-proof.js';
import { decodeRunResult, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import type { InstalledMcpContext } from './installed-mcp-journey.js';
import { MCP_BEFORE, MCP_AFTER } from './installed-mcp-model.js';
import { MCP_RECOVERY_FIXTURE_ARGV, MCP_RECOVERY_HOLD_ARGV, MCP_RECOVERY_REFUSED_ARGV, MCP_RECOVERY_REFUSED_STATUS_LINE,
  MCP_RECOVERY_UNRESOLVED_ARGV, MCP_RECOVERY_MISSING_ARGV, MCP_RECOVERY_ADAPTER, MCP_RECOVERY_EFFECT } from './installed-mcp-recovery-package.js';
import { INSTALLED_MCP_RECOVERY_CASES, INSTALLED_MCP_STATUS_USER_REPLAY_CASE, installedMcpRecoveryRegistration, installedMcpRecoveryObjective,
  type createInstalledMcpRecoveryModelResponder, type InstalledMcpRecoveryCase } from './installed-mcp-recovery-model.js';
import { MCP_RETRY_HTTP_TOOL, MCP_RETRY_HTTP_RESULT, type createInstalledMcpRetryHttpHandler } from './installed-mcp-retry-http.js';
import type { InstalledMcpRecoveryBirthSelector } from './installed-mcp-recovery-birth.js';

type Data = Record<string, any>;
type Context = Pick<InstalledMcpContext, 'workspaceRoot' | 'cliqHome' | 'uid' | 'gid' | 'model' | 'guestToolchainManifestId' |
  'send' | 'nextId' | 'readCas' | 'download' | 'reconnect' | 'restart' | 'assertWorkerFree' | 'assertOriginalProcessAbsent' |
  'assertVerifierEvidence' | 'assertDeliveryEvidence' | 'mark'> & {
    runtimeBundleId: string; modelResponder: ReturnType<typeof createInstalledMcpRecoveryModelResponder>;
    httpEndpointRegistrationId: string; httpResponder: ReturnType<typeof createInstalledMcpRetryHttpHandler>;
    userReplayOnly: boolean;
    crashAfterRefusedStatus(input: InstalledMcpRecoveryBirthSelector): Promise<Readonly<{
      birthDigest: string; killedAt: number; originalStateOwnerEpoch: number; successorStateOwnerEpoch: number; successorSupervisorInstanceId: string;
    }>>;
  };
const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, ONE = { ...ZERO, toolCalls: 1 };
const signed = (core: Data) => ({ ...core, requestDigest: canonicalSha256(core) });
const same = (a: unknown, b: unknown) => assert.equal(canonicalSha256(a), canonicalSha256(b));
const RETRY_ARGV = '--immutable-noop-effect-exit-no-reply';
export const INSTALLED_MCP_RECOVERY_PROFILE = 'installed_signed_mcp_original_unknown_retry_status_and_owning_stop_v2';
export const INSTALLED_MCP_STATUS_USER_REPLAY_PROFILE = 'installed_signed_mcp_status_real_exhaustion_user_replay_v1';

export async function runInstalledMcpRecoveryCases(context: Context) {
  const send = async (frame: Data, timeout = 30_000): Promise<Data> => {
    const response = await context.send(frame, timeout), result = response.result;
    if (response.protocolVersion !== 1 || response.ok !== true || !result || result.method !== frame.method)
      assert.fail('the real installed MCP recovery request was refused');
    return result;
  };
  const get = (runId: string, timeout = 30_000) => send({ protocolVersion: 1, method: 'run.get', runId }, timeout);
  const read = async (ref: string): Promise<Data> => {
    assert.match(ref, /^[0-9a-f]{64}$/u); const bytes = await context.readCas(ref);
    assert(bytes.length <= 1_048_576); assert.equal(sha256Bytes(bytes), ref);
    const data = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    assert(canonicalJsonBytes(data).equals(bytes)); return data as Data;
  };
  async function identity(filename: string) {
    const file = await lstat(filename, { bigint: true }); assert(file.isFile() && !file.isSymbolicLink() && file.nlink === 1n);
    return Object.fromEntries(['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs']
      .map(key => [key, file[key as keyof typeof file]!.toString()]));
  }
  async function retired(rawRef: string, projectionRef: string, purpose: 'run' | 'recovery' | 'admin' | 'http_admin', refused = false) {
    const raw = await context.readCas(rawRef); assert(raw.length <= 16_777_216); assert.equal(sha256Bytes(raw), rawRef);
    if (refused) { assert.equal(purpose, 'recovery'); assert(!raw.includes(Buffer.from('cliq-fixture-refused-status-sentinel'))); }
    // run.get's ordinary production readers validate the exact raw/projection
    // with the genuinely loaded signed native decoder. This external observer
    // does not install one or manufacture a native ownership receipt.
    const lifecycle = await read(projectionRef);
    assert.equal(lifecycle.format, purpose === 'http_admin' ? 'cliq-mcp-admin-native-lifecycle-v1'
      : purpose === 'recovery' ? 'cliq-mcp-stdio-recovery-native-lifecycle-v1' : 'cliq-mcp-stdio-native-lifecycle-v1');
    if (purpose !== 'http_admin') { assert.equal(lifecycle.binding.kind, purpose); assert.equal(lifecycle.joined.ownerDrained, true);
      assert.equal(lifecycle.joined.responseRefused, refused); }
    else assert.equal(lifecycle.joined.protocolCompleted, true);
    if (purpose === 'recovery') {
      const spec = await read(lifecycle.binding.sandboxLaunchSpecRef), registry = await read(lifecycle.binding.registryRevisionRef);
      assert.equal(spec.owner.kind, 'reconciliation_probe'); assert.equal(spec.executable.role, 'mcp_recovery_adapter');
      assert.equal(spec.executable.executableId, lifecycle.binding.adapterExecutableId);
      assert.equal(spec.executable.executableDigest, lifecycle.binding.adapterExecutableDigest);
      assert.equal(lifecycle.images.server.digest, spec.executable.executableDigest);
      assert.equal(lifecycle.images.client.digest, spec.runtime.launcher.executableDigest);
      assert.equal(registry.transport.kind, 'stdio'); assert.equal(registry.transport.executable.kind, 'runtime_bundle');
      assert.equal(new Set([lifecycle.images.server.digest, lifecycle.images.client.digest, registry.transport.executable.executableDigest]).size, 3);
    }
    assert(lifecycle.containment && lifecycle.retirement); assert(lifecycle.joined.deathJoined && lifecycle.joined.outputCustodyRetired);
    assert.equal(lifecycle.containment.cgroupPopulated, 1);
    assert.equal(lifecycle.retirement.cgroupPopulated, 0); assert.equal(lifecycle.retirement.namespaceInitDeadAndReaped, 1);
    assert.equal(lifecycle.retirement.remainingTrackedDescendants, 0);
    assert.equal(lifecycle.retirement.namespaceInitStartToken, lifecycle.containment.namespaceInitStartToken);
    const token = /^linux-namespace-init:([1-9][0-9]*):([1-9][0-9]*):monitor:([1-9][0-9]*):([1-9][0-9]*)$/u.exec(lifecycle.containment.namespaceInitStartToken);
    assert(token); for (const [pid, start] of [[token[1], token[2]], [token[3], token[4]]]) await context.assertOriginalProcessAbsent(Number(pid), start!);
    assert.match(lifecycle.containment.processStartToken, /^linux-proc-start-ticks:[1-9][0-9]*$/u);
    await context.assertOriginalProcessAbsent(lifecycle.containment.pid, lifecycle.containment.processStartToken.slice('linux-proc-start-ticks:'.length));
    return lifecycle;
  }
  async function firstAutomaticClosure(ref: string) {
    const seen = new Set<string>();
    for (;;) {
      assert(seen.size < 17 && !seen.has(ref)); seen.add(ref);
      const wait = decodeMcpInvocationWait(await read(ref)), state = wait.probeState;
      if (state.phase === 'automatic_pending' && state.automaticProbeCount === 1) return wait;
      if (state.phase === 'automatic_pending' && state.automaticProbeCount === 0) return undefined;
      if (state.phase === 'automatic_in_flight' || state.phase === 'user_in_flight') {
        if (state.dispatch.subjectKind !== 'mcp_recovery') assert.fail('the original status wait has a foreign probe dispatch');
        ref = state.dispatch.previousWaitingSubjectRef; continue;
      }
      if (!state.lastProbeEvidenceRef) assert.fail('the actual original probe history is incomplete');
      const evidence = decodeMcpStatusProbeWrapper(await read(state.lastProbeEvidenceRef));
      ref = evidence.waitingSubjectRef;
    }
  }
  async function refusedRetirement(closure: ReturnType<typeof decodeMcpStatusProbeClosure>) {
    assert.equal(closure.lateStatusCaptureRef, undefined); assert.equal(closure.lateStatusCaptureDigest, undefined);
    const value = decodeMcpStatusRetirement(await read(closure.retirementRef));
    assert.equal(value.retirementDigest, closure.retirementDigest); assert.equal(value.nativeClosure.kind, 'linux_original_response_unavailable');
    assert(value.joined?.kind === 'mcp_stdio_recovery_response_unavailable_joined'); assert.equal(value.joined.reason, 'native_response_refused');
    assert.equal(value.joined.tokenRevoked, true); assert.equal(value.joined.matchingActiveReleaseCount, 0);
    assert.equal(value.joined.statusReleased, true); assert.equal(value.joined.outputCustodyRetired, true);
    assert.equal(value.joined.pipesJoined, true); assert.equal(value.joined.tasksJoined, true);
    const original = await retired(value.nativeClosure.lifecycleRawRef, value.nativeClosure.lifecycleProjectionRef, 'recovery', true);
    assert.equal(original.joined.protocolCompleted, false); assert.equal(original.joined.statusReleased, true);
    assert.equal(original.progressKind, 9); assert.equal(Object.hasOwn(original.joined, 'effectReleased'), false);
    assert.match(original.controller.processStartToken, /^linux-proc-start-ticks:[1-9][0-9]*$/u);
    await context.assertOriginalProcessAbsent(original.controller.pid, original.controller.processStartToken.slice('linux-proc-start-ticks:'.length));
    await assertRefusedPayloadAbsent({ value, closure, original });
    return original;
  }
  async function assertRefusedPayloadAbsent(value: unknown) {
    const audit = canonicalJsonBytes(value);
    assert(!audit.includes(Buffer.from('cliq-fixture-refused-status-sentinel')));
    for (const raw of [MCP_RECOVERY_REFUSED_STATUS_LINE, MCP_RECOVERY_REFUSED_STATUS_LINE + '\n']) {
      const hash = sha256Bytes(Buffer.from(raw));
      assert(!audit.includes(Buffer.from(hash)));
      await assert.rejects(context.readCas(hash), { code: 'ENOENT' });
    }
  }
  async function assertUnresolvedStatus(wrapper: ReturnType<typeof decodeMcpStatusProbeWrapper>, deadlineAt: string, originalInstanceRef: string) {
    if (wrapper.outcome !== 'subject_observation' || wrapper.subjectEvidenceKind !== 'mcp_recovery')
      assert.fail('a schema-valid nonmatching status must preserve its actual observation');
    assert(wrapper.observedAt < deadlineAt);
    const evidence = decodeMcpRecoveryProbeEvidence(await read(wrapper.subjectEvidenceRef));
    assert.equal(evidence.evidenceDigest, wrapper.subjectEvidenceDigest); assert.equal(evidence.disposition, 'unresolved');
    const capture = await read(evidence.statusCaptureRef);
    assert.equal(capture.captureDigest, evidence.statusCaptureDigest); assert.equal(capture.schemaValid, true);
    assert.equal(capture.disposition, 'unresolved'); assert.equal(capture.responseProjection, 'structured_content');
    assert.equal(capture.statusResponseRef, evidence.statusResponseRef); assert.equal(capture.captures.length, 3);
    assert.equal(capture.binding.originalInstanceIdentityRef, originalInstanceRef);
    const response = await read(evidence.statusResponseRef);
    same(response, { originalExecutionObserved: false, profileClass: 'immutable_preexisting_noop_target', targetState: 'preexisting_noop' });
    const completed = decodeMcpRecoveryPredicate(await read(evidence.completedPredicateRef));
    const failed = decodeMcpRecoveryPredicate(await read(evidence.failedPredicateRef));
    assert.equal(completed.predicateDigest, evidence.completedPredicateDigest); assert.equal(failed.predicateDigest, evidence.failedPredicateDigest);
    assert.equal(evaluateMcpRecoveryPredicates({ completed, failed, response, schemaValid: true }), 'unresolved');
    const retirement = decodeMcpStatusRetirement(await read(capture.retirementRef));
    assert.equal(retirement.retirementDigest, capture.retirementDigest); assert.equal(retirement.nativeClosure.kind, 'linux_original_join');
    const lifecycle = await retired(retirement.nativeClosure.lifecycleRawRef, retirement.nativeClosure.lifecycleProjectionRef, 'recovery');
    assert.equal(lifecycle.joined.statusReleased, true); assert.equal(lifecycle.joined.protocolCompleted, true);
  }
  async function exerciseExhaustedUserReplay(runId: string, original: Data, first: ReturnType<typeof decodeMcpInvocationWait>, originalInstanceRef: string) {
    // These are observation limits only. The production owner schedules all
    // eight attempts using actual canonical time and its original backoffs.
    const by = Date.now() + 6_600_000, backoffs = [1_000, 5_000, 30_000, 120_000, 600_000, 1_800_000, 3_600_000];
    let exhausted: Data, wait: ReturnType<typeof decodeMcpInvocationWait>, lastCount = 1;
    const sameEffect = (cut: Data) => {
      assert.equal(cut.snapshot.run.status, 'waiting'); assert.equal(cut.snapshot.run.waitingReason, 'reconciliation');
      same(cut.journal, original.journal); same(cut.items, original.items);
      same(cut.snapshot.run.budgetConsumed, original.snapshot.run.budgetConsumed); same(cut.snapshot.run.budgetReserved, ZERO);
    };
    for (;;) {
      const remaining = by - Date.now(); assert(remaining > 0, 'the real automatic status schedule did not exhaust');
      exhausted = await get(runId, Math.min(remaining, 30_000)); sameEffect(exhausted);
      wait = decodeMcpInvocationWait(await read(exhausted.snapshot.run.waitingOnRef)); same(wait.subject, first.subject);
      const state = wait.probeState; assert.equal(state.userProbeCount, 0);
      assert(state.automaticProbeCount >= lastCount);
      if (state.automaticProbeCount !== lastCount) {
        lastCount = state.automaticProbeCount; context.mark('mcp_recovery_exhaustion_attempt_' + lastCount);
      }
      if (state.phase === 'automatic_exhausted') break;
      if (state.phase === 'user_in_flight') assert.fail('no user probe was requested before genuine automatic exhaustion');
      const sleep = state.phase === 'automatic_pending' ? Date.parse(state.nextProbeAt) - Date.now() : 500;
      await delay(Math.max(100, Math.min(20_000, sleep, remaining)));
    }
    const nonces = new Set<string>(); let firstStartedAt: string | undefined, eighthStartedAt: string | undefined, cursor = wait;
    for (let ordinal = 8; ordinal >= 1; ordinal--) {
      const state = cursor.probeState;
      if (state.phase !== 'automatic_exhausted' && state.phase !== 'automatic_pending') assert.fail('the automatic closure chain is incomplete');
      assert.equal(state.phase, ordinal === 8 ? 'automatic_exhausted' : 'automatic_pending');
      assert.equal(state.automaticProbeCount, ordinal); assert.equal(state.userProbeCount, 0);
      assert(state.lastProbeEvidenceRef && state.lastProbeEvidenceDigest);
      const wrapper = decodeMcpStatusProbeWrapper(await read(state.lastProbeEvidenceRef));
      assert.equal(wrapper.evidenceDigest, state.lastProbeEvidenceDigest);
      assert.equal(wrapper.probeKind, 'automatic'); assert.equal(wrapper.probeOrdinal, ordinal);
      if (ordinal === 1) same(cursor, first);
      if (state.phase === 'automatic_pending') {
        assert.equal(Date.parse(state.nextProbeAt), Date.parse(wrapper.observedAt) + backoffs[ordinal - 1]!);
        assert(firstStartedAt && firstStartedAt >= state.nextProbeAt);
      }
      const active = decodeMcpInvocationWait(await read(wrapper.waitingSubjectRef)); same(active.subject, first.subject);
      if (active.probeState.phase !== 'automatic_in_flight' || active.probeState.dispatch.subjectKind !== 'mcp_recovery')
        assert.fail('the retained automatic closure changed its original MCP purpose');
      const dispatch = active.probeState.dispatch;
      assert.equal(active.probeState.automaticProbeCount, ordinal); assert.equal(active.probeState.userProbeCount, 0);
      assert.equal(dispatch.probeNonceDigest, wrapper.probeNonceDigest); assert.equal(dispatch.dispatchDigest, wrapper.probeDispatchDigest);
      assert.equal(dispatch.probeDeadlineAt, wrapper.probeDeadlineAt);
      assert.equal(Date.parse(dispatch.probeDeadlineAt) - Date.parse(dispatch.probeStartedAt), 30_000);
      assert(!nonces.has(dispatch.probeNonceDigest)); nonces.add(dispatch.probeNonceDigest); firstStartedAt = dispatch.probeStartedAt;
      eighthStartedAt ??= dispatch.probeStartedAt;
      await assertUnresolvedStatus(wrapper, dispatch.probeDeadlineAt, originalInstanceRef);
      cursor = decodeMcpInvocationWait(await read(dispatch.previousWaitingSubjectRef)); same(cursor.subject, first.subject);
    }
    assert.equal(nonces.size, 8); assert.equal(cursor.probeState.phase, 'automatic_pending');
    assert.equal(cursor.probeState.automaticProbeCount, 0);
    assert(firstStartedAt && eighthStartedAt);
    assert(Date.parse(eighthStartedAt) - Date.parse(firstStartedAt) >= backoffs.reduce((total, ms) => total + ms, 0));
    const requestCore = { protocolVersion: 1, method: 'run.reconcile', requestId: context.nextId(), runId,
      expectedRevision: exhausted.snapshot.run.revision, waitingOnRef: exhausted.snapshot.run.waitingOnRef, resolution: { kind: 'probe_now' } };
    const request = signed(requestCore);
    context.mark('mcp_recovery_exhausted_user_probe');
    const enqueued = await context.send(request);
    assert.equal(enqueued.ok, true); const result = enqueued.result;
    assert(result); assert.equal(result.method, 'run.reconcile'); assert.equal(result.resolution.kind, 'probe_enqueued');
    assert.equal(result.resolution.userProbeCount, 1); assert.equal(result.snapshot.run.id, runId);
    const userWaitRef = result.snapshot.run.waitingOnRef, inFlight = decodeMcpInvocationWait(await read(userWaitRef));
    const user = inFlight.probeState; same(inFlight.subject, first.subject);
    if (user.phase !== 'user_in_flight' || user.dispatch.subjectKind !== 'mcp_recovery') assert.fail('the first response lost its actual user nonce');
    assert.equal(user.automaticProbeCount, 8); assert.equal(user.userProbeCount, 1);
    assert.equal(user.dispatch.previousWaitingSubjectRef, requestCore.waitingOnRef);
    assert.equal(user.dispatch.controlRequestId, requestCore.requestId); assert.equal(user.dispatch.controlRequestDigest, request.requestDigest);
    assert.equal(user.dispatch.dispatchDigest, result.resolution.dispatchDigest); assert(!nonces.has(user.dispatch.probeNonceDigest));
    assert.equal(Date.parse(user.dispatch.probeDeadlineAt) - Date.parse(user.dispatch.probeStartedAt), 30_000);
    assert.deepEqual(await context.send(request), enqueued);
    await context.reconnect(); assert.deepEqual(await context.send(request), enqueued);
    const userBy = Date.now() + 60_000; let closed: Data;
    for (;;) {
      const remaining = userBy - Date.now(); assert(remaining > 0, 'the actual user status probe did not close');
      closed = await get(runId, Math.min(remaining, 30_000)); sameEffect(closed);
      const next = decodeMcpInvocationWait(await read(closed.snapshot.run.waitingOnRef)); same(next.subject, first.subject);
      assert.equal(next.probeState.automaticProbeCount, 8); assert.equal(next.probeState.userProbeCount, 1);
      if (next.probeState.phase === 'automatic_exhausted') {
        const evidence = decodeMcpStatusProbeWrapper(await read(next.probeState.lastProbeEvidenceRef));
        assert.equal(evidence.evidenceDigest, next.probeState.lastProbeEvidenceDigest);
        assert.equal(evidence.waitingSubjectRef, userWaitRef); assert.equal(evidence.probeKind, 'user_requested'); assert.equal(evidence.probeOrdinal, 1);
        assert.equal(evidence.probeDispatchDigest, user.dispatch.dispatchDigest); assert.equal(evidence.probeNonceDigest, user.dispatch.probeNonceDigest);
        assert.equal(evidence.probeDeadlineAt, user.dispatch.probeDeadlineAt);
        await assertUnresolvedStatus(evidence, user.dispatch.probeDeadlineAt, originalInstanceRef);
        break;
      }
      assert.equal(closed.snapshot.run.waitingOnRef, userWaitRef); await delay(100);
    }
    const changed = signed({ ...requestCore, expectedRevision: closed.snapshot.run.revision, waitingOnRef: closed.snapshot.run.waitingOnRef });
    assert.notEqual(changed.requestDigest, request.requestDigest);
    const conflict = await context.send(changed); assert.equal(conflict.ok, false); assert.equal(conflict.error?.code, 'REQUEST_ID_CONFLICT');
    same(await get(runId), closed); await context.restart();
    assert.deepEqual(await context.send(request), enqueued); same(await get(runId), closed);
    await context.assertWorkerFree(runId, closed);
    return closed;
  }
  const cases: Data[] = [];
  const selectedCases: readonly InstalledMcpRecoveryCase[] = context.userReplayOnly
    ? [INSTALLED_MCP_STATUS_USER_REPLAY_CASE] : INSTALLED_MCP_RECOVERY_CASES;
  for (const kind of selectedCases) {
    context.mark(`mcp_recovery_${kind}`); context.modelResponder.begin(kind);
    const completedStatus = kind === 'signed_status_completed', confirmedFailure = kind === 'signed_status_failed',
      refusedStop = kind === 'signed_status_refused_owning_stop', strictSuccessor = kind === 'signed_status_refused_successor',
      refusedTimeout = kind === 'signed_status_refused_timeout', owningStop = kind === 'signed_status_owning_stop' || refusedStop,
      userReplay = kind === INSTALLED_MCP_STATUS_USER_REPLAY_CASE,
      ordinaryUnresolved = kind === 'signed_status_unresolved' || userReplay, firstClosure = refusedTimeout || ordinaryUnresolved,
      http = kind === 'http_retry_completed', knownResult = completedStatus || confirmedFailure || http,
      observeActive = owningStop || strictSuccessor,
      reconcile = completedStatus || confirmedFailure || observeActive || firstClosure, registrationId = installedMcpRecoveryRegistration(kind);
    if (http) context.httpResponder.begin();
    const grant = !http ? (await send(signed({ protocolVersion: 1, method: 'authorization.create', requestId: context.nextId(), decision: {
      kind: 'execution_identity_read', purpose: 'mcp_stdio', target: { kind: 'runtime_bundle_executable',
        runtimeBundleId: context.runtimeBundleId, executableId: 'mcp-static-stdio-fixture-v1' } } }))).grant : undefined;
    if (!http && !grant) assert.fail('stdio registration must retain its actual original identity-read grant');
    const registration = signed({ protocolVersion: 1, method: 'mcp.register', requestId: context.nextId(), registrationId,
      target: http ? { kind: 'streamable_http', endpointRegistrationId: context.httpEndpointRegistrationId, credentialGrantIds: [] }
        : { kind: 'stdio', executionIdentityGrantId: grant.grantId,
        argv: [{ kind: 'non_secret_literal', value: refusedStop || refusedTimeout || strictSuccessor ? MCP_RECOVERY_REFUSED_ARGV :
          owningStop ? MCP_RECOVERY_HOLD_ARGV : ordinaryUnresolved ? MCP_RECOVERY_UNRESOLVED_ARGV :
            confirmedFailure ? MCP_RECOVERY_MISSING_ARGV : reconcile ? MCP_RECOVERY_FIXTURE_ARGV : RETRY_ARGV }] },
      assertStatelessPerCall: true, toolRecovery: { [http ? MCP_RETRY_HTTP_TOOL : MCP_RECOVERY_EFFECT]: reconcile
        ? { kind: 'reconcile', bundledAdapterId: MCP_RECOVERY_ADAPTER, idempotencyKeyJsonPointer: '/idempotencyKey' }
        : { kind: 'retry', acknowledgeDuplicateEffectRisk: true, idempotencyKeyJsonPointer: '/idempotencyKey' } },
      lifecycle: { launchTimeoutMs: 5_000, callTimeoutMs: reconcile ? 5_000 : 60_000, maxLaunchesPerCall: 2 } });
    const registered = await context.send(registration);
    assert.equal(registered.ok, true, 'normal production validation must admit only this complete exact signed/risk-consented contract');
    const summary = registered.result?.registry; assert(summary); assert.equal(summary.toolCount, http ? 1 : 2);
    const receipt = decodeMcpRegistrationReceipt(await read(summary.registrationReceiptRef));
    const admin = decodeAdminProbeClosureEvidence(await read(receipt.probeClosureEvidenceRef));
    assert.equal(admin.closureKind, 'containment_dead'); assert.equal(admin.evidenceDigest, receipt.probeClosureEvidenceDigest);
    if (!admin.nativeLifecycleRef || !admin.nativeLifecycleProjectionRef) assert.fail('registration requires both actual raw and projection');
    const originalAdmin = await retired(admin.nativeLifecycleRef, admin.nativeLifecycleProjectionRef, http ? 'http_admin' : 'admin');
    if (!http) assert.equal(originalAdmin.joined.effectReleased, false); assert.deepEqual(await context.send(registration), registered);

    const workspace = path.join(context.workspaceRoot, `mcp-recovery-${kind}`); await mkdir(workspace, { mode: 0o700 }); await chown(workspace, context.uid, context.gid);
    const check = "import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';test('owned recovery edit',async()=>assert.equal(await readFile(new URL('./example.txt',import.meta.url),'utf8')," + JSON.stringify(MCP_AFTER) + "));\n";
    for (const [name, text] of [['example.txt', MCP_BEFORE], ['check.test.mjs', check]]) {
      assert(name !== undefined && text !== undefined); const filename = path.join(workspace, name);
      await writeFile(filename, text, { flag: 'wx', mode: 0o644 }); await chown(filename, context.uid, context.gid);
    }
    const before = await identity(path.join(workspace, 'example.txt')), workspaceId = sha256Bytes(Buffer.from(workspace));
    const directory = path.join(context.cliqHome, 'workspaces', workspaceId); await mkdir(directory, { recursive: true, mode: 0o700 });
    for (const filename of [path.dirname(directory), directory]) await chown(filename, context.uid, context.gid);
    const trust = path.join(directory, 'trust.json'); await writeFile(trust, canonicalJsonBytes({ version: 1, workspaceId, workspaceRealPath: workspace,
      decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 }); await chown(trust, context.uid, context.gid);
    const session = (await send(signed({ protocolVersion: 1, method: 'session.create', requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
      workspacePath: workspace, name: 'Owned MCP recovery lifecycle' }))).snapshot.session;
    const verifiers: Data[] = [];
    if (knownResult) {
      const verifier = (await send(signed({ protocolVersion: 1, method: 'authorization.create', requestId: context.nextId(), decision: {
        kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain', guestToolchainManifestId: context.guestToolchainManifestId, toolId: 'node' } } }))).grant;
      verifiers.push({ id: 'node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
        argv: ['--test', '--test-concurrency=1', 'check.test.mjs'].map(value => ({ kind: 'non_secret_literal', value })), cwd: '.', env: {},
        writableEphemeralPaths: [], identityReadGrantId: verifier.grantId, timeoutMs: 10_000, retries: 0, outputLimitBytes: 65_536 });
    }
    const wallTimeMs = userReplay ? 6_900_000 : 300_000;
    const submit = signed({ protocolVersion: 1, method: 'run.submit', requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
      sessionId: session.id, expectedContextRevision: session.contextRevision, workspacePath: workspace, objective: installedMcpRecoveryObjective(kind),
      model: context.model, policyMode: 'yolo', budgets: { wallTimeMs, modelTokens: 2_000_000, costMicros: 10_000_000,
        toolCalls: 1000, repairAttempts: 0, childDepth: 0, childConcurrency: 1 }, dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [],
      registeredMcpServerIds: [registrationId], skillIds: [], verifiers, allowUnverified: false });
    const admission = await context.send(submit); assert.equal(admission.ok, true); const runId = admission.result?.snapshot.run.id; assert(runId);
    if (userReplay) {
      const run = admission.result?.snapshot.run;
      assert.equal(Date.parse(run.deadlineAt) - Date.parse(run.createdAt), wallTimeMs);
    }
    const by = Date.now() + 90_000;
    let cut: Data, observedStatusWait: ReturnType<typeof decodeMcpInvocationWait> | undefined, closedStatusWait: typeof observedStatusWait;
    for (;;) {
      const remaining = by - Date.now(); assert(remaining > 0, 'the original installed recovery campaign observation window expired');
      cut = await get(runId, Math.min(30_000, remaining)); assert(Date.now() < by);
      if (observeActive && cut.snapshot.run.status === 'waiting' && cut.snapshot.run.waitingReason === 'reconciliation' && cut.snapshot.run.waitingOnRef) {
        const wait = decodeMcpInvocationWait(await read(cut.snapshot.run.waitingOnRef));
        if (wait.probeState.phase === 'automatic_in_flight') { observedStatusWait = wait; break; }
      }
      if (firstClosure && cut.snapshot.run.status === 'waiting' && cut.snapshot.run.waitingReason === 'reconciliation' && cut.snapshot.run.waitingOnRef) {
        closedStatusWait = await firstAutomaticClosure(cut.snapshot.run.waitingOnRef);
        if (closedStatusWait) break;
      }
      if (!observeActive && !firstClosure && cut.snapshot.run.status === (knownResult ? 'succeeded' : 'failed')) break;
      assert(!['failed', 'succeeded', 'cancelled', 'completed_unverified'].includes(cut.snapshot.run.status), 'the original recovery Run reached the wrong terminal state');
      await delay(100);
    }
    const effects = cut.journal.filter((row: Data) => row.opKind === 'mcp'), launches = cut.journal.filter((row: Data) => row.opKind === 'mcp-server');
    const claims = effects.filter((row: Data) => row.phase === 'dispatch_claimed'), unknowns = effects.filter((row: Data) => row.phase === 'unknown');
    assert.equal(claims.length, http ? 3 : reconcile ? 1 : 2); assert.equal(unknowns.length, http ? 2 : claims.length);
    assert.equal(launches.filter((row: Data) => row.phase === 'dispatch_claimed').length, http ? 0 : claims.length);
    assert.equal(effects.filter((row: Data) => row.phase === 'prepared').length, claims.length, 'no extra unclaimed attempt may be prepared');
    for (const unknown of unknowns) {
      const budget = decodeBudgetSettlement(await read(unknown.budgetSettlementRef)); same(budget.reserved, ONE); same(budget.released, ONE); same(budget.consumed, ONE);
    }
    for (const terminal of launches.filter((row: Data) => row.phase === 'failed')) {
      const failure = decodeMcpServerLaunchFailure(await read(terminal.errorRef)); assert.equal(failure.reason, 'owning_call_unknown');
      assert.equal(failure.nativeClosure.kind, 'linux_original_join');
      const actual = await retired(failure.nativeClosure.lifecycleRawRef, failure.nativeClosure.lifecycleProjectionRef, 'run');
      assert.equal(actual.joined.effectReleased, true); const budget = decodeBudgetSettlement(await read(terminal.budgetSettlementRef));
      same(budget.reserved, ONE); same(budget.released, ONE); same(budget.consumed, ONE);
    }
    assert.equal(launches.filter((row: Data) => row.phase === 'failed').length, http ? 0 : claims.length);
    const prepared = effects.filter((row: Data) => row.phase === 'prepared');
    const firstRequest = await read(prepared[0].requestRef), frozenInput = await read(firstRequest.inputRef);
    assert.match(frozenInput.value.idempotencyKey, /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u);
    for (const row of effects) assert.equal(row.idempotencyKey, firstRequest.idempotencyKey);
    same(cut.snapshot.run.budgetReserved, ZERO); await context.assertWorkerFree(runId, cut);
    assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE); same(await identity(path.join(workspace, 'example.txt')), before);
    assert.deepEqual(await context.send(submit), admission);
    if (firstClosure) {
      // The first backoff is only one second. A later automatic inspection may
      // start during these independent reads. Reopen its real previous-wait
      // chain and require the same first closure and untouched effect.
      await context.reconnect(); const reconnected = await get(runId);
      same(reconnected.journal, cut.journal); same(reconnected.items, cut.items);
      same(await firstAutomaticClosure(reconnected.snapshot.run.waitingOnRef), closedStatusWait);
    } else {
      same(await get(runId), cut); await context.reconnect(); same(await get(runId), cut);
    }

    if (knownResult) {
      if (!http) {
        const disposition = confirmedFailure ? 'failed' : 'completed';
        assert.deepEqual(effects.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', 'unknown', disposition]);
        const terminal = effects.at(-1), originalUnknown = unknowns[0]; same(terminal.budgetDelta, ZERO);
        assert.equal(terminal.budgetSettlementRef, originalUnknown.budgetSettlementRef);
        const resolution = decodeMcpReconciledEffectResult(await read(confirmedFailure ? terminal.errorRef : terminal.resultRef));
        assert.equal(resolution.disposition, disposition);
        assert.equal(resolution.code, confirmedFailure ? 'TOOL_EXECUTION_FAILED' : 'TOOL_RESULT_UNAVAILABLE');
        assert.equal(resolution.effect, confirmedFailure ? 'confirmed_failed' : 'confirmed_completed');
        assert.equal(resolution.originalResponse, 'unavailable');
        if (confirmedFailure) {
          assert.equal(terminal.resultRef, undefined); assert.equal(terminal.evidenceRef, resolution.probeEvidenceRef);
          assert.equal(terminal.evidenceDigest, resolution.probeEvidenceDigest);
        }
        const wrapper = decodeMcpStatusProbeWrapper(await read(resolution.probeEvidenceRef));
        assert.equal(wrapper.evidenceDigest, resolution.probeEvidenceDigest);
        if (wrapper.outcome !== 'subject_observation' || wrapper.subjectEvidenceKind !== 'mcp_recovery')
          assert.fail('only the real signed status may resolve the original effect');
        const evidence = decodeMcpRecoveryProbeEvidence(await read(wrapper.subjectEvidenceRef));
        assert.equal(evidence.evidenceDigest, wrapper.subjectEvidenceDigest); assert.equal(evidence.disposition, disposition);
        const capture = await read(evidence.statusCaptureRef); assert.equal(capture.captureDigest, evidence.statusCaptureDigest);
        assert.equal(capture.binding.originalInstanceIdentityRef, claims[0].evidenceRef); assert.equal(capture.binding.statusRequestDigest, evidence.statusRequestDigest);
        assert.equal(capture.statusResponseRef, evidence.statusResponseRef); assert.equal(capture.disposition, disposition);
        assert.equal(capture.schemaValid, true);
        const status = await read(evidence.statusResponseRef); same(status, { originalExecutionObserved: false,
          profileClass: confirmedFailure ? 'immutable_missing_noop_target' : 'immutable_preexisting_noop_target',
          targetState: confirmedFailure ? 'missing_immutable_target' : 'preexisting_noop' });
        if (confirmedFailure) {
          const completed = decodeMcpRecoveryPredicate(await read(evidence.completedPredicateRef));
          const failed = decodeMcpRecoveryPredicate(await read(evidence.failedPredicateRef));
          assert.equal(completed.predicateDigest, evidence.completedPredicateDigest); assert.equal(failed.predicateDigest, evidence.failedPredicateDigest);
          assert.equal(evaluateMcpRecoveryPredicates({ completed, failed, response: status, schemaValid: true }), 'failed');
        }
        const retirement = decodeMcpStatusRetirement(await read(capture.retirementRef)); assert.equal(retirement.retirementDigest, capture.retirementDigest);
        assert.equal(retirement.nativeClosure.kind, 'linux_original_join');
        const actual = await retired(retirement.nativeClosure.lifecycleRawRef, retirement.nativeClosure.lifecycleProjectionRef, 'recovery');
        assert.equal(actual.joined.statusReleased, true); assert.equal(Object.hasOwn(actual.joined, 'effectReleased'), false);
        const callCaptures = capture.captures.filter((entry: Data) => entry.phase === 'tools_call'); assert.equal(callCaptures.length, 1);
        const call = decodeMcpStdioCapture(await read(callCaptures[0].captureRef)); const raw = await context.readCas(call.rawResponseRef);
        assert.equal(sha256Bytes(raw), call.rawResponseRef); assert.equal(raw.length, call.rawFinitePrefixBytes);
      } else {
        assert.deepEqual(effects.map((row: Data) => [row.attempt, row.phase]), [[0, 'prepared'], [0, 'dispatch_claimed'], [0, 'unknown'],
          [1, 'prepared'], [1, 'dispatch_claimed'], [1, 'unknown'], [2, 'prepared'], [2, 'dispatch_claimed'], [2, 'completed']]);
        const identities = await Promise.all(claims.map(async (claim: Data) => {
          const identity = decodeMcpHttpRetryClaimIdentity(await read(claim.evidenceRef));
          assert.equal(identity.identityDigest, claim.evidenceDigest); assert.equal(identity.binding.dispatchId, claim.dispatchId);
          assert.equal(identity.binding.dispatchJournalSeq, claim.seq); assert.equal(identity.binding.attempt, claim.attempt);
          assert.equal(identity.binding.brokerFenceTokenDigest, claim.brokerFenceTokenDigest); return identity;
        }));
        for (let index = 0; index < 2; index++) {
          const closure = decodeMcpRetryDispatchClosure(await read(prepared[index + 1].evidenceRef));
          assert.equal(closure.unknownJournalSeq, unknowns[index].seq); assert.equal(closure.kind, 'original_native_joined');
          assert.equal(closure.originalClaimIdentity.kind, 'http_retry_binding'); assert.equal(closure.originalClaimIdentity.ref, claims[index].evidenceRef);
          assert.equal(closure.callDeadlineMs, identities[0].binding.deadlineMs);
        }
        for (const identity of identities) assert.equal(identity.binding.deadlineMs, identities[0].binding.deadlineMs, 'productive retries cannot reset the first real native deadline');
        assert.equal(new Set(claims.map((claim: Data) => claim.dispatchId)).size, 3, 'each retry must have a distinct actual permanent claim');
        const completed = effects.at(-1), settlement = decodeBudgetSettlement(await read(completed.budgetSettlementRef)); same(settlement.consumed, ONE);
        assert(!unknowns.some((unknown: Data) => unknown.budgetSettlementRef === completed.budgetSettlementRef));
        const observation = await read(completed.resultRef), capture = await read(observation.captureRef);
        assert.equal(observation.captureDigest, capture.captureDigest); assert.equal(capture.binding.dispatchId, claims[2].dispatchId);
        assert.equal(capture.binding.brokerFenceTokenDigest, claims[2].brokerFenceTokenDigest);
        const calls = capture.captures.filter((entry: Data) => entry.phase === 'tools_call'); assert.equal(calls.length, 1);
        const call = decodeMcpHttpCapture(await read(calls[0].captureRef)); assert.equal(call.termination, 'http_eof');
        const raw = await context.readCas(call.rawResponseRef); assert.equal(raw.length, call.rawFinitePrefixBytes); assert.equal(sha256Bytes(raw), call.rawFinitePrefixDigest);
        assert(raw.includes(Buffer.from(MCP_RETRY_HTTP_RESULT)));
        await context.httpResponder.waitForJoined(by); const peer = context.httpResponder.inspect();
        assert.equal(peer.clients, 4); assert.equal(peer.effects, 3); assert.equal(peer.posts, 15); assert.equal(peer.originalKey, firstRequest.idempotencyKey);
      }
      const files = [{ path: 'check.test.mjs', before: check, after: check }, { path: 'example.txt', before: MCP_BEFORE, after: MCP_AFTER }];
      await context.assertVerifierEvidence(cut, files);
      for (const method of ['run.result', 'run.diff']) {
        const result = await send({ protocolVersion: 1, method, runId }), descriptor = method === 'run.result' ? result.result : result.diff;
        const bytes = await context.download(descriptor.ref); assert.equal(sha256Bytes(bytes), descriptor.ref);
        if (method === 'run.result') assert.equal(decodeRunResult(parseJsonStrict(bytes.toString())).runId, runId);
        else assert.equal(decodeWorkspaceDiff(parseJsonStrict(bytes.toString())).resultSourceRef, decodeRunResult(await read(cut.snapshot.run.resultRef)).resultSourceRef);
      }
      await context.restart(); same(await get(runId), cut);
      const apply = signed({ protocolVersion: 1, method: 'run.apply', requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
        sourceRunId: runId, expectedRunResultRef: cut.snapshot.run.resultRef, budgets: { wallTimeMs: 300_000, toolCalls: 1000 } });
      const applied = await context.send(apply); assert.equal(applied.ok, true); const deliveryId = applied.result?.snapshot.run.id; assert(deliveryId);
      const deliveryBy = Date.now() + 90_000; let delivery: Data;
      for (;;) {
        const remaining = deliveryBy - Date.now(); assert(remaining > 0); delivery = await get(deliveryId, Math.min(30_000, remaining)); assert(Date.now() < deliveryBy);
        if (delivery.snapshot.run.status === 'succeeded') break;
        assert(!['failed', 'cancelled', 'completed_unverified', 'waiting'].includes(delivery.snapshot.run.status)); await delay(100);
      }
      await context.assertWorkerFree(deliveryId, delivery); await context.assertDeliveryEvidence(delivery, cut, new Map(files.map(file => [file.path, file.after])));
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_AFTER); assert.deepEqual(await context.send(apply), applied);
    } else if (strictSuccessor) {
      assert.deepEqual(effects.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', 'unknown']);
      if (!observedStatusWait || observedStatusWait.probeState.phase !== 'automatic_in_flight')
        assert.fail('the genuine original nonce is absent at the successor cut');
      const dispatch = observedStatusWait.probeState.dispatch;
      if (dispatch.subjectKind !== 'mcp_recovery') assert.fail('the actual successor cut has a foreign dispatch purpose');
      const preparation = decodeMcpStatusProbePreparation(await read(dispatch.preparationRef));
      assert.equal(preparation.preparationDigest, dispatch.preparationDigest);
      const crashed = await context.crashAfterRefusedStatus({ runId, nonce: preparation.nonce, probeNonceDigest: dispatch.probeNonceDigest,
        probeDispatchDigest: dispatch.dispatchDigest, probeDeadlineAt: dispatch.probeDeadlineAt,
        originalStateOwnerEpoch: preparation.inspectorStateOwnerEpoch, originalSupervisorInstanceId: preparation.inspectorSupervisorInstanceId,
        originalSupervisor: preparation.originalSupervisor, originalController: preparation.controller });
      const successorBy = Date.now() + 90_000;
      let next: Awaited<ReturnType<typeof firstAutomaticClosure>>, recovered: Data;
      for (;;) {
        const remaining = successorBy - Date.now(); assert(remaining > 0);
        recovered = await get(runId, Math.min(remaining, 30_000));
        assert.equal(recovered.snapshot.run.status, 'waiting'); assert.equal(recovered.snapshot.run.waitingReason, 'reconciliation');
        next = await firstAutomaticClosure(recovered.snapshot.run.waitingOnRef);
        if (next) break;
        await delay(100);
      }
      if (!next || next.probeState.phase !== 'automatic_pending' || !next.probeState.lastProbeEvidenceRef)
        assert.fail('the strict successor did not close the actual original nonce');
      assert.equal(next.probeState.automaticProbeCount, 1); assert.equal(next.probeState.userProbeCount, 0);
      same(next.subject, observedStatusWait.subject); same(recovered.journal, cut.journal); same(recovered.items, cut.items);
      same(recovered.snapshot.run.budgetConsumed, cut.snapshot.run.budgetConsumed); same(recovered.snapshot.run.budgetReserved, ZERO);
      const wrapper = decodeMcpStatusProbeWrapper(await read(next.probeState.lastProbeEvidenceRef));
      if (wrapper.outcome !== 'probe_timeout') assert.fail('the successor may close the old nonce only at its original deadline');
      assert.equal(wrapper.evidenceDigest, next.probeState.lastProbeEvidenceDigest);
      assert.equal(wrapper.probeNonceDigest, dispatch.probeNonceDigest); assert.equal(wrapper.probeDispatchDigest, dispatch.dispatchDigest);
      assert.equal(wrapper.probeDeadlineAt, dispatch.probeDeadlineAt);
      const closure = decodeMcpStatusProbeClosure(await read(wrapper.timeoutClosureRef));
      assert.equal(closure.closureDigest, wrapper.timeoutClosureDigest); assert(closure.closedAt >= dispatch.probeDeadlineAt);
      assert.equal(closure.lateStatusCaptureRef, undefined); assert.equal(closure.lateStatusCaptureDigest, undefined);
      assert(Date.parse(next.probeState.nextProbeAt) >= Date.parse(closure.closedAt) + 1_000);
      const retirement = decodeMcpStatusRetirement(await read(closure.retirementRef)), native = retirement.nativeClosure;
      if (native.kind !== 'linux_successor_response_unavailable_cleanup') assert.fail('the original refused-output retirement needs actual separate successor cleanup');
      assert.equal(retirement.retirementDigest, closure.retirementDigest); assert.equal(retirement.joined, undefined);
      assert.equal(native.lifecycleRawRef, crashed.birthDigest);
      const original = await retired(native.lifecycleRawRef, native.lifecycleProjectionRef, 'recovery', true);
      assert.equal(original.progressKind, 9); assert.equal(original.joined.statusReleased, true);
      assert.equal(original.joined.protocolCompleted, false); assert(original.retirement.observedAtMs <= crashed.killedAt);
      const domain = retirement.creatorProcessDomain; assert(domain);
      assert.equal(domain.creatorStateOwnerEpoch, crashed.originalStateOwnerEpoch);
      assert.equal(domain.inspectorStateOwnerEpoch, crashed.successorStateOwnerEpoch);
      const cleanup = await read(native.cleanupProjectionRef), cleanupRaw = await context.readCas(native.cleanupRawRef);
      assert.equal(sha256Bytes(cleanupRaw), native.cleanupRawRef); assert.equal(cleanup.originalBirthDigest, crashed.birthDigest);
      assert.equal(cleanup.currentChecker.stateOwnerEpoch, crashed.successorStateOwnerEpoch);
      assert.equal(cleanup.currentChecker.supervisorInstanceId, crashed.successorSupervisorInstanceId);
      assert.equal(cleanup.priorSupervisorDead, true); assert.equal(cleanup.priorControllerDead, true);
      assert.equal(cleanup.outputCustodyRetired, true); assert.equal(cleanup.remainingDescendants, 0);
      assert(!cleanupRaw.includes(Buffer.from('cliq-fixture-refused-status-sentinel')));
      await assertRefusedPayloadAbsent({ original, retirement, closure, cleanup });
      await context.assertWorkerFree(runId, recovered);
      for (const method of ['run.result', 'run.diff']) { const result = await context.send({ protocolVersion: 1, method, runId });
        assert.equal(result.ok, false); assert.equal(result.error?.code, 'RESULT_UNAVAILABLE'); }
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE); same(await identity(path.join(workspace, 'example.txt')), before);
    } else if (owningStop) {
      assert.deepEqual(effects.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', 'unknown']);
      if (!observedStatusWait || observedStatusWait.probeState.phase !== 'automatic_in_flight') assert.fail('the genuine original status nonce was not observed in flight');
      const dispatch = observedStatusWait.probeState.dispatch; assert.equal(dispatch.subjectKind, 'mcp_recovery');
      assert.equal(observedStatusWait.probeState.automaticProbeCount, 1); assert.equal(observedStatusWait.probeState.userProbeCount, 0);
      // This is an ordinary observer delay, not a process pause or a proof.
      // The mandatory real retirement statusReleased assertion below must
      // independently show the intended cut was reached, or this case fails.
      await delay(500); await context.restart();
      const after = await get(runId), nextWait = decodeMcpInvocationWait(await read(after.snapshot.run.waitingOnRef));
      assert.equal(after.snapshot.run.status, 'waiting'); same(after.journal, cut.journal); same(after.items, cut.items);
      same(after.snapshot.run.budgetConsumed, cut.snapshot.run.budgetConsumed); same(after.snapshot.run.budgetReserved, ZERO);
      same(nextWait.subject, observedStatusWait.subject);
      if (nextWait.probeState.phase !== 'automatic_pending') assert.fail('owning shutdown must close only the original nonce and preserve waiting');
      assert.equal(nextWait.probeState.automaticProbeCount, 1); assert.equal(nextWait.probeState.userProbeCount, 0);
      assert(Date.parse(nextWait.probeState.nextProbeAt) >= Date.parse(dispatch.probeDeadlineAt) + 1_000,
        'shutdown must not advance the original thirty-second deadline and first backoff');
      if (!nextWait.probeState.lastProbeEvidenceRef || !nextWait.probeState.lastProbeEvidenceDigest) assert.fail('the actual cancellation closure must be durable');
      const wrapper = decodeMcpStatusProbeWrapper(await read(nextWait.probeState.lastProbeEvidenceRef));
      assert.equal(wrapper.evidenceDigest, nextWait.probeState.lastProbeEvidenceDigest);
      if (wrapper.outcome !== 'probe_cancelled') assert.fail('owning shutdown cannot masquerade as status observation or timeout');
      assert.equal(wrapper.probeNonceDigest, dispatch.probeNonceDigest); assert.equal(wrapper.probeDispatchDigest, dispatch.dispatchDigest);
      assert.equal(wrapper.probeDeadlineAt, dispatch.probeDeadlineAt);
      const closure = decodeMcpStatusProbeClosure(await read(wrapper.cancellationClosureRef));
      assert.equal(closure.closureDigest, wrapper.cancellationClosureDigest);
      assert.equal(closure.format, 'cliq-reconciliation-probe-cancellation-closure-v1');
      assert(closure.closedAt < dispatch.probeDeadlineAt, 'the intended active original nonce must close before its unchanged deadline');
      const retirement = decodeMcpStatusRetirement(await read(closure.retirementRef)); assert.equal(retirement.retirementDigest, closure.retirementDigest);
      assert.equal(retirement.nativeClosure.kind, refusedStop ? 'linux_original_response_unavailable' : 'linux_original_join');
      const actual = refusedStop ? await refusedRetirement(closure) :
        await retired(retirement.nativeClosure.lifecycleRawRef, retirement.nativeClosure.lifecycleProjectionRef, 'recovery');
      assert.equal(actual.joined.statusReleased, true, 'a persisted pre-birth wait alone does not validate active status cancellation');
      assert.equal(actual.joined.protocolCompleted, false); assert.equal(Object.hasOwn(actual.joined, 'effectReleased'), false);
      await context.assertWorkerFree(runId, after);
      const earlyProbe = signed({ protocolVersion: 1, method: 'run.reconcile', requestId: context.nextId(), runId,
        expectedRevision: after.snapshot.run.revision, waitingOnRef: after.snapshot.run.waitingOnRef, resolution: { kind: 'probe_now' } });
      const refusal = await context.send(earlyProbe); assert.equal(refusal.ok, false); assert.equal(refusal.error?.code, 'INVALID_REQUEST');
      assert.equal(canonicalSha256(await get(runId)), canonicalSha256(after),
        'an early user request must not replace a counted automatic nonce, reset its schedule or charge');
      for (const method of ['run.result', 'run.diff']) { const refused = await context.send({ protocolVersion: 1, method, runId });
        assert.equal(refused.ok, false); assert.equal(refused.error?.code, 'RESULT_UNAVAILABLE'); }
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE); same(await identity(path.join(workspace, 'example.txt')), before);
    } else if (firstClosure) {
      assert.deepEqual(effects.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', 'unknown']);
      if (!closedStatusWait || closedStatusWait.probeState.phase !== 'automatic_pending') assert.fail('the first original status closure is absent');
      const next = closedStatusWait.probeState;
      assert.equal(next.automaticProbeCount, 1); assert.equal(next.userProbeCount, 0);
      if (!next.lastProbeEvidenceRef || !next.lastProbeEvidenceDigest) assert.fail('the original status closure evidence is absent');
      const wrapper = decodeMcpStatusProbeWrapper(await read(next.lastProbeEvidenceRef));
      assert.equal(wrapper.evidenceDigest, next.lastProbeEvidenceDigest); assert.equal(wrapper.probeOrdinal, 1);
      const oldWait = decodeMcpInvocationWait(await read(wrapper.waitingSubjectRef));
      if (oldWait.probeState.phase !== 'automatic_in_flight') assert.fail('the original status nonce is absent');
      const dispatch = oldWait.probeState.dispatch;
      same(oldWait.subject, closedStatusWait.subject);
      assert.equal(wrapper.probeNonceDigest, dispatch.probeNonceDigest); assert.equal(wrapper.probeDispatchDigest, dispatch.dispatchDigest);
      assert.equal(wrapper.probeDeadlineAt, dispatch.probeDeadlineAt);
      assert(Date.parse(next.nextProbeAt) >= Date.parse(wrapper.observedAt) + 1_000);
      if (refusedTimeout) {
        if (wrapper.outcome !== 'probe_timeout') assert.fail('a refused status response may only close this normally running nonce at its original deadline');
        const closure = decodeMcpStatusProbeClosure(await read(wrapper.timeoutClosureRef));
        assert.equal(closure.closureDigest, wrapper.timeoutClosureDigest);
        assert(closure.closedAt >= dispatch.probeDeadlineAt);
        await refusedRetirement(closure);
      } else {
        await assertUnresolvedStatus(wrapper, dispatch.probeDeadlineAt, claims[0].evidenceRef);
      }
      if (userReplay) await exerciseExhaustedUserReplay(runId, cut, closedStatusWait, claims[0].evidenceRef);
      else {
        await context.restart(); const after = await get(runId);
        assert.equal(after.snapshot.run.status, 'waiting'); same(after.journal, cut.journal); same(after.items, cut.items);
        same(after.snapshot.run.budgetConsumed, cut.snapshot.run.budgetConsumed); same(after.snapshot.run.budgetReserved, ZERO);
        same(await firstAutomaticClosure(after.snapshot.run.waitingOnRef), closedStatusWait);
      }
      for (const method of ['run.result', 'run.diff']) { const result = await context.send({ protocolVersion: 1, method, runId });
        assert.equal(result.ok, false); assert.equal(result.error?.code, 'RESULT_UNAVAILABLE'); }
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE); same(await identity(path.join(workspace, 'example.txt')), before);
    } else {
      assert.deepEqual(effects.map((row: Data) => [row.attempt, row.phase]), [[0, 'prepared'], [0, 'dispatch_claimed'], [0, 'unknown'],
        [1, 'prepared'], [1, 'dispatch_claimed'], [1, 'unknown']]);
      const previous = decodeMcpRetryDispatchClosure(await read(prepared[1].evidenceRef));
      assert.equal(previous.unknownJournalSeq, unknowns[0].seq); assert.equal(previous.nextAttempt, 1); assert.equal(previous.kind, 'original_native_joined');
      const detail = await read(cut.snapshot.run.terminalDetailRef); assert.equal(detail.abandonedRetryInvocations.length, 1);
      const retained = detail.abandonedRetryInvocations[0]; assert.equal(retained.unknownJournalSeq, unknowns[1].seq);
      assert.equal(retained.budgetSettlementRef, unknowns[1].budgetSettlementRef);
      const last = decodeMcpRetryDispatchClosure(await read(retained.dispatchFenceOrDeathEvidenceRef));
      assert.equal(last.unknownJournalSeq, unknowns[1].seq); assert.equal(last.kind, 'original_native_joined'); assert.equal(last.callDeadlineMs, previous.callDeadlineMs);
      const stop = decodeAgentStop(await read(cut.snapshot.run.stopIntentRef), cut.snapshot.run);
      if (stop.origin !== 'runtime' || stop.runtimeSubtype !== 'runtime' || stop.reason !== 'runtime_failed' || !stop.runtimeFailureRef)
        assert.fail('capacity exhaustion must use the sole real resource Stop');
      const failure = await read(stop.runtimeFailureRef); assert.equal(failure.failureKind, 'mcp_call_resource_exhausted');
      assert.equal(failure.resource, 'server_launch_capacity'); assert.equal(failure.limit, 2); assert.equal(failure.used, 2);
      const items = await Promise.all(cut.items.map((item: Data) => read(item.payloadRef))), carrier = items.filter(item => item.kind === 'tool_result' && item.opId === unknowns[1].opId);
      assert.equal(carrier.length, 1); assert.equal(carrier[0].outcome, 'cancelled');
      const result = decodeRetryUnknownCancelledResult(await read(carrier[0].resultRef)); assert.equal(result.unknownJournalSeq, unknowns[1].seq);
      assert.equal(result.dispatchFenceOrDeathEvidenceRef, retained.dispatchFenceOrDeathEvidenceRef); assert.equal(cut.snapshot.run.budgetConsumed.toolCalls, 4);
      await context.restart(); same(await get(runId), cut); assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE);
      same(await identity(path.join(workspace, 'example.txt')), before);
    }
    assert.equal(context.modelResponder.posts(kind), knownResult ? 3 : 1);
    if (userReplay) {
      return { diagnosticOnly: true, qualified: true, profile: INSTALLED_MCP_STATUS_USER_REPLAY_PROFILE,
        cases: [{ kind, realAutomaticProbes: 8, minimumRealBackoffsMs: 6_156_000, userProbes: 1, originalDeadlineMs: 30_000,
          originalFullChargePreserved: true, originalFirstResponseReplayed: true, changedRequestRefused: true, reconnectAndRestart: true, noEffectRedispatch: true }],
        statusUserReplayQualified: true, actualProviderQualified: false,
        completeI1Qualified: false, completeI2Qualified: false, completeI3Qualified: false, completeI4Qualified: false };
    }
    cases.push({ kind, actualSignedStaticImage: true, nativeAdminRetired: true, originalUnknownFullCharge: true,
      genuineOriginalNativeJoin: true, effectClaims: claims.length, launchClaims: http ? 0 : claims.length,
      ...(completedStatus || confirmedFailure ? { independentSignedReadonlyStatus: true, originalResponseUnavailable: true, originalExecutionObserved: false,
        targetProfileClass: confirmedFailure ? 'immutable_missing_noop_target' : 'immutable_preexisting_noop_target',
        ...(confirmedFailure ? { immutableRequiredTargetAbsent: true, originalUnknownChargeUnchanged: true } : {}),
        requiredNodeVerified: true, exactResultReviewedAndApplied: true }
        : http ? { exactOriginalNativeDeadline: true, originalKeyAcrossThreeTrueClaims: true, twoFullyChargedUnknowns: true,
          laterRealClaimedResultPreserved: true, noFourthAttempt: true, requiredNodeVerified: true, exactResultReviewedAndApplied: true }
          : owningStop ? { actualStatusReleasedBeforeStop: true, originalNativeCancellationJoined: true, stopWithinOriginalTwoSeconds: true,
          originalNonceAndDeadlinePreserved: true, originalAutomaticCountPreserved: true, backoffNotAdvanced: true, earlyUserProbeRefused: true,
          ...(refusedStop ? { refusedResponseJoinedAndAudited: true, refusedPayloadAndDigestAbsent: true } : {}) }
          : refusedTimeout ? { boundedMalformedStatusReceivedAndJoined: true, originalDeadlineAndBackoffPreserved: true,
            refusedPayloadAndDigestAbsent: true, unknownAndOriginalFullChargePreserved: true }
          : ordinaryUnresolved ? { schemaValidStatusObservedAndJoined: true, neitherOriginalSignedPredicateMatched: true,
            originalBackoffPreserved: true, unknownAndOriginalFullChargePreserved: true }
          : strictSuccessor ? { originalCompleteRefusedBirthObservedBeforeCrash: true, actualOriginalSupervisorDeath: true,
            exactStrictSuccessorCleanup: true, originalDeadlineAndBackoffPreserved: true, refusedPayloadAndDigestAbsent: true }
          : { originalServerLaunchLimit: 2, noThirdAttemptOrLaunch: true, originalDeadlineUnchanged: true, oneTerminalUnusedUnknown: true }),
      noModelResend: true, originalAdmissionReplayed: true, reconnectAndRestart: true, allRecordedWorkersRetired: true });
  }
  return { diagnosticOnly: true, qualified: true, profile: INSTALLED_MCP_RECOVERY_PROFILE, cases,
    signedImmutableNoopStatusCompletedQualified: true, stdioRetryServerCapacityQualified: true,
    originalEffectExecutionQualified: false, originalEffectPayloadRecovered: false, signedStatusFailedQualified: true,
    signedStatusUnresolvedQualified: true, maliciousOrRefusedStatusQualified: true, boundedMalformedStatusOwningStopQualified: true,
    statusOldNonceSuccessorCleanupQualified: false, refusedStatusOldNonceSuccessorCleanupQualified: true,
    statusUserReplayQualified: false, activeStatusStopQualified: true, statusEarlyUserRefusalQualified: true, httpRetryCap3Qualified: true,
    retryPositiveLaterClaimPrecedenceQualified: true, retryUnclaimedFailureAfterUnknownQualified: false, typedRetentionQualified: false, exactClaimStopCutQualified: false,
    actualProviderQualified: false, completeI1Qualified: false, completeI2Qualified: false, completeI3Qualified: false, completeI4Qualified: false };
}
