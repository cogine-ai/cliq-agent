// Actual signed installed entry and authenticated v1 UDS only. No native
// factories, generated recovery evidence, process suspension or private writes.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chown, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeAdminProbeClosureEvidence, decodeManualAbandonAttestation, decodeManualInvocationWait,
  decodeMcpRegistrationReceipt } from '../../../src/kernel/mcp.js';
import { decodeMcpServerInstanceIdentity, decodeMcpServerLaunchReceipt, decodeMcpStdioCapture } from '../../../src/kernel/mcp-stdio.js';
import { decodeMcpServerLaunchFailure } from '../../../src/kernel/mcp-server-authorization.js';
import { decodeAgentStop } from '../../../src/runtime/stop.js';
import { decodeBudgetSettlement } from '../../../src/state/decoders.js';
import { decodeRunResult, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import type { InstalledMcpContext } from './installed-mcp-journey.js';
import { MCP_BEFORE, MCP_AFTER } from './installed-mcp-model.js';
import { INSTALLED_MCP_STDIO_CASES, INSTALLED_MCP_STDIO_TOOL, installedMcpStdioKnown, installedMcpStdioMode,
  installedMcpStdioObjective, installedMcpStdioRegistrationId, type createInstalledMcpStdioModelResponder } from './installed-mcp-stdio-model.js';

type Data = Record<string, any>;
type Response = { protocolVersion: 1; ok: boolean; result?: Data; error?: Data };
type Reader = (ref: string) => Promise<Buffer>;
type Context = Pick<InstalledMcpContext, 'workspaceRoot' | 'cliqHome' | 'uid' | 'gid' | 'model' | 'guestToolchainManifestId' |
  'send' | 'nextId' | 'readCas' | 'download' | 'reconnect' | 'restart' | 'assertWorkerFree' | 'assertOriginalProcessAbsent' |
  'assertVerifierEvidence' | 'assertDeliveryEvidence' | 'mark'> & {
    runtimeBundleId: string; modelResponder: ReturnType<typeof createInstalledMcpStdioModelResponder>;
  };
const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const ONE = { ...ZERO, toolCalls: 1 };
const signed = (core: Data) => ({ ...core, requestDigest: canonicalSha256(core) });
const same = (a: unknown, b: unknown) => assert.equal(canonicalSha256(a), canonicalSha256(b));
function accepted(response: Response, method: string): Data {
  assert(response.protocolVersion === 1 && response.ok === true && response.result?.method === method,
    'the actual installed stdio request was refused');
  return response.result!;
}
async function object(read: Reader, ref: string): Promise<Data> {
  assert.match(ref, /^[0-9a-f]{64}$/u);
  const bytes = await read(ref); assert(bytes.length <= 1_048_576); assert.equal(sha256Bytes(bytes), ref);
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  assert(canonicalJsonBytes(value).equals(bytes)); return value as Data;
}
async function fileIdentity(filename: string) {
  const info = await lstat(filename, { bigint: true }); assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1n);
  return Object.fromEntries(['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs']
    .map(key => [key, info[key as keyof typeof info]!.toString()]));
}
export const INSTALLED_MCP_STDIO_PROFILE = 'installed_signed_static_stdio_separate_launch_effect_known_unknown_manual_v1';

export async function runInstalledMcpStdioCases(context: Context) {
  const send = async (frame: Data, timeout = 30_000) => accepted(await context.send(frame, timeout), String(frame.method));
  const get = (runId: string, timeout = 30_000) => send({ protocolVersion: 1, method: 'run.get', runId }, timeout);
  const read = (ref: string) => object(context.readCas, ref);
  const cases: Data[] = [];
  async function retired(rawRef: string, projectionRef: string, expected: 'admin' | 'run') {
    const raw = await context.readCas(rawRef); assert(raw.length <= 16_777_216); assert.equal(sha256Bytes(raw), rawRef);
    // The actual authenticated registration/run reader audits this exact raw
    // and projection pair with its loaded fixed native decoder. This external
    // observer never installs a StateOwner or manufactures a decoder owner.
    const original = await read(projectionRef);
    assert.equal(original.format, 'cliq-mcp-stdio-native-lifecycle-v1'); assert.equal(original.schemaVersion, 1);
    assert.equal(original.binding.kind, expected); assert(original.containment && original.retirement);
    assert(original.joined.deathJoined && original.joined.outputCustodyRetired && original.joined.ownerDrained);
    assert.equal(original.joined.responseRefused, false);
    assert.equal(original.containment.cgroupPopulated, 1); assert.equal(original.retirement.cgroupPopulated, 0);
    assert.equal(original.retirement.namespaceInitDeadAndReaped, 1); assert.equal(original.retirement.remainingTrackedDescendants, 0);
    assert.equal(original.retirement.namespaceInitStartToken, original.containment.namespaceInitStartToken);
    const match = /^linux-namespace-init:([1-9][0-9]*):([1-9][0-9]*):monitor:([1-9][0-9]*):([1-9][0-9]*)$/u
      .exec(original.containment.namespaceInitStartToken); assert(match);
    for (const [pid, start] of [[match[1], match[2]], [match[3], match[4]]]) await context.assertOriginalProcessAbsent(Number(pid), start!);
    assert.match(original.containment.processStartToken, /^linux-proc-start-ticks:[1-9][0-9]*$/u);
    await context.assertOriginalProcessAbsent(original.containment.pid, original.containment.processStartToken.slice('linux-proc-start-ticks:'.length));
    return original;
  }
  for (const kind of INSTALLED_MCP_STDIO_CASES) {
    context.mark(`mcp_stdio_${kind}`); context.modelResponder.begin(kind);
    const registrationId = installedMcpStdioRegistrationId(kind);
    const identity = (await send(signed({ protocolVersion: 1, method: 'authorization.create', requestId: context.nextId(),
      decision: { kind: 'execution_identity_read', purpose: 'mcp_stdio', target: { kind: 'runtime_bundle_executable',
        runtimeBundleId: context.runtimeBundleId, executableId: 'mcp-static-stdio-fixture-v1' } } }))).grant;
    assert.equal(identity.purpose, 'mcp_stdio'); assert.equal(identity.state, 'active');
    const registrationFrame = signed({ protocolVersion: 1, method: 'mcp.register', requestId: context.nextId(), registrationId,
      target: { kind: 'stdio', executionIdentityGrantId: identity.grantId,
        argv: [{ kind: 'non_secret_literal', value: installedMcpStdioMode(kind) }] }, assertStatelessPerCall: true,
      toolRecovery: { [INSTALLED_MCP_STDIO_TOOL]: { kind: 'manual' } },
      lifecycle: { launchTimeoutMs: 5000, callTimeoutMs: 20_000, maxLaunchesPerCall: 1 } });
    const registrationResponse = await context.send(registrationFrame), summary = accepted(registrationResponse, 'mcp.register').registry;
    assert.equal(summary.registryRevision, 1); assert.equal(summary.transport, 'stdio'); assert.equal(summary.toolCount, 1);
    const receipt = decodeMcpRegistrationReceipt(await read(summary.registrationReceiptRef));
    const closure = decodeAdminProbeClosureEvidence(await read(receipt.probeClosureEvidenceRef));
    assert.equal(closure.closureKind, 'containment_dead'); assert.equal(closure.adminOperationId, receipt.adminOperationId);
    assert.equal(closure.attempt, receipt.adminAttempt); assert.equal(closure.evidenceDigest, receipt.probeClosureEvidenceDigest);
    assert(closure.nativeLifecycleRef && closure.nativeLifecycleProjectionRef);
    const admin = await retired(closure.nativeLifecycleRef, closure.nativeLifecycleProjectionRef, 'admin');
    assert.equal(admin.joined.protocolCompleted, true); assert.equal(admin.joined.effectReleased, false);
    assert.deepEqual(await context.send(registrationFrame), registrationResponse);
    assert((await send({ protocolVersion: 1, method: 'mcp.list' })).registrations.some((row: Data) =>
      row.registrationId === registrationId && row.manifestDigest === summary.manifestDigest));

    const workspace = path.join(context.workspaceRoot, `mcp-stdio-${kind}`);
    await mkdir(workspace, { mode: 0o700 }); await chown(workspace, context.uid, context.gid);
    const check = "import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';test('owned stdio-assisted edit',async()=>assert.equal(await readFile(new URL('./example.txt',import.meta.url),'utf8')," + JSON.stringify(MCP_AFTER) + "));\n";
    for (const [name, text] of [['example.txt', MCP_BEFORE], ['check.test.mjs', check]]) {
      const filename = path.join(workspace, name!); await writeFile(filename, text!, { flag: 'wx', mode: 0o644 }); await chown(filename, context.uid, context.gid);
    }
    const before = await fileIdentity(path.join(workspace, 'example.txt')), workspaceId = sha256Bytes(Buffer.from(workspace));
    const directory = path.join(context.cliqHome, 'workspaces', workspaceId); await mkdir(directory, { recursive: true, mode: 0o700 });
    for (const filename of [path.dirname(directory), directory]) await chown(filename, context.uid, context.gid);
    const trust = path.join(directory, 'trust.json'); await writeFile(trust, canonicalJsonBytes({ version: 1, workspaceId,
      workspaceRealPath: workspace, decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 });
    await chown(trust, context.uid, context.gid);
    const session = (await send(signed({ protocolVersion: 1, method: 'session.create', requestId: context.nextId(),
      admissionKey: randomBytes(32).toString('base64url'), workspacePath: workspace, name: 'Owned stdio lifecycle' }))).snapshot.session;
    const verifiers: Data[] = [];
    if (installedMcpStdioKnown(kind)) {
      const grant = (await send(signed({ protocolVersion: 1, method: 'authorization.create', requestId: context.nextId(),
        decision: { kind: 'execution_identity_read', purpose: 'verifier', target: {
          kind: 'guest_toolchain', guestToolchainManifestId: context.guestToolchainManifestId, toolId: 'node' } } }))).grant;
      verifiers.push({ id: 'node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
        argv: ['--test', '--test-concurrency=1', 'check.test.mjs'].map(value => ({ kind: 'non_secret_literal', value })),
        cwd: '.', env: {}, writableEphemeralPaths: [], identityReadGrantId: grant.grantId, timeoutMs: 10_000, retries: 0, outputLimitBytes: 65_536 });
    }
    const submit = signed({ protocolVersion: 1, method: 'run.submit', requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
      sessionId: session.id, expectedContextRevision: session.contextRevision, workspacePath: workspace, objective: installedMcpStdioObjective(kind),
      model: context.model, policyMode: 'yolo', budgets: { wallTimeMs: 300_000, modelTokens: 2_000_000, costMicros: 10_000_000,
        toolCalls: 1000, repairAttempts: 0, childDepth: 0, childConcurrency: 1 }, dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [],
      registeredMcpServerIds: [registrationId], skillIds: [], verifiers, allowUnverified: false });
    const admission = await context.send(submit), runId = accepted(admission, 'run.submit').snapshot.run.id;
    const by = Date.now() + 90_000; let cut: Data, cancellation: Data | undefined;
    for (;;) {
      const remaining = by - Date.now(); assert(remaining > 0, 'stdio source exceeded the original 90-second observation window');
      cut = await get(runId, Math.min(30_000, remaining)); assert(Date.now() < by);
      if (kind === 'unknown_cancel' && !cancellation && cut.journal.some((row: Data) => row.opKind === 'mcp' && row.phase === 'dispatch_claimed')) {
        // Ordinary cancellation, without a suspension or a fabricated release
        // cut. The final original native lifecycle must independently prove
        // that a real effect was released; otherwise this case fails.
        await delay(100);
        const cancellationRemaining = by - Date.now(); assert(cancellationRemaining > 0);
        const cancellationCut = await get(runId, Math.min(30_000, cancellationRemaining));
        assert.equal(cancellationCut.snapshot.run.status, 'running', 'the intended active ordinary cancellation target was not observed');
        cancellation = signed({ protocolVersion: 1, method: 'run.cancel', requestId: context.nextId(), runId,
          expectedRevision: cancellationCut.snapshot.run.revision });
        accepted(await context.send(cancellation), 'run.cancel');
      }
      if (installedMcpStdioKnown(kind) ? cut.snapshot.run.status === 'succeeded'
        : cut.snapshot.run.status === 'waiting' && cut.snapshot.run.waitingReason === 'reconciliation') break;
      assert(!['failed', 'cancelled', 'completed_unverified'].includes(cut.snapshot.run.status), 'stdio source reached an unexpected terminal state');
      await delay(100);
    }
    const effect = cut.journal.filter((row: Data) => row.opKind === 'mcp'), launch = cut.journal.filter((row: Data) => row.opKind === 'mcp-server');
    assert.deepEqual(effect.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', installedMcpStdioKnown(kind) ? 'completed' : 'unknown']);
    assert.deepEqual(launch.map((row: Data) => row.phase), ['prepared', 'dispatch_claimed', installedMcpStdioKnown(kind) ? 'completed' : 'failed']);
    const claim = effect[1]!, effectFinal = effect[2]!, launchFinal = launch[2]!;
    assert.equal(launchFinal.seq, effectFinal.seq + 1); assert.equal(launchFinal.timestamp, effectFinal.timestamp);
    const effectBudget = decodeBudgetSettlement(await read(effectFinal.budgetSettlementRef));
    const launchBudget = decodeBudgetSettlement(await read(launchFinal.budgetSettlementRef));
    for (const settlement of [effectBudget, launchBudget]) { same(settlement.consumed, ONE); same(settlement.released, ONE); same(settlement.reserved, ONE); }
    const instance = decodeMcpServerInstanceIdentity(await read(claim.evidenceRef)); assert.equal(instance.identityDigest, claim.evidenceDigest);
    assert.equal(instance.launchOpId, launch[0]!.opId); assert.equal(instance.launchDispatchId, launch[1]!.dispatchId);
    let original;
    if (installedMcpStdioKnown(kind)) {
      const terminal = decodeMcpServerLaunchReceipt(await read(launchFinal.receiptRef));
      assert.equal(terminal.instanceIdentityRef, claim.evidenceRef); assert.equal(terminal.nativeClosure.kind, 'linux_original_join');
      original = await retired(terminal.nativeClosure.lifecycleRawRef, terminal.nativeClosure.lifecycleProjectionRef, 'run');
      const observation = await read(effectFinal.resultRef), capture = await read(observation.captureRef);
      assert.equal(observation.captureDigest, capture.captureDigest); assert.equal(capture.binding.instanceIdentityRef, claim.evidenceRef);
      const calls = capture.captures.filter((entry: Data) => entry.phase === 'tools_call'); assert.equal(calls.length, 1);
      const call = decodeMcpStdioCapture(await read(calls[0]!.captureRef)); assert.equal(call.phase, 'tools_call');
      const bytes = await context.readCas(call.rawResponseRef); assert.equal(bytes.length, call.rawFinitePrefixBytes);
      assert(bytes.includes(Buffer.from('called once'))); assert.equal(sha256Bytes(bytes), call.rawResponseRef);
    } else {
      const terminal = decodeMcpServerLaunchFailure(await read(launchFinal.errorRef));
      assert.equal(terminal.reason, 'owning_call_unknown'); assert.equal(terminal.instance, 'initialized');
      assert.equal(terminal.nativeClosure.kind, 'linux_original_join');
      original = await retired(terminal.nativeClosure.lifecycleRawRef, terminal.nativeClosure.lifecycleProjectionRef, 'run');
    }
    assert.equal(original.joined.effectReleased, true); assert.equal(original.joined.execReleased, true);
    same(cut.snapshot.run.budgetReserved, ZERO); await context.assertWorkerFree(runId, cut);
    assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE); same(await fileIdentity(path.join(workspace, 'example.txt')), before);
    assert.deepEqual(await context.send(submit), admission); same(await get(runId), cut); await context.reconnect(); same(await get(runId), cut);
    if (installedMcpStdioKnown(kind)) {
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
      const response = await context.send(apply), deliveryId = accepted(response, 'run.apply').snapshot.run.id;
      const deliveryBy = Date.now() + 90_000; let delivery: Data;
      for (;;) {
        const remaining = deliveryBy - Date.now(); assert(remaining > 0, 'stdio Delivery exceeded its original 90-second observation window');
        delivery = await get(deliveryId, Math.min(30_000, remaining)); assert(Date.now() < deliveryBy);
        if (delivery.snapshot.run.status === 'succeeded') break;
        assert(!['failed', 'cancelled', 'completed_unverified', 'waiting'].includes(delivery.snapshot.run.status)); await delay(100);
      }
      await context.assertWorkerFree(deliveryId, delivery); await context.assertDeliveryEvidence(delivery, cut, new Map(files.map(file => [file.path, file.after])));
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_AFTER); assert.deepEqual(await context.send(apply), response);
    } else {
      assert.equal(cut.snapshot.run.budgetConsumed.toolCalls, 2);
      const wait = decodeManualInvocationWait(await read(cut.snapshot.run.waitingOnRef)); assert.equal(wait.subject.opId, claim.opId);
      same(wait.probeState, { phase: 'manual_only', automaticProbeCount: 0, userProbeCount: 0 });
      if (kind === 'unknown_cancel') {
        assert(cancellation); assert.equal(decodeAgentStop(await read(cut.snapshot.run.stopIntentRef), cut.snapshot.run).origin, 'user_cancel');
      }
      if (kind === 'unknown_restart') { await context.restart(); same(await get(runId), cut); }
      const acknowledge = signed({ protocolVersion: 1, method: 'run.reconcile', requestId: context.nextId(), runId,
        expectedRevision: cut.snapshot.run.revision, waitingOnRef: cut.snapshot.run.waitingOnRef,
        resolution: { kind: 'abandon_run', acknowledgeExactRisk: true } });
      const response = await context.send(acknowledge); assert.equal(accepted(response, 'run.reconcile').resolution.kind, 'abandoned_run');
      cut = await get(runId); assert.equal(cut.snapshot.run.status, 'cancelled');
      const abandoned = cut.journal.filter((row: Data) => row.opKind === 'mcp' && row.phase === 'abandoned'); assert.equal(abandoned.length, 1);
      same(abandoned[0]!.budgetDelta, ZERO); assert.equal(abandoned[0]!.budgetSettlementRef, effectFinal.budgetSettlementRef);
      const attestation = decodeManualAbandonAttestation(await read(abandoned[0]!.attestationRef));
      assert.equal(attestation.unknownJournalSeq, effectFinal.seq); assert.equal(attestation.requestDigest, acknowledge.requestDigest);
      const items = await Promise.all(cut.items.map((row: Data) => read(row.payloadRef)));
      assert.equal(items.filter(item => item.kind === 'tool_abandoned' && item.opId === claim.opId).length, 1);
      assert.equal(items.filter(item => item.kind === 'tool_result' && item.opId === claim.opId).length, 0);
      assert.equal(cut.snapshot.run.budgetConsumed.toolCalls, 2); same(cut.snapshot.run.budgetReserved, ZERO);
      await context.assertWorkerFree(runId, cut); assert.deepEqual(await context.send(acknowledge), response);
      await context.restart(); same(await get(runId), cut); assert.deepEqual(await context.send(acknowledge), response);
      for (const method of ['run.result', 'run.diff']) { const refused = await context.send({ protocolVersion: 1, method, runId });
        assert.equal(refused.ok, false); assert.equal(refused.error?.code, 'RESULT_UNAVAILABLE'); }
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE); same(await fileIdentity(path.join(workspace, 'example.txt')), before);
    }
    assert.equal(context.modelResponder.posts(kind), installedMcpStdioKnown(kind) ? 3 : 1);
    cases.push({ kind, actualSignedStaticImage: true, nativeAdminRetired: true, launchClaims: 1, effectClaims: 1,
      separateLaunchCharge: 1, separateEffectCharge: 1, completed: installedMcpStdioKnown(kind),
      manualAbandonment: !installedMcpStdioKnown(kind), originalAdmissionReplayed: true, noResend: true, allRecordedWorkersRetired: true });
  }
  return { diagnosticOnly: true, qualified: true, profile: INSTALLED_MCP_STDIO_PROFILE, cases,
    staticStdioProfileQualified: true, stdioQualified: false, retryRiskQualified: false, reconcileAdapterQualified: false, actualProviderQualified: false,
    activeAdminStopQualified: false, zeroIoNoReleaseQualified: false, knownUnusableResultQualified: false,
    successorClaimedCrashQualified: false, exactClaimStopCutQualified: false, initializationPublicationFailureQualified: false,
    preclaimReservationStopQualified: false, completeI1Qualified: false, completeI2Qualified: false };
}
