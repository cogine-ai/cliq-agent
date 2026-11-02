// Real installed requests only. The surrounding owner supplies the original
// signed package, UDS, HTTPS service, process observations and final joins.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chown, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeAdminProbeClosureEvidence, decodeManualAbandonAttestation, decodeManualInvocationWait,
  decodeMcpRegistrationReceipt, decodeToolAbandonedItem, decodeMcpHttpCapture } from '../../../src/kernel/mcp.js';
import { decodeAgentStop } from '../../../src/runtime/stop.js';
import { decodeBudgetSettlement } from '../../../src/state/decoders.js';
import { decodeRunResult, decodeWorkspaceDiff } from '../../../src/state/result-artifacts.js';
import { INSTALLED_MCP_CASES, OWNED_MCP_TOOL, type InstalledMcpCase, type createInstalledMcpResponder } from './installed-mcp-responder.js';
import { createInstalledMcpModelResponder, installedMcpKnown, installedMcpObjective, installedMcpRegistrationId,
  MCP_BEFORE, MCP_AFTER } from './installed-mcp-model.js';

type Data = Record<string, any>;
type Response = { protocolVersion: 1; ok: boolean; result?: Data; error?: Data };
type Reader = (ref: string) => Promise<Buffer>;
const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const signed = (core: Data) => ({ ...core, requestDigest: canonicalSha256(core) });
const same = (left: unknown, right: unknown) => assert.equal(canonicalSha256(left), canonicalSha256(right));
function accepted(response: Response, method: string): Data {
  assert(response.protocolVersion === 1 && response.ok === true && response.result?.method === method,
    'the real installed MCP request was refused');
  return response.result!;
}
async function object(read: Reader, ref: string): Promise<Data> {
  assert.match(ref, /^[0-9a-f]{64}$/u);
  const bytes = await read(ref); assert(bytes.length <= 1_048_576); assert.equal(sha256Bytes(bytes), ref);
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  assert(canonicalJsonBytes(value).equals(bytes)); return value as Data;
}
async function fileIdentity(filename: string) {
  const info = await lstat(filename, { bigint: true });
  assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1n);
  return Object.fromEntries(['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs']
    .map(key => [key, info[key as keyof typeof info]!.toString()]));
}
export const INSTALLED_MCP_PROFILE = 'installed_stateless_http_known_unknown_manual_restart_v1';
export type InstalledMcpContext = {
  workspaceRoot: string; cliqHome: string; uid: number; gid: number; model: Data;
  guestToolchainManifestId: string; endpointIds: ReadonlyMap<InstalledMcpCase, string>;
  send(frame: Data, timeout?: number): Promise<Response>; nextId(): string;
  readCas: Reader; download: Reader; reconnect(): Promise<void>; restart(): Promise<void>;
  assertWorkerFree(runId: string, cut: Data): Promise<void>;
  assertEndpointJoined(kind: InstalledMcpCase, deadlineAt: number): Promise<void>;
  assertOriginalProcessAbsent(pid: number, startTicks: string): Promise<void>;
  assertVerifierEvidence(cut: Data, files: readonly { path: string; before: string; after: string }[]): Promise<void>;
  assertDeliveryEvidence(cut: Data, sourceCut: Data, files: ReadonlyMap<string, string>): Promise<void>;
  responder: ReturnType<typeof createInstalledMcpResponder>;
  modelResponder: ReturnType<typeof createInstalledMcpModelResponder>;
  mark(phase: string): void;
};

export async function runInstalledMcpCases(context: InstalledMcpContext) {
  const send = async (frame: Data, timeout = 30_000) => accepted(await context.send(frame, timeout), String(frame.method));
  const get = (runId: string, timeout = 30_000) => send({ protocolVersion: 1, method: 'run.get', runId }, timeout);
  const read = (ref: string) => object(context.readCas, ref);
  const cases: Data[] = [];
  let successorAcknowledgement = false, higherStopPreserved = false;
  for (const kind of INSTALLED_MCP_CASES) {
    context.mark(`mcp_${kind}`); context.responder.begin(kind); context.modelResponder.begin(kind);
    const endpoint = context.endpointIds.get(kind); assert(endpoint);
    const registrationId = installedMcpRegistrationId(kind), registrationFrame = signed({ protocolVersion: 1,
      method: 'mcp.register', requestId: context.nextId(), registrationId,
      target: { kind: 'streamable_http', endpointRegistrationId: endpoint, credentialGrantIds: [] },
      assertStatelessPerCall: true, toolRecovery: { [OWNED_MCP_TOOL]: { kind: 'manual' } } });
    const registrationResponse = await context.send(registrationFrame, 30_000);
    const summary = accepted(registrationResponse, 'mcp.register').registry;
    assert.equal(summary.registryRevision, 1);
    assert.equal(summary.transport, 'streamable_http'); assert.equal(summary.toolCount, 1);
    const receipt = decodeMcpRegistrationReceipt(await read(summary.registrationReceiptRef));
    const closure = decodeAdminProbeClosureEvidence(await read(receipt.probeClosureEvidenceRef));
    assert.equal(closure.closureKind, 'containment_dead');
    assert.equal(closure.adminOperationId, receipt.adminOperationId); assert.equal(closure.attempt, receipt.adminAttempt);
    assert.equal(closure.evidenceDigest, receipt.probeClosureEvidenceDigest);
    assert(closure.nativeLifecycleRef && closure.nativeLifecycleProjectionRef);
    const rawLifecycle = await context.readCas(closure.nativeLifecycleRef);
    assert.equal(sha256Bytes(rawLifecycle), closure.nativeLifecycleDigest);
    const physical = await read(closure.nativeLifecycleProjectionRef);
    assert.equal(canonicalSha256(physical), closure.nativeLifecycleProjectionDigest);
    assert.equal(physical.binding.adminOperationId, receipt.adminOperationId);
    assert.equal(physical.binding.attempt, receipt.adminAttempt);
    assert.equal(physical.joined.deathJoined, true); assert.equal(physical.joined.outputCustodyRetired, true);
    assert.equal(physical.joined.protocolCompleted, true); assert(physical.containment && physical.retirement);
    assert.equal(physical.containment.cgroupPopulated, 1); assert.equal(physical.retirement.cgroupPopulated, 0);
    assert.equal(physical.retirement.namespaceInitDeadAndReaped, 1); assert.equal(physical.retirement.remainingTrackedDescendants, 0);
    same(physical.retirement.namespaceInitStartToken, physical.containment.namespaceInitStartToken);
    const token = physical.containment.namespaceInitStartToken as string;
    const processes = /^linux-namespace-init:([1-9][0-9]*):([1-9][0-9]*):monitor:([1-9][0-9]*):([1-9][0-9]*)$/u.exec(token);
    assert(processes, 'the actual Admin namespace and monitor identities are absent');
    for (const [pid, start] of [[processes[1], processes[2]], [processes[3], processes[4]]])
      await context.assertOriginalProcessAbsent(Number(pid), start!);
    assert.match(physical.containment.processStartToken, /^linux-proc-start-ticks:[1-9][0-9]*$/u);
    await context.assertOriginalProcessAbsent(physical.containment.pid,
      physical.containment.processStartToken.slice('linux-proc-start-ticks:'.length));
    assert.deepEqual(await context.send(registrationFrame, 30_000), registrationResponse,
      'registration replay must preserve its original discovery and retirement');
    assert.equal(context.responder.inspect(kind).clients, 1);
    assert((await send({ protocolVersion: 1, method: 'mcp.list' })).registrations.some((entry: Data) =>
      entry.registrationId === registrationId && entry.manifestDigest === summary.manifestDigest));

    const workspace = path.join(context.workspaceRoot, `mcp-${kind}`);
    await mkdir(workspace, { mode: 0o700 }); await chown(workspace, context.uid, context.gid);
    const check = "import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';test('owned MCP-assisted edit',async()=>assert.equal(await readFile(new URL('./example.txt',import.meta.url),'utf8')," + JSON.stringify(MCP_AFTER) + "));\n";
    for (const [name, text] of [['example.txt', MCP_BEFORE], ['check.test.mjs', check]]) {
      const filename = path.join(workspace, name!); await writeFile(filename, text!, { flag: 'wx', mode: 0o644 }); await chown(filename, context.uid, context.gid);
    }
    const before = await fileIdentity(path.join(workspace, 'example.txt'));
    const workspaceId = sha256Bytes(Buffer.from(workspace)), directory = path.join(context.cliqHome, 'workspaces', workspaceId);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    for (const filename of [path.dirname(directory), directory]) await chown(filename, context.uid, context.gid);
    const trust = path.join(directory, 'trust.json');
    await writeFile(trust, canonicalJsonBytes({ version: 1, workspaceId, workspaceRealPath: workspace,
      decision: 'trusted', decidedAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 }); await chown(trust, context.uid, context.gid);
    const session = (await send(signed({ protocolVersion: 1, method: 'session.create', requestId: context.nextId(),
      admissionKey: randomBytes(32).toString('base64url'), workspacePath: workspace, name: 'Owned MCP lifecycle' }))).snapshot.session;
    const verifiers: Data[] = [];
    if (installedMcpKnown(kind)) {
      const grant = (await send(signed({ protocolVersion: 1, method: 'authorization.create', requestId: context.nextId(),
        decision: { kind: 'execution_identity_read', purpose: 'verifier', target: {
          kind: 'guest_toolchain', guestToolchainManifestId: context.guestToolchainManifestId, toolId: 'node' } } }))).grant;
      verifiers.push({ id: 'node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
        argv: ['--test', '--test-concurrency=1', 'check.test.mjs'].map(value => ({ kind: 'non_secret_literal', value })),
        cwd: '.', env: {}, writableEphemeralPaths: [], identityReadGrantId: grant.grantId, timeoutMs: 10_000, retries: 0, outputLimitBytes: 65_536 });
    }
    const submit = signed({ protocolVersion: 1, method: 'run.submit', requestId: context.nextId(),
      admissionKey: randomBytes(32).toString('base64url'), sessionId: session.id, expectedContextRevision: session.contextRevision,
      workspacePath: workspace, objective: installedMcpObjective(kind), model: context.model, policyMode: 'yolo',
      budgets: { wallTimeMs: 300_000, modelTokens: 2_000_000, costMicros: 10_000_000, toolCalls: 1000,
        repairAttempts: 0, childDepth: 0, childConcurrency: 1 }, dependency: { mode: 'none' }, sourceIncludes: [], sourceExcludes: [],
      registeredMcpServerIds: [registrationId], skillIds: [], verifiers, allowUnverified: false });
    const admission = await context.send(submit, 30_000), runId = accepted(admission, 'run.submit').snapshot.run.id;
    const by = Date.now() + 90_000;
    let cut: Data;
    for (;;) {
      const remaining = by - Date.now();
      assert(remaining > 0, 'MCP source case exhausted the original 90-second observation window');
      cut = await get(runId, Math.min(30_000, remaining));
      assert(Date.now() < by, 'the observed MCP result arrived after the original 90-second window');
      if (installedMcpKnown(kind) ? cut.snapshot.run.status === 'succeeded'
        : cut.snapshot.run.status === 'waiting' && cut.snapshot.run.waitingReason === 'reconciliation') break;
      assert(!['failed', 'cancelled', 'completed_unverified'].includes(cut.snapshot.run.status), 'the real MCP case reached an unexpected terminal state');
      assert(Date.now() < by, 'MCP source case exceeded the original 90-second terminal observation window'); await delay(100);
    }
    const mcp = cut.journal.filter((row: Data) => row.opKind === 'mcp'), claim = mcp.find((row: Data) => row.phase === 'dispatch_claimed');
    assert(claim); assert.equal(mcp.filter((row: Data) => row.phase === 'dispatch_claimed').length, 1);
    const prepared = mcp.find((row: Data) => row.phase === 'prepared'); assert(prepared);
    const final = mcp.at(-1); assert(final);
    assert.equal(final.phase, installedMcpKnown(kind) ? 'completed' : 'unknown');
    const settlement = decodeBudgetSettlement(await read(final.budgetSettlementRef));
    same(settlement.consumed, prepared.budgetDelta); assert.equal(settlement.consumed.toolCalls, 1);
    same(cut.snapshot.run.budgetReserved, ZERO); await context.assertWorkerFree(runId, cut);
    await context.assertEndpointJoined(kind, by);
    const expectedExternalCalls = kind === 'discovery_changed' ? 0 : 1;
    const owned = context.responder.inspect(kind);
    assert.equal(owned.clients, 2); assert.equal(owned.callRequests, expectedExternalCalls); assert.equal(owned.effects, expectedExternalCalls);
    assert.equal(owned.pingReplies, kind === 'known_sse_ping' ? 1 : 0);
    assert.equal(context.modelResponder.posts(kind), installedMcpKnown(kind) ? 3 : 1);
    assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE);
    same(await fileIdentity(path.join(workspace, 'example.txt')), before);
    assert.deepEqual(await context.send(submit, 30_000), admission); same(await get(runId), cut);
    await context.reconnect(); same(await get(runId), cut);

    if (installedMcpKnown(kind)) {
      const observation = await read(final.resultRef), originalCapture = await read(observation.captureRef);
      assert.equal(observation.captureDigest, originalCapture.captureDigest);
      assert.equal(originalCapture.binding.dispatchId, claim.dispatchId);
      assert.equal(originalCapture.binding.brokerFenceTokenDigest, claim.brokerFenceTokenDigest);
      const toolCapture = originalCapture.captures.filter((entry: Data) => entry.phase === 'tools_call');
      assert.equal(toolCapture.length, 1);
      const capture = decodeMcpHttpCapture(await read(toolCapture[0].captureRef));
      assert.equal(capture.phase, 'tools_call');
      assert.equal(capture.termination, kind === 'known_sse_ping' ? 'sse_response_event' : 'http_eof');
      const raw = await context.readCas(capture.rawResponseRef);
      assert.equal(raw.length, capture.rawFinitePrefixBytes); assert.equal(sha256Bytes(raw), capture.rawFinitePrefixDigest);
      if (kind === 'known_sse_ping') {
        assert(capture.receivedTailBytes > 0); assert(raw.includes(Buffer.from('already received tail')));
      }
      const files = [{ path: 'check.test.mjs', before: check, after: check }, { path: 'example.txt', before: MCP_BEFORE, after: MCP_AFTER }];
      await context.assertVerifierEvidence(cut, files);
      for (const method of ['run.result', 'run.diff']) {
        const value = await send({ protocolVersion: 1, method, runId });
        const descriptor = method === 'run.result' ? value.result : value.diff, bytes = await context.download(descriptor.ref);
        assert.equal(sha256Bytes(bytes), descriptor.ref);
        if (method === 'run.result') assert.equal(decodeRunResult(parseJsonStrict(bytes.toString())).runId, runId);
        else assert.equal(decodeWorkspaceDiff(parseJsonStrict(bytes.toString())).resultSourceRef,
          decodeRunResult(await read(cut.snapshot.run.resultRef)).resultSourceRef);
      }
      await context.restart(); same(await get(runId), cut);
      const apply = signed({ protocolVersion: 1, method: 'run.apply', requestId: context.nextId(), admissionKey: randomBytes(32).toString('base64url'),
        sourceRunId: runId, expectedRunResultRef: cut.snapshot.run.resultRef, budgets: { wallTimeMs: 300_000, toolCalls: 1000 } });
      const applied = await context.send(apply, 30_000), deliveryId = accepted(applied, 'run.apply').snapshot.run.id;
      const deliveryBy = Date.now() + 90_000;
      let delivery: Data;
      for (;;) {
        const remaining = deliveryBy - Date.now();
        assert(remaining > 0, 'MCP Delivery exhausted the original 90-second observation window');
        delivery = await get(deliveryId, Math.min(30_000, remaining));
        assert(Date.now() < deliveryBy, 'the observed MCP Delivery result arrived after the original 90-second window');
        if (delivery.snapshot.run.status === 'succeeded') break;
        assert(!['failed', 'cancelled', 'completed_unverified', 'waiting'].includes(delivery.snapshot.run.status), 'the explicit exact-result MCP Delivery did not succeed');
        assert(Date.now() < deliveryBy, 'MCP Delivery exceeded the original 90-second terminal window'); await delay(100);
      }
      await context.assertWorkerFree(deliveryId, delivery);
      await context.assertDeliveryEvidence(delivery, cut, new Map(files.map(file => [file.path, file.after])));
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_AFTER);
      assert.deepEqual(await context.send(apply, 30_000), applied);
    } else {
      const wait = decodeManualInvocationWait(await read(cut.snapshot.run.waitingOnRef));
      assert.equal(wait.subject.opId, claim.opId); assert.equal(wait.subject.attempt, claim.attempt);
      same(wait.probeState, { phase: 'manual_only', automaticProbeCount: 0, userProbeCount: 0 });
      if (kind === 'unknown_after_effect_restart') { await context.restart(); same(await get(runId), cut); successorAcknowledgement = true; }
      let cancel: Data | undefined;
      if (kind === 'unknown_cancel_then_ack') {
        cancel = signed({ protocolVersion: 1, method: 'run.cancel', requestId: context.nextId(), runId, expectedRevision: cut.snapshot.run.revision });
        accepted(await context.send(cancel), 'run.cancel'); cut = await get(runId);
        assert.equal(cut.snapshot.run.status, 'waiting');
        assert.equal(decodeAgentStop(await read(cut.snapshot.run.stopIntentRef), cut.snapshot.run).origin, 'user_cancel');
      }
      for (const fields of [{ expectedRevision: cut.snapshot.run.revision - 1, waitingOnRef: cut.snapshot.run.waitingOnRef },
        { expectedRevision: cut.snapshot.run.revision, waitingOnRef: 'a'.repeat(64) }]) {
        const refused = await context.send(signed({ protocolVersion: 1, method: 'run.reconcile', requestId: context.nextId(), runId,
          ...fields, resolution: { kind: 'abandon_run', acknowledgeExactRisk: true } }));
        assert.equal(refused.ok, false); assert(['REVISION_CONFLICT', 'INVALID_REQUEST'].includes(refused.error?.code)); same(await get(runId), cut);
      }
      const acknowledgement = signed({ protocolVersion: 1, method: 'run.reconcile', requestId: context.nextId(), runId,
        expectedRevision: cut.snapshot.run.revision, waitingOnRef: cut.snapshot.run.waitingOnRef,
        resolution: { kind: 'abandon_run', acknowledgeExactRisk: true } });
      const response = await context.send(acknowledgement, 30_000), terminal = accepted(response, 'run.reconcile');
      assert.equal(terminal.resolution.kind, 'abandoned_run');
      cut = await get(runId); assert.equal(cut.snapshot.run.status, 'cancelled'); assert.equal(cut.snapshot.run.terminalReason, 'cancelled_by_user');
      const abandoned = cut.journal.filter((row: Data) => row.opKind === 'mcp' && row.phase === 'abandoned'); assert.equal(abandoned.length, 1);
      same(abandoned[0].budgetDelta, ZERO); assert.equal(abandoned[0].budgetSettlementRef, final.budgetSettlementRef);
      const attestation = decodeManualAbandonAttestation(await read(abandoned[0].attestationRef));
      assert.equal(attestation.requestDigest, acknowledgement.requestDigest); assert.equal(attestation.unknownJournalSeq, final.seq);
      const items = await Promise.all(cut.items.map((row: Data) => read(row.payloadRef)));
      const marker = items.filter(item => item.kind === 'tool_abandoned'); assert.equal(marker.length, 1);
      assert.equal(decodeToolAbandonedItem(marker[0]).opId, claim.opId);
      assert.equal(items.filter(item => item.kind === 'tool_result' && item.opId === claim.opId).length, 0);
      const stop = decodeAgentStop(await read(cut.snapshot.run.stopIntentRef), cut.snapshot.run);
      assert.equal(stop.origin, cancel ? 'user_cancel' : 'manual_abandon');
      if (cancel) { assert.equal(stop.origin === 'user_cancel' ? stop.requestId : undefined, cancel.requestId); higherStopPreserved = true; }
      assert.equal(cut.snapshot.run.budgetConsumed.toolCalls, 1); same(cut.snapshot.run.budgetReserved, ZERO);
      await context.assertWorkerFree(runId, cut);
      assert.deepEqual(await context.send(acknowledgement, 30_000), response);
      await context.restart(); same(await get(runId), cut); assert.deepEqual(await context.send(acknowledgement, 30_000), response);
      for (const method of ['run.result', 'run.diff']) {
        const refused = await context.send({ protocolVersion: 1, method, runId });
        assert.equal(refused.ok, false); assert.equal(refused.error?.code, 'RESULT_UNAVAILABLE');
      }
      assert.equal(await readFile(path.join(workspace, 'example.txt'), 'utf8'), MCP_BEFORE);
      same(await fileIdentity(path.join(workspace, 'example.txt')), before);
    }
    same(context.responder.inspect(kind), owned);
    assert.equal(context.modelResponder.posts(kind), installedMcpKnown(kind) ? 3 : 1);
    cases.push({ kind, nativeAdminRetired: true, callClaims: 1, externalEffects: expectedExternalCalls,
      modelPosts: context.modelResponder.posts(kind), completed: installedMcpKnown(kind), manualAbandonment: !installedMcpKnown(kind),
      originalAdmissionReplayed: true, allRecordedWorkersRetired: true, noResend: true });
  }
  assert(successorAcknowledgement && higherStopPreserved);
  return { diagnosticOnly: true, qualified: true, profile: INSTALLED_MCP_PROFILE, cases,
    successorAcknowledgement, higherStopPreserved, actualProviderQualified: false, authenticatedBearerQualified: false,
    stdioQualified: false, retryRiskQualified: false, reconcileAdapterQualified: false,
    adminRetryQualified: false, activeAdminStopQualified: false, zeroIoNoReleaseQualified: false,
    knownUnusableResultQualified: false, successorClaimedCrashQualified: false,
    exactClaimStopCutQualified: false, completeI1Qualified: false };
}
