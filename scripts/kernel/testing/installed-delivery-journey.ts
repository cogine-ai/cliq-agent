// Fixed consumers of the one real installed-node fixture. These methods send
// only public v1 requests; fixture-owner edits happen before new admission.
// There is no StateOwner, SQL writer, native handle or feature override here.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chown, lstat, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { StateOwnerRecordV1 } from '../../../src/kernel/types.js';
import { decodeSourceManifest, decodeWorkspaceEntries } from '../../../src/state/decoders.js';
import { decodeDeliveryTerminalProjectionEvidence } from '../../../src/kernel/publication.js';
import { decodeRunResult } from '../../../src/state/result-artifacts.js';
import { assertInstalledDeliveryOutcome, assertInstalledDeliveryVerifier } from './installed-delivery-result.js';
import type { InstalledVerifierRetirementIdentity } from './installed-verifier-evidence.js';
import type { InstalledWorkerRetirementBinding } from './installed-worker-lease.js';
import { assertInstalledPublicationStopResult, type InstalledPublicationStopResult } from './installed-publication-stop-result.js';

type Response = { protocolVersion: 1; ok: boolean; method?: string; result?: Record<string, any>; error?: Record<string, unknown> };
type Source = { cut: Record<string, any>; submit: Record<string, unknown>; admission: Response;
  files: readonly { path: string; before: string; after: string }[]; workspace: string };
type Admission = { core: Record<string, unknown> & { requestDigest: string }; response: Response; runId: string };
type Context = {
  createSource(kind: 'publish' | 'merge' | 'cancel'): Promise<Source>;
  send(request: Record<string, unknown>, timeout?: number): Promise<Response>;
  readRetainedArtifact(ref: string): Promise<Buffer>; downloadPublicArtifact(ref: string): Promise<Buffer>;
  readOwnerHistory(): Promise<readonly StateOwnerRecordV1[]>;
  nextId(): string; uid: number; gid: number;
  assertRunWorkersRetired(runId: string, observedLaunchIds: readonly string[], publicationRetirement?: InstalledWorkerRetirementBinding | null): Promise<number>;
  assertVerifierProcessesAbsent(retirement: InstalledVerifierRetirementIdentity): Promise<void>;
  mark(phase: string): void; reconnect(): Promise<void>; restart(): Promise<void>;
  cleanupCrash(source: Source): Promise<void>;
  originalStop?(source: Source, operation: {
    apply(): Promise<Admission>; capture(runId: string): Promise<Record<string, any>>;
  }): Promise<{ admitted: Admission; beforeCut: Record<string, any>; terminalBy: number;
    verify(proof: InstalledPublicationStopResult): Promise<void> }>;
};
const ZERO = { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 };
const metadata = async (filename: string) => {
  const info = await lstat(filename, { bigint: true });
  assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1n);
  return Object.fromEntries(['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].map(key =>
    [key, info[key as keyof typeof info]!.toString()]));
};

export async function runInstalledDeliveryCases(context: Context, options: Readonly<{ faultCase?: 'original_stop' | 'late_result' }> = {}) {
  assert.deepEqual(Object.keys(options), options.faultCase === undefined ? [] : ['faultCase']);
  assert(options.faultCase === undefined || options.faultCase === 'original_stop' || options.faultCase === 'late_result');
  if (options.faultCase === 'original_stop') assert.equal(typeof context.originalStop, 'function');
  const request = (core: Record<string, unknown>) => ({ ...core, requestDigest: canonicalSha256(core) });
  const accepted = (response: Response, method: string) => {
    assert.equal(response.protocolVersion, 1); assert.equal(response.ok, true, 'actual explicit Delivery method must be accepted');
    assert(response.result && response.result.method === method); return response.result;
  };
  const send = async (core: Record<string, unknown>, timeout = 5000) => accepted(await context.send(core, timeout), String(core.method));
  const observedLaunches = new Map<string, Set<string>>();
  const get = async (runId: string) => {
    const cut = await send({ protocolVersion: 1, method: 'run.get', runId }), launchId = cut.snapshot.run.activeWorkerLaunchId;
    if (launchId) {
      const launches = observedLaunches.get(runId) ?? new Set<string>(); launches.add(launchId);
      assert(launches.size <= 16); observedLaunches.set(runId, launches);
    }
    return cut;
  };
  const retirements = async (runId: string, publicationRetirement?: InstalledWorkerRetirementBinding | null) => {
    const launches = observedLaunches.get(runId) ?? [];
    return context.assertRunWorkersRetired(runId, [...launches], publicationRetirement);
  };
  const terminal = async (runId: string, by = Date.now() + 90000) => {
    for (;;) {
      const cut = await get(runId);
      if (['succeeded', 'completed_unverified', 'failed', 'cancelled'].includes(cut.snapshot.run.status)) return cut;
      assert(Date.now() < by, 'actual explicit Delivery did not reach terminal within its fixed 90-second qualification window');
      await delay(50);
    }
  };
  const object = async (ref: string): Promise<any> => {
    const bytes = await context.readRetainedArtifact(ref); assert.equal(sha256Bytes(bytes), ref);
    const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    assert(canonicalJsonBytes(value).equals(bytes)); return value;
  };
  const apply = async (source: Source) => {
    const core = request({ protocolVersion: 1, method: 'run.apply', requestId: context.nextId(),
      admissionKey: randomBytes(32).toString('base64url'), sourceRunId: source.cut.snapshot.run.id,
      expectedRunResultRef: source.cut.snapshot.run.resultRef, budgets: { wallTimeMs: 300000, toolCalls: 1000 } });
    const response = await context.send(core, 30000), result = accepted(response, 'run.apply');
    assert.equal(result.snapshot.operation, 'delivery'); assert.equal(result.snapshot.run.revision, 1);
    assert.notEqual(result.snapshot.run.id, source.cut.snapshot.run.id);
    return { core, response, runId: result.snapshot.run.id as string };
  };
  const addOwnerFile = async (source: Source, filename: 'owner-note.txt' | 'cancel.flag', text: string) => {
    const target = path.join(source.workspace, filename);
    await writeFile(target, text, { flag: 'wx', mode: 0o644 }); await chown(target, context.uid, context.gid);
    const info = await lstat(target); assert.equal(info.uid, context.uid); assert.equal(info.gid, context.gid); assert.equal(info.nlink, 1);
    return { path: filename, text, original: await metadata(target) };
  };
  const files = (source: Source, extra?: { path: string; text: string }) => [
    ...source.files.map(file => ({ path: file.path, text: file.after })), ...(extra ? [{ path: extra.path, text: extra.text }] : []),
  ];
  const inspect = async (source: Source, expected: readonly { path: string; text: string }[]) => {
    assert.deepEqual((await readdir(source.workspace)).sort(), expected.map(file => file.path).sort(),
      'the actual workspace must contain the complete expected projection, not only the edited known path');
    for (const file of expected) {
      const target = path.join(source.workspace, file.path), info = await lstat(target);
      assert(info.isFile() && !info.isSymbolicLink() && info.uid === context.uid && info.gid === context.gid &&
        info.nlink === 1 && (info.mode & 0o7777) === 0o644);
      assert.equal(await readFile(target, 'utf8'), file.text);
    }
  };
  type Completed = { source: Source; admitted: Awaited<ReturnType<typeof apply>>; cut: Record<string, any>;
    sessionCut: Record<string, any>; kind: 'publish' | 'no_op' | 'merge'; expected: ReturnType<typeof files>;
    queries: Response[]; proof: Awaited<ReturnType<typeof assertInstalledDeliveryOutcome>> };
  const completed: Completed[] = [];
  const reads = async (cut: Record<string, any>) => {
    const result = decodeRunResult(await object(cut.snapshot.run.resultRef));
    const replies: Response[] = [];
    for (const method of ['run.result', 'run.diff']) {
      const response = await context.send({ protocolVersion: 1, method, runId: cut.snapshot.run.id });
      const value = accepted(response, method), descriptor = method === 'run.result' ? value.result : value.diff;
      const ref = method === 'run.result' ? cut.snapshot.run.resultRef : result.diffRef;
      assert.equal(value.runId, cut.snapshot.run.id); assert.equal(descriptor.ref, ref); assert.equal(descriptor.digest, ref);
      assert.equal(descriptor.mediaType, 'application/json');
      if (method === 'run.result') assert.equal(value.verificationClosureRef, result.verificationClosureRef);
      const bytes = await context.downloadPublicArtifact(ref); assert.equal(bytes.length, descriptor.sizeBytes); assert.equal(sha256Bytes(bytes), ref);
      replies.push(response);
    }
    assert(result.deliveryTerminalProjectionEvidenceRef);
    const projectionBytes = await context.downloadPublicArtifact(result.deliveryTerminalProjectionEvidenceRef);
    const projection = decodeDeliveryTerminalProjectionEvidence(parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(projectionBytes)));
    assert.equal(projection.observedSourceRef, result.resultSourceRef); assert.equal(projection.selectedBranch, 'forward_finalize');
    const source = decodeSourceManifest(await object(result.resultSourceRef)), entries = decodeWorkspaceEntries(await object(source.entriesRef));
    for (const entry of entries.entries) {
      assert.equal(entry.kind, 'file'); if (entry.kind !== 'file') throw new Error('fixed Delivery fixture contains a non-file');
      const bytes = await context.downloadPublicArtifact(entry.blobRef); assert.equal(bytes.length, entry.size); assert.equal(sha256Bytes(bytes), entry.blobRef);
    }
    const events = await send({ protocolVersion: 1, method: 'run.attach', runId: cut.snapshot.run.id, afterEventSeq: 0, limit: 1000 });
    assert.equal(events.nextEventSeq, events.highWaterEventSeq);
    const terminals = events.events.filter((event: any) => event.kind === 'state_changed' && ['succeeded', 'failed', 'cancelled', 'completed_unverified'].includes(event.status));
    assert.equal(terminals.length, 1); assert.equal(terminals[0].status, 'succeeded');
    assert.equal(terminals[0].resultRef, cut.snapshot.run.resultRef);
    assert.deepEqual(await get(cut.snapshot.run.id), cut, 'inspection must never advance or execute the Run');
    return replies;
  };
  const finish = async (source: Source, admitted: Admission, kind: Completed['kind'], expected: Completed['expected'], terminalBy?: number) => {
    const cut = await terminal(admitted.runId, terminalBy), sessionCut = await send({ protocolVersion: 1, method: 'session.get', sessionId: cut.snapshot.run.sessionId });
    const proof = await assertInstalledDeliveryOutcome({ cut, sessionCut, sourceCut: source.cut, sourceResultRef: source.cut.snapshot.run.resultRef,
      expectedFiles: expected, kind, readRetainedArtifact: context.readRetainedArtifact, readOwnerHistory: context.readOwnerHistory });
    for (const identity of proof.verifierRetirementIdentities) await context.assertVerifierProcessesAbsent(identity);
    const workerCount = await retirements(admitted.runId, proof.publicationWorkerRetirement);
    if (kind === 'no_op') assert.equal(workerCount, 0, 'this inherited noOp must have no recorded WorkerLaunch');
    else assert(workerCount > 0, 'actual publication requires at least one real positively retired worker');
    await inspect(source, expected);
    const queries = await reads(cut);
    assert.deepEqual(await context.send(admitted.core, 30000), admitted.response, 'original apply replay returns its exact original admission');
    completed.push({ source, admitted, cut, sessionCut, kind, expected, queries, proof }); return cut;
  };

  context.mark('delivery_verified_source_and_publication');
  const first = await context.createSource('publish'), originalSource = canonicalSha256(first.cut);
  const firstAdmission = await apply(first), firstCut = await finish(first, firstAdmission, 'publish', files(first));
  assert.equal(canonicalSha256(await get(first.cut.snapshot.run.id)), originalSource);

  context.mark('delivery_nonwaiting_approval_refused');
  const approve = await context.send(request({ protocolVersion: 1, method: 'run.approve', requestId: context.nextId(),
    runId: firstAdmission.runId, expectedRevision: firstCut.snapshot.run.revision, waitingOnRef: '0'.repeat(64), decision: 'allow' }));
  assert.equal(approve.ok, false); assert(['RUN_TERMINAL', 'INVALID_REQUEST'].includes(String(approve.error?.code)));
  assert.equal(approve.error?.retryable, false); assert.deepEqual(await get(firstAdmission.runId), firstCut);

  context.mark('delivery_noop_complete_projection');
  const beforeNoOp = await Promise.all(files(first).map(file => metadata(path.join(first.workspace, file.path))));
  await finish(first, await apply(first), 'no_op', files(first));
  assert.deepEqual(await Promise.all(files(first).map(file => metadata(path.join(first.workspace, file.path)))), beforeNoOp,
    'noOp must not rewrite any original projected inode');

  context.mark('delivery_merge_real_local_verifier');
  const merged = await context.createSource('merge'), note = await addOwnerFile(merged, 'owner-note.txt', 'owned A-only nonconflicting content\n');
  await finish(merged, await apply(merged), 'merge', files(merged, note));
  assert.deepEqual(await metadata(path.join(merged.workspace, note.path)), note.original, 'A-only original inode must be preserved');

  context.mark('delivery_cancel_after_observed_verifier_claim');
  const cancelledSource = await context.createSource('cancel'), flag = await addOwnerFile(cancelledSource, 'cancel.flag', 'owned cancellation trigger\n');
  const cancellationAdmission = await apply(cancelledSource), claimBy = Date.now() + 90000;
  let claimedCut: Record<string, any>;
  for (;;) {
    claimedCut = await get(cancellationAdmission.runId);
    const claims = claimedCut.journal.filter((row: any) => row.opKind === 'verifier' && row.phase === 'dispatch_claimed');
    if (claims.length === 1 && claimedCut.snapshot.run.status === 'running') break;
    assert(!['succeeded', 'failed', 'cancelled', 'completed_unverified'].includes(claimedCut.snapshot.run.status),
      'a real active verifier claim must be observed, never inferred from an already terminal Run');
    assert(Date.now() < claimBy, 'the genuine delivery verifier claim was not observed within the fixed qualification window'); await delay(50);
  }
  const cancellation = request({ protocolVersion: 1, method: 'run.cancel', requestId: context.nextId(),
    runId: cancellationAdmission.runId, expectedRevision: claimedCut.snapshot.run.revision });
  const cancellationResponse = await context.send(cancellation); accepted(cancellationResponse, 'run.cancel');
  const cancelled = await terminal(cancellationAdmission.runId), stoppedRun = cancelled.snapshot.run;
  assert.equal(stoppedRun.status, 'cancelled'); assert.equal(stoppedRun.terminalReason, 'cancelled_by_user'); assert(!stoppedRun.resultRef);
  assert(!cancelled.journal.some((row: any) => row.opKind === 'model' || row.opKind === 'tool' || row.opKind === 'publish'));
  assert.equal(cancelled.journal.filter((row: any) => row.phase === 'dispatch_claimed').length, 1);
  const stoppedIdentity = await assertInstalledDeliveryVerifier({ cut: cancelled, sourceCut: cancelledSource.cut, outcome: 'stopped',
    readRetainedArtifact: context.readRetainedArtifact, readOwnerHistory: context.readOwnerHistory,
    cancellation: { request: cancellation, response: cancellationResponse } });
  await context.assertVerifierProcessesAbsent(stoppedIdentity);
  assert.deepEqual(stoppedRun.budgetConsumed, { ...ZERO, toolCalls: 1 });
  assert.deepEqual(stoppedRun.budgetReserved, ZERO); assert(!stoppedRun.activeWorkerLaunchId);
  assert(await retirements(stoppedRun.id) > 0);
  await inspect(cancelledSource, [...cancelledSource.files.map(file => ({ path: file.path, text: file.before })), flag]);
  assert.deepEqual(await metadata(path.join(cancelledSource.workspace, flag.path)), flag.original);
  for (const method of ['run.result', 'run.diff']) {
    const response = await context.send({ protocolVersion: 1, method, runId: stoppedRun.id });
    assert.equal(response.ok, false); assert.equal(response.error?.code, 'RESULT_UNAVAILABLE'); assert.equal(response.error?.retryable, false);
  }

  context.mark('delivery_reconnect_and_actual_supervisor_restart');
  const revalidate = async () => {
    for (const entry of completed) {
      assert.deepEqual(await get(entry.source.cut.snapshot.run.id), entry.source.cut);
      assert.deepEqual(await get(entry.admitted.runId), entry.cut);
      assert.deepEqual(await context.send(entry.admitted.core, 30000), entry.admitted.response);
      assert.deepEqual(await reads(entry.cut), entry.queries);
      const sessionCut = await send({ protocolVersion: 1, method: 'session.get', sessionId: entry.cut.snapshot.run.sessionId });
      const proof = await assertInstalledDeliveryOutcome({ cut: entry.cut, sessionCut, sourceCut: entry.source.cut, sourceResultRef: entry.source.cut.snapshot.run.resultRef,
        expectedFiles: entry.expected, kind: entry.kind, readRetainedArtifact: context.readRetainedArtifact, readOwnerHistory: context.readOwnerHistory });
      for (const identity of proof.verifierRetirementIdentities) await context.assertVerifierProcessesAbsent(identity);
      await inspect(entry.source, entry.expected);
      await retirements(entry.admitted.runId, proof.publicationWorkerRetirement);
    }
    assert.deepEqual(await get(stoppedRun.id), cancelled);
    assert.deepEqual(await context.send(cancellationAdmission.core, 30000), cancellationAdmission.response);
    assert.deepEqual(await context.send(cancellation), cancellationResponse);
    const identity = await assertInstalledDeliveryVerifier({ cut: cancelled, sourceCut: cancelledSource.cut, outcome: 'stopped',
      readRetainedArtifact: context.readRetainedArtifact, readOwnerHistory: context.readOwnerHistory,
      cancellation: { request: cancellation, response: cancellationResponse } });
    await context.assertVerifierProcessesAbsent(identity); await retirements(stoppedRun.id);
  };
  for (const action of [context.reconnect, context.restart]) { await action(); await revalidate(); }
  let originalPublicationStopCase: Record<string, unknown> | undefined;
  if (options.faultCase === 'original_stop') {
    const stopped = await context.originalStop!(first, { apply: () => apply(first), capture: get });
    await finish(first, stopped.admitted, 'publish', files(first), stopped.terminalBy);
    const entry = completed.pop()!;
    const prove = () => assertInstalledPublicationStopResult({ beforeCut: stopped.beforeCut, cut: entry.cut, sessionCut: entry.sessionCut,
      sourceCut: first.cut, sourceResultRef: first.cut.snapshot.run.resultRef, expectedFiles: entry.expected,
      readRetainedArtifact: context.readRetainedArtifact, readOwnerHistory: context.readOwnerHistory });
    const proof = await prove(); await stopped.verify(proof);
    await context.reconnect();
    // Recheck both the extra case and every original core outcome after the
    // actual owner-2 stop/owner-3 start. Do not turn this into a fourth source
    // or change the default three successful cases' report cardinality.
    completed.push(entry);
    try { await revalidate(); await stopped.verify(await prove()); }
    finally { assert.equal(completed.pop(), entry); }
    const { verifierRetirementIdentities, publicationWorkerRetirement, ...outcome } = entry.proof;
    assert.equal(verifierRetirementIdentities.length, 0);
    originalPublicationStopCase = { ...outcome, verifierRetirementCount: 0,
      originalClaimAndGracefulOwnerClosureVerified: true, noUnknownOrRedispatch: true };
  } else await context.cleanupCrash(first);
  return { diagnosticOnly: true, qualified: true, cleanupCrashQualified: originalPublicationStopCase === undefined,
    ...(options.faultCase === 'late_result' ? { latePublicationResultQualified: false, preciseInFlightPublicationStopQualified: false } : {}),
    ...(originalPublicationStopCase ? { originalPublicationStopCase, preciseInFlightPublicationStopQualified: true,
      latePublicationResultQualified: false } : {}), cases: completed.map(entry => {
    const { verifierRetirementIdentities, publicationWorkerRetirement, ...proof } = entry.proof;
    return { ...proof, verifierRetirementCount: verifierRetirementIdentities.length };
  }),
    sourceRunsQualifiedByOriginalFullVerifierReader: 3, actualModelPostsOnlyForSource: 6,
    nonwaitingApproveRefusedWithoutMutation: true, noOpOriginalInodesUnchanged: true, aOnlyInodePreserved: true,
    cancelledAfterObservedVerifierClaim: true, cancelledWithoutPublication: true, cancellationSettledExactlyOnce: true,
    verifierReleaseBeforeCancelObserved: false, preciseInFlightVerifierCancelQualified: false,
    exactVerifierProcessLifetimesIndependentlyAbsent: true,
    actualInspectionMatched: true, sameOriginalApplyReplayAfterReconnectAndRestart: true,
    directPolicyQualified: true, interactiveApprovalQualified: false, actualProviderQualified: false,
    allRecordedDeliveryWorkersPositivelyRetired: true, inheritedNoOpRecordedWorkerLaunches: 0,
    publicResultDiffProjectionAndResultFilesFullyDownloaded: true, completeI4Qualified: false,
    observedWorkersRetiredByOriginalReadonlyHistory: [...observedLaunches.values()].reduce((sum, launches) => sum + launches.size, 0),
    unobservedWorkerAbsenceTreatedAsProof: false,
    preciseClaimedCloseCutQualified: false, allCrashCutsQualified: false, rebootQualified: false, completeI1Qualified: false };
}
