// Read-only assertions over an actual public installed cut and original CAS.
// No fixture row, native result, grant, clock or process proof is constructed.
import assert from 'node:assert/strict';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { builtinCaptureModelContent, decodeBuiltinToolCapture } from '../../../src/state/builtin-tool-capture.js';
import { builtinToolInputBytes, decodeBuiltinToolInput } from '../../../src/sandbox/builtin-tool-data.js';
import { decodeBuiltinProcessContainment, decodeBuiltinScriptSandboxLaunchSpec } from '../../../src/state/execution-closure.js';
import { decodeRunResult, decodeVerificationClosure } from '../../../src/state/result-artifacts.js';
import { decodeWorkspaceState, decodeSourceManifest, decodeSourceProjection, decodeWorkspaceEntries, decodeWorkspaceGenerationSnapshotEvidence } from '../../../src/state/decoders.js';
import { decodeSourceIncludeAuthorization } from '../../../src/state/source-include-artifacts.js';
import { readSourceIncludeClassification } from '../../../src/state/source-include-classification.js';
import { toolCheckpointId, validateMatchingWorkerDeath } from '../../../src/state/tool-checkpoint.js';
import type { InstalledWorkerRetirementInspection } from './installed-worker-lease.js';

export function installedToolsCalls(before: string, after: string) {
  const reads = Array.from({ length: 15 }, (_, index) => ({ name: ['read', 'ls', 'find', 'grep'][index % 4]!,
    input: index % 4 === 0 ? { path: 'example.txt', start_line: index + 1, end_line: index + 1 } : index % 4 === 1 ? { path: '.' }
      : index % 4 === 2 ? { path: '.', name: 'example' } : { path: '.', pattern: 'before' } }));
  return [...reads, { name: 'edit', input: { path: 'example.txt', old_text: before, new_text: after } },
    { name: 'bash', input: { command: "printf 'owned native bash output\\n'; exit 7" } },
    { name: 'bash', input: { command: "printf 'must never run\\n' > denied.txt" } },
    { name: 'request_input', input: { prompt: 'Confirm the owned installed tool result.', responseKind: 'text', maximumResponseBytes: 256 } }]
    .map((call, index) => ({ ...call, callId: `owned-installed-tools-${index}` }));
}
export function installedReadOnlyGitCall(after: string) {
  const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
  return { callId: 'owned-installed-private-git-readonly', name: 'bash', input: { command:
    "set -eu\n/usr/bin/git status --porcelain\n/usr/bin/git diff -- example.txt\n" +
    "if GIT_OPTIONAL_LOCKS=1 /usr/bin/git add -- example.txt; then printf '%s\\n' 'UNEXPECTED_GIT_WRITE'; exit 42; fi\n" +
    "printf '%s' 'temporary authorized worktree write' > example.txt\n" +
    `printf '%s' ${quote(after)} > example.txt\n` + "printf '%s\\n' 'CLIQ_PRIVATE_GIT_READ_ONLY_OK'\n" } };
}
export type InstalledToolsEvidence = {
  qualified: true; readCalls: 15; executedToolCalls: 17; deniedCalls: 1; inputReplies: 1;
  sameParentForFirstFourteenReads: true; fifteenthReadUsedNewParent: true;
  actualReadParentObservedAlive: true; scopeCapacityCheckpointUnchanged: true;
  eachOriginalClaimCompletedOnce: true; rawOutputsAndInvocationDeathChecked: true;
  bashExitCode: 7; workerFreeWaits: true; waitingInputRestartPreserved: true;
  exactControlReplay: true; staleReplyRefused: true; hostFilesUnchanged: true;
  status: 'completed_unverified'; actualVerifierQualified: false;
  originalBuiltinIncludeCaptured: true; originalCaptureDescriptorMatched: true; originalAuthorizationPreservedAfterEdit: true;
};

export async function assertInstalledToolsOutcome(input: { cut: Record<string, any>; sessionCut: Record<string, any>; readCas(ref: string): Promise<Buffer>;
  calls: readonly { name: string; callId: string; input: Record<string, unknown> }[]; observedReadParent: InstalledWorkerRetirementInspection;
  originalHostFile: Readonly<Record<string, string>>; controls: { approvals: number; denials: number;
    inputReplies: number; restarted: boolean; replayed: boolean; staleRefused: boolean } }): Promise<InstalledToolsEvidence> {
  const { cut, calls } = input, run = cut.snapshot.run;
  assert.equal(run.status, 'completed_unverified'); assert.equal(run.terminalReason, 'no_required_verifier');
  assert.equal(run.activeWorkerLaunchId, undefined); assert.equal(run.waitingOnRef, undefined); assert.equal(run.stopIntentRef, undefined);
  const object = async <T = Record<string, any>>(ref: string): Promise<T> => {
    const bytes = await input.readCas(ref); assert.equal(sha256Bytes(bytes), ref);
    const value = parseJsonStrict(new TextDecoder('utf8', { fatal: true }).decode(bytes)); assert(canonicalJsonBytes(value).equals(bytes)); return value as T;
  };
  const items = await Promise.all(cut.items.map((row: any) => object(row.payloadRef)));
  const batches = items.filter(item => item.kind === 'assistant_tool_batch'); assert.equal(batches.length, 1);
  const batch = batches[0]!; assert.equal(batch.calls.length, calls.length);
  assert.deepEqual(batch.calls.map((call: any) => [call.callId, call.toolName]), calls.map(call => [call.callId, call.name]));
  const results = items.filter(item => item.kind === 'tool_result'); assert.equal(results.length, calls.length);
  assert.deepEqual(results.map(item => [item.callId, item.index]), calls.map((call, index) => [call.callId, index]));
  const claims = cut.journal.filter((row: any) => row.opKind === 'tool' && row.phase === 'dispatch_claimed'); assert.equal(claims.length, 17);
  assert.equal(cut.journal.filter((row: any) => row.opKind === 'verifier').length, 0);
  const parents: string[] = [], generations: string[] = [];
  let firstReadWorkspace: string | undefined;
  for (let index = 0; index < 17; index++) {
    const call = calls[index]!, result = results[index]!;
    const payload = await object(result.resultRef), content = await object(payload.modelContentRef);
    const opId = identityHash('cliq-tool-operation-v1', run.id, batch.itemId, call.callId);
    const rows = cut.journal.filter((row: any) => row.opId === opId);
    assert.deepEqual(rows.map((row: any) => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
    const [prepared, claim, completed] = rows;
    assert.equal(prepared.attempt, 0); assert.equal(claim.attempt, 0); assert.equal(completed.attempt, 0);
    const observation = await object(completed.resultRef);
    assert.equal(observation.observationDigest, digestOmitting(observation, 'observationDigest'));
    assert.equal(observation.outcome, 'executed'); assert.equal(payload.journalResultRef, completed.resultRef);
    const checkpoint = cut.checkpoints.find((value: any) => value.id === toolCheckpointId(run.id, opId, 0)); assert(checkpoint);
    assert.equal(checkpoint.journalSeq, completed.seq); assert.equal(checkpoint.runItemSeq, cut.items.find((row: any) => row.itemId === result.itemId).itemSeq);
    if (index < 15) {
      assert.equal(observation.postEffect, undefined); firstReadWorkspace ??= checkpoint.workspaceStateRef;
      assert.equal(checkpoint.workspaceStateRef, firstReadWorkspace);
    } else assert(observation.postEffect);
    if (call.name === 'edit') { assert.equal(observation.captureRef, undefined); continue; }
    const capture = decodeBuiltinToolCapture(await object(observation.captureRef)); assert.equal(capture.captureDigest, observation.captureDigest);
    assert.equal(capture.dispatchId, claim.dispatchId); assert.equal(capture.requestRef, prepared.requestRef);
    assert.equal(capture.targetRef, prepared.target); assert.equal(capture.grantRef, prepared.grantRef);
    assert.equal(capture.opId, opId); assert.equal(capture.tool, call.name); assert.equal(capture.leaseEpoch, claim.leaseEpoch);
    const launch = decodeBuiltinScriptSandboxLaunchSpec(await object(claim.sandboxLaunchSpecRef));
    const containment = decodeBuiltinProcessContainment(await object(capture.containmentRef), launch.parentWorkerContainmentRef);
    const death = await object(capture.deathEvidenceRef);
    assert.equal(capture.sandboxLaunchSpecRef, claim.sandboxLaunchSpecRef); assert.equal(death.evidenceDigest, digestOmitting(death, 'evidenceDigest'));
    assert.equal(death.containmentRef, capture.containmentRef); assert.equal(death.sandboxLaunchSpecRef, claim.sandboxLaunchSpecRef);
    assert.equal(canonicalSha256(death.owner), canonicalSha256(launch.owner));
    assert.equal(canonicalSha256(containment.owner), canonicalSha256(launch.owner));
    assert.equal(canonicalSha256(death.backend), canonicalSha256({ ...containment.backend, cgroupPopulated: 0,
      namespaceInitDeadAndReaped: true, remainingTrackedDescendants: 0 }));
    assert(capture.endedAt <= death.observedAt && death.observedAt <= observation.observedAt);
    const stdout = await input.readCas(capture.stdoutRef), stderr = await input.readCas(capture.stderrRef);
    assert.equal(stdout.length, capture.stdoutByteCount); assert.equal(stderr.length, capture.stderrByteCount);
    const capsule = decodeBuiltinToolInput(builtinToolInputBytes(capture.tool, call.input, launch.resources));
    const model = builtinCaptureModelContent(capture, stdout, stderr, capsule);
    assert.equal(canonicalSha256(observation.content), canonicalSha256(model)); assert.equal(canonicalSha256(content.content), canonicalSha256(model));
    assert.equal(launch.filesystem.kind, 'run_generation');
    if (launch.filesystem.kind !== 'run_generation') throw new TypeError('missing actual original tool generation');
    if (index < 15) { parents.push(launch.owner.workerLaunchId); generations.push(launch.filesystem.generationRef); }
    else { assert.equal(capture.terminationReason, 'exit'); assert.equal(capture.terminationReason === 'exit' && capture.exitCode, 7);
      assert.equal(stdout.toString('utf8'), 'owned native bash output\n'); assert.equal(stderr.length, 0); }
  }
  assert(parents.slice(0, 14).every(value => value === parents[0])); assert.equal(input.observedReadParent.launchId, parents[0]);
  assert(generations.slice(0, 14).every(value => value === generations[0])); assert.notEqual(parents[14], parents[0]); assert.notEqual(generations[14], generations[0]);
  const nextRequest = await object(claims[14].requestRef);
  const priorCheckpoint = cut.checkpoints.find((value: any) => value.id === toolCheckpointId(run.id, claims[13].opId, 0)); assert(priorCheckpoint);
  const capacityId = identityHash('cliq-tool-capacity-checkpoint-v1', run.id, parents[0]!, nextRequest.frontierRef,
    String(priorCheckpoint.basedOnRunRevision + 1), 'scope_capacity');
  const capacity = cut.checkpoints.filter((value: any) => value.id === capacityId); assert.equal(capacity.length, 1);
  for (const field of ['workspaceStateRef', 'contextManifestRef', 'journalSeq', 'runItemSeq'])
    assert.equal(capacity[0][field], priorCheckpoint[field]);
  assert.equal(capacity[0].reason, 'auto');
  const snapshot = decodeWorkspaceGenerationSnapshotEvidence(await object(input.observedReadParent.snapshotEvidenceRef));
  assert.equal(snapshot.checkpointId, capacityId); assert.equal(snapshot.workspaceStateRef, firstReadWorkspace);
  assert.equal(snapshot.generationRef, generations[0]); assert.equal(snapshot.purpose, 'sealed_to_checkpoint');
  const parentDeath = validateMatchingWorkerDeath(await object(snapshot.quiescenceEvidenceRef),
    await object(input.observedReadParent.retirementEvidenceRef), 'capacity rotation original worker death');
  assert.equal(parentDeath.containmentRef, input.observedReadParent.processContainmentRef);
  assert.equal(input.observedReadParent.retiredAt, capacity[0].createdAt);
  for (const index of [17, 18]) {
    const payload = await object(results[index]!.resultRef);
    assert.equal(cut.journal.some((row: any) => row.opId === identityHash('cliq-tool-operation-v1', run.id, batch.itemId, calls[index]!.callId)), false);
    assert.equal(payload.outcome, index === 17 ? 'denied' : 'executed');
    if (index === 18) assert.equal(payload.source, 'user_input');
  }
  assert.equal(items.filter(item => item.kind === 'user_input').length, 1);
  assert.deepEqual(input.controls, { approvals: 2, denials: 1, inputReplies: 1, restarted: true, replayed: true, staleRefused: true });
  const final = decodeRunResult(await object(run.resultRef)), verification = decodeVerificationClosure(await object(final.verificationClosureRef));
  assert.equal(final.runId, run.id);
  assert.equal(verification.verification.kind, 'local');
  if (verification.verification.kind !== 'local') throw new TypeError('tools case cannot inherit verification');
  assert.equal(verification.verification.outcome, 'unverified'); assert.equal(verification.verification.entries.length, 0);
  assert(verification.verification.unverifiedConsentRef); await object(verification.verification.unverifiedConsentRef);
  const source = decodeSourceManifest(await object(final.resultSourceRef)), entries = decodeWorkspaceEntries(await object(source.entriesRef));
  const base = decodeSourceManifest(await object(final.baseSourceRef)), before = decodeWorkspaceEntries(await object(base.entriesRef));
  const projection = decodeSourceProjection(await object(base.sourceProjectionRef));
  assert.deepEqual(projection.explicitIncludes.map(({ path, scope }) => ({ path, scope })), [{ path: 'example.txt', scope: 'entry' }]);
  assert.equal(base.git, undefined); assert.equal(projection.classificationIndexRef, undefined);
  const authorizationRef = projection.explicitIncludes[0]!.authorizationRef;
  const authorization = decodeSourceIncludeAuthorization(await object(authorizationRef));
  assert.equal(authorization.kind, 'builtin_nonignored');
  if (authorization.kind !== 'builtin_nonignored') assert.fail('the ordinary fixture must use its actual builtin classification');
  assert.equal(authorization.runId, run.id); assert.equal(authorization.sessionId, run.sessionId);
  assert.equal(authorization.workspaceIdentityDigest, base.workspaceIdentityDigest);
  assert.equal(authorization.capturedEntriesRef, base.entriesRef); assert.equal(authorization.capturedTreeDigest, base.treeDigest);
  assert(authorization.createdAt <= run.createdAt);
  const original = before.entries.find(entry => entry.path === 'example.txt');
  assert(original?.kind === 'file');
  const classification = await readSourceIncludeClassification({ readBoundedBytes: async (ref, maximum) => {
    // Complete bytes still come from the same real, independently checked
    // installed CAS reader. This adapter supplies only a data size ceiling.
    const bytes = await input.readCas(ref); assert.equal(sha256Bytes(bytes), ref); assert(bytes.length <= maximum); return bytes;
  } }, authorization.classificationEvidenceRef);
  assert.equal(classification.evidence.evidenceDigest, authorization.classificationEvidenceDigest);
  assert.equal(classification.evidence.capturedEntriesRef, base.entriesRef);
  assert.equal(classification.evidence.capturedTreeDigest, base.treeDigest);
  assert.equal(classification.evidence.inspectionId, authorization.inspectionId);
  assert(classification.evidence.observedAt >= authorization.createdAt && classification.evidence.observedAt <= run.createdAt);
  assert.equal(classification.entries.length, 1);
  const observed = classification.entries[0]!;
  assert.equal(observed.path, 'example.txt'); assert.equal(observed.entryKind, 'file');
  assert.equal(observed.workspaceEntryDigest, canonicalSha256(original)); assert.equal(observed.classification, 'nonignored_in_root');
  assert.equal(observed.deviceId, input.originalHostFile.dev); assert.equal(observed.fileId, input.originalHostFile.ino);
  assert.equal(String(observed.linkCount), input.originalHostFile.nlink);
  assert.equal(source.sourceProjectionRef, base.sourceProjectionRef); assert.equal(source.sourceProjectionDigest, base.sourceProjectionDigest);
  const editInput = calls[15]!.input; assert('new_text' in editInput && typeof editInput.new_text === 'string');
  assert.equal(typeof editInput.old_text, 'string');
  assert((await input.readCas(original.blobRef)).equals(Buffer.from(editInput.old_text as string)));
  const after = Buffer.from(editInput.new_text), afterRef = sha256Bytes(after);
  assert.equal(canonicalSha256(entries.entries), canonicalSha256(before.entries.map(entry => entry.path === 'example.txt'
    ? { path: entry.path, kind: 'file', mode: entry.mode, blobRef: afterRef, size: after.length } : entry)));
  assert((await input.readCas(afterRef)).equals(after)); assert.equal(entries.entries.some(entry => entry.path === 'denied.txt'), false);
  const state = decodeWorkspaceState(await object(cut.checkpoints.at(-1).workspaceStateRef));
  assert.equal(state.runId, run.id); assert.equal(state.entriesRef, source.entriesRef);
  const terminalItems = await Promise.all(input.sessionCut.items.map((row: any) => object(row.payloadRef)));
  const published = terminalItems.filter(item => item.kind === 'run_terminal' && item.runId === run.id); assert.equal(published.length, 1);
  assert.equal(published[0].status, 'completed_unverified'); assert.equal(published[0].resultRef, run.resultRef);
  return { qualified: true, readCalls: 15, executedToolCalls: 17, deniedCalls: 1, inputReplies: 1,
    sameParentForFirstFourteenReads: true, fifteenthReadUsedNewParent: true, actualReadParentObservedAlive: true,
    scopeCapacityCheckpointUnchanged: true, eachOriginalClaimCompletedOnce: true, rawOutputsAndInvocationDeathChecked: true,
    bashExitCode: 7, workerFreeWaits: true, waitingInputRestartPreserved: true, exactControlReplay: true,
    staleReplyRefused: true, hostFilesUnchanged: true, status: 'completed_unverified', actualVerifierQualified: false,
    originalBuiltinIncludeCaptured: true, originalCaptureDescriptorMatched: true, originalAuthorizationPreservedAfterEdit: true };
}
