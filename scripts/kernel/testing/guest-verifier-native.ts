import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { identityHash } from '../../../src/kernel/identity.js';
import type { ProcessContainmentDeathEvidenceV1, ProcessContainmentPlanV1, SandboxLaunchSpecV1 } from '../../../src/kernel/execution.js';
import type { VerificationReceipt, VerifierStopEvidence, VerifierStopItem } from '../../../src/kernel/verifier.js';
import type { RunFrontier, SourceManifest, WorkspaceEntryManifest, WorkspaceStateManifest } from '../../../src/kernel/types.js';
import { stopCheckpointId } from '../../../src/runtime/stop.js';
import { createLinuxWorkerCampaignFixture } from '../../../src/sandbox/testing/worker-campaign-fixture.js';
import { sampleCanonicalNow } from '../../../src/state/canonical-time.js';
import { openStateStore, publishInProcessChannel, type StateStore } from '../../../src/state/store.js';
import { uuidv7 } from '../../../src/state/testing/fixtures.js';
import { verifierCheckpointId, type VerifierRetirementV1 } from '../../../src/state/verifier-recovery.js';
import { inspectInstalledWorkerRetirementHistory } from './installed-worker-lease.js';
import { recordGuestVerifierBoundaryFailure } from './guest-verifier-diagnostics.js';

const successfulScript = `import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import {spawn, spawnSync} from 'node:child_process';
test('same-image Node, readonly source, no ambient runtime or executable writable surface', async () => {
  const boundary = stage => { try { fs.writeSync(1, 'CLIQ_GUEST_BOUNDARY_V1:' + stage + '\\n'); } catch {} };
  boundary('runtime_identity');
  assert.equal(process.version, 'v24.21.0');
  assert.equal(process.execPath, '/usr/bin/node');
  assert.equal(process.cwd(), '/work');
  boundary('source_read');
  assert.equal(fs.readFileSync('a', 'utf8'), 'after\\n');
  boundary('environment');
  assert.equal(process.env.PATH, '/usr/bin');
  for (const key of ['NODE_OPTIONS','LD_PRELOAD','LD_LIBRARY_PATH']) assert.equal(process.env[key], undefined);
  boundary('ambient_paths');
  for (const name of ['/bin/sh','/usr/bin/git','/usr/local/bin/node','/etc/passwd','/host']) assert.equal(fs.existsSync(name), false);
  boundary('source_readonly');
  assert.throws(() => fs.writeFileSync('a', 'not allowed'), {code:'EROFS'});
  boundary('descriptor_surface');
  for (const fd of fs.readdirSync('/proc/self/fd')) {
    let target; try { target = fs.readlinkSync('/proc/self/fd/' + fd); } catch (e) { if (e.code === 'ENOENT') continue; throw e; }
    assert.doesNotMatch(target, /cliq-guest|cliq-scope|cliq-verifier|objects\\/sha256|state\\.sqlite/);
  }
  boundary('workspace_noexec');
  assert.equal(spawnSync('/work/untrusted-elf', [], {timeout:1000}).error?.code, 'EACCES');
  boundary('tmp_noexec');
  const libc = ['/lib/x86_64-linux-gnu/libc.so.6','/usr/lib/x86_64-linux-gnu/libc.so.6'].find(name=>fs.existsSync(name));
  assert.ok(libc); fs.copyFileSync(libc, '/tmp/untrusted-elf'); fs.chmodSync('/tmp/untrusted-elf', 0o755);
  assert.equal(spawnSync('/tmp/untrusted-elf', [], {timeout:1000}).error?.code, 'EACCES');
  boundary('loader_noexec');
  const loader = spawnSync('/lib64/ld-linux-x86-64.so.2', ['/tmp/untrusted-elf'], {encoding:'utf8',timeout:1000});
  assert.equal(loader.status, 127); assert.match(loader.stderr, /failed to map segment|Operation not permitted|Permission denied/);
  boundary('network_denied');
  await new Promise((resolve,reject) => { const socket = net.createConnection({host:'127.0.0.1',port:9});
    socket.once('error', error => { try { assert.equal(error.code,'EPERM'); resolve(); } catch (e) { reject(e); } });
    socket.once('connect', () => { socket.destroy(); reject(new Error('network boundary bypassed')); }); });
  boundary('child_node');
  const child = spawnSync('/usr/bin/node', ['--no-addons','-e','process.stdout.write(process.version)'], {encoding:'utf8',timeout:1000});
  assert.equal(child.status, 0); assert.equal(child.stdout,'v24.21.0');
  boundary('child_domain');
  const background = spawn('/usr/bin/node', ['--no-addons','-e','setInterval(()=>{},1000)'], {detached:true,stdio:'ignore'});
  await new Promise((resolve,reject) => { background.once('spawn',resolve); background.once('error',reject); });
  background.unref(); await new Promise(resolve => setTimeout(resolve,250));
  boundary('complete');
});
`;

async function stageCandidate(fixture: Awaited<ReturnType<typeof createLinuxWorkerCampaignFixture>>, store: StateStore) {
  const execution = await store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
  const edited = await execution.executeCurrentTool({ expectedRunRevision: store.getRun(fixture.runId).revision });
  const active = await execution.activateCurrentWorker({ expectedRunRevision: edited.revision });
  const agent = await store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed.releaseKeys });
  // Only this model decoder/settlement prefix is offline. Its actual edit,
  // candidate snapshots, native workers and verifier processes are not injected.
  const prepared = await agent.prepareModel({ expectedRunRevision: active.revision, leaseEpoch: active.leaseEpoch });
  await store.claimInvocationDispatch({ runId: fixture.runId, expectedRunRevision: prepared.run.revision,
    leaseEpoch: active.leaseEpoch, opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    dispatchId: identityHash('cliq-guest-campaign-final-model-v1', fixture.runId) });
  const response = agent.model.start(prepared.prepared, { status: 200, mediaType: 'application/json' });
  response.push(Buffer.from(JSON.stringify({ id: 'guest-campaign-final', object: 'response', status: 'completed', model: 'model-1',
    output: [{ type: 'message', id: 'guest-campaign-final-message', role: 'assistant', status: 'completed',
      content: [{ type: 'output_text', text: 'The private edit is ready for required checks.', annotations: [] }] }] })));
  const completed = await agent.completeModel({ opId: prepared.entry.opId, attempt: prepared.entry.attempt,
    expectedRunRevision: prepared.run.revision, result: response.finish(sampleCanonicalNow(), agent.resolveToolInput) });
  assert.equal(completed.disposition, 'candidate_required');
  const candidate = await execution.finishCurrentFinalTurn({ expectedRunRevision: store.getRun(fixture.runId).revision });
  assert.equal(candidate.nextStep, 'verify'); assert.equal(candidate.activeWorkerLaunchId, undefined);
  return { execution, candidate, agent };
}

/** Real StateStore authorization/admission and native execution, with an
 * explicitly offline retained model prefix. No provider or release qualification
 * follows from this campaign; no receipt, process result, or death is injected. */
export async function qualifyLinuxGuestVerifier(input: {
  installationRoot: string; guestImageRoot: string; cgroupParent: string; stateVolume: string;
}) {
  assert.equal(process.platform, 'linux', 'guest verifier qualification cannot be skipped');
  const sourceExecutable = await readFile(path.join(input.installationRoot, 'cliq-linux-worker'));
  const cases = [
    { name: 'pass-boundaries-child-domain', script: successfulScript, timeoutMs: 10_000,
      reason: 'exit', outcome: 'passed', exitCode: 0 },
    { name: 'real-assertion-failure', script: `import test from 'node:test'; import assert from 'node:assert/strict';
test('actual failure',()=>assert.equal(1,2));`, timeoutMs: 10_000, reason: 'exit', outcome: 'assertion_failed', exitCode: 1 },
    { name: 'real-timeout', script: `import test from 'node:test';
test('must really time out',()=>new Promise(()=>{setInterval(()=>{},50)}));`, timeoutMs: 1000, reason: 'timeout', outcome: 'infra_failed' },
    { name: 'real-output-cap', script: `import test from 'node:test'; import fs from 'node:fs';
test('must really exceed output cap',()=>{for(let i=0;i<32;i++)fs.writeSync(1,Buffer.alloc(65536,0x78));});`,
      timeoutMs: 10_000, reason: 'resource_failure', outcome: 'infra_failed' },
  ] as const;
  const reports = [];
  for (const scenario of cases) {
    const fixture = await createLinuxWorkerCampaignFixture({ ...input, label: `guest-${scenario.name}`,
      verifier: { guestImageRoot: input.guestImageRoot, script: Buffer.from(scenario.script), sourceExecutable,
        timeoutMs: scenario.timeoutMs, outputLimitBytes: 65_536, maxOpenFiles: 64 } });
    let store = fixture.store;
    try {
      const hostBefore = await stat(path.join(fixture.workspace, 'a'), { bigint: true });
      const { execution, candidate } = await stageCandidate(fixture, store);
      const before = await store.readRecoveryClosure(fixture.runId), priorLaunches = new Set(before.workerLaunches.map(launch => launch.launchId));
      const frontier = await store.artifacts.readCanonical<RunFrontier>(candidate.frontierRef!);
      assert.equal(frontier.kind, 'verify');
      if (frontier.kind !== 'verify') throw new Error('candidate has no exact verifier frontier');
      const result = await execution.executeCurrentVerifier({ expectedRunRevision: candidate.revision });
      const after = await store.readRecoveryClosure(fixture.runId);
      const attempts = after.journal.filter(row => row.opKind === 'verifier');
      assert.deepEqual(attempts.map(row => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
      assert.equal(new Set(attempts.map(row => row.opId)).size, 1); assert.ok(attempts.every(row => row.attempt === 0));
      const claim = attempts.find(row => row.phase === 'dispatch_claimed')!, done = attempts.find(row => row.phase === 'completed')!;
      assert.ok(claim.sandboxLaunchSpecRef && done.receiptRef);
      const launch = await store.artifacts.readCanonical<SandboxLaunchSpecV1>(claim.sandboxLaunchSpecRef);
      assert.equal(launch.owner.kind, 'run_invocation'); assert.equal(launch.purpose, 'verifier');
      if (launch.owner.kind !== 'run_invocation') throw new Error('verifier did not claim its real nested invocation');
      assert.ok(!priorLaunches.has(launch.owner.workerLaunchId), 'the dead final-candidate worker cannot be reused');
      const verifierWorker = inspectInstalledWorkerRetirementHistory(fixture.stateRoot, process.geteuid!(),
        { runId: fixture.runId, launchId: launch.owner.workerLaunchId });
      assert.equal(verifierWorker.phase, 'retired'); assert.equal(verifierWorker.generationWriteState, 'sealed');
      assert.equal(verifierWorker.generationPhase, 'sealed');
      assert.ok(!before.workspaceGenerations.some(generation => generation.generationRef === verifierWorker.workspaceGenerationRef),
        'the dead final-candidate generation cannot be reused by the verifier');
      assert.equal(after.run.activeWorkerLaunchId, undefined);
      const receipt = await store.artifacts.readCanonical<VerificationReceipt>(done.receiptRef);
      assert.equal(receipt.runId, fixture.runId); assert.equal(receipt.attempt, 0);
      // Read complete CAS objects through the original full-hash/held-FD path
      // before projecting diagnostics. No TAP or output bytes enter reports.
      const stdout = await store.artifacts.readBytes(receipt.stdoutRef), stderr = await store.artifacts.readBytes(receipt.stderrRef);
      assert.ok(stdout.length + stderr.length <= 65_536);
      if (scenario.reason === 'resource_failure') assert.ok(receipt.stdoutTruncated || receipt.stderrTruncated);
      else assert.equal(receipt.stdoutTruncated || receipt.stderrTruncated, false);
      try {
        assert.equal(receipt.terminationReason, scenario.reason); assert.equal(receipt.outcome, scenario.outcome);
        if ('exitCode' in scenario) assert.equal(receipt.exitCode, scenario.exitCode);
      } catch (error) {
        if (scenario.name === 'pass-boundaries-child-domain') recordGuestVerifierBoundaryFailure(error, receipt.outcome, stdout);
        throw error;
      }
      assert.equal(receipt.sourceDigestBefore, receipt.sourceDigestAfter);
      assert.equal(receipt.resultSourceRef, frontier.resultSourceRef);
      const source = await store.artifacts.readCanonical<SourceManifest>(receipt.resultSourceRef);
      assert.equal(receipt.sourceDigestBefore, source.manifestDigest);
      const checkpoint = after.latestCheckpoint;
      const workspace = await store.artifacts.readCanonical<WorkspaceStateManifest>(checkpoint.workspaceStateRef);
      assert.equal(workspace.entriesRef, source.entriesRef, 'the actual verifier checkpoint preserves exact candidate source');
      const entries = await store.artifacts.readCanonical<WorkspaceEntryManifest>(workspace.entriesRef);
      const editedFile = entries.entries.find(entry => entry.path === 'a');
      assert.ok(editedFile?.kind === 'file'); assert.deepEqual(await store.artifacts.readBytes(editedFile.blobRef), Buffer.from('after\n'));
      if (scenario.outcome === 'passed') assert.match(stdout.toString('utf8'), /same-image Node/);
      const retirement = await store.artifacts.readCanonical<VerifierRetirementV1>(receipt.containmentEvidenceRef);
      assert.equal(retirement.format, 'cliq-verifier-retirement-v1');
      assert.equal(retirement.runId, fixture.runId); assert.equal(retirement.opId, claim.opId);
      assert.equal(retirement.attempt, claim.attempt); assert.equal(retirement.dispatchId, claim.dispatchId);
      assert.equal(retirement.leaseEpoch, claim.leaseEpoch); assert.equal(retirement.checkpointId, checkpoint.id);
      assert.equal(verifierWorker.leaseEpoch, claim.leaseEpoch);
      assert.equal(verifierWorker.retirementEvidenceRef, retirement.parentRetirementEvidenceRef);
      assert.equal(verifierWorker.snapshotEvidenceRef, retirement.snapshotEvidenceRef);
      assert.equal(retirement.workspaceStateRef, checkpoint.workspaceStateRef);
      assert.equal(retirement.sourceAfterRef, receipt.resultSourceRef); assert.equal(retirement.sourceAfterDigest, receipt.sourceDigestAfter);
      const death = await store.artifacts.readCanonical<ProcessContainmentDeathEvidenceV1>(retirement.deathEvidenceRef);
      assert.equal(death.containmentRef, retirement.containmentRef);
      const plan = await store.artifacts.readCanonical<ProcessContainmentPlanV1>(death.planRef);
      assert.equal(plan.owner.kind, 'run_invocation'); assert.equal(death.backend.kind, 'linux');
      if (plan.owner.kind !== 'run_invocation' || death.backend.kind !== 'linux') throw new Error('verifier lacks its real Linux invocation death');
      assert.equal(plan.owner.dispatchId, claim.dispatchId); assert.equal(plan.owner.workerLaunchId, launch.owner.workerLaunchId);
      assert.equal(death.backend.cgroupPopulated, 0); assert.equal(death.backend.namespaceInitDeadAndReaped, true);
      assert.equal(death.backend.remainingTrackedDescendants, 0);
      assert.match(await readFile(path.join(death.backend.cgroupPath, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
      assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
      const hostAfter = await stat(path.join(fixture.workspace, 'a'), { bigint: true });
      assert.equal(hostAfter.dev, hostBefore.dev); assert.equal(hostAfter.ino, hostBefore.ino);
      assert.equal(hostAfter.mode, hostBefore.mode); assert.equal(hostAfter.mtimeNs, hostBefore.mtimeNs);
      assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1,
        'the one permanently claimed verifier is charged exactly once');
      assert.equal(after.run.budgetReserved.toolCalls, 0);
      assert.equal(after.run.budgetConsumed.modelTokens, before.run.budgetConsumed.modelTokens);
      assert.equal(after.run.budgetConsumed.costMicros, before.run.budgetConsumed.costMicros);
      await assert.rejects(execution.executeCurrentVerifier({ expectedRunRevision: candidate.revision }), 'old cut cannot replay the permanent verifier claim');
      const revision = result.revision, checkpointId = checkpoint.id, receiptRef = done.receiptRef;
      await store.close(); store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
      const reopened = await store.readRecoveryClosure(fixture.runId);
      assert.equal(reopened.run.revision, revision); assert.equal(reopened.latestCheckpoint.id, checkpointId);
      assert.equal(reopened.journal.filter(row => row.opKind === 'verifier' && row.phase === 'dispatch_claimed').length, 1);
      assert.equal(reopened.journal.find(row => row.opKind === 'verifier' && row.phase === 'completed')?.receiptRef, receiptRef);
      const reopenedAgent = await store.loadAgentRun({ runId: fixture.runId, material: fixture.authority.material, releaseKeys: fixture.signed.releaseKeys });
      await assert.rejects(reopenedAgent.prepareVerifier({ expectedRunRevision: revision, leaseEpoch: reopened.run.leaseEpoch }),
        'completed verifier cannot be silently prepared again after restart');
      reports.push({ scenario: scenario.name, runtimeBundleDigest: fixture.signed.bundle.manifestDigest,
        guestImageDigest: fixture.signed.guest!.manifest.guestImageDigest, sourceDigest: source.manifestDigest,
        commandDigest: receipt.commandDigest, receiptRef, checkpointId, permanentVerifierClaims: 1,
        terminationReason: receipt.terminationReason, outcome: receipt.outcome, outputByteCount: stdout.length + stderr.length,
        sourceUnchanged: true, wholeDomainDead: true, qualified: true });
    } finally { await store.close(); await fixture.dispose(); }
  }
  {
    const fixture = await createLinuxWorkerCampaignFixture({ ...input, label: 'guest-inflight-cancel',
      verifier: { guestImageRoot: input.guestImageRoot, sourceExecutable, maxOpenFiles: 64, timeoutMs: 30_000, outputLimitBytes: 65_536,
        script: Buffer.from(`import test from 'node:test'; test('real in-flight cancellation',()=>new Promise(()=>{setInterval(()=>{},50)}));`) } });
    let store = fixture.store;
    try {
      const { execution, candidate, agent } = await stageCandidate(fixture, store);
      const before = await store.readRecoveryClosure(fixture.runId);
      let settled = false;
      const running = execution.executeCurrentVerifier({ expectedRunRevision: candidate.revision });
      const joined = running.then(value => { settled = true; return { value }; }, error => { settled = true; return { error }; });
      const started = performance.now(); let actualNode = false; let invocationPath: string | undefined;
      while (!actualNode && !settled && performance.now() - started < 15_000) {
        const cut = await store.readRecoveryClosure(fixture.runId);
        const claim = cut.journal.find(row => row.opKind === 'verifier' && row.phase === 'dispatch_claimed');
        if (claim?.sandboxLaunchSpecRef) {
          const launch = await store.artifacts.readCanonical<SandboxLaunchSpecV1>(claim.sandboxLaunchSpecRef);
          const plan = await store.artifacts.readCanonical<ProcessContainmentPlanV1>(launch.containmentPlanRef);
          if (plan.backend.kind !== 'linux') throw new Error('cancel campaign requires the actual nested Linux cgroup');
          invocationPath = plan.backend.cgroupPath;
          let pids = '';
          try { pids = (await readFile(path.join(invocationPath, 'cgroup.procs'), 'utf8')).trim(); }
          catch (error) {
            // The durable claim precedes asynchronous extraction/CREATE. A
            // missing directory here is no observation, never death proof.
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
          }
          if (pids) for (const value of pids.split('\n')) {
            assert.match(value, /^[1-9][0-9]{0,9}$/u);
            try { if ((await readFile(`/proc/${value}/comm`, 'utf8')).trim() === 'node') actualNode = true; }
            catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
          }
        }
        if (!actualNode) await delay(25);
      }
      assert.ok(actualNode && invocationPath && !settled, 'cancel only after the real claimed guest Node is executing');
      await agent.cancelRun({ ...await publishInProcessChannel(store), requestId: uuidv7(), expectedRunRevision: store.getRun(fixture.runId).revision });
      const stopStarted = performance.now(); await execution.requestStop();
      assert.ok(performance.now() - stopStarted <= 2000, 'actual in-flight verifier cancellation must join within the existing stop bound');
      await joined;
      const measured = await store.readRecoveryClosure(fixture.runId);
      const measuredClaim = measured.journal.find(row => row.opKind === 'verifier' && row.phase === 'dispatch_claimed')!;
      assert.ok(measuredClaim);
      const measuredInvocation = await store.artifacts.readCanonical<SandboxLaunchSpecV1>(measuredClaim.sandboxLaunchSpecRef!);
      if (measuredInvocation.owner.kind !== 'run_invocation') throw new Error('controlled stop has no original verifier parent');
      const measuredParent = inspectInstalledWorkerRetirementHistory(fixture.stateRoot, process.geteuid!(),
        { runId: fixture.runId, launchId: measuredInvocation.owner.workerLaunchId });
      const verifierCheckpoint = measured.latestCheckpoint;
      assert.equal(verifierCheckpoint.id, verifierCheckpointId(fixture.runId, measuredClaim.opId, measuredClaim.attempt));
      const failed = measured.journal.filter(row => row.opId === measuredClaim.opId && row.attempt === measuredClaim.attempt).at(-1)!;
      assert.equal(failed.phase, 'failed'); assert.equal(verifierCheckpoint.journalSeq, failed.seq);
      const stopped = await execution.finishCurrentStop({ expectedRunRevision: store.getRun(fixture.runId).revision });
      assert.equal(stopped.status, 'cancelled'); assert.equal(stopped.terminalReason, 'cancelled_by_user');
      assert.equal(stopped.activeWorkerLaunchId, undefined);
      const after = await store.readRecoveryClosure(fixture.runId);
      assert.equal(after.journal.filter(row => row.opKind === 'verifier' && row.phase === 'dispatch_claimed').length, 1);
      assert.equal(after.journal.filter(row => row.opKind === 'verifier' && row.phase === 'completed').length, 0,
        'cancellation cannot manufacture a process result for an interrupted invocation');
      const stopItems = [];
      for (const row of after.items) {
        const item = await store.artifacts.readCanonical<Record<string, unknown>>(row.payloadRef);
        if (item.kind === 'verifier_stop') stopItems.push({ item: item as unknown as VerifierStopItem, row });
      }
      assert.equal(stopItems.length, 1, 'the released invocation retains one real controlled-stop observation, never an infrastructure receipt');
      const { item, row: stopRow } = stopItems[0]!, evidence = await store.artifacts.readCanonical<VerifierStopEvidence>(item.containmentEvidenceRef);
      const claim = after.journal.find(row => row.opKind === 'verifier' && row.phase === 'dispatch_claimed')!;
      assert.equal(evidence.terminationReason, 'controller_stop');
      assert.equal(evidence.stopIntentRef, after.run.stopIntentRef); assert.equal(item.stopIntentRef, after.run.stopIntentRef);
      assert.equal(item.opId, claim.opId); assert.equal(item.attempt, claim.attempt); assert.equal(evidence.leaseEpoch, claim.leaseEpoch);
      assert.ok(evidence.startedAt >= claim.timestamp && evidence.endedAt >= evidence.startedAt);
      assert.ok(Number.isSafeInteger(evidence.durationMs) && evidence.durationMs >= 0);
      assert.equal(evidence.exitCode, undefined); assert.equal(evidence.signal, undefined);
      const retirement = await store.artifacts.readCanonical<VerifierRetirementV1>(evidence.retirementRef);
      assert.equal(retirement.runId, fixture.runId); assert.equal(retirement.opId, claim.opId);
      assert.equal(retirement.dispatchId, claim.dispatchId); assert.equal(retirement.attempt, claim.attempt);
      assert.equal(retirement.checkpointId, verifierCheckpoint.id);
      assert.equal(verifierCheckpoint.runItemSeq, stopRow.itemSeq);
      assert.equal(failed.errorRef, item.containmentEvidenceRef); assert.equal(failed.timestamp, stopRow.createdAt);
      assert.equal(retirement.workspaceStateRef, verifierCheckpoint.workspaceStateRef);
      assert.equal(after.latestCheckpoint.id, stopCheckpointId(fixture.runId, after.run.stopIntentRef!));
      assert.notEqual(after.latestCheckpoint.id, verifierCheckpoint.id);
      assert.equal(after.latestCheckpoint.workspaceStateRef, verifierCheckpoint.workspaceStateRef);
      assert.equal(after.latestCheckpoint.contextManifestRef, verifierCheckpoint.contextManifestRef);
      assert.equal(after.latestCheckpoint.runItemSeq, verifierCheckpoint.runItemSeq);
      assert.equal(after.latestCheckpoint.journalSeq, failed.seq);
      const invocation = await store.artifacts.readCanonical<SandboxLaunchSpecV1>(claim.sandboxLaunchSpecRef!);
      if (invocation.owner.kind !== 'run_invocation') throw new Error('controlled stop has no original verifier parent');
      const parentLaunchId = invocation.owner.workerLaunchId;
      assert.equal(canonicalSha256(invocation), canonicalSha256(measuredInvocation));
      assert.equal(measuredParent.launchId, parentLaunchId); assert.equal(measuredParent.phase, 'retired');
      assert.equal(measuredParent.generationWriteState, 'sealed'); assert.equal(measuredParent.generationPhase, 'sealed');
      assert.equal(measuredParent.retirementEvidenceRef, retirement.parentRetirementEvidenceRef);
      assert.equal(measuredParent.snapshotEvidenceRef, retirement.snapshotEvidenceRef);
      const { observedAt: _measuredAt, ...originalParent } = measuredParent;
      const { observedAt: _afterAt, ...afterParent } = inspectInstalledWorkerRetirementHistory(fixture.stateRoot, process.geteuid!(),
        { runId: fixture.runId, launchId: parentLaunchId });
      assert.equal(canonicalSha256(afterParent), canonicalSha256(originalParent),
        'worker-free terminal Stop preserves the original verifier parent retirement lineage');
      assert.equal(evidence.sourceDigestBefore, evidence.sourceDigestAfter);
      assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1);
      assert.equal(after.run.budgetReserved.toolCalls, 0);
      assert.equal(after.run.budgetConsumed.modelTokens, before.run.budgetConsumed.modelTokens);
      assert.equal(after.run.budgetConsumed.costMicros, before.run.budgetConsumed.costMicros);
      assert.match(await readFile(path.join(invocationPath, 'cgroup.events'), 'utf8'), /(?:^|\n)populated 0\n/u);
      assert.deepEqual(await readFile(path.join(fixture.workspace, 'a')), fixture.original);
      const checkpointId = after.latestCheckpoint.id;
      await store.close(); store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
      const reopened = await store.readRecoveryClosure(fixture.runId);
      assert.equal(reopened.run.status, 'cancelled'); assert.equal(reopened.latestCheckpoint.id, checkpointId);
      assert.equal(reopened.journal.filter(row => row.opKind === 'verifier' && row.phase === 'dispatch_claimed').length, 1);
      const next = await store.loadRunExecution({ runId: fixture.runId, material: fixture.authority.material });
      await assert.rejects(next.executeCurrentVerifier({ expectedRunRevision: reopened.run.revision }));
      reports.push({ scenario: 'actual-inflight-cancel', runtimeBundleDigest: fixture.signed.bundle.manifestDigest,
        guestImageDigest: fixture.signed.guest!.manifest.guestImageDigest, checkpointId, permanentVerifierClaims: 1,
        stopEvidenceRef: item.containmentEvidenceRef, terminationReason: evidence.terminationReason,
        wholeDomainDead: true, sourceUnchanged: true, qualified: true });
    } finally { await store.close(); await fixture.dispose(); }
  }
  return { scope: 'real CI-signed guest Node + read-only same-candidate verifier invocation; existing offline model prefix only',
    source: 'injected Ed25519 CI root; not a Cliq release, provider, macOS, dependency-acquisition, or full installed qualification', reports,
    unverifiedCuts: ['after_permanent_claim_before_release', 'actual_32_mapped_file_closure', 'full_installed_required_verifier_run'],
    reportDigest: canonicalSha256(reports), qualified: true };
}
