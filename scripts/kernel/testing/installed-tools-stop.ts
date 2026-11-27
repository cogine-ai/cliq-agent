// Actual readonly observation of the original installed Bash claim. The
// existing signed-image observer supplies the full bytes/identity/FD checks;
// none of these observations is execution, cancellation or death authority.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { GuestToolchainManifest, ProcessContainmentPlanV1 } from '../../../src/kernel/execution.js';
import { decodeBuiltinScriptSandboxLaunchSpec } from '../../../src/state/execution-closure.js';
import { decodeBuiltinToolCapture } from '../../../src/state/builtin-tool-capture.js';
import { observeGuestVerifierProcess } from './guest-verifier-process.js';
import { inspectInstalledWorkerIdentity, type InstalledWorkerIdentityInspection } from './installed-worker-lease.js';

export const INSTALLED_BASH_STARTED = 'CLIQ_BASH_ACTIVE\n';
export const installedBashStopCall = Object.freeze({ callId: 'owned-installed-bash-stop', name: 'bash',
  input: Object.freeze({ command: "printf 'CLIQ_BASH_ACTIVE\\n'; /usr/bin/node --no-addons -e 'setInterval(()=>{},1000)'; :" }) });
export type InstalledBashProcesses = Readonly<{ parent: InstalledWorkerIdentityInspection;
  bash: Readonly<{ pid: number; processStartToken: string }>; child: Readonly<{ pid: number; processStartToken: string }> }>;

export async function observeInstalledBash(input: { stateRoot: string; uid: number; cut: Record<string, any>;
  guest: GuestToolchainManifest; supervisorInstanceId: string; deadline: number; readCas(ref: string): Promise<Buffer>;
  processIdentity(pid: number, uid: number, parent?: number): Promise<string> }): Promise<InstalledBashProcesses | undefined> {
  const run = input.cut.snapshot.run;
  const claims = input.cut.journal.filter((entry: any) => entry.opKind === 'tool' && entry.phase === 'dispatch_claimed');
  assert(claims.length <= 1); if (!claims.length) return;
  const claim = claims[0]; if (input.cut.journal.some((entry: any) => entry.opId === claim.opId && entry.phase === 'completed')) return;
  const object = async <T>(ref: string): Promise<T> => {
    const bytes = await input.readCas(ref); assert.equal(sha256Bytes(bytes), ref);
    const data = parseJsonStrict(new TextDecoder('utf8', { fatal: true }).decode(bytes)); assert(canonicalJsonBytes(data).equals(bytes)); return data as T;
  };
  const launch = decodeBuiltinScriptSandboxLaunchSpec(await object(claim.sandboxLaunchSpecRef));
  const plan = await object<ProcessContainmentPlanV1>(launch.containmentPlanRef);
  assert.equal(plan.planDigest, digestOmitting(plan, 'planDigest')); assert.equal(plan.planDigest, launch.containmentPlanDigest);
  assert.equal(plan.backend.kind, 'linux'); if (plan.backend.kind !== 'linux') throw new TypeError('missing original Linux tool plan');
  const bash = input.guest.admittedExecutables.filter(entry => entry.logicalName === 'bash' && entry.canonicalGuestPath === '/bin/bash'); assert.equal(bash.length, 1);
  let text = '';
  try { text = await readFile(path.join(plan.backend.cgroupPath, 'cgroup.procs'), 'utf8'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
  assert(Buffer.byteLength(text) <= 65536); const ids = text.trim() ? text.trim().split('\n') : [];
  assert(ids.length <= 4096 && ids.every(id => /^[1-9][0-9]{0,9}$/u.test(id)));
  let actualBash: InstalledBashProcesses['bash'] | undefined, actualChild: InstalledBashProcesses['child'] | undefined;
  for (const value of ids) {
    const pid = Number(value);
    let status: string;
    try { status = await readFile(`/proc/${pid}/status`, 'utf8'); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
    assert(Buffer.byteLength(status) <= 65536);
    const nested = status.match(/^NSpid:\s+([0-9\s]+)$/mu); assert(nested);
    const namespacePid = Number(nested[1]!.trim().split(/\s+/u).at(-1));
    // PID 2 is the original fixed Node adapter. A different real Node child is
    // necessary to establish that Bash actually passed its first command.
    if (namespacePid <= 2) continue;
    const observedBash = await observeGuestVerifierProcess({ pid, uid: input.uid, cgroupPath: plan.backend.cgroupPath,
      executablePath: '/bin/bash', executableDigest: bash[0]!.digest, deadline: input.deadline });
    if (observedBash.kind === 'matched') actualBash = { pid, processStartToken: await input.processIdentity(pid, input.uid) };
    const observedNode = await observeGuestVerifierProcess({ pid, uid: input.uid, cgroupPath: plan.backend.cgroupPath,
      executablePath: '/usr/bin/node', executableDigest: input.guest.node.digest, deadline: input.deadline });
    if (observedNode.kind === 'matched') actualChild = { pid, processStartToken: await input.processIdentity(pid, input.uid) };
  }
  if (!actualBash || !actualChild) return;
  assert.equal(await input.processIdentity(actualChild.pid, input.uid, actualBash.pid), actualChild.processStartToken);
  assert.equal(await input.processIdentity(actualBash.pid, input.uid), actualBash.processStartToken);
  const parent = inspectInstalledWorkerIdentity(input.stateRoot, { uid: input.uid, runId: run.id, launchId: run.activeWorkerLaunchId,
    leaseEpoch: run.leaseEpoch, runRevision: run.revision, supervisorInstanceId: input.supervisorInstanceId, deadlineAt: run.deadlineAt });
  assert.equal(parent.launchId, launch.owner.workerLaunchId);
  return Object.freeze({ parent, bash: actualBash, child: actualChild });
}

export async function assertInstalledBashStopped(input: { cut: Record<string, any>; readCas(ref: string): Promise<Buffer>;
  mode: 'user_cancel' | 'supervisor_restart'; original: InstalledBashProcesses; physicallyJoinedWithinTwoSeconds: true;
  leaseContinuedPastOriginalExpiry: boolean }) {
  const object = async <T = Record<string, any>>(ref: string): Promise<T> => {
    const bytes = await input.readCas(ref); assert.equal(sha256Bytes(bytes), ref);
    const value = parseJsonStrict(new TextDecoder('utf8', { fatal: true }).decode(bytes)); assert(canonicalJsonBytes(value).equals(bytes)); return value as T;
  };
  const run = input.cut.snapshot.run, rows = input.cut.journal.filter((row: any) => row.opKind === 'tool');
  assert.deepEqual(rows.map((row: any) => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
  assert.equal(rows[1].supervisorInstanceId, input.original.parent.supervisorInstanceId); assert.equal(rows[1].leaseEpoch, input.original.parent.leaseEpoch);
  const observation = await object(rows[2].resultRef), capture = decodeBuiltinToolCapture(await object(observation.captureRef));
  assert.equal(capture.captureDigest, observation.captureDigest); assert.equal(capture.terminationReason, 'controller_stop');
  assert.equal(capture.dispatchId, rows[1].dispatchId); assert.equal(capture.sandboxLaunchSpecRef, rows[1].sandboxLaunchSpecRef);
  assert.equal(capture.tool, 'bash'); assert.equal(observation.outcome, 'executed'); assert(observation.postEffect);
  const stdout = await input.readCas(capture.stdoutRef), stderr = await input.readCas(capture.stderrRef);
  assert.equal(stdout.length, capture.stdoutByteCount); assert.equal(stderr.length, capture.stderrByteCount);
  assert(stdout.toString('utf8').includes(INSTALLED_BASH_STARTED)); assert.equal(capture.stdoutTruncated, false);
  assert.equal(observation.content.terminationReason, 'controller_stop'); assert.equal(Object.hasOwn(observation.content, 'exitCode'), false);
  assert.equal(Object.hasOwn(observation.content, 'noEffect'), false);
  const death = await object(capture.deathEvidenceRef); assert.equal(death.evidenceDigest, digestOmitting(death, 'evidenceDigest'));
  assert.equal(death.kind, 'containment_all_descendants_dead'); assert.equal(death.backend.cgroupPopulated, 0);
  assert.equal(death.backend.namespaceInitDeadAndReaped, true); assert.equal(death.backend.remainingTrackedDescendants, 0);
  assert.equal(canonicalSha256(run.budgetReserved), canonicalSha256({ modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }));
  if (input.mode === 'user_cancel') { assert.equal(run.status, 'cancelled'); assert.equal(run.terminalReason, 'cancelled_by_user'); assert(run.stopIntentRef); }
  else { assert.equal(run.status, 'completed_unverified'); assert.equal(run.stopIntentRef, undefined); }
  assert.equal(input.leaseContinuedPastOriginalExpiry, input.mode === 'supervisor_restart');
  return { qualified: true, mode: input.mode, actualBashAndNonAdapterNodeObserved: true, originalProcessLifetimesAbsent: true,
    originalClaimCompletedOnce: true, genuineControllerStopRetained: true, partialStdoutPreserved: true,
    parentPostEffectSealed: true, physicallyJoinedWithinTwoSeconds: true, noRedispatch: true,
    status: run.status, leaseContinuedPastOriginalExpiry: input.leaseContinuedPastOriginalExpiry, actualVerifierQualified: false };
}
