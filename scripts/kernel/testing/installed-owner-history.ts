// Independent actual SQL/CAS owner observations for the three installed lifetimes.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readFile, readlink, stat } from 'node:fs/promises';
import path from 'node:path';
import { KERNEL_CAS_DIRECTORY } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { digestOmitting, parseCanonicalTime, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import type { PlatformProcessIdentityV1, StateLockIdentityV1, StateOwnerAcquisitionEvidenceV1,
  StateOwnerRecordV1, StateOwnerTransitionEvidenceV1, StateRootIdentityV1 } from '../../../src/kernel/types.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import { inspectInstalledOwnerHistory } from './installed-read-control.js';

type RootInput = { stateRoot: string; uid: number };
const imageFields = ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
const equalJson = (actual: unknown, expected: unknown) => assert.deepEqual(canonicalJsonBytes(actual), canonicalJsonBytes(expected));

export async function readInstalledCasJson<T>(input: RootInput, ref: string): Promise<T> {
  assert.match(ref, /^[0-9a-f]{64}$/u);
  const filename = path.join(input.stateRoot, KERNEL_CAS_DIRECTORY, ref);
  const before = await lstat(filename, { bigint: true });
  assert(before.isFile() && !before.isSymbolicLink()); assert.equal(before.nlink, 1n);
  assert.equal(before.uid, BigInt(input.uid)); assert.equal(before.mode & 0o7777n, 0o400n);
  const bytes = await readFile(filename), after = await lstat(filename, { bigint: true });
  for (const key of imageFields) assert.equal(after[key], before[key]);
  assert.equal(BigInt(bytes.byteLength), after.size); assert.equal(sha256Bytes(bytes), ref);
  const value = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as T;
  assert.deepEqual(canonicalJsonBytes(value), bytes);
  return value;
}

export async function qualifyInstalledOwnerProcess(input: RootInput & {
  pid: number; selectedImage: string; imageDigest: string;
}, owner: StateOwnerRecordV1, report: Record<string, unknown>) {
  const identity = await readInstalledCasJson<PlatformProcessIdentityV1>(input, owner.processIdentityRef);
  report.identity = identity;
  const raw = await readFile(`/proc/${input.pid}/stat`, 'utf8');
  assert(raw.startsWith(`${input.pid} (`));
  const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert(!['Z', 'X', 'x'].includes(fields[0]!)); assert.match(fields[19]!, /^(0|[1-9][0-9]*)$/u);
  equalJson(identity, { schemaVersion: 1, format: 'cliq-platform-process-identity-v1', platform: 'linux',
    pid: input.pid, processStartToken: `linux-proc-start-ticks:${fields[19]}`, ownerUid: input.uid,
    executableImageDigest: input.imageDigest, observedAt: owner.acquiredAt, identityDigest: identity.identityDigest });
  assert.equal(identity.identityDigest, digestOmitting(identity, 'identityDigest'));
  assert.equal(owner.processIdentityDigest, identity.identityDigest); assert.equal(owner.supervisorExecutableDigest, input.imageDigest);
  const selected = await lstat(input.selectedImage, { bigint: true });
  const bootstrap = await lstat(path.join(input.stateRoot, 'runtime/bootstrap'), { bigint: true });
  const actualImage = `/proc/${input.pid}/exe`, actual = await stat(actualImage, { bigint: true });
  assert.equal(await readlink(actualImage), input.selectedImage, 'actual process must execute selected inode, not bootstrap');
  for (const key of imageFields) assert.equal(actual[key], selected[key]);
  assert(actual.dev !== bootstrap.dev || actual.ino !== bootstrap.ino, 'identical bytes do not prove terminal selected-inode exec');
  assert.equal(createHash('sha256').update(await readFile(actualImage)).digest('hex'), input.imageDigest);
  const confirmed = await readFile(`/proc/${input.pid}/stat`, 'utf8');
  assert(confirmed.startsWith(`${input.pid} (`));
  const confirmedFields = confirmed.slice(confirmed.lastIndexOf(')') + 2).trim().split(/\s+/u);
  assert(!['Z', 'X', 'x'].includes(confirmedFields[0]!)); assert.equal(confirmedFields[19], fields[19]);
  report.process = { pid: input.pid, processStartToken: identity.processStartToken, image: input.selectedImage };
  return identity;
}

export async function qualifyInstalledOwnerLinks(input: RootInput & {
  bundle: RuntimeBundleManifest; imageDigest: string; report: Record<string, unknown>;
}) {
  input.report.qualified = false;
  const history = inspectInstalledOwnerHistory(input.stateRoot); input.report.history = history;
  const owners = history.owners;
  assert(owners.length >= 2 && owners.length <= 3, 'only the manual and automatic installed successors are qualified');
  for (const key of ['supervisorInstanceId', 'processIdentityRef', 'instanceNonceDigest'] as const)
    assert.equal(new Set(owners.map(owner => owner[key])).size, owners.length);
  const supervisor = input.bundle.entries.find(entry => entry.role === 'supervisor'); assert(supervisor);
  const evidence: Record<string, unknown>[] = []; input.report.evidence = evidence;
  for (const owner of owners) {
    const observed: Record<string, unknown> = { ownerEpoch: owner.ownerEpoch }; evidence.push(observed);
    assert.equal(owner.runtimeBundleRef, canonicalSha256(input.bundle));
    assert.equal(owner.runtimeBundleManifestDigest, input.bundle.manifestDigest);
    assert.equal(owner.supervisorEntryId, supervisor.entryId); assert.equal(owner.supervisorEntryVersion, supervisor.version);
    assert.equal(owner.supervisorExecutableDigest, input.imageDigest);
    assert.equal(owner.stateLockIdentityRef, owners[0]!.stateLockIdentityRef);
    assert.equal(owner.stateLockIdentityDigest, owners[0]!.stateLockIdentityDigest);
    const identity = await readInstalledCasJson<PlatformProcessIdentityV1>(input, owner.processIdentityRef); observed.identity = identity;
    assert.equal(identity.schemaVersion, 1); assert.equal(identity.format, 'cliq-platform-process-identity-v1');
    assert.equal(identity.platform, 'linux'); assert.equal(identity.ownerUid, input.uid);
    assert.equal(identity.executableImageDigest, input.imageDigest); assert.equal(identity.observedAt, owner.acquiredAt);
    assert.equal(identity.identityDigest, digestOmitting(identity, 'identityDigest')); assert.equal(owner.processIdentityDigest, identity.identityDigest);
    const acquisition = await readInstalledCasJson<StateOwnerAcquisitionEvidenceV1>(input, owner.acquisitionEvidenceRef);
    observed.acquisition = acquisition;
    const common = { schemaVersion: 1, format: 'cliq-state-owner-acquisition-evidence-v1', ownerEpoch: owner.ownerEpoch,
      supervisorInstanceId: owner.supervisorInstanceId, runtimeBundleRef: owner.runtimeBundleRef,
      runtimeBundleManifestDigest: owner.runtimeBundleManifestDigest, processIdentityRef: owner.processIdentityRef,
      processIdentityDigest: owner.processIdentityDigest, stateLockIdentityRef: owner.stateLockIdentityRef,
      stateLockIdentityDigest: owner.stateLockIdentityDigest, instanceNonceDigest: owner.instanceNonceDigest,
      acquiredAt: owner.acquiredAt, evidenceDigest: acquisition.evidenceDigest };
    assert.equal(acquisition.evidenceDigest, digestOmitting(acquisition, 'evidenceDigest'));
    assert.equal(owner.acquisitionEvidenceDigest, acquisition.evidenceDigest);
    if (owner.ownerEpoch === 1) {
      assert(acquisition.kind === 'genesis');
      equalJson(acquisition, { ...common, kind: 'genesis', ownerTableObservation: 'empty',
        kernelGenerationIdentityRef: acquisition.kernelGenerationIdentityRef,
        kernelGenerationIdentityDigest: acquisition.kernelGenerationIdentityDigest });
    } else {
      const prior = owners[owner.ownerEpoch - 2]!; assert(prior.state === 'terminal');
      const reason = owner.ownerEpoch === 2 ? 'graceful_release' : 'superseded_after_owner_death';
      assert.equal(prior.terminalReason, reason);
      equalJson(acquisition, { ...common,
        kind: owner.ownerEpoch === 2 ? 'acquire_after_graceful_release' : 'takeover_after_owner_death',
        priorOwnerEpoch: prior.ownerEpoch, priorTerminalRowDigest: prior.rowDigest,
        priorTransitionEvidenceRef: prior.transitionEvidenceRef, priorTransitionEvidenceDigest: prior.transitionEvidenceDigest,
        priorTerminalReason: reason });
      assert.notEqual(owner.supervisorInstanceId, prior.supervisorInstanceId);
      assert.notEqual(owner.processIdentityRef, prior.processIdentityRef); assert.notEqual(owner.instanceNonceDigest, prior.instanceNonceDigest);
    }
    if (owner.state === 'terminal') {
      const transition = await readInstalledCasJson<StateOwnerTransitionEvidenceV1>(input, owner.transitionEvidenceRef);
      observed.transition = transition;
      parseCanonicalTime(transition.observedAt);
      assert.equal(transition.evidenceDigest, digestOmitting(transition, 'evidenceDigest'));
      assert.equal(owner.transitionEvidenceDigest, transition.evidenceDigest);
      const prior = { schemaVersion: 1, format: 'cliq-state-owner-transition-evidence-v1', priorOwnerEpoch: owner.ownerEpoch,
        priorSupervisorInstanceId: owner.supervisorInstanceId, priorProcessIdentityRef: owner.processIdentityRef,
        priorProcessIdentityDigest: owner.processIdentityDigest, stateLockIdentityRef: owner.stateLockIdentityRef,
        stateLockIdentityDigest: owner.stateLockIdentityDigest, observedAt: transition.observedAt, evidenceDigest: transition.evidenceDigest };
      if (owner.terminalReason === 'graceful_release') {
        equalJson(transition, { ...prior, kind: 'graceful_release', releasingProcessIdentityRef: owner.processIdentityRef,
          releasingProcessIdentityDigest: owner.processIdentityDigest });
      } else {
        const successor = owners[owner.ownerEpoch]; assert(successor);
        equalJson(transition, { ...prior, kind: 'superseded_after_owner_death', priorProcessObservation: 'absent_or_start_token_mismatch',
          successorOwnerEpoch: successor.ownerEpoch, successorSupervisorInstanceId: successor.supervisorInstanceId,
          successorRuntimeBundleRef: successor.runtimeBundleRef, successorRuntimeBundleManifestDigest: successor.runtimeBundleManifestDigest,
          successorProcessIdentityRef: successor.processIdentityRef, successorProcessIdentityDigest: successor.processIdentityDigest,
          successorInstanceNonceDigest: successor.instanceNonceDigest, observedAt: successor.acquiredAt });
      }
    }
  }
  const lock = await readInstalledCasJson<StateLockIdentityV1>(input, owners[0]!.stateLockIdentityRef); input.report.lock = lock;
  const root = await readInstalledCasJson<StateRootIdentityV1>(input, lock.stateRootIdentityRef); input.report.stateRoot = root;
  const lockInfo = await lstat(path.join(input.stateRoot, 'runtime/state-owner.lock'), { bigint: true });
  assert(lockInfo.isFile() && !lockInfo.isSymbolicLink()); assert.equal(lockInfo.nlink, 1n);
  assert.equal(lockInfo.uid, BigInt(input.uid)); assert.equal(lockInfo.mode & 0o7777n, 0o600n);
  equalJson(lock, { schemaVersion: 1, format: 'cliq-state-lock-identity-v1', stateRootIdentityRef: lock.stateRootIdentityRef,
    stateRootIdentityDigest: root.identityDigest, canonicalRootRelativePath: 'runtime/state-owner.lock',
    deviceId: lockInfo.dev.toString(), fileId: lockInfo.ino.toString(), ownerUid: input.uid, mode: 0o600, linkCount: 1,
    identityDigest: lock.identityDigest });
  assert.equal(lock.identityDigest, digestOmitting(lock, 'identityDigest')); assert.equal(owners[0]!.stateLockIdentityDigest, lock.identityDigest);
  const rootInfo = await lstat(input.stateRoot, { bigint: true }); assert(rootInfo.isDirectory() && !rootInfo.isSymbolicLink());
  equalJson(root, { schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: 'linux', canonicalAbsolutePath: input.stateRoot,
    ownerUid: input.uid, deviceId: rootInfo.dev.toString(), directoryFileId: rootInfo.ino.toString(), mode: 0o700,
    openedNoFollow: true, layoutVersion: 1, identityDigest: root.identityDigest });
  assert.equal(rootInfo.uid, BigInt(input.uid)); assert.equal(rootInfo.mode & 0o7777n, 0o700n);
  assert.equal(root.identityDigest, digestOmitting(root, 'identityDigest'));
  assert.deepEqual(inspectInstalledOwnerHistory(input.stateRoot), history);
  input.report.qualified = true;
  return history;
}
