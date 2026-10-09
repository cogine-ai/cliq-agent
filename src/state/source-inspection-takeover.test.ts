import assert from 'node:assert/strict';
import { fork, type ChildProcess } from 'node:child_process';
import { lstat, mkdir, mkdtemp, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import type { SourceInspectionAttemptV1, SourceInspectionRetirementEvidenceV1, SourceInspectionTargetV1 } from '../kernel/execution.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { PlatformProcessIdentityV1, StateOwnerAcquisitionEvidenceV1, WorkspaceIdentityV1 } from '../kernel/types.js';
import { testFixture } from '../model/testing/fixtures.js';
import { createWorkspaceTrustContext, writePersistedWorkspaceTrust } from '../session/trust.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { loadNativeStateOwner, type HeldStateOwnerLock } from './native-owner.js';
import { readSourceInspectionAttempt } from './source-inspection.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { openStateStore, publishInProcessChannel, type StateStoreRuntimeAuthority } from './store.js';
import { admissionKey, uuidv7 } from './testing/fixtures.js';
import { sourceInspectionRequest } from './testing/source-inspection-fixtures.js';
import { ownerAt } from './testing/state-owner-process.js';
import { signedToolBundle } from './testing/tool-authority.js';
import { fixtureSandboxProfile } from './testing/worker-launch.js';

const SOURCE_BYTES = 'actual source bytes at the Supervisor crash boundary\n';
type Reply = { state: string; mode?: string; pid?: number; token?: string; message?: string; code?: string; failedCloses?: number;
  row?: SourceInspectionAttemptV1; ownerEpoch?: number };
type FixtureChild = { child: ChildProcess; exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  request(command: Record<string, unknown>): Promise<Reply>; kill(): Promise<void> };

async function bounded<T>(operation: Promise<T>, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} did not finish within 20 seconds`)), 20_000);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}

async function childFor(children: FixtureChild[]): Promise<FixtureChild> {
  const child = fork(new URL('./testing/source-inspection-crash-child.ts', import.meta.url), [], {
    execArgv: ['--expose-gc', '--import', 'tsx'], serialization: 'advanced', stdio: ['ignore', 'ignore', 'pipe', 'ipc']
  });
  let diagnostic = '';
  child.stderr!.on('data', (chunk: Buffer) => { diagnostic = (diagnostic + chunk.toString()).slice(-4096); });
  child.on('error', () => {});
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  function reply(): Promise<Reply> {
    return new Promise((resolve, reject) => {
      const cleanup = () => { clearTimeout(timer); child.off('message', received); child.off('exit', lost); child.off('error', failed); };
      const received = (message: unknown) => { cleanup(); resolve(message as Reply); };
      const lost = () => { cleanup(); reject(new Error(`source child exited before its required reply: ${diagnostic}`)); };
      const failed = (error: Error) => { cleanup(); reject(error); };
      const timer = setTimeout(() => { cleanup(); reject(new Error(`source child reply timed out: ${diagnostic}`)); }, 20_000);
      child.once('message', received); child.once('exit', lost); child.once('error', failed);
    });
  }
  const fixture: FixtureChild = { child, exited,
    async request(command) {
      const received = reply();
      const sent = new Promise<void>((resolve, reject) => {
        try { child.send(command, error => error ? reject(error) : resolve()); }
        catch (error) { reject(error); }
      });
      const [, message] = await Promise.all([sent, received]); return message;
    },
    async kill() {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await bounded(exited, 'actual source child exit');
    }
  };
  children.push(fixture);
  assert.equal((await reply()).state, 'ready');
  return fixture;
}

test('a successor retains its real OS lock after an unjoined startup CAS close failure, even after strong GC', async t => {
  const f = await fixture(t), capture = await childFor(f.children);
  const paused = await capture.request({ mode: 'source-write', stateRoot: f.stateRoot, authority: f.authority,
    request: f.request, sourceBytes: SOURCE_BYTES });
  assert.equal(paused.state, 'paused', paused.message);
  const original = retained(f.stateRoot); assert.equal(original.phase, 'capturing');
  await capture.kill(); assert.equal((await capture.exited).signal, 'SIGKILL');
  await rename(f.workspace, `${f.workspace}-moved`); await rename(f.home, `${f.home}-moved`);
  const uncertain = await childFor(f.children);
  const failed = await uncertain.request({ mode: 'recovery-close-fault', stateRoot: f.stateRoot, authority: f.authority,
    request: f.request, sourceBytes: SOURCE_BYTES, targetRef: original.targetRef });
  assert.equal(failed.state, 'faulted', `required actual startup close fault was not observed: ${failed.code} ${failed.message}`);
  assert.ok(failed.failedCloses! > 0); assert.equal(failed.code, 'RECOVERY_REQUIRED');
  const owner = ownerAt(f.stateRoot); assert.equal(owner.ownerEpoch, original.stateOwnerEpoch + 1); assert.equal(owner.state, 'active');
  assert.deepEqual(retained(f.stateRoot), original, 'uncertain startup cannot retire the original capture');
  // A SQL alive-owner check could also refuse Store.open. Probe the actual OS
  // flock directly, and close an unexpectedly acquired fixture FD before RED.
  const native = await loadNativeStateOwner();
  let incorrectlyAcquired: HeldStateOwnerLock | undefined;
  try { incorrectlyAcquired = native.acquireLock(f.stateRoot, false); }
  catch (error) { assert.match(error instanceof Error ? error.message : String(error), /OS lock is already held/); }
  if (incorrectlyAcquired) {
    incorrectlyAcquired.close();
    assert.fail('failed startup released its actual OS lock while the uncertain owning process remains alive');
  }
  const competitor = await childFor(f.children);
  const blocked = await competitor.request({ mode: 'recover', stateRoot: f.stateRoot, authority: f.authority,
    request: f.request, sourceBytes: SOURCE_BYTES });
  assert.equal(blocked.state, 'error'); assert.match(blocked.message!, /OS lock is already held/);
  await competitor.kill(); await uncertain.kill(); assert.equal((await uncertain.exited).signal, 'SIGKILL');
  const successor = await childFor(f.children);
  const recovered = await successor.request({ mode: 'recover', stateRoot: f.stateRoot, authority: f.authority,
    request: f.request, sourceBytes: SOURCE_BYTES });
  assert.equal(recovered.state, 'replayed', recovered.message);
  assert.deepEqual(await bounded(successor.exited, 'post-fault successor exit'), { code: 0, signal: null });
  const row = retained(f.stateRoot); assert.equal(row.phase, 'retired');
  if (row.phase !== 'retired' || row.outcome.kind !== 'failed') assert.fail('post-death cleanup must retain a failed capture');
  assert.equal(row.inspectionId, original.inspectionId); assert.equal(row.stagingNonceDigest, original.stagingNonceDigest);
});

async function fixture(t: TestContext, gitMetadata = false) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'cliq-source-takeover-'));
  const stateRoot = path.join(directory, 'state'), home = path.join(directory, 'home'), workspace = path.join(directory, 'workspace');
  const children: FixtureChild[] = [];
  for (const member of [stateRoot, home, workspace]) await mkdir(member, { mode: 0o700 });
  const trust = await createWorkspaceTrustContext(workspace, home); await writePersistedWorkspaceTrust(trust, 'trusted');
  await writeFile(path.join(workspace, 'source'), SOURCE_BYTES);
  if (gitMetadata) {
    // Real descriptor-visible repository metadata exercises the currently
    // unsupported Git capture prefix. No Git program or qualification runs.
    await mkdir(path.join(workspace, '.git'), { mode: 0o700 });
    await writeFile(path.join(workspace, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n\tbare = false\n');
  }
  const signed = await signedToolBundle(testFixture().assembly, []);
  const profile = fixtureSandboxProfile(); profile.allowedOwners = ['source_inspection']; profile.profileDigest = digestOmitting(profile, 'profileDigest');
  const authority: StateStoreRuntimeAuthority = { bundle: signed.bundle, releaseKeys: signed.releaseKeys,
    sourceInspection: { controlledHome: home, sandboxProfile: profile } };
  const store = await openStateStore(stateRoot, authority);
  try {
    const identity = await publishInProcessChannel(store);
    const created = await store.createSession({ ...identity, requestId: uuidv7(), admissionKey: admissionKey('takeover-session'), workspacePath: workspace });
    const request = sourceInspectionRequest({ sessionId: created.session.id, workspacePath: workspace });
    t.after(async () => {
      await Promise.all(children.map(child => child.kill()));
      const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
      let pending: boolean;
      try { pending = !!driver.prepare("SELECT inspection_id FROM source_inspection_attempts WHERE phase != 'retired' LIMIT 1").get(); }
      finally { driver.close(); }
      if (pending) { t.diagnostic(`preserving unretired actual crash fixture: ${stateRoot}`); return; }
      await rm(directory, { recursive: true, force: true });
    });
    await store.close();
    return { directory, stateRoot, home, workspace, authority, request, children };
  } catch (error) { await store.close(); throw error; }
}

function retained(stateRoot: string) {
  const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const rows = driver.prepare(`SELECT principal_id, admission_key, admission_intent_digest FROM source_inspection_attempts`)
      .all<{ principal_id: string; admission_key: string; admission_intent_digest: string }>();
    assert.equal(rows.length, 1, 'one public capture owns exactly one real attempt');
    const row = rows[0]!;
    return readSourceInspectionAttempt(driver, { principalId: row.principal_id, admissionKey: row.admission_key,
      admissionIntentDigest: row.admission_intent_digest })!;
  } finally { driver.close(); }
}

for (const scenario of [
  { mode: 'source-write', gitMetadata: false, description: 'the reserved staging still present' },
  { mode: 'retirement-write', gitMetadata: false, description: 'staging removed before the retirement SQL commit' },
  { mode: 'retirement-write', gitMetadata: true, description: 'an unsupported Git target still in its no-process capturing prefix' }
] as const) {
  test(`successor retires actual interrupted source capture with ${scenario.description}`, async t => {
    const { mode } = scenario;
    const f = await fixture(t, scenario.gitMetadata), child = await childFor(f.children);
    const paused = await child.request({ mode, stateRoot: f.stateRoot, authority: f.authority,
      request: f.request, sourceBytes: SOURCE_BYTES });
    assert.equal(paused.state, 'paused', paused.message); assert.equal(paused.mode, mode);
    const before = retained(f.stateRoot), prior = ownerAt(f.stateRoot);
    assert.equal(before.phase, 'capturing'); assert.equal(before.stateOwnerEpoch, prior.ownerEpoch);
    assert.equal(before.supervisorInstanceId, prior.supervisorInstanceId);
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(f.stateRoot, KERNEL_CAS_DIRECTORY)));
    const process = await artifacts.readCanonical<PlatformProcessIdentityV1>(prior.processIdentityRef);
    assert.equal(process.pid, child.child.pid); assert.equal(process.pid, paused.pid); assert.equal(process.processStartToken, paused.token);
    if (scenario.gitMetadata) {
      const target = await artifacts.readCanonical<SourceInspectionTargetV1>(before.targetRef);
      const workspace = await artifacts.readCanonical<WorkspaceIdentityV1>(target.workspaceIdentityRef);
      if (workspace.kind !== 'live') assert.fail('the real Git metadata fixture must retain its live source identity');
      assert.match(workspace.repositoryIdentityRef ?? '', /^[0-9a-f]{64}$/);
      assert.equal(Object.hasOwn(before, 'inputRef'), false); assert.equal(Object.hasOwn(before, 'plan'), false);
      assert.equal(Object.hasOwn(before, 'processContainmentRef'), false);
    }
    const stagePath = path.join(f.stateRoot, 'runtime', 'source-inspections', identityHash(before.inspectionId, before.stagingNonceDigest));
    if (mode === 'source-write') {
      const stage = await lstat(stagePath, { bigint: true });
      assert.ok(stage.isDirectory()); assert.equal(String(stage.dev), before.stagingIdentity.deviceId);
      assert.equal(String(stage.ino), before.stagingIdentity.fileId); assert.equal(Number(stage.uid), before.stagingIdentity.ownerUid);
    } else await assert.rejects(lstat(stagePath), { code: 'ENOENT' });
    await child.kill(); assert.equal((await child.exited).signal, 'SIGKILL');
    // Retained cleanup/replay must not reopen either live source or Trust home.
    await rename(f.workspace, `${f.workspace}-moved`); await rename(f.home, `${f.home}-moved`);
    const successor = await childFor(f.children);
    const first = await successor.request({ mode: 'recover', stateRoot: f.stateRoot, authority: f.authority,
      request: f.request, sourceBytes: SOURCE_BYTES });
    assert.equal(first.state, 'replayed', `real successor failed: ${first.code} ${first.message}`);
    assert.deepEqual(await bounded(successor.exited, 'successor graceful exit'), { code: 0, signal: null });
    const after = retained(f.stateRoot);
    assert.equal(after.phase, 'retired');
    if (after.phase !== 'retired' || after.outcome.kind !== 'failed') assert.fail('an interrupted capture is a retained failure, never fabricated capture success');
    assert.equal(after.inspectionId, before.inspectionId); assert.equal(after.stagingNonceDigest, before.stagingNonceDigest);
    assert.deepEqual(after.stagingIdentity, before.stagingIdentity); assert.equal(after.stateOwnerEpoch, before.stateOwnerEpoch);
    assert.equal(after.supervisorInstanceId, before.supervisorInstanceId); assert.equal(after.deadlineAt, before.deadlineAt);
    await assert.rejects(lstat(stagePath), { code: 'ENOENT' });
    const evidence = await artifacts.readCanonical<SourceInspectionRetirementEvidenceV1>(after.retirementEvidenceRef);
    assert.equal(evidence.captureOwnerClosure.kind, 'owning_process_dead'); assert.deepEqual(evidence.processClosure, { kind: 'not_planned' });
    if (evidence.captureOwnerClosure.kind !== 'owning_process_dead') assert.fail('missing original owning process death');
    const acquisition = await artifacts.readCanonical<StateOwnerAcquisitionEvidenceV1>(evidence.captureOwnerClosure.stateOwnerAcquisitionEvidenceRef);
    assert.equal(acquisition.kind, 'takeover_after_owner_death');
    if (acquisition.kind !== 'takeover_after_owner_death') assert.fail('missing actual native takeover');
    assert.equal(acquisition.priorOwnerEpoch, before.stateOwnerEpoch);
    const driver = openSqliteDriver(path.join(f.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const original = readStateOwner(driver, before.stateOwnerEpoch)!;
      assert.equal(original.state, 'terminal');
      if (original.state !== 'terminal') assert.fail('original owner must be terminal');
      assert.equal(original.terminalReason, 'superseded_after_owner_death');
      assert.equal(acquisition.priorTerminalRowDigest, original.rowDigest);
    } finally { driver.close(); }
    const reopened = await childFor(f.children);
    const replay = await reopened.request({ mode: 'recover', stateRoot: f.stateRoot, authority: f.authority,
      request: f.request, sourceBytes: SOURCE_BYTES });
    assert.equal(replay.state, 'replayed', replay.message); assert.deepEqual(replay.row, after);
    assert.deepEqual(await bounded(reopened.exited, 'reopened successor graceful exit'), { code: 0, signal: null });
    assert.deepEqual(retained(f.stateRoot), after);
  });
}
