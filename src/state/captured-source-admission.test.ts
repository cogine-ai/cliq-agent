import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { digestOmitting } from '../kernel/identity.js';
import type { VerifierSpec, WorkspaceEntryManifest, WorkspaceStateManifest } from '../kernel/types.js';
import { testFixture } from '../model/testing/fixtures.js';
import type { AdmitRunInput } from './reducers/admission.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel, type StateStore } from './store.js';
import { admissionKey, makePrivateDir, makeShortPrivateDir, uuidv7 } from './testing/fixtures.js';
import { signedToolBundle } from './testing/tool-authority.js';
import type { CapturedWorkspaceSourceTree, NonGitSourceCapturePolicy } from './workspace-source-tree.js';

const supported = process.platform === 'darwin' || process.platform === 'linux';
const policy: NonGitSourceCapturePolicy = { knownCredentialRoots: [], declaredEphemeralPaths: [],
  limits: { maxEntries: 100, maxBytes: 1024 * 1024 } };

async function fixture() {
  const authority = await signedToolBundle(testFixture().assembly, []);
  const stateRoot = await makeShortPrivateDir('cliq-source-admit-');
  const workspace = await makePrivateDir('.cliq-source-admit-ws-');
  let store = await openStateStore(stateRoot, authority);
  const principalId = 'captured-source-principal';
  const channel = await publishInProcessChannel(store, principalId);
  const { session } = await store.createSession({ principalId, requestId: uuidv7(),
    admissionKey: admissionKey('source-session'), workspacePath: workspace, name: 'source fixture', ...channel });
  // These are explicitly M2 reducer fixtures. They qualify no worker,
  // assembly, strong execution backend or release-ready public run.submit.
  const assembly = await store.artifacts.publishCanonical(
    { schemaVersion: 1, format: 'cliq-m2-assembly-placeholder-v1' }, 'cliq-run-assembly-v1');
  const runPolicy = await store.artifacts.publishCanonical(
    { schemaVersion: 1, format: 'cliq-m2-policy-placeholder-v1' }, 'cliq-run-policy-v1');
  const sandbox = await store.artifacts.publishCanonical(
    { schemaVersion: 1, format: 'cliq-m2-sandbox-placeholder-v1' }, 'cliq-sandbox-profile-v1');
  const verifier: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [], specDigest: '' };
  verifier.specDigest = digestOmitting(verifier, 'specDigest');
  const verifierArtifact = await store.artifacts.publishCanonical(verifier, 'cliq-verifier-spec-v1');
  const binding = { principalId, sessionId: session.id, expectedContextRevision: session.contextRevision,
    admissionKey: admissionKey('source-run') };
  const request = (capture: CapturedWorkspaceSourceTree): AdmitRunInput => ({ ...binding, ...channel,
    requestId: uuidv7(), workspacePath: workspace, objective: 'inspect captured source', allowUnverified: true,
    assemblyRef: assembly.ref, policyRef: runPolicy.ref, sandboxProfileRef: sandbox.ref,
    verifierSpecRef: verifierArtifact.ref, sourceProjectionRef: capture.sourceProjectionRef,
    frozenIgnoreRulesRef: capture.frozenIgnoreRulesRef, baseWorkspaceManifestRef: capture.baseWorkspaceManifestRef });
  return { stateRoot, workspace, binding, authority, request,
    get store() { return store; },
    capture: (selectedPolicy = policy) => store.captureNonGitRunSource({ ...binding, workspacePath: workspace,
      policy: selectedPolicy }),
    reopen: async () => { await store.close(); store = await openStateStore(stateRoot, authority); },
    close: async () => { await store.close(); await rm(stateRoot, { recursive: true, force: true });
      await rm(workspace, { recursive: true, force: true }); } };
}

function counts(stateRoot: string) {
  const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    return Object.fromEntries(['runs', 'checkpoints', 'run_events'].map((table) => [table,
      Number(driver.prepare(`SELECT count(*) AS count FROM ${table}`).get<{ count: unknown }>()!.count)]));
  } finally { driver.close(); }
}

test('signed StateStore admits a captured real tree and recovers its retained source after restart and drift',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await mkdir(path.join(f.workspace, 'src'));
      await writeFile(path.join(f.workspace, 'src', 'program.ts'), 'export const value = 1;\n');
      const capture = await f.capture();
      const input = f.request(capture);
      const admitted = await f.store.admitCapturedRun(input, capture);
      assert.deepEqual(counts(f.stateRoot), { runs: 1, checkpoints: 1, run_events: 1 });
      const closure = await f.store.readRecoveryClosure(admitted.run.id);
      const state = await f.store.artifacts.readCanonical<WorkspaceStateManifest>(closure.latestCheckpoint.workspaceStateRef);
      assert.equal(state.privateGitStateRef, undefined);
      assert.equal(state.baseWorkspaceManifestRef, capture.baseWorkspaceManifestRef);
      const entries = await f.store.artifacts.readCanonical<WorkspaceEntryManifest>(state.entriesRef);
      assert.deepEqual(entries, capture.entries);
      const file = entries.entries.find((entry) => entry.kind === 'file')!;
      assert.equal(file.kind, 'file');
      if (file.kind !== 'file') throw new Error('source fixture lost file');
      await rm(path.join(f.workspace, 'src'), { recursive: true });
      await writeFile(path.join(f.workspace, 'new-file'), 'new real workspace bytes');
      // Replay uses the first committed admission, with fresh channel auth;
      // it does not consult or recapture the changed workspace.
      const replay = await f.store.admitCapturedRun(input, capture);
      assert.equal(replay.replayed, true);
      assert.equal(replay.run.id, admitted.run.id);
      await f.reopen();
      const recovered = await f.store.readRecoveryClosure(admitted.run.id);
      assert.equal(recovered.latestCheckpoint.workspaceStateRef, closure.latestCheckpoint.workspaceStateRef);
      assert.equal((await f.store.artifacts.readBytes(file.blobRef)).toString(), 'export const value = 1;\n');
      const channel = await publishInProcessChannel(f.store, f.binding.principalId);
      const replayAfterRestart = await f.store.admitCapturedRun({ ...input, ...channel }, capture);
      assert.equal(replayAfterRestart.replayed, true);
      assert.deepEqual(counts(f.stateRoot), { runs: 1, checkpoints: 1, run_events: 1 });
      const newCapture = await f.capture();
      await assert.rejects(f.store.admitCapturedRun({ ...f.request(newCapture), ...channel,
        admissionKey: admissionKey('different-run') }, capture), /not bound/);
    } finally { await f.close(); }
  });

test('same-size ordinary-file mutation after response publication rolls back the entire admission transaction',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await writeFile(path.join(f.workspace, 'ordinary'), 'original');
      const source = await f.capture();
      const publish = f.store.artifacts.publishCanonical.bind(f.store.artifacts);
      let responses = 0;
      f.store.artifacts.publishCanonical = async (value, kind) => {
        const artifact = await publish(value, kind);
        if (kind === 'cliq-control-response-v1') {
          responses += 1;
          writeFileSync(path.join(f.workspace, 'ordinary'), 'changed!');
        }
        return artifact;
      };
      await assert.rejects(f.store.admitCapturedRun(f.request(source), source), { code: 'ARTIFACT_MISMATCH' });
      assert.equal(responses, 1);
      assert.deepEqual(counts(f.stateRoot), { runs: 0, checkpoints: 0, run_events: 0 });
    } finally { await f.close(); }
  });

test('a new default-selected path after capture cannot be silently omitted by Run admission',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      const source = await f.capture();
      const publish = f.store.artifacts.publishCanonical.bind(f.store.artifacts);
      f.store.artifacts.publishCanonical = async (value, kind) => {
        const artifact = await publish(value, kind);
        if (kind === 'cliq-control-response-v1') writeFileSync(path.join(f.workspace, 'new'), 'unselected earlier');
        return artifact;
      };
      await assert.rejects(f.store.admitCapturedRun(f.request(source), source), /path set changed/);
      assert.deepEqual(counts(f.stateRoot), { runs: 0, checkpoints: 0, run_events: 0 });
    } finally { await f.close(); }
  });

test('artifact-only or cross-admission capture objects do not authorize a new captured-source admission',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      const source = await f.capture();
      assert.throws(() => f.store.admitCapturedRun(f.request(source), undefined as unknown as CapturedWorkspaceSourceTree),
        /live source capture is required/);
      await assert.rejects(f.store.admitCapturedRun(f.request(source), structuredClone(source)), /not bound/);
      await assert.rejects(f.store.admitCapturedRun({ ...f.request(source),
        admissionKey: admissionKey('different-run') }, source), /not bound/);
      await assert.rejects(f.store.captureNonGitRunSource({ ...f.binding, principalId: 'other-principal',
        workspacePath: f.workspace, policy }), /caller or Session cursor differs/);
      await assert.rejects(f.store.captureNonGitRunSource({ ...f.binding, expectedContextRevision: 0,
        workspacePath: f.workspace, policy }), /caller or Session cursor differs/);
      assert.deepEqual(counts(f.stateRoot), { runs: 0, checkpoints: 0, run_events: 0 });
    } finally { await f.close(); }
  });

test('source capture snapshots caller policy and close drains it before releasing the signed StateOwner',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await writeFile(path.join(f.workspace, 'keep'), 'ordinary');
      const mutable = { ...policy, declaredEphemeralPaths: ['hidden'] };
      await writeFile(path.join(f.workspace, 'hidden'), 'not selected');
      const capturing = f.capture(mutable);
      mutable.declaredEphemeralPaths.length = 0;
      const closing = f.store.close();
      const source = await capturing;
      assert.deepEqual(source.entries.entries.map((entry) => entry.path), ['keep']);
      await closing;
      assert.throws(() => f.store.captureNonGitRunSource({ ...f.binding, workspacePath: f.workspace, policy }), /closing/);
      assert.throws(() => f.store.admitCapturedRun(f.request(source), source), /closing/);
    } finally { await f.close(); }
  });

test('unsigned StateStore cannot load a source publisher through an ambient helper',
  { skip: !supported }, async () => {
    const stateRoot = await makeShortPrivateDir('cliq-source-unsigned-');
    let store: StateStore | undefined;
    try {
      store = await openStateStore(stateRoot);
      assert.throws(() => store!.captureNonGitRunSource({ principalId: 'untrusted', sessionId: 'unused',
        expectedContextRevision: 1, admissionKey: admissionKey('unused'), workspacePath: stateRoot, policy }),
        /requires a signed StateOwner/);
    } finally { await store?.close(); await rm(stateRoot, { recursive: true, force: true }); }
  });

test('close drains a captured-source admission before releasing its owner and the committed Run survives restart',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      await writeFile(path.join(f.workspace, 'ordinary'), 'source bytes');
      const source = await f.capture();
      const submitting = f.store.admitCapturedRun(f.request(source), source);
      const closing = f.store.close();
      const admitted = await submitting;
      await closing;
      assert.deepEqual(counts(f.stateRoot), { runs: 1, checkpoints: 1, run_events: 1 });
      await f.reopen();
      const recovery = await f.store.readRecoveryClosure(admitted.run.id);
      assert.equal(recovery.runSpec.baseWorkspaceManifestRef, source.baseWorkspaceManifestRef);
    } finally { await f.close(); }
  });

test('captured-source admission freezes caller request bytes before asynchronous artifact reads',
  { skip: !supported }, async () => {
    const f = await fixture();
    try {
      const source = await f.capture();
      const input = f.request(source);
      const submitting = f.store.admitCapturedRun(input, source);
      input.baseWorkspaceManifestRef = '0'.repeat(64);
      input.sourceExcludes = [{ path: 'injected', scope: 'subtree' }];
      input.objective = 'changed after admission started';
      const admitted = await submitting;
      const closure = await f.store.readRecoveryClosure(admitted.run.id);
      assert.equal(closure.runSpec.baseWorkspaceManifestRef, source.baseWorkspaceManifestRef);
      assert.equal((await f.store.artifacts.readCanonical<{ utf8: string }>(closure.runSpec.objectiveRef)).utf8,
        'inspect captured source');
    } finally { await f.close(); }
  });
