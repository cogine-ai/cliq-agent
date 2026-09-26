import assert from 'node:assert/strict';
import { createHash, randomFillSync } from 'node:crypto';
import { chmod, mkdir, mkdtemp, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type {
  FrozenIgnoreRulesV1,
  GitIndexSnapshotV1,
  SourceManifest,
  SourceProjectionSpec,
  VerifierSpec,
  WorkspaceEntryManifest,
  WorkspaceIdentityV1
} from '../kernel/types.js';
import { KernelStorageError } from './errors.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { openStateStore, publishInProcessChannel, type StateStore } from './store.js';

function uuidv7(): string {
  const bytes = Buffer.alloc(16);
  const unixMs = Date.now();
  bytes.writeUInt32BE(Math.floor(unixMs / 0x1_0000), 0);
  bytes.writeUInt16BE(unixMs & 0xffff, 4);
  randomFillSync(bytes, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function admissionKey(label: string): string {
  return Buffer.from(label.padEnd(16, '0')).toString('base64url');
}

async function makePrivateDir(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(process.cwd(), prefix));
  await chmod(directory, 0o700);
  return directory;
}

function inspectKernel<T>(stateRoot: string, read: (driver: ReturnType<typeof openSqliteDriver>) => T): T {
  const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    return read(driver);
  } finally {
    driver.close();
  }
}

async function publishEmptySourceGraph(
  store: StateStore,
  workspaceIdentityDigest: string,
  options: {
    repositoryIdentityDigest?: string;
    file?: { bytes: Buffer; declaredSize: number };
  } = {}
) {
  const rules: FrozenIgnoreRulesV1 = {
    schemaVersion: 1,
    format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1',
    ...(options.repositoryIdentityDigest === undefined ? {} : {
      repositoryIdentityDigest: options.repositoryIdentityDigest
    }),
    sources: [],
    rules: [],
    rulesDigest: ''
  };
  rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
  const rulesArtifact = await store.artifacts.publishCanonical(rules, 'cliq-frozen-ignore-rules-v1');

  const projection: SourceProjectionSpec = {
    schemaVersion: 1,
    matcherVersion: 'cliq-exact-path-v1',
    frozenIgnoreRulesRef: rulesArtifact.ref,
    frozenIgnoreRulesDigest: rules.rulesDigest,
    explicitIncludes: [],
    explicitExcludes: [],
    maxChangedPaths: 10_000,
    maxChangedBytes: 512 * 1024 * 1024,
    projectionDigest: ''
  };
  projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
  const projectionArtifact = await store.artifacts.publishCanonical(projection, 'cliq-source-projection-v1');

  const entries: WorkspaceEntryManifest = {
    schemaVersion: 1,
    format: 'cliq-workspace-entries-v1',
    entries: [],
    entryCount: 0,
    byteCount: 0,
    treeDigest: ''
  };
  if (options.file !== undefined) {
    const blob = await store.artifacts.publishBytes(
      options.file.bytes, 'application/octet-stream', 'cliq-workspace-file-v1'
    );
    entries.entries = [{
      path: 'file.txt', kind: 'file', mode: 0o644,
      size: options.file.declaredSize, blobRef: blob.ref
    }];
    entries.entryCount = 1;
    entries.byteCount = options.file.declaredSize;
  }
  entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
  const entriesArtifact = await store.artifacts.publishCanonical(entries, 'cliq-workspace-entries-v1');

  const source: SourceManifest = {
    schemaVersion: 1,
    format: 'cliq-source-manifest-v1',
    role: 'base',
    workspaceIdentityDigest,
    entriesRef: entriesArtifact.ref,
    sourceProjectionRef: projectionArtifact.ref,
    sourceProjectionDigest: projection.projectionDigest,
    frozenIgnoreRulesRef: rulesArtifact.ref,
    frozenIgnoreRulesDigest: rules.rulesDigest,
    treeDigest: entries.treeDigest,
    manifestDigest: ''
  };
  if (options.repositoryIdentityDigest !== undefined) {
    const indexHeader = Buffer.alloc(12);
    indexHeader.write('DIRC', 0, 'ascii');
    indexHeader.writeUInt32BE(2, 4);
    const canonicalIndexBytes = Buffer.concat([
      indexHeader,
      createHash('sha1').update(indexHeader).digest()
    ]);
    const indexBytes = await store.artifacts.publishBytes(
      canonicalIndexBytes, 'application/octet-stream', 'cliq-git-index-canonical-v2'
    );
    const emptyTreeObjectId = createHash('sha1').update(Buffer.from('tree 0\0', 'utf8')).digest('hex');
    const indexSnapshot = {
      schemaVersion: 1 as const,
      format: 'cliq-git-index-snapshot-v1' as const,
      repositoryIdentityDigest: options.repositoryIdentityDigest,
      objectFormat: 'sha1' as const,
      canonicalIndexVersion: 2 as const,
      entries: [],
      canonicalIndexBytesRef: indexBytes.ref,
      canonicalIndexBytesDigest: indexBytes.ref,
      canonicalIndexByteCount: canonicalIndexBytes.byteLength,
      indexTreeObjectId: emptyTreeObjectId,
      snapshotDigest: ''
    };
    indexSnapshot.snapshotDigest = digestOmitting(indexSnapshot, 'snapshotDigest');
    const indexArtifact = await store.artifacts.publishCanonical(indexSnapshot, indexSnapshot.format);
    source.git = {
      repositoryIdentityDigest: options.repositoryIdentityDigest,
      head: { kind: 'unborn', branch: 'refs/heads/main' },
      indexRef: indexArtifact.ref,
      indexTreeObjectId: emptyTreeObjectId
    };
  }
  source.manifestDigest = digestOmitting(source, 'manifestDigest');
  const sourceArtifact = await store.artifacts.publishCanonical(source, 'cliq-source-manifest-v1');

  const verifier: VerifierSpec = {
    schemaVersion: 1,
    format: 'cliq-verifier-spec-v1',
    verifiers: [],
    specDigest: ''
  };
  verifier.specDigest = digestOmitting(verifier, 'specDigest');
  const verifierArtifact = await store.artifacts.publishCanonical(verifier, 'cliq-verifier-spec-v1');
  const assemblyArtifact = await store.artifacts.publishCanonical(
    { schemaVersion: 1, format: 'cliq-m1-assembly-placeholder-v1' },
    'cliq-run-assembly-v1'
  );
  const policyArtifact = await store.artifacts.publishCanonical(
    { schemaVersion: 1, format: 'cliq-m1-policy-placeholder-v1' },
    'cliq-run-policy-v1'
  );
  const sandboxArtifact = await store.artifacts.publishCanonical(
    { schemaVersion: 1, format: 'cliq-m1-sandbox-placeholder-v1' },
    'cliq-sandbox-profile-v1'
  );

  return {
    sourceProjectionRef: projectionArtifact.ref,
    frozenIgnoreRulesRef: rulesArtifact.ref,
    baseWorkspaceManifestRef: sourceArtifact.ref,
    verifierSpecRef: verifierArtifact.ref,
    assemblyRef: assemblyArtifact.ref,
    policyRef: policyArtifact.ref,
    sandboxProfileRef: sandboxArtifact.ref
  };
}

test('M1 store admits a queued Run with an initial Checkpoint and recovers it', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-store-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const created = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('session-one'),
      workspacePath: workspace,
      name: 'demo',
      ...channel
    });
    assert.equal(created.replayed, false);
    assert.equal(created.session.contextRevision, 1);
    assert.equal(created.session.latestItemSeq, 0);
    assert.equal(created.session.name, 'demo');

    const workspaceIdentity = (await store.artifacts.readCanonical(
      created.session.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    assert.equal(workspaceIdentity.kind, 'live');
    const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
    const admitted = await store.admitRun({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('run-one'),
      sessionId: created.session.id,
      expectedContextRevision: 1,
      workspacePath: workspace,
      objective: 'inspect the workspace',
      allowUnverified: true,
      ...channel,
      ...source
    });

    assert.equal(admitted.replayed, false);
    assert.equal(admitted.run.status, 'queued');
    assert.equal(admitted.run.revision, 1);
    assert.equal(admitted.run.leaseEpoch, 0);
    assert.equal(admitted.run.nextStep, 'agent');
    assert.equal(admitted.run.activeWorkerLaunchId, undefined);
    assert.ok(admitted.run.latestCheckpointId.length > 0);

    const closure = await store.readRecoveryClosure(admitted.run.id);
    assert.equal(closure.runSpec.operation, 'agent');
    assert.equal(closure.runSpec.schemaVersion, 1);
    assert.equal(closure.latestCheckpoint.reason, 'initial');
    assert.equal(closure.latestCheckpoint.basedOnRunRevision, 0);
    assert.equal(closure.latestCheckpoint.runItemSeq, 0);
    assert.equal(closure.latestCheckpoint.journalSeq, 0);
    assert.equal(closure.latestCheckpoint.workspaceStateRef !== closure.runSpec.baseWorkspaceManifestRef, true);
    assert.deepEqual(closure.items, []);
    assert.deepEqual(closure.journal, []);
    assert.deepEqual(closure.workerLaunches, []);
    assert.deepEqual(closure.workspaceGenerations, []);
    assert.deepEqual(closure.childAllocations, []);
    assert.equal(store.getRun(admitted.run.id).revision, 1);
    assert.equal(store.getSession(created.session.id).id, created.session.id);
    inspectKernel(stateRoot, (driver) => {
      const event = driver
        .prepare('SELECT event_seq FROM run_events WHERE run_id = ?')
        .get<{ event_seq: unknown }>(admitted.run.id);
      assert.equal(Number(event?.event_seq), 1);
      assert.equal(
        Number(driver.prepare('SELECT count(*) AS count FROM run_events WHERE run_id = ?').get<{ count: unknown }>(admitted.run.id)?.count),
        1
      );
    });
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('Run admission checks source file bytes before committing its response', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-file-state-');
  const workspace = await makePrivateDir('.cliq-m1-file-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const created = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('session-file-size'),
      workspacePath: workspace,
      ...channel
    });
    const workspaceIdentity = (await store.artifacts.readCanonical(
      created.session.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    const requestId = uuidv7();
    const runKey = admissionKey('run-file-size');
    const request = {
      principalId, requestId, admissionKey: runKey,
      sessionId: created.session.id, expectedContextRevision: 1,
      workspacePath: workspace, objective: 'read file bytes', allowUnverified: true,
      ...channel
    };
    const badSource = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest, {
      file: { bytes: Buffer.from('abc'), declaredSize: 2 }
    });
    await assert.rejects(
      () => store.admitRun({ ...request, ...badSource }),
      (error: unknown) => error instanceof KernelStorageError &&
        error.code === 'ARTIFACT_MISMATCH' && /size does not match/.test(error.message)
    );
    inspectKernel(stateRoot, (driver) => {
      assert.equal(Number(driver.prepare('SELECT count(*) AS count FROM runs')
        .get<{ count: unknown }>()?.count), 0);
    });
    const goodSource = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest, {
      file: { bytes: Buffer.from('abc'), declaredSize: 3 }
    });
    const mismatchedTree = await store.artifacts.readCanonical<SourceManifest>(goodSource.baseWorkspaceManifestRef);
    mismatchedTree.treeDigest = '0'.repeat(64);
    mismatchedTree.manifestDigest = digestOmitting(mismatchedTree, 'manifestDigest');
    const mismatchedManifest = await store.artifacts.publishCanonical(mismatchedTree, mismatchedTree.format);
    await assert.rejects(
      () => store.admitRun({ ...request, ...goodSource, baseWorkspaceManifestRef: mismatchedManifest.ref }),
      (error: unknown) => error instanceof KernelStorageError &&
        error.code === 'ARTIFACT_MISMATCH' && /entries do not match its tree digest/.test(error.message)
    );
    inspectKernel(stateRoot, (driver) => {
      assert.equal(Number(driver.prepare('SELECT count(*) AS count FROM runs')
        .get<{ count: unknown }>()?.count), 0);
    });
    const admitted = await store.admitRun({ ...request, ...goodSource });
    assert.equal(admitted.run.status, 'queued');
    assert.equal((await store.readRecoveryClosure(admitted.run.id)).run.id, admitted.run.id);
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('admission-key replay returns the original Session and Run without a second row', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-replay-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const key = admissionKey('session-replay');
    const first = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: key,
      workspacePath: workspace,
      ...channel
    });
    const second = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: key,
      workspacePath: workspace,
      ...channel
    });
    assert.equal(second.replayed, true);
    assert.equal(second.session.id, first.session.id);

    const workspaceIdentity = (await store.artifacts.readCanonical(
      first.session.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
    const runKey = admissionKey('run-replay');
    const admitted = await store.admitRun({
      principalId,
      requestId: uuidv7(),
      admissionKey: runKey,
      sessionId: first.session.id,
      expectedContextRevision: 1,
      workspacePath: workspace,
      objective: 'do the work',
      allowUnverified: true,
      ...channel,
      ...source
    });
    const replayed = await store.admitRun({
      principalId,
      requestId: uuidv7(),
      admissionKey: runKey,
      sessionId: first.session.id,
      expectedContextRevision: 1,
      workspacePath: workspace,
      objective: 'do the work',
      allowUnverified: true,
      ...channel,
      ...source
    });
    assert.equal(replayed.replayed, true);
    assert.equal(replayed.run.id, admitted.run.id);
    assert.equal(replayed.run.latestCheckpointId, admitted.run.latestCheckpointId);
    inspectKernel(stateRoot, (driver) => {
      assert.equal(
        Number(driver.prepare('SELECT count(*) AS count FROM sessions').get<{ count: unknown }>()?.count),
        1
      );
      assert.equal(Number(driver.prepare('SELECT count(*) AS count FROM runs').get<{ count: unknown }>()?.count), 1);
    });
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('same admission key with a different intent is ADMISSION_KEY_CONFLICT', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-conflict-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const key = admissionKey('session-conflict');
    await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: key,
      workspacePath: workspace,
      name: 'one',
      ...channel
    });
    await assert.rejects(
      () =>
        store.createSession({
          principalId,
          requestId: uuidv7(),
          admissionKey: key,
          workspacePath: workspace,
          name: 'two',
          ...channel
        }),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'ADMISSION_KEY_CONFLICT'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('reused requestId with different bytes is REQUEST_ID_CONFLICT', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-reqid-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const requestId = uuidv7();
    await store.createSession({
      principalId,
      requestId,
      admissionKey: admissionKey('session-a'),
      workspacePath: workspace,
      ...channel
    });
    await assert.rejects(
      () =>
        store.createSession({
          principalId,
          requestId,
          admissionKey: admissionKey('session-b'),
          workspacePath: workspace,
          ...channel
        }),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'REQUEST_ID_CONFLICT'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('replacing the workspace root after Session create is ARTIFACT_MISMATCH', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-moved-');
  const parent = await makePrivateDir('.cliq-m1-parent-');
  const workspace = path.join(parent, 'workspace');
  await mkdir(workspace, { mode: 0o700 });
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const created = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('session-moved'),
      workspacePath: workspace,
      ...channel
    });
    // Linux ext4 often reuses the same inode after rm+mkdir at this path.
    // Swap in a precreated directory so the captured root identity must change.
    const replacement = path.join(parent, 'workspace-new');
    await mkdir(replacement, { mode: 0o700 });
    await rm(workspace, { recursive: true, force: true });
    await rename(replacement, workspace);
    const workspaceIdentity = (await store.artifacts.readCanonical(
      created.session.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
    await assert.rejects(
      () =>
        store.admitRun({
          principalId,
          requestId: uuidv7(),
          admissionKey: admissionKey('run-moved'),
          sessionId: created.session.id,
          expectedContextRevision: 1,
          workspacePath: workspace,
          objective: 'should fail',
          allowUnverified: true,
          ...channel,
          ...source
        }),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(parent, { recursive: true, force: true });
  }
});

test('Session commit rechecks the held workspace root after asynchronous artifact publication', async (t) => {
  const stateRoot = await makePrivateDir('.cliq-m1-session-swap-');
  const parent = await makePrivateDir('.cliq-m1-session-swap-parent-');
  const workspace = path.join(parent, 'workspace');
  const replacement = path.join(parent, 'replacement');
  const original = path.join(parent, 'original');
  await mkdir(workspace, { mode: 0o700 });
  await mkdir(replacement, { mode: 0o700 });
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const input = { principalId, requestId: uuidv7(), admissionKey: admissionKey('session-swap'),
      workspacePath: workspace, ...channel };
    const publish = store.artifacts.publishCanonical.bind(store.artifacts);
    const injected = t.mock.method(store.artifacts, 'publishCanonical', async (value: unknown, kind: string) => {
      const artifact = await publish(value, kind);
      if (kind === 'cliq-control-response-v1') {
        await rename(workspace, original);
        await rename(replacement, workspace);
      }
      return artifact;
    });
    await assert.rejects(store.createSession(input),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    injected.mock.restore();
    inspectKernel(stateRoot, (driver) => {
      assert.equal(Number(driver.prepare('SELECT count(*) AS count FROM sessions').get<{ count: unknown }>()?.count), 0);
      assert.equal(Number(driver.prepare('SELECT count(*) AS count FROM control_requests').get<{ count: unknown }>()?.count), 0);
    });
    await rename(workspace, replacement);
    await rename(original, workspace);
    assert.equal((await store.createSession(input)).replayed, false);
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(parent, { recursive: true, force: true });
  }
});

test('Run admission rechecks the held workspace root inside its final SQLite transaction', async (t) => {
  const stateRoot = await makePrivateDir('.cliq-m1-run-swap-');
  const parent = await makePrivateDir('.cliq-m1-run-swap-parent-');
  const workspace = path.join(parent, 'workspace');
  const replacement = path.join(parent, 'replacement');
  const original = path.join(parent, 'original');
  await mkdir(workspace, { mode: 0o700 });
  await mkdir(replacement, { mode: 0o700 });
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const session = await store.createSession({ principalId, requestId: uuidv7(),
      admissionKey: admissionKey('session-run-swap'), workspacePath: workspace, ...channel });
    const identity = await store.artifacts.readCanonical<WorkspaceIdentityV1>(session.session.workspaceIdentityRef);
    const source = await publishEmptySourceGraph(store, identity.identityDigest);
    const input = { principalId, requestId: uuidv7(), admissionKey: admissionKey('run-swap'),
      sessionId: session.session.id, expectedContextRevision: 1, workspacePath: workspace,
      objective: 'prove commit identity', allowUnverified: true, ...channel, ...source };
    const publish = store.artifacts.publishCanonical.bind(store.artifacts);
    const injected = t.mock.method(store.artifacts, 'publishCanonical', async (value: unknown, kind: string) => {
      const artifact = await publish(value, kind);
      if (kind === 'cliq-control-response-v1') {
        await rename(workspace, original);
        await rename(replacement, workspace);
      }
      return artifact;
    });
    await assert.rejects(store.admitRun(input),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'ARTIFACT_MISMATCH');
    injected.mock.restore();
    inspectKernel(stateRoot, (driver) => {
      assert.equal(Number(driver.prepare('SELECT count(*) AS count FROM runs').get<{ count: unknown }>()?.count), 0);
      assert.equal(Number(driver.prepare('SELECT count(*) AS count FROM checkpoints').get<{ count: unknown }>()?.count), 0);
    });
    await rename(workspace, replacement);
    await rename(original, workspace);
    assert.equal((await store.admitRun(input)).replayed, false);
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(parent, { recursive: true, force: true });
  }
});

test('session.create rejects a symlinked workspace root', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-symlink-');
  const realWorkspace = await makePrivateDir('.cliq-m1-ws-');
  const parent = await makePrivateDir('.cliq-m1-link-parent-');
  const linked = path.join(parent, 'linked');
  await symlink(realWorkspace, linked);
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    await assert.rejects(
      () =>
        store.createSession({
          principalId,
          requestId: uuidv7(),
          admissionKey: admissionKey('session-link'),
          workspacePath: linked,
          ...channel
        }),
      (error: unknown) =>
        error instanceof KernelStorageError &&
        (error.code === 'ARTIFACT_MISMATCH' || error.code === 'INVALID_REQUEST')
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(realWorkspace, { recursive: true, force: true });
    await rm(parent, { recursive: true, force: true });
  }
});

test('Git workspaces bind their repository and canonical index through admission and recovery', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-git-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  await mkdir(path.join(workspace, '.git'), { mode: 0o700 });
  await writeFile(path.join(workspace, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n', {
    mode: 0o600
  });
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const created = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('session-git'),
      workspacePath: workspace,
      ...channel
    });
    const workspaceIdentity = (await store.artifacts.readCanonical(
      created.session.workspaceIdentityRef
    )) as Extract<WorkspaceIdentityV1, { kind: 'live' }>;
    assert.equal(workspaceIdentity.kind, 'live');
    assert.equal(typeof workspaceIdentity.repositoryIdentityRef, 'string');
    assert.equal(typeof workspaceIdentity.repositoryIdentityDigest, 'string');
    const source = await publishEmptySourceGraph(
      store, workspaceIdentity.identityDigest,
      { repositoryIdentityDigest: workspaceIdentity.repositoryIdentityDigest }
    );
    const admitted = await store.admitRun({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('run-git'),
      sessionId: created.session.id,
      expectedContextRevision: 1,
      workspacePath: workspace,
      objective: 'inspect the empty Git workspace',
      allowUnverified: true,
      ...channel,
      ...source
    });
    assert.equal(admitted.run.status, 'queued');
    assert.equal((await store.readRecoveryClosure(admitted.run.id)).run.id, admitted.run.id);

    const sourceManifest = await store.artifacts.readCanonical<SourceManifest>(source.baseWorkspaceManifestRef);
    const index = await store.artifacts.readCanonical<GitIndexSnapshotV1>(sourceManifest.git!.indexRef);
    const wrongIndex: GitIndexSnapshotV1 = {
      ...index, indexTreeObjectId: '0'.repeat(40), snapshotDigest: ''
    };
    wrongIndex.snapshotDigest = digestOmitting(wrongIndex, 'snapshotDigest');
    const wrongIndexRef = (await store.artifacts.publishCanonical(wrongIndex, wrongIndex.format)).ref;
    const wrongSource: SourceManifest = {
      ...sourceManifest, git: { ...sourceManifest.git!, indexRef: wrongIndexRef }, manifestDigest: ''
    };
    wrongSource.manifestDigest = digestOmitting(wrongSource, 'manifestDigest');
    const wrongSourceRef = (await store.artifacts.publishCanonical(wrongSource, wrongSource.format)).ref;
    await assert.rejects(() => store.admitRun({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('run-git-bad-index'),
      sessionId: created.session.id,
      expectedContextRevision: 1,
      workspacePath: workspace,
      objective: 'inspect the empty Git workspace',
      allowUnverified: true,
      ...channel,
      ...source,
      baseWorkspaceManifestRef: wrongSourceRef
    }), /Git index tree does not match/);
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('concurrent same-key Session and Run admission returns the committed row', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-race-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const sessionKey = admissionKey('session-race');
    const [firstSession, secondSession] = await Promise.all([
      store.createSession({
        principalId,
        requestId: uuidv7(),
        admissionKey: sessionKey,
        workspacePath: workspace,
        ...channel
      }),
      store.createSession({
        principalId,
        requestId: uuidv7(),
        admissionKey: sessionKey,
        workspacePath: workspace,
        ...channel
      })
    ]);
    assert.equal(firstSession.session.id, secondSession.session.id);
    assert.equal([firstSession.replayed, secondSession.replayed].filter(Boolean).length, 1);
    const storedSession = store.getSession(firstSession.session.id);
    assert.equal(firstSession.session.createdAt, storedSession.createdAt);
    assert.equal(secondSession.session.createdAt, storedSession.createdAt);
    assert.equal(firstSession.session.contextProjectionRef, storedSession.contextProjectionRef);
    assert.equal(secondSession.session.contextProjectionRef, storedSession.contextProjectionRef);

    const workspaceIdentity = (await store.artifacts.readCanonical(
      storedSession.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
    const runKey = admissionKey('run-race');
    const [firstRun, secondRun] = await Promise.all([
      store.admitRun({
        principalId,
        requestId: uuidv7(),
        admissionKey: runKey,
        sessionId: storedSession.id,
        expectedContextRevision: 1,
        workspacePath: workspace,
        objective: 'race the admission',
        allowUnverified: true,
        ...channel,
        ...source
      }),
      store.admitRun({
        principalId,
        requestId: uuidv7(),
        admissionKey: runKey,
        sessionId: storedSession.id,
        expectedContextRevision: 1,
        workspacePath: workspace,
        objective: 'race the admission',
        allowUnverified: true,
        ...channel,
        ...source
      })
    ]);
    assert.equal(firstRun.run.id, secondRun.run.id);
    assert.equal([firstRun.replayed, secondRun.replayed].filter(Boolean).length, 1);
    const storedRun = store.getRun(firstRun.run.id);
    assert.equal(firstRun.run.createdAt, storedRun.createdAt);
    assert.equal(secondRun.run.createdAt, storedRun.createdAt);
    assert.equal(firstRun.run.latestCheckpointId, storedRun.latestCheckpointId);
    assert.equal(secondRun.run.latestCheckpointId, storedRun.latestCheckpointId);
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('concurrent different-key Sessions do not mark the time fence clock_regressed', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-keys-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const [left, right] = await Promise.all([
      store.createSession({
        principalId,
        requestId: uuidv7(),
        admissionKey: admissionKey('session-left'),
        workspacePath: workspace,
        ...channel
      }),
      store.createSession({
        principalId,
        requestId: uuidv7(),
        admissionKey: admissionKey('session-right'),
        workspacePath: workspace,
        ...channel
      })
    ]);
    assert.equal(left.replayed, false);
    assert.equal(right.replayed, false);
    assert.notEqual(left.session.id, right.session.id);
    const third = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('session-third'),
      workspacePath: workspace,
      ...channel
    });
    assert.equal(third.replayed, false);
    inspectKernel(stateRoot, (driver) => {
      const fence = driver
        .prepare('SELECT state FROM canonical_time_fence WHERE id = 1')
        .get<{ state: string }>();
      assert.equal(fence?.state, 'healthy');
      assert.equal(Number(driver.prepare('SELECT count(*) AS count FROM sessions').get<{ count: unknown }>()?.count), 3);
    });
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('admitRun rejects a Session owned by another principal', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-owner-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const owner = await publishInProcessChannel(store, 'principal-owner');
    const stranger = await publishInProcessChannel(store, 'principal-stranger');
    const created = await store.createSession({
      principalId: 'principal-owner',
      requestId: uuidv7(),
      admissionKey: admissionKey('session-owner'),
      workspacePath: workspace,
      ...owner
    });
    const workspaceIdentity = (await store.artifacts.readCanonical(
      created.session.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
    await assert.rejects(
      () =>
        store.admitRun({
          principalId: 'principal-stranger',
          requestId: uuidv7(),
          admissionKey: admissionKey('run-stranger'),
          sessionId: created.session.id,
          expectedContextRevision: 1,
          workspacePath: workspace,
          objective: 'should not attach',
          allowUnverified: true,
          ...stranger,
          ...source
        }),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('reopening the store recovers the admitted Run from SQLite and CAS', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-reopen-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const first = await openStateStore(stateRoot);
  let runId = '';
  let sessionId = '';
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(first, principalId);
    const created = await first.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('session-reopen'),
      workspacePath: workspace,
      ...channel
    });
    const workspaceIdentity = (await first.artifacts.readCanonical(
      created.session.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    const source = await publishEmptySourceGraph(first, workspaceIdentity.identityDigest);
    const admitted = await first.admitRun({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('run-reopen'),
      sessionId: created.session.id,
      expectedContextRevision: 1,
      workspacePath: workspace,
      objective: 'survive reopen',
      allowUnverified: true,
      ...channel,
      ...source
    });
    runId = admitted.run.id;
    sessionId = created.session.id;
  } finally {
    await first.close();
  }

  const second = await openStateStore(stateRoot);
  try {
    const session = second.getSession(sessionId);
    const run = second.getRun(runId);
    const closure = await second.readRecoveryClosure(runId);
    assert.equal(session.id, sessionId);
    assert.equal(run.status, 'queued');
    assert.equal(closure.run.id, runId);
    assert.equal(closure.latestCheckpoint.reason, 'initial');
    assert.equal(closure.runSpec.operation, 'agent');
    assert.equal(second.ownerEpoch, 2);
    inspectKernel(stateRoot, (driver) => {
      const owners = driver
        .prepare(`SELECT owner_epoch, state FROM state_owners ORDER BY owner_epoch`)
        .all<{ owner_epoch: unknown; state: string }>();
      assert.equal(owners.length, 2);
      assert.equal(Number(owners[0]?.owner_epoch), 1);
      assert.equal(owners[0]?.state, 'terminal');
      assert.equal(Number(owners[1]?.owner_epoch), 2);
      assert.equal(owners[1]?.state, 'active');
    });
  } finally {
    await second.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('same admission key with different budgets is ADMISSION_KEY_CONFLICT', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-budget-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const created = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('session-budget'),
      workspacePath: workspace,
      ...channel
    });
    const workspaceIdentity = (await store.artifacts.readCanonical(
      created.session.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
    const key = admissionKey('run-budget');
    await store.admitRun({
      principalId,
      requestId: uuidv7(),
      admissionKey: key,
      sessionId: created.session.id,
      expectedContextRevision: 1,
      workspacePath: workspace,
      objective: 'budgeted work',
      allowUnverified: true,
      budgets: { wallTimeMs: 3_600_000 },
      ...channel,
      ...source
    });
    await assert.rejects(
      () =>
        store.admitRun({
          principalId,
          requestId: uuidv7(),
          admissionKey: key,
          sessionId: created.session.id,
          expectedContextRevision: 1,
          workspacePath: workspace,
          objective: 'budgeted work',
          allowUnverified: true,
          budgets: { wallTimeMs: 7_200_000 },
          ...channel,
          ...source
        }),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'ADMISSION_KEY_CONFLICT'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('session.create rejects a symlinked .git/config', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-gitcfg-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const outside = await makePrivateDir('.cliq-m1-gitcfg-target-');
  await mkdir(path.join(workspace, '.git'), { mode: 0o700 });
  await writeFile(path.join(outside, 'config'), '[core]\n\trepositoryformatversion = 0\n', { mode: 0o600 });
  await symlink(path.join(outside, 'config'), path.join(workspace, '.git', 'config'));
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    await assert.rejects(
      () =>
        store.createSession({
          principalId,
          requestId: uuidv7(),
          admissionKey: admissionKey('session-gitcfg'),
          workspacePath: workspace,
          ...channel
        }),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('an empty required verifier set without allowUnverified is INVALID_REQUEST', async () => {
  const stateRoot = await makePrivateDir('.cliq-m1-consent-');
  const workspace = await makePrivateDir('.cliq-m1-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const principalId = 'cliq-test-principal';
    const channel = await publishInProcessChannel(store, principalId);
    const created = await store.createSession({
      principalId,
      requestId: uuidv7(),
      admissionKey: admissionKey('session-consent'),
      workspacePath: workspace,
      ...channel
    });
    const workspaceIdentity = (await store.artifacts.readCanonical(
      created.session.workspaceIdentityRef
    )) as WorkspaceIdentityV1;
    const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
    await assert.rejects(
      () =>
        store.admitRun({
          principalId,
          requestId: uuidv7(),
          admissionKey: admissionKey('run-no-consent'),
          sessionId: created.session.id,
          expectedContextRevision: 1,
          workspacePath: workspace,
          objective: 'needs consent',
          allowUnverified: false,
          ...channel,
          ...source
        }),
      (error: unknown) => error instanceof KernelStorageError && error.code === 'INVALID_REQUEST'
    );
  } finally {
    await store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});
