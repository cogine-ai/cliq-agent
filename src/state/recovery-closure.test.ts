import assert from 'node:assert/strict';
import { randomFillSync } from 'node:crypto';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { digestOmitting } from '../kernel/identity.js';
import type {
  FrozenIgnoreRulesV1,
  RunSpec,
  SourceManifest,
  SourceProjectionSpec,
  VerifierSpec,
  WorkspaceEntryManifest,
  WorkspaceIdentityV1,
  WorkspaceStateManifest
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

async function publishEmptySourceGraph(store: StateStore, workspaceIdentityDigest: string) {
  const rules: FrozenIgnoreRulesV1 = {
    schemaVersion: 1,
    format: 'cliq-frozen-ignore-rules-v1',
    matcherVersion: 'cliq-git-wildmatch-v1',
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
  entries.treeDigest = digestOmitting(entries, 'treeDigest');
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

async function admitQueuedRun(store: StateStore, workspace: string) {
  const principalId = 'cliq-test-principal';
  const channel = await publishInProcessChannel(store, principalId);
  const created = await store.createSession({
    principalId,
    requestId: uuidv7(),
    admissionKey: admissionKey('recovery-session'),
    workspacePath: workspace,
    ...channel
  });
  const workspaceIdentity = (await store.artifacts.readCanonical(
    created.session.workspaceIdentityRef
  )) as WorkspaceIdentityV1;
  const source = await publishEmptySourceGraph(store, workspaceIdentity.identityDigest);
  const admitted = await store.admitRun({
    principalId,
    requestId: uuidv7(),
    admissionKey: admissionKey('recovery-run'),
    sessionId: created.session.id,
    expectedContextRevision: 1,
    workspacePath: workspace,
    objective: 'recovery probe',
    allowUnverified: true,
    ...channel,
    ...source
  });
  return { admitted, principalId, channel, source };
}

test('readRecoveryClosure rejects delivery RunSpecs during M1 recovery', async () => {
  const stateRoot = await makePrivateDir('.cliq-recovery-delivery-');
  const workspace = await makePrivateDir('.cliq-recovery-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const { admitted, channel, source } = await admitQueuedRun(store, workspace);
    const agentSpec = (await store.artifacts.readCanonical(admitted.run.specRef)) as RunSpec;
    const deliverySpec: RunSpec = { ...agentSpec, operation: 'delivery' };
    const deliveryArtifact = await store.artifacts.publishCanonical(deliverySpec, 'cliq-run-spec-v1');
    const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      driver.prepare('UPDATE runs SET spec_ref = ? WHERE id = ?').run(deliveryArtifact.ref, admitted.run.id);
    } finally {
      driver.close();
    }
    await assert.rejects(
      () => store.readRecoveryClosure(admitted.run.id),
      (error: unknown) =>
        error instanceof KernelStorageError &&
        error.code === 'RECOVERY_REQUIRED' &&
        /only accepts agent RunSpecs/i.test(error.message)
    );
    assert.equal(admitted.run.specRef !== deliveryArtifact.ref, true);
    assert.equal(channel.channelIdentityRef.length > 0, true);
    assert.equal(source.baseWorkspaceManifestRef.length > 0, true);
  } finally {
    store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('readRecoveryClosure rejects post-checkpoint journal rows', async () => {
  const stateRoot = await makePrivateDir('.cliq-recovery-journal-');
  const workspace = await makePrivateDir('.cliq-recovery-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const { admitted } = await admitQueuedRun(store, workspace);
    const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      driver
        .prepare(
          `INSERT INTO run_journal (run_id, seq, op_id, op_kind, attempt, phase, entry_json)
           VALUES (?, 1, 'op-1', 'test', 1, 'committed', '{}')`
        )
        .run(admitted.run.id);
    } finally {
      driver.close();
    }
    await assert.rejects(
      () => store.readRecoveryClosure(admitted.run.id),
      (error: unknown) =>
        error instanceof KernelStorageError &&
        error.code === 'RECOVERY_REQUIRED' &&
        /post-checkpoint items or Journal rows/i.test(error.message)
    );
  } finally {
    store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});

test('readRecoveryClosure rejects workspace state not bound to the admitted RunSpec', async () => {
  const stateRoot = await makePrivateDir('.cliq-recovery-state-');
  const workspace = await makePrivateDir('.cliq-recovery-ws-');
  const store = await openStateStore(stateRoot);
  try {
    const { admitted, source } = await admitQueuedRun(store, workspace);
    const closure = await store.readRecoveryClosure(admitted.run.id);
    const workspaceState = (await store.artifacts.readCanonical(
      closure.latestCheckpoint.workspaceStateRef
    )) as WorkspaceStateManifest;
    const tampered: WorkspaceStateManifest = {
      ...workspaceState,
      baseWorkspaceManifestRef: source.assemblyRef,
      stateDigest: ''
    };
    tampered.stateDigest = digestOmitting(tampered, 'stateDigest');
    const tamperedArtifact = await store.artifacts.publishCanonical(tampered, 'cliq-workspace-state-v1');
    const driver = openSqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      driver
        .prepare('UPDATE checkpoints SET workspace_state_ref = ? WHERE id = ?')
        .run(tamperedArtifact.ref, closure.latestCheckpoint.id);
    } finally {
      driver.close();
    }
    await assert.rejects(
      () => store.readRecoveryClosure(admitted.run.id),
      (error: unknown) =>
        error instanceof KernelStorageError &&
        error.code === 'RECOVERY_REQUIRED' &&
        /not bound to the admitted RunSpec/i.test(error.message)
    );
  } finally {
    store.close();
    await rm(stateRoot, { recursive: true, force: true });
    await rm(workspace, { recursive: true, force: true });
  }
});
