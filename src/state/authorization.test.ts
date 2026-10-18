import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting, identityHash } from '../kernel/identity.js';
import type { RunAssemblyV1, RunSpec, VerifierSpec } from '../kernel/types.js';
import type { VerifierRequest } from '../kernel/control-submit.js';
import { testFixture } from '../model/testing/fixtures.js';
import { BUILTIN_POLICY_RULES, modeDecisions } from '../policy/tool-policy.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { SandboxProfileV1 } from '../kernel/execution.js';
import { openStateStore } from './store.js';
import { admissionKey } from './testing/fixtures.js';
import { openSqliteDriver } from './sqlite-driver.js';
import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import path from 'node:path';
import { open, rename, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { isJoinedCasPublicationFailure } from './cas.js';
import { createQueuedFixture, disposeFixture, uuidv7 } from './testing/fixtures.js';
import { publishInProcessChannel } from './store.js';
import { signedVerifierAuthority } from './testing/verifier-authority.js';

test('verifier identity authorization is retained, replayable, and explicitly revocable without executing a Run', async () => {
  const signed = await signedVerifierAuthority();
  const fixture = await createQueuedFixture('verifier-identity-retained', { runtimeAuthority: { bundle: signed.bundle, releaseKeys: signed.releaseKeys }, assembly: async store => {
    for (const object of signed.objects) await store.artifacts.publishBytes(object.bytes, 'application/octet-stream', 'offline-verifier-object');
    const { assembly } = await import('../model/testing/fixtures.js').then(module => module.testFixture());
    return (await store.artifacts.publishCanonical(assembly, assembly.format)).ref;
  } });
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(),
      decision: { kind: 'execution_identity_read', purpose: 'verifier',
        target: { kind: 'guest_toolchain', guestToolchainManifestId: signed.manifestId, toolId: 'node' } } };
    const request = { ...core, requestDigest: canonicalSha256(core) };
    const created = await fixture.store.createAuthorization(request, identity);
    assert.equal(created.replayed, false);
    assert.equal(created.response.result.method, 'authorization.create');
    assert.equal(created.response.result.grant.state, 'active');
    assert.equal(created.response.result.grant.useCount, 0);
    assert.equal(created.response.result.grant.rowVersion, 1);
    assert.deepEqual((await fixture.store.createAuthorization(request, identity)).response, created.response);
    const corrupt = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const saved = corrupt.prepare('SELECT row_json FROM authorization_grants WHERE grant_id = ?').get<{ row_json: string }>(created.response.result.grant.grantId)!;
      const altered = { ...JSON.parse(saved.row_json), unrecognizedAuthority: true, rowDigest: '' };
      altered.rowDigest = digestOmitting(altered, 'rowDigest');
      corrupt.prepare('UPDATE authorization_grants SET row_json = ? WHERE grant_id = ?').run(JSON.stringify(altered), created.response.result.grant.grantId);
      try { await assert.rejects(fixture.store.createAuthorization(request, identity), { code: 'RECOVERY_REQUIRED' }); }
      finally { corrupt.prepare('UPDATE authorization_grants SET row_json = ? WHERE grant_id = ?').run(saved.row_json, created.response.result.grant.grantId); }
    } finally { corrupt.close(); }
    const conflictCore = { ...core, ttlMs: 1000 };
    await assert.rejects(fixture.store.createAuthorization({ ...conflictCore, requestDigest: canonicalSha256(conflictCore) }, identity),
      { code: 'REQUEST_ID_CONFLICT' });
    let accessorRead = false;
    const accessor = { ...request };
    Object.defineProperty(accessor, 'decision', { enumerable: true, get() { accessorRead = true; return request.decision; } });
    await assert.rejects(fixture.store.createAuthorization(accessor, identity), { code: 'INVALID_REQUEST' });
    assert.equal(accessorRead, false, 'untrusted accessors are rejected before snapshot/hash traversal');
    const revokeCore = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId: created.response.result.grant.grantId };
    const revoke = { ...revokeCore, requestDigest: canonicalSha256(revokeCore) };
    const [revoked, concurrentRevoke] = await Promise.all([fixture.store.revokeAuthorization(revoke, identity), fixture.store.revokeAuthorization(revoke, identity)]);
    assert.deepEqual(concurrentRevoke.response, revoked.response);
    assert.equal(revoked.response.result.method, 'authorization.revoke');
    if (revoked.response.result.method !== 'authorization.revoke') assert.fail('revoke result');
    assert.equal(revoked.response.result.disposition, 'revoked');
    assert.equal(revoked.response.result.grant.state, 'revoked');
    assert.deepEqual((await fixture.store.revokeAuthorization(revoke, identity)).response, revoked.response);
    const revokeHistory = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const altered = await fixture.store.artifacts.publishCanonical({ ...revoked.response, extraAuthority: true }, 'cliq-control-response-v1');
      const original = revokeHistory.prepare('SELECT response_ref FROM control_requests WHERE principal_id = ? AND method = ? AND request_id = ?')
        .get<{ response_ref: string }>(identity.principalId, 'authorization.revoke', revoke.requestId)!;
      revokeHistory.prepare('UPDATE control_requests SET response_ref = ? WHERE principal_id = ? AND method = ? AND request_id = ?')
        .run(altered.ref, identity.principalId, 'authorization.revoke', revoke.requestId);
      try { await assert.rejects(fixture.store.revokeAuthorization(revoke, identity), /exact historical outcome/); }
      finally { revokeHistory.prepare('UPDATE control_requests SET response_ref = ? WHERE principal_id = ? AND method = ? AND request_id = ?')
        .run(original.response_ref, identity.principalId, 'authorization.revoke', revoke.requestId); }
    } finally { revokeHistory.close(); }
    const conflictRevoke = { ...revokeCore, grantId: 'not-a-grant' };
    await assert.rejects(fixture.store.revokeAuthorization({ ...conflictRevoke, requestDigest: canonicalSha256(conflictRevoke) }, identity),
      { code: 'REQUEST_ID_CONFLICT' });
    assert.deepEqual((await fixture.store.createAuthorization(request, identity)).response, created.response,
      'creation replay returns its original active summary, never recreates authority');
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    const successor = await publishInProcessChannel(fixture.store);
    assert.deepEqual((await fixture.store.createAuthorization(request, successor)).response, created.response);
    assert.deepEqual((await fixture.store.revokeAuthorization(revoke, successor)).response, revoked.response);
    assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).run.revision, 1);
  } finally { await disposeFixture(fixture); }
});

test('Run admission consumes a real identity authorization once and freezes the exact verifier command and environment', async t => {
  const signed = await signedVerifierAuthority({ imageByteCount: 2 * 1024 ** 2 });
  let assembly!: RunAssemblyV1;
  const fixture = await createQueuedFixture('verifier-admission-once', { runtimeAuthority: { bundle: signed.bundle, releaseKeys: signed.releaseKeys },
    assembly: async store => {
      for (const object of signed.objects) await store.artifacts.publishBytes(object.bytes, 'application/octet-stream', 'offline-verifier-object');
      assembly = testFixture().assembly;
      Object.assign(assembly.runtime, { runtimeBundleRef: canonicalSha256(signed.bundle), runtimeBundleManifestDigest: signed.bundle.manifestDigest,
        guestToolchainManifestRef: signed.manifestRef, guestToolchainManifestDigest: signed.manifest.manifestDigest });
      assembly.assemblyDigest = digestOmitting(assembly, 'assemblyDigest');
      return (await store.artifacts.publishCanonical(assembly, assembly.format)).ref;
    } });
  try {
    const identity = await publishInProcessChannel(fixture.store), baseRun = fixture.store.getRun(fixture.runId);
    const base = await fixture.store.artifacts.readCanonical<RunSpec>(baseRun.specRef);
    const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(), decision: {
      kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain', guestToolchainManifestId: signed.manifestId, toolId: 'node' } } };
    const created = await fixture.store.createAuthorization({ ...core, requestDigest: canonicalSha256(core) }, identity);
    const verifier: VerifierRequest = { id: 'node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
      argv: [{ kind: 'non_secret_literal', value: '--test' }, { kind: 'non_secret_literal', value: '--test-concurrency=1' },
        { kind: 'non_secret_literal', value: 'check.test.mjs' }], cwd: '.', env: {},
      writableEphemeralPaths: [], identityReadGrantId: created.response.result.grant.grantId, timeoutMs: 1000, retries: 0, outputLimitBytes: 65_536 };
    const command = { schemaVersion: 1, format: 'cliq-verifier-command-v1', verifierId: 'node-tests', verifierVersion: '1', executable: {
      kind: 'guest_toolchain', guestToolchainManifestRef: signed.manifestRef, guestToolchainManifestDigest: signed.manifest.manifestDigest,
      toolId: 'node', executionPath: '/usr/bin/node', executableDigest: signed.manifest.node.digest, abiFingerprint: signed.manifest.manifestDigest },
      argv: verifier.argv, cwd: '.', commandDigest: '' };
    command.commandDigest = digestOmitting(command, 'commandDigest');
    const commandArtifact = await fixture.store.artifacts.publishCanonical(command, command.format);
    const environment = { schemaVersion: 1, format: 'cliq-verifier-environment-v1', verifierId: 'node-tests', verifierVersion: '1',
      commandRef: commandArtifact.ref, commandDigest: command.commandDigest, variables: [], writableEphemeralPaths: [],
      sourceProjectionRef: base.sourceProjectionRef, sourceAccess: 'read_only', networkAccess: 'denied', sandboxProfile: 'cliq-verifier-readonly-v1',
      runtimeBundleRef: canonicalSha256(signed.bundle), runtimeBundleManifestDigest: signed.bundle.manifestDigest,
      guestToolchainManifestRef: signed.manifestRef, guestToolchainManifestDigest: signed.manifest.manifestDigest, environmentDigest: '' };
    environment.environmentDigest = digestOmitting(environment, 'environmentDigest');
    const envArtifact = await fixture.store.artifacts.publishCanonical(environment, environment.format);
    const entry: VerifierSpec['verifiers'][number] = { index: 0, id: 'node-tests', version: '1', gate: 'required', commandRef: commandArtifact.ref,
      commandDigest: command.commandDigest, environmentRef: envArtifact.ref, environmentDigest: environment.environmentDigest,
      timeoutMs: 1000, retries: 0, outputLimitBytes: 65_536, entryDigest: '' };
    entry.entryDigest = digestOmitting(entry, 'entryDigest');
    const spec: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [entry], specDigest: '' };
    spec.specDigest = digestOmitting(spec, 'specDigest');
    const specArtifact = await fixture.store.artifacts.publishCanonical(spec, spec.format);
    const profileEntry = signed.bundle.entries.find(member => member.role === 'policy_engine')!;
    const policy: RunPolicySnapshotV1 = { schemaVersion: 1, format: 'cliq-run-policy-v1', principalId: identity.principalId,
      workspaceIdentityDigest: (await fixture.store.artifacts.readCanonical<{ identityDigest: string }>(fixture.store.getSession(baseRun.sessionId).workspaceIdentityRef)).identityDigest,
      mode: 'yolo', engine: { id: 'cliq-policy-v1', version: profileEntry.version, runtimeBundleRef: canonicalSha256(signed.bundle),
        profileEntryId: profileEntry.entryId, profileRef: profileEntry.digest,
        profileDigest: (await fixture.store.artifacts.readCanonical<{ profileDigest: string }>(profileEntry.digest)).profileDigest },
      toolManifestRef: assembly.tools.manifestRef, toolManifestDigest: assembly.tools.manifestDigest, decisions: modeDecisions('yolo'),
      decisionRules: [...BUILTIN_POLICY_RULES], repositoryRequestRefs: [], createdAt: baseRun.createdAt, policyDigest: '' };
    policy.policyDigest = digestOmitting(policy, 'policyDigest');
    const policyArtifact = await fixture.store.artifacts.publishCanonical(policy, policy.format);
    const sandbox = await fixture.store.artifacts.readCanonical<SandboxProfileV1>(base.sandboxProfileRef);
    sandbox.resources.maxSingleFileBytes = signed.manifest.guestImageByteCount;
    sandbox.resources.maxProcesses = 32;
    sandbox.profileDigest = digestOmitting(sandbox, 'profileDigest');
    const exactSandbox = await fixture.store.artifacts.publishCanonical(sandbox, sandbox.format);
    const source = await fixture.store.artifacts.readCanonical<{ frozenIgnoreRulesRef: string }>(base.baseWorkspaceManifestRef);
    const input = { ...identity, requestId: uuidv7(), admissionKey: admissionKey('authorized-verifier'), sessionId: baseRun.sessionId,
      expectedContextRevision: 1, workspacePath: fixture.workspace, objective: 'run required node tests', allowUnverified: false,
      assemblyRef: base.assemblyRef, policyRef: policyArtifact.ref, sandboxProfileRef: exactSandbox.ref,
      sourceProjectionRef: base.sourceProjectionRef, frozenIgnoreRulesRef: source.frozenIgnoreRulesRef,
      baseWorkspaceManifestRef: base.baseWorkspaceManifestRef, verifierSpecRef: specArtifact.ref, verifierRequests: [verifier] };
    const lower = structuredClone(sandbox); lower.resources.maxSingleFileBytes = 1024 ** 2;
    lower.profileDigest = digestOmitting(lower, 'profileDigest');
    const lowerArtifact = await fixture.store.artifacts.publishCanonical(lower, lower.format);
    await assert.rejects(fixture.store.admitRun({ ...input, sandboxProfileRef: lowerArtifact.ref }),
      (error: unknown) => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'UNSUPPORTED_EXECUTION_IDENTITY');
    const fewer = structuredClone(sandbox); fewer.resources.maxProcesses = 31; fewer.profileDigest = digestOmitting(fewer, 'profileDigest');
    const fewerArtifact = await fixture.store.artifacts.publishCanonical(fewer, fewer.format);
    await assert.rejects(fixture.store.admitRun({ ...input, sandboxProfileRef: fewerArtifact.ref }),
      (error: unknown) => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'UNSUPPORTED_EXECUTION_IDENTITY');
    const { verifierRequests: _requests, ...missing } = input;
    await assert.rejects(fixture.store.admitRun(missing), (error: unknown) => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'AUTHORIZATION_REQUIRED');
    await assert.rejects(fixture.store.admitRun({ ...input, verifierRequests: [{ ...verifier, argv: [...verifier.argv.slice(0, 2),
      { kind: 'non_secret_literal', value: 'different.test.mjs' }] }] }),
      { code: 'ARTIFACT_MISMATCH' });
    await assert.rejects(fixture.store.admitRun({ ...input, verifierRequests: [{ ...verifier, executionGrantId: 'unimplemented' }] }),
      (error: unknown) => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'UNSUPPORTED_EXECUTION_IDENTITY');
    for (const unsupported of [{ ...verifier, env: { EXPLICIT: { kind: 'non_secret_literal' as const, value: 'value' } } },
      { ...verifier, argv: [verifier.argv[0]!, verifier.argv[2]!] }, { ...verifier, writableEphemeralPaths: ['output'] }]) {
      await assert.rejects(fixture.store.admitRun({ ...input, verifierRequests: [unsupported] }),
        (error: unknown) => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'UNSUPPORTED_EXECUTION_IDENTITY');
    }
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    try {
      const expiringCore = { ...core, requestId: uuidv7(), ttlMs: 1000 };
      const expiring = await fixture.store.createAuthorization({ ...expiringCore, requestDigest: canonicalSha256(expiringCore) }, identity);
      t.mock.timers.tick(1000);
      await assert.rejects(fixture.store.admitRun({ ...input, requestId: uuidv7(), admissionKey: admissionKey('expired-identity'),
        verifierRequests: [{ ...verifier, identityReadGrantId: expiring.response.result.grant.grantId }] }),
      (error: unknown) => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'AUTHORIZATION_REQUIRED');
    } finally { t.mock.timers.reset(); }
    const expectedRunId = identityHash('cliq-run-id-v1', identity.principalId, 'run.submit', input.admissionKey);
    const sample = await open(path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, commandArtifact.ref), 'r');
    const prototype = Object.getPrototypeOf(sample) as { writeFile: FileHandle['writeFile'] }, originalWrite = prototype.writeFile;
    await sample.close();
    const failure = Object.assign(new Error('verifier receipt ENOSPC after actual CAS write'), { code: 'ENOSPC' });
    let injected = 0;
    const writer = t.mock.method(prototype, 'writeFile', async function(this: FileHandle, ...args: unknown[]) {
      await Reflect.apply(originalWrite, this, args);
      if (Buffer.isBuffer(args[0]) && args[0].includes(Buffer.from('"kind":"run_admission"')) &&
          args[0].includes(Buffer.from(`"runId":"${expectedRunId}"`)) && !injected++) throw failure;
    });
    try {
      await assert.rejects(fixture.store.admitRun(input), error => error === failure);
      assert.equal(injected, 1); assert(isJoinedCasPublicationFailure(failure));
      assert.throws(() => fixture.store.getRun(expectedRunId), { code: 'NOT_FOUND' });
    } finally { writer.mock.restore(); }
    const driver = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      // Existing isolated SQLite fault seam: the genuine owning admission
      // transaction must roll back both the Run and the preceding consumption.
      driver.exec("CREATE TRIGGER verifier_admission_test_rollback BEFORE INSERT ON runs BEGIN SELECT RAISE(ABORT, 'injected verifier admission rollback'); END");
      await assert.rejects(fixture.store.admitRun(input), /injected verifier admission rollback/);
      assert.throws(() => fixture.store.getRun(expectedRunId), { code: 'NOT_FOUND' });
    } finally { driver.exec('DROP TRIGGER verifier_admission_test_rollback'); driver.close(); }
    const admitted = await fixture.store.admitRun(input);
    assert.equal(admitted.run.status, 'queued');
    const frozen = await fixture.store.artifacts.readCanonical<RunSpec>(admitted.run.specRef);
    assert.equal(frozen.verifierSpecRef, specArtifact.ref); assert.equal(frozen.unverifiedConsentRef, undefined);
    assert.equal(frozen.sandboxProfileRef, exactSandbox.ref, 'the exact user resource envelope is retained, never clamped or increased');
    assert.deepEqual((await fixture.store.admitRun(input)).response, admitted.response);
    const commandPath = path.join(fixture.stateRoot, KERNEL_CAS_DIRECTORY, commandArtifact.ref), retainedCommand = path.join(fixture.stateRoot, 'retained-command-test');
    await rename(commandPath, retainedCommand);
    try {
      await assert.rejects(fixture.store.admitRun(input));
      await assert.rejects(stat(commandPath), { code: 'ENOENT' }, 'historical replay must not recreate missing command bytes');
    } finally { await rename(retainedCommand, commandPath); }
    const revokeCore = { protocolVersion: 1, method: 'authorization.revoke', requestId: uuidv7(), grantId: verifier.identityReadGrantId };
    const revoked = await fixture.store.revokeAuthorization({ ...revokeCore, requestDigest: canonicalSha256(revokeCore) }, identity);
    assert.equal(revoked.response.result.method, 'authorization.revoke');
    if (revoked.response.result.method !== 'authorization.revoke') assert.fail('revoke response');
    assert.equal(revoked.response.result.disposition, 'already_consumed'); assert.equal(revoked.response.result.grant.useCount, 1);
    await assert.rejects(fixture.store.admitRun({ ...input, requestId: uuidv7(), admissionKey: admissionKey('same-identity-second') }),
      (error: unknown) => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'AUTHORIZATION_REQUIRED');
    const advisoryCore = { ...core, requestId: uuidv7() };
    const advisoryGrant = await fixture.store.createAuthorization({ ...advisoryCore, requestDigest: canonicalSha256(advisoryCore) }, identity);
    const advisoryEntry = { ...entry, gate: 'advisory' as const, entryDigest: '' };
    advisoryEntry.entryDigest = digestOmitting(advisoryEntry, 'entryDigest');
    const advisorySpec = { ...spec, verifiers: [advisoryEntry], specDigest: '' };
    advisorySpec.specDigest = digestOmitting(advisorySpec, 'specDigest');
    const advisoryArtifact = await fixture.store.artifacts.publishCanonical(advisorySpec, advisorySpec.format);
    const advisoryInput = { ...input, requestId: uuidv7(), admissionKey: admissionKey('advisory-identity'), allowUnverified: true,
      verifierSpecRef: advisoryArtifact.ref, verifierRequests: [{ ...verifier, required: false, identityReadGrantId: advisoryGrant.response.result.grant.grantId }] };
    const advisory = await fixture.store.admitRun(advisoryInput);
    const advisoryRunSpec = await fixture.store.artifacts.readCanonical<RunSpec>(advisory.run.specRef);
    assert(advisoryRunSpec.unverifiedConsentRef, 'advisory-only Run retains original explicit unverified consent');
    assert.deepEqual((await fixture.store.admitRun(advisoryInput)).response, advisory.response);
    await fixture.store.close();
    fixture.store = await openStateStore(fixture.stateRoot, fixture.runtimeAuthority);
    const successor = await publishInProcessChannel(fixture.store);
    assert.deepEqual((await fixture.store.admitRun({ ...input, ...successor })).response, admitted.response);
    assert.deepEqual((await fixture.store.admitRun({ ...advisoryInput, ...successor })).response, advisory.response);
    await fixture.store.close();
    const history = openSqliteDriver(path.join(fixture.stateRoot, KERNEL_DATABASE_FILENAME));
    try {
      const original = history.prepare('SELECT grant_id, owner_principal_id, state, row_json FROM authorization_grants WHERE grant_id = ?')
        .get<{ grant_id: string; owner_principal_id: string; state: string; row_json: string }>(verifier.identityReadGrantId)!;
      history.prepare('DELETE FROM authorization_grants WHERE grant_id = ?').run(verifier.identityReadGrantId);
      try { await assert.rejects(openStateStore(fixture.stateRoot, fixture.runtimeAuthority), { code: 'RECOVERY_REQUIRED' }); }
      finally { history.prepare('INSERT INTO authorization_grants (grant_id, owner_principal_id, state, row_json) VALUES (?, ?, ?, ?)')
        .run(original.grant_id, original.owner_principal_id, original.state, original.row_json); }
    } finally { history.close(); }
  } finally { await disposeFixture(fixture); }
});

test('identity authorization refuses an unavailable signed toolchain before publishing a grant', async () => {
  const fixture = await createQueuedFixture('verifier-identity-unsupported');
  try {
    const identity = await publishInProcessChannel(fixture.store);
    const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(),
      decision: { kind: 'execution_identity_read', purpose: 'verifier',
        target: { kind: 'guest_toolchain', guestToolchainManifestId: 'not-installed', toolId: 'node' } } };
    await assert.rejects(fixture.store.createAuthorization({ ...core, requestDigest: canonicalSha256(core) }, identity),
      (error: unknown) => error instanceof Error && 'refusalCode' in error && error.refusalCode === 'UNSUPPORTED_EXECUTION_IDENTITY');
    assert.equal((await fixture.store.readRecoveryClosure(fixture.runId)).run.revision, 1);
  } finally { await disposeFixture(fixture); }
});
