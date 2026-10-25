import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import type { SourceInspectionAttemptV1, SourceInspectionInputV2, SourceInspectionTargetV2 } from '../kernel/execution.js';
import { DEFAULT_SANDBOX_RESOURCES } from '../kernel/control-submit.js';
import { digestOmitting, identityHash, sha256Bytes } from '../kernel/identity.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { signedVerifierAuthority } from './testing/verifier-authority.js';
import { installedSandboxProfile } from './installed-sandbox-profile.js';
import { publishSourceGitLaunch, readRetainedSourceGitLaunch } from './source-git-launch.js';

async function fixture(t: TestContext) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'source-git-launch-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(directory, 'cas'), { mode: 0o700 });
  const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(directory, 'cas'))), signed = await signedVerifierAuthority();
  const keys = generateKeyPairSync('ed25519');
  const root = { schemaVersion: 1, format: 'cliq-sandbox-root-profile-v1', protocol: 'cliq-fresh-empty-root-v1',
    filesystemKind: 'fresh_ephemeral_tmpfs', fixedDirectories: ['/home/cliq', '/tmp', '/work'], persistent: false,
    networkConfiguration: 'none', profileDigest: '' }; root.profileDigest = digestOmitting(root, 'profileDigest');
  const bytes = canonicalJsonBytes(root), helper = Buffer.from('nonexecuted fixed helper metadata fixture\n');
  const entry = { entryId: 'installed-empty-root', role: 'sandbox_root_profile', version: '1', relativePath: 'profiles/empty-root.json',
    executable: false, digest: sha256Bytes(bytes), byteCount: bytes.length };
  const inspector = { entryId: 'source_git_inspector', role: 'platform_helper', version: '1', relativePath: 'helpers/source-git-inspector.mjs',
    executable: false, digest: sha256Bytes(helper), byteCount: helper.length };
  const controllerBytes = Buffer.from('nonexecuted controller metadata fixture\n');
  const controller = { entryId: 'linux_worker_controller', role: 'platform_helper', version: '1', relativePath: 'native/controller',
    executable: true, digest: sha256Bytes(controllerBytes), byteCount: controllerBytes.length };
  const manifest = { ...signed.manifest, git: { ...signed.manifest.git, canonicalGuestPath: '/usr/bin/git' },
    publisherKeyId: 'source-launch-fixture', manifestDigest: '', signatureRef: '' };
  const { manifestDigest: _guestDigest, signatureRef: _guestSignature, ...guestCore } = manifest;
  manifest.manifestDigest = canonicalSha256(guestCore);
  const guestSignature = sign(null, Buffer.from(`cliq-guest-toolchain-v1\0${manifest.manifestDigest}`), keys.privateKey);
  manifest.signatureRef = sha256Bytes(guestSignature);
  const guestBytes = canonicalJsonBytes(manifest), manifestRef = sha256Bytes(guestBytes);
  const guestEntry = { ...signed.bundle.entries.find(value => value.entryId === 'offline-guest-root-entry')!, digest: manifestRef, byteCount: guestBytes.length };
  const signatureEntry = { entryId: identityHash('runtime-bundle-object-v1', manifest.signatureRef), role: 'bundle_object', version: '1',
    relativePath: `objects/sha256/${manifest.signatureRef.slice(0, 2)}/${manifest.signatureRef}`, executable: false,
    digest: manifest.signatureRef, byteCount: guestSignature.length };
  const bundle = { ...signed.bundle, entries: [...signed.bundle.entries.filter(value =>
    ![entry.entryId, inspector.entryId, controller.entryId, guestEntry.entryId].includes(value.entryId)), entry, inspector, controller,
    guestEntry, signatureEntry], guestToolchainManifestRefs: [manifestRef],
    structuredArtifacts: signed.bundle.structuredArtifacts.map(value => value.kind !== 'guest_toolchain' ? value : {
      ...value, artifactRef: manifestRef, semanticDigest: manifest.manifestDigest, memberRefs: [manifest.guestImageRef, manifest.signatureRef].sort() }),
    publisherKeyId: 'source-launch-fixture', manifestDigest: '', signature: '' };
  const { signature: _signature, manifestDigest: _digest, ...core } = bundle;
  bundle.manifestDigest = canonicalSha256(core);
  bundle.signature = sign(null, Buffer.from(`cliq-runtime-bundle-v1\0${bundle.manifestDigest}`), keys.privateKey).toString('base64');
  const releaseKeys = [{ keyId: bundle.publisherKeyId, publicKeyPem: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }];
  for (const object of [...signed.objects, { bytes, ref: entry.digest }, { bytes: helper, ref: inspector.digest }, { bytes: controllerBytes, ref: controller.digest },
    { bytes: guestBytes, ref: manifestRef }, { bytes: guestSignature, ref: manifest.signatureRef }])
    await artifacts.publishBytes(object.bytes, 'application/octet-stream', 'own-source-launch-data');
  const profile = installedSandboxProfile(), target: SourceInspectionTargetV2 = {
    schemaVersion: 2, format: 'cliq-source-inspection-target-v2', principalId: 'principal', method: 'run.submit',
    admissionKey: 'abcdefghijklmnopqrstuv', admissionIntentDigest: 'c'.repeat(64), originalRequestRef: 'd'.repeat(64), originalRequestDigest: 'd'.repeat(64),
    sessionId: 'session', expectedContextRevision: 0, workspaceIdentityRef: 'e'.repeat(64), workspaceIdentityDigest: 'e'.repeat(64),
    sourceReadGrantRefs: [], runtimeBundleRef: canonicalSha256(bundle), runtimeBundleManifestDigest: bundle.manifestDigest,
    sandboxProfileRef: canonicalSha256(profile), sandboxProfileDigest: profile.profileDigest,
    inspectionGrantId: identityHash('own-source-launch-grant'), inspectionReceiptRef: 'f'.repeat(64), inspectionReceiptDigest: 'a'.repeat(64),
    ignoreReadConsents: [], targetDigest: '' };
  target.targetDigest = digestOmitting(target, 'targetDigest');
  const row: Extract<SourceInspectionAttemptV1, { phase: 'capturing' }> = { schemaVersion: 1,
    inspectionId: identityHash('cliq-source-inspection-v1', target.principalId, target.method, target.admissionKey, target.admissionIntentDigest),
    attempt: 1, principalId: target.principalId, method: target.method, admissionKey: target.admissionKey, admissionIntentDigest: target.admissionIntentDigest,
    targetRef: canonicalSha256(target), targetDigest: target.targetDigest, workspaceIdentityDigest: target.workspaceIdentityDigest,
    stateOwnerEpoch: 1, supervisorInstanceId: 'supervisor', stagingNonceDigest: '1'.repeat(64),
    stagingIdentity: { deviceId: '1', fileId: '2', ownerUid: process.getuid!(), mode: 448 }, cancelRequested: false,
    rowVersion: 1, createdAt: '2026-10-25T00:00:00.000Z', deadlineAt: '2027-10-25T01:00:00.000Z',
    updatedAt: '2026-10-25T00:00:00.000Z', phase: 'capturing', rowDigest: '' }; row.rowDigest = digestOmitting(row, 'rowDigest');
  const input: SourceInspectionInputV2 = { schemaVersion: 2, format: 'cliq-source-inspection-input-v2', inspectionId: row.inspectionId,
    targetRef: row.targetRef, targetDigest: row.targetDigest, repositoryIdentityDigest: '2'.repeat(64),
    inspectionGrantId: target.inspectionGrantId, inspectionReceiptRef: target.inspectionReceiptRef,
    inspectionReceiptDigest: target.inspectionReceiptDigest, recipe: 'cliq-source-git-inspection-v1',
    snapshotPolicy: 'ephemeral_native_sealed_shards', resources: { ...DEFAULT_SANDBOX_RESOURCES }, inputDigest: '' };
  input.inputDigest = digestOmitting(input, 'inputDigest');
  const reservation = { cgroupPath: '/cliq/own-source-data', cgroupId: '4', deviceId: '3', fileId: '4', ownerUid: process.getuid!(),
    observedAtMs: Date.parse(row.createdAt), pidNamespaceReservationId: `source-pending:${row.stagingNonceDigest}`,
    subreaperStartToken: 'linux-subreaper:1:1' };
  await artifacts.publishCanonical(bundle, 'own-signed-runtime-data');
  await artifacts.publishCanonical(profile, profile.format);
  return { directory, artifacts, row, target, input, reservation, bundle, releaseKeys, sandboxProfile: profile,
    toolchain: { manifestRef, manifest, abiFingerprint: 'offline-abi-not-native' } };
}

test('source Git launch data binds a distinct read-only InputV2 mount and fixed signed Node/helper without Run authority', async t => {
  const f = await fixture(t), result = await publishSourceGitLaunch(f.artifacts, f, '3'.repeat(64));
  assert.equal(result.spec.purpose, 'source_inspection');
  assert.equal(result.spec.filesystem.kind, 'isolated_empty_root');
  assert.deepEqual(result.spec.mounts.filter(mount => mount.kind === 'source_git_inspection_input'), [{
    kind: 'source_git_inspection_input', inputRef: canonicalSha256(f.input), inputDigest: f.input.inputDigest,
    targetPath: '/scratch/input', access: 'read_only', purpose: 'input' }]);
  assert(!result.spec.mounts.some(mount => mount.targetPath === '/input'));
  assert.equal(result.spec.environment.home, '/scratch/home'); assert.equal(result.spec.environment.tmpdir, '/scratch/tmp');
  assert.deepEqual(result.spec.owner, result.containmentPlan.owner);
  assert.equal(result.spec.owner.kind, 'source_inspection');
  assert(!Object.hasOwn(result.containmentPlan, 'parentContainmentRef'));
  assert(!Object.hasOwn(result.spec, 'operationGrantRef')); assert(!Object.hasOwn(result.spec, 'parentWorkerContainmentRef'));
  assert.deepEqual(await f.artifacts.readCanonical(result.plan.sandboxLaunchSpecRef), result.spec);
  assert.equal(result.plan.reservedBackendIdentity.kind, 'linux');
  // This is real CAS/signed-data publication only: the fabricated data
  // reservation is deliberately not a native scope, launch or SQL permit.
});

test('retained source launch reopens the complete original CAS recipe and rejects rehashed plan/spec substitutions', async t => {
  const f = await fixture(t), launch = await publishSourceGitLaunch(f.artifacts, f, '3'.repeat(64));
  const prepared: Extract<SourceInspectionAttemptV1, { phase: 'prepared' }> = { ...f.row, phase: 'prepared',
    inputRef: launch.inputRef, inputDigest: f.input.inputDigest, plan: launch.plan };
  const observedAt = new Date(Date.parse(launch.spec.createdAt) + 1000).toISOString();
  const audit = (row = prepared) => readRetainedSourceGitLaunch(f.artifacts, row, f.target, f.input, observedAt);
  await audit();
  await assert.rejects(audit({ ...prepared, plan: { ...prepared.plan, containmentPlanRef: '9'.repeat(64) } }));
  await assert.rejects(audit({ ...prepared, plan: { ...prepared.plan, sandboxLaunchSpecRef: '9'.repeat(64) } }));
  await assert.rejects(audit({ ...prepared, plan: { ...prepared.plan, containmentPlanDigest: '9'.repeat(64) } }));
  for (const change of [
    { owner: { ...launch.containmentPlan.owner, supervisorInstanceId: 'foreign-owner' } },
    { backend: { ...launch.containmentPlan.backend, cgroupNameReservationDigest: '9'.repeat(64) } },
    { parentContainmentRef: '9'.repeat(64) },
    { createdAt: f.row.deadlineAt }
  ]) {
    const plan = { ...launch.containmentPlan, ...change, planDigest: '' };
    plan.planDigest = digestOmitting(plan, 'planDigest');
    const saved = await f.artifacts.publishCanonical(plan, plan.format);
    await assert.rejects(audit({ ...prepared, plan: { ...prepared.plan,
      containmentPlanRef: saved.ref, containmentPlanDigest: plan.planDigest } }));
  }
  for (const change of [
    { purpose: 'worker_activation' },
    { owner: { ...launch.spec.owner, targetRef: '9'.repeat(64) } },
    { processInvocation: { ...launch.spec.processInvocation, inputRef: '9'.repeat(64) } },
    { mounts: [] }, { sourceInspectionInputDigest: '9'.repeat(64) },
    { resources: { ...launch.spec.resources, maxProcesses: 1 } }
  ]) {
    const spec = { ...launch.spec, ...change, launchSpecDigest: '' };
    spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
    const saved = await f.artifacts.publishCanonical(spec, spec.format);
    await assert.rejects(audit({ ...prepared, plan: { ...prepared.plan,
      sandboxLaunchSpecRef: saved.ref, sandboxLaunchSpecDigest: spec.launchSpecDigest } }));
  }
  // A valid semantic graph still requires the original complete helper bytes.
  const helper = f.bundle.entries.find(entry => entry.entryId === 'source_git_inspector')!;
  await rm(path.join(f.directory, 'cas', helper.digest));
  await assert.rejects(audit());
});

test('source Git launch refuses foreign target/input/resource/runtime or caller-selected helper data', async t => {
  const f = await fixture(t);
  for (const edit of [
    () => ({ ...f, input: { ...f.input, targetRef: '9'.repeat(64) } }),
    () => ({ ...f, target: { ...f.target, inspectionReceiptRef: '9'.repeat(64) } }),
    () => ({ ...f, row: { ...f.row, cancelRequested: true } }),
    () => ({ ...f, reservation: { ...f.reservation, fileId: '5' } }),
    () => ({ ...f, bundle: { ...f.bundle, manifestDigest: '9'.repeat(64) } }),
    () => ({ ...f, toolchain: { ...f.toolchain, manifest: { ...f.toolchain.manifest,
      node: { ...f.toolchain.manifest.node, canonicalGuestPath: '/caller/node' } } } })
  ]) await assert.rejects(publishSourceGitLaunch(f.artifacts, edit(), '3'.repeat(64)));
  const abort = new AbortController(), reason = new Error('own source launch cancelled'); abort.abort(reason);
  await assert.rejects(publishSourceGitLaunch(f.artifacts, f, '3'.repeat(64), abort.signal), error => error === reason);
});
