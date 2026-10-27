// Existing native-campaign component only. The caller owns a disposable
// StateRoot/controller, genuine same-lock input and signed installed runtime.
// No Run, SQL acceptance, completion capability or durable proof is minted.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { setImmediate } from 'node:timers/promises';
import { chmod, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import { KERNEL_CAS_DIRECTORY } from '../../../src/config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import type { SandboxResourceSpec } from '../../../src/kernel/execution.js';
import { digestOmitting, identityHash } from '../../../src/kernel/identity.js';
import { testFixture } from '../../../src/model/testing/fixtures.js';
import { ArtifactCatalog as ActualArtifactCatalog } from '../../../src/state/artifacts.js';
import { ContentAddressedStore } from '../../../src/state/cas.js';
import type { ArtifactCatalog } from '../../../src/state/artifacts.js';
import { joinResourceOperations, ResourceRetirementError } from '../../../src/state/errors.js';
import { validateGuestToolchainMetadata, type RetainedVerifierToolchain } from '../../../src/state/guest-toolchain.js';
import { borrowPreparingGitInputForExecution, loadNativeStateOwner, openPreparingGitInput, openRetainedPreparingGitInput,
  stateRootIdentityForLock, assertRetainedPreparingGitInputOwner, type HeldPreparingGitInput,
  type HeldStateOwnerLock, type HeldGenerationTree, type HeldWorkerReservation } from '../../../src/state/native-owner.js';
import { workerCampaignSandboxProfile } from '../../../src/sandbox/testing/worker-campaign-fixture.js';
import { signedLinuxWorkerTestRuntime } from '../../../src/sandbox/testing/worker-runtime.js';
import { builtinInputContracts } from '../../../src/tools/builtin-inputs.js';
import { normalizeGitIndex } from '../../../src/workspace/git-index.js';
import { decodeSourceGitInspectionOutput } from '../../../src/workspace/source-git-output.js';
import { buildSourceGitInspectorAsset } from './source-git-inspector-package.js';
import { assertLinuxWorkerController, readNativeControllerPreparationBirth, readNativeRetainedPreparingGitRetirement, type LinuxWorkerController,
  type NativePreparingGitRecipe, type NativePreparingGitRetirementObservation, type NativePreparingGitScope,
  type NativeSourceGitOutputReader, type HeldPreparingGitScope, openLinuxWorkerLauncher } from '../../../src/sandbox/linux-worker.js';

import { observeRetainedPreparingGeneration, readRetainedPreparingGenerationRetirement } from '../../../src/workspace/run-workspace/preparation-retirement.js';

type OriginalLeaf = Readonly<{ ref: string; byteCount: number }>;
export type PreparingGitNativeCancellationInput = Readonly<{
  controller: LinuxWorkerController; input: HeldPreparingGitInput; artifacts: ArtifactCatalog;
  recipe: NativePreparingGitRecipe; toolchain: RetainedVerifierToolchain;
  leaves: readonly [OriginalLeaf, OriginalLeaf, OriginalLeaf, OriginalLeaf];
  signal?: AbortSignal;
}>;

/** Exercise an actual pending FINISH, followed immediately by cancellation.
 * The same raw receiver must join FINISH, never reinterpret it as CANCEL.
 * This component does not replace the installed Run journey or crash cuts. */
export async function qualifyPreparingGitFinishCancellation(selected: PreparingGitNativeCancellationInput) {
  assertLinuxWorkerController(selected.controller); borrowPreparingGitInputForExecution(selected.input);
  assert.equal(selected.leaves.length, 4);
  const leaves = selected.leaves.map(leaf => {
    assert.match(leaf.ref, /^[0-9a-f]{64}$/u); assert(Number.isSafeInteger(leaf.byteCount) && leaf.byteCount > 0);
    return Object.freeze({ ref: leaf.ref, byteCount: leaf.byteCount });
  });
  assert.equal(leaves[0]!.ref, selected.input.identity.inputIntentRef);
  let held: HeldPreparingGitScope | undefined, scope: NativePreparingGitScope | undefined;
  const readers = new Set<NativeSourceGitOutputReader>();
  let result: NativePreparingGitRetirementObservation | undefined, stoppedAt = 0, stopElapsedMs = 0;
  let primary: { error: unknown } | undefined;
  const cleanup: unknown[] = [];
  const wait = async <T>(observe: () => T | undefined, deadline: number, reducing = false): Promise<T> => {
    for (;;) {
      if (!reducing) selected.signal?.throwIfAborted();
      const observed = observe();
      if (observed !== undefined) return observed;
      assert(performance.now() < deadline, 'real native preparing operation exceeded its original deadline');
      await setImmediate();
    }
  };
  const closeReader = (reader: NativeSourceGitOutputReader) => {
    if (!readers.delete(reader)) return;
    reader.close();
  };
  try {
    held = await selected.controller.openPreparingGit({ input: selected.input, recipe: selected.recipe,
      toolchain: selected.toolchain, ...(selected.signal ? { signal: selected.signal } : {}) });
    const deadline = performance.now() + 30_000;
    scope = held.reserve();
    await wait(() => scope!.pollReserved(), deadline);
    const readyDeadline = Math.min(deadline, performance.now() + 5000);
    scope.createBlocked();
    const original = await wait(() => scope!.pollReady(), readyDeadline);
    scope.releaseCapture();
    for (const [role, leaf] of leaves.entries()) {
      await wait(() => scope!.declareInput(role, leaf.ref, leaf.byteCount) ? true : undefined, deadline);
      // Full exhaustion also joins the original CAS reader's actual close.
      for await (const bytes of selected.artifacts.readChunks(leaf.ref, leaf.byteCount)) {
        for (let offset = 0; offset < bytes.length; offset += 65_536) {
          const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + 65_536));
          await wait(() => scope!.writeInput(chunk) ? true : undefined, deadline);
        }
      }
      await wait(() => scope!.endInput() ? true : undefined, deadline);
    }
    await wait(() => scope!.finishInput() ? true : undefined, deadline);
    const sealed = await wait(() => scope!.pollSealed(), deadline);
    assert.equal(sealed.byteCount, leaves.reduce((sum, leaf) => sum + leaf.byteCount, 0));
    assert.equal(sealed.entryCount, 4); assert.equal(sealed.shardCount, 4);
    scope.continueFixedGit();
    const actual = await wait(() => scope!.pollResult(), deadline);
    const outputs = [actual.files.inspection, actual.files.index, actual.files.pack, actual.files.packIndex];
    for (const reader of outputs) readers.add(reader);
    if (actual.excludeRule) readers.add(actual.excludeRule);
    for (const key of ['pid', 'namespaceInitPid', 'processStartToken', 'namespaceInitStartToken', 'cgroupId', 'pidNamespaceId'] as const)
      assert.equal(actual.death[key], original[key]);
    assert.equal(actual.death.cgroupPopulated, 0); assert.equal(actual.death.namespaceInitDeadAndReaped, 1);
    assert.equal(actual.death.remainingTrackedDescendants, 0); assert.equal(actual.excludeRule, null);
    for (const [index, reader] of outputs.entries()) {
      const leaf = leaves[index]!; assert.deepEqual(reader.identity, { sha256: leaf.ref, byteCount: leaf.byteCount });
      const digest = createHash('sha256'); let length = 0;
      try {
        for (;;) {
          selected.signal?.throwIfAborted(); reader.assertHeld();
          const bytes = reader.readChunk(); if (bytes === undefined) break;
          assert(Buffer.isBuffer(bytes) && bytes.length > 0); length += bytes.length;
          assert(length <= leaf.byteCount); digest.update(bytes); await setImmediate();
        }
        assert.equal(length, leaf.byteCount); assert.equal(digest.digest('hex'), leaf.ref);
      } finally { closeReader(reader); }
    }
    await held.closeRuntime();
    selected.signal?.throwIfAborted();
    stoppedAt = performance.now();
    // No pause or timing guess: the original receiver still owns its pending
    // FINISH until poll consumes that exact response, even if C already joined.
    scope.retire(); scope.stop();
    result = await wait(() => scope!.pollStopped(), stoppedAt + 2000, true);
    assert.equal(result.origin, 'original_owner_joined'); assert.equal(result.completed, 1); assert.equal(result.lastBirthPhase, 10);
    assert.equal(result.originalControllerPid, selected.controller.pid);
    assert.equal(result.originalControllerStartToken, selected.controller.processStartToken);
    for (const key of ['runId', 'generationId', 'launchId', 'spawnNonceDigest', 'activationNonceDigest', 'generationCreationNonceDigest',
      'generationRef', 'inputIntentRef', 'originalSupervisorPid', 'originalSupervisorStartToken'] as const)
      assert.equal(result[key], selected.input.identity[key]);
    // The original controller remains the same live owner after this cut;
    // cancelled test work receives no capability to promote its final BIND.
    assert.equal(readNativeControllerPreparationBirth(selected.controller.preparationBirth).identity.pid, selected.controller.pid);
  } catch (error) { primary = { error }; }
  finally {
    for (const reader of [...readers]) try { closeReader(reader); } catch (error) { cleanup.push(error); }
    if (scope && !result) try { scope.stop(); await wait(() => scope!.pollStopped(), performance.now() + 2000, true); }
    catch (error) { cleanup.push(error); }
    try { await selected.controller.close(); } catch (error) { cleanup.push(error); }
    if (held) try { await held.closeRuntime(); } catch (error) { cleanup.push(error); }
    try { selected.input.close(); } catch (error) { cleanup.push(error); }
    if (stoppedAt) stopElapsedMs = performance.now() - stoppedAt;
  }
  if (cleanup.length) throw new ResourceRetirementError('native FINISH cancellation component did not join',
    new AggregateError([...(primary ? [primary.error] : []), ...cleanup]));
  if (primary) throw primary.error;
  assert(result); assert(stopElapsedMs < 2000, 'complete original FINISH cancellation and controller join must stay below 2 seconds');
  return Object.freeze({ retirement: result, stopElapsedMs });
}

/** Ordinary input data for one staged blob. No host Git creates or verifies
 * this fixture: the real signed child must independently check its pack,
 * index CRC/offset, tree and all-and-only reachable set before returning. */
export function preparingGitNativeInputData(repositoryIdentityDigest: string, resources: SandboxResourceSpec) {
  const payload = Buffer.from('before\n'), object = createHash('sha1').update(`blob ${payload.length}\0`).update(payload).digest();
  const entry = Buffer.alloc(64); entry.writeUInt32BE(0o100644, 24); object.copy(entry, 40); entry.writeUInt16BE(1, 60); entry.write('a', 62);
  const header = Buffer.from('444952430000000200000001', 'hex'), indexBody = Buffer.concat([header, entry]);
  const index = Buffer.concat([indexBody, createHash('sha1').update(indexBody).digest()]);
  const normalized = normalizeGitIndex(index, 'sha1', { maxBytes: resources.maxSingleFileBytes, maxEntries: 100_000 });
  assert(normalized.canonicalBytes.equals(index));
  const packHeader = Buffer.from('5041434b0000000200000001', 'hex');
  const packedObject = Buffer.concat([Buffer.from([0x30 | payload.length]), deflateSync(payload)]);
  const packBody = Buffer.concat([packHeader, packedObject]), packDigest = createHash('sha1').update(packBody).digest();
  const pack = Buffer.concat([packBody, packDigest]);
  let crc = 0xffffffff;
  for (const byte of packedObject) { crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0); }
  const fanout = Buffer.alloc(1024); for (let bucket = object[0]!; bucket < 256; bucket++) fanout.writeUInt32BE(1, bucket * 4);
  const checks = Buffer.alloc(8); checks.writeUInt32BE((crc ^ 0xffffffff) >>> 0, 0); checks.writeUInt32BE(12, 4);
  const idxBody = Buffer.concat([Buffer.from('ff744f6300000002', 'hex'), fanout, object, checks, packDigest]);
  const packIndex = Buffer.concat([idxBody, createHash('sha1').update(idxBody).digest()]);
  const config = { schemaVersion: 1, format: 'cliq-sanitized-git-config-v1',
    core: { repositoryFormatVersion: 0, fileMode: true, bare: false }, configDigest: '' };
  config.configDigest = digestOmitting(config, 'configDigest');
  const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
  const metadata = decodeSourceGitInspectionOutput(canonicalJsonBytes({ schemaVersion: 1, format: 'cliq-source-git-inspection-output-v1',
    repositoryIdentityDigest, objectFormat: 'sha1', head: { kind: 'unborn', branch: 'main' }, refs: [],
    index: { entries: normalized.entries, indexTreeObjectId: normalized.indexTreeObjectId, byteCount: index.length, sha256: sha(index) },
    pack: { byteCount: pack.length, sha256: sha(pack), trailerObjectHash: packDigest.toString('hex'),
      indexByteCount: packIndex.length, indexSha256: sha(packIndex), objectIds: [object.toString('hex')] }, sanitizedConfig: config }),
  { repositoryIdentityDigest, resources });
  return [canonicalJsonBytes(metadata), index, pack, packIndex] as const;
}

/** Called only by the existing real Linux guest campaign, on its disposable
 * owned volume/delegation. Business fields here are inert fixture data;
 * actual authority is limited to the genuine native resource lifetime. */
export async function qualifyPreparingGitNativeCampaign(selected: {
  installationRoot: string; guestImageRoot: string; cgroupParent: string; stateVolume: string;
}) {
  assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64'); assert.notEqual(process.getuid!(), 0);
  const root = await mkdtemp(path.join(selected.stateVolume, 'preparing-native-'));
  const runId = identityHash('cliq-native-component-run-v1', root), generationId = identityHash('cliq-native-component-generation-v1', root);
  const launchId = identityHash('cliq-native-component-launch-v1', root), spawnNonceDigest = canonicalSha256([root, 'spawn']);
  const profile = workerCampaignSandboxProfile({ maxOpenFiles: 128 }), resource = profile.resources;
  const principal = testFixture(), builtin = builtinInputContracts.edit;
  let launcher: Awaited<ReturnType<typeof openLinuxWorkerLauncher>> | undefined, controller: LinuxWorkerController | undefined;
  let lock: HeldStateOwnerLock | undefined, tree: HeldGenerationTree | undefined, reservation: HeldWorkerReservation | undefined;
  let input: HeldPreparingGitInput | undefined, primary: { error: unknown } | undefined, report: Awaited<ReturnType<typeof qualifyPreparingGitFinishCancellation>> | undefined;
  const cleanup: unknown[] = [];
  let successorConfig: { installation: NativeSuccessorConfiguration['installation']; toolchain: NativeSuccessorConfiguration['toolchain'] } | undefined;
  try {
    await chmod(root, 0o700);
    const native = await loadNativeStateOwner(); lock = native.acquireLock(root, true);
    tree = lock.createGenerationTree(runId, generationId); reservation = lock.createWorkerReservation(launchId, spawnNonceDigest);
    const sourceGitInspector = await buildSourceGitInspectorAsset(fileURLToPath(new URL('../../../', import.meta.url)));
    const signed = await signedLinuxWorkerTestRuntime({ ...selected, sourceGitInspector, assembly: principal.assembly, sandboxProfile: profile,
      tools: [{ name: builtin.name, version: '1', description: 'Offline native fixture', access: builtin.access,
        inputSchemaRef: canonicalSha256(builtin.inputSchema), inputSchemaDigest: canonicalSha256(builtin.inputSchema), replayClass: builtin.replayClass,
        execution: { kind: 'builtin', adapterId: 'edit', adapterVersion: '1', adapterCodeDigest: '' } }] });
    assert(signed.guest);
    const manifestBytes = canonicalJsonBytes(signed.guest.manifest), signature = signed.guest.objects.find(value => value.ref === signed.guest!.manifest.signatureRef);
    assert(signature);
    successorConfig = { installation: { installationRoot: selected.installationRoot, cgroupParent: selected.cgroupParent,
      runtimeAuthority: { bundle: signed.bundle, releaseKeys: signed.releaseKeys } }, toolchain: { manifestRef: signed.guest.manifestRef,
      manifestBytes: manifestBytes.toString('base64'), signatureBytes: signature.bytes.toString('base64') } };
    const toolchain = validateGuestToolchainMetadata(signed.bundle, signed.guest.manifestRef, manifestBytes, signature.bytes, signed.releaseKeys);
    const repositoryIdentityDigest = canonicalSha256([root, 'native-input-data']);
    const recipe: NativePreparingGitRecipe = { ...resource, stateOwnerEpoch: 1, supervisorInstanceId: 'native-component', sessionId: 'native-component',
      stateOwnerRowDigest: canonicalSha256({ actualNativeOwnerPid: process.pid, actualStartToken: native.processStartToken(), root: lock.root }),
      sourceCheckpointId: 'native-component', sourceWorkspaceStateRef: canonicalSha256([root, 'source-data']), repositoryIdentityDigest };
    const contents = preparingGitNativeInputData(repositoryIdentityDigest, resource);
    const casRoot = path.join(root, KERNEL_CAS_DIRECTORY); await mkdir(casRoot, { recursive: true, mode: 0o700 });
    const artifacts = new ActualArtifactCatalog(new ContentAddressedStore(casRoot));
    const metadata = await joinResourceOperations(contents.map(bytes => artifacts.publishBytes(bytes, 'application/octet-stream', 'native-component-data')));
    const leaves = metadata.map(value => ({ ref: value.ref, byteCount: value.byteLength })) as unknown as PreparingGitNativeCancellationInput['leaves'];
    input = openPreparingGitInput(lock, reservation, tree, { runId, generationId, launchId, spawnNonceDigest,
      activationNonceDigest: canonicalSha256([root, 'activation']), generationCreationNonceDigest: canonicalSha256([root, 'directory-birth-data']),
      generationRef: canonicalSha256({ kind: 'actual-native-component-directory-data', runId, generationId, ...tree.identity }), inputIntentRef: leaves[0].ref });
    launcher = await openLinuxWorkerLauncher({ installationRoot: selected.installationRoot, cgroupParent: selected.cgroupParent,
      runtimeAuthority: { bundle: signed.bundle, releaseKeys: signed.releaseKeys } });
    controller = await launcher.startController();
    report = await qualifyPreparingGitFinishCancellation({ controller, input, artifacts, recipe, toolchain, leaves });
  } catch (error) { primary = { error }; }
  finally {
    if (controller) try { await controller.close(); } catch (error) { cleanup.push(error); }
    if (launcher) try { await launcher.close(); } catch (error) { cleanup.push(error); }
    for (const resource of [input, tree, reservation, lock]) if (resource) try { resource.close(); } catch (error) { cleanup.push(error); }
    if (!primary && !cleanup.length) await rm(root, { recursive: true });
  }
  if (cleanup.length) throw new ResourceRetirementError('native preparing campaign cleanup did not join',
    new AggregateError([...(primary ? [primary.error] : []), ...cleanup]));
  if (primary) throw primary.error;
  assert(report);
  assert(successorConfig);
  const successorRetirement = await qualifyPreparingGitSuccessor(selected, successorConfig.installation, successorConfig.toolchain, resource);
  return { scenario: 'preparing-finish-cancel-original-reply', ...report, successorRetirement,
    scope: 'actual same-controller CAS-only Git and resource lifecycle; no accepted Run or installed-journey qualification' };
}


type NativeSuccessorConfiguration = {
  root: string; installation: import('../../../src/sandbox/linux-worker.js').LinuxWorkerInstallation;
  toolchain: { manifestRef: string; manifestBytes: string; signatureBytes: string };
  resources: SandboxResourceSpec; metadataRef: string;
};
type OriginalPreparingExit = {
  identity: import('../../../src/kernel/types.js').WorkspaceGenerationIdentityV1;
  input: HeldPreparingGitInput['identity']; recipe: NativePreparingGitRecipe;
  controller: ReturnType<typeof readNativeControllerPreparationBirth>;
};

/** The same genuine raw recipe reaches READY, then its own test driver exits.
 * There is no process suspension, forged birth/receipt, SQL or accepted Run. */
async function nativeOriginalReadyExit(config: NativeSuccessorConfiguration): Promise<never> {
  const native = await loadNativeStateOwner(), lock = native.acquireLock(config.root, true);
  const runId = identityHash('native-original-run', config.root), checkpoint = identityHash('native-original-checkpoint', config.root);
  const sourceRef = canonicalSha256([config.root, 'original-source']), nonce = canonicalSha256([config.root, 'original-birth']);
  const generationId = identityHash(runId, checkpoint, sourceRef, nonce), launchId = identityHash('native-original-launch', config.root);
  const spawn = canonicalSha256([config.root, 'original-spawn']), tree = lock.createGenerationTree(runId, generationId);
  const rootIdentity = stateRootIdentityForLock(lock);
  const identity: import('../../../src/kernel/types.js').WorkspaceGenerationIdentityV1 = {
    schemaVersion: 1, format: 'cliq-workspace-generation-identity-v1', runId, generationId,
    workspaceIdentityDigest: canonicalSha256([config.root, 'workspace-data']), sourceCheckpointId: checkpoint,
    sourceWorkspaceStateRef: sourceRef, sourceWorkspaceStateDigest: canonicalSha256([config.root, 'state-data']),
    sourceTreeDigest: canonicalSha256([config.root, 'tree-data']), creationNonceDigest: nonce,
    locator: { kind: 'linux_directory', stateRootIdentityRef: canonicalSha256(rootIdentity), stateRootIdentityDigest: rootIdentity.identityDigest,
      canonicalRootRelativePath: `runs/${runId}/generations/${generationId}`, deviceId: tree.identity.deviceId,
      directoryFileId: tree.identity.fileId, ownerUid: tree.identity.ownerUid, mode: 448 }, createdAt: new Date().toISOString(), identityDigest: '' };
  identity.identityDigest = digestOmitting(identity, 'identityDigest');
  const reservation = lock.createWorkerReservation(launchId, spawn);
  const input = openPreparingGitInput(lock, reservation, tree, { runId, generationId, launchId, spawnNonceDigest: spawn,
    activationNonceDigest: canonicalSha256([config.root, 'original-activation']), generationCreationNonceDigest: nonce,
    generationRef: canonicalSha256(identity), inputIntentRef: config.metadataRef });
  const recipe: NativePreparingGitRecipe = { ...config.resources, stateOwnerEpoch: 1, supervisorInstanceId: 'native-component-original',
    stateOwnerRowDigest: canonicalSha256({ actualNativeOwnerPid: process.pid, actualStartToken: native.processStartToken(), root: lock.root }),
    sessionId: 'native-component-original', sourceCheckpointId: checkpoint, sourceWorkspaceStateRef: sourceRef,
    repositoryIdentityDigest: canonicalSha256([config.root, 'repository-data']) };
  const toolchain = validateGuestToolchainMetadata(config.installation.runtimeAuthority.bundle, config.toolchain.manifestRef,
    Buffer.from(config.toolchain.manifestBytes, 'base64'), Buffer.from(config.toolchain.signatureBytes, 'base64'), config.installation.runtimeAuthority.releaseKeys);
  const launcher = await openLinuxWorkerLauncher(config.installation), controller = await launcher.startController();
  const controllerBirth = readNativeControllerPreparationBirth(controller.preparationBirth);
  const held = await controller.openPreparingGit({ input, recipe, toolchain }), scope = held.reserve();
  const wait = async <T>(poll: () => T | undefined, end: number): Promise<T> => {
    for (;;) { const value = poll(); if (value !== undefined) return value;
      assert(performance.now() < end, 'original real native READY exceeded its unchanged deadline'); await setImmediate(); }
  };
  await wait(() => scope.pollReserved(), performance.now() + 30_000);
  scope.createBlocked(); await wait(() => scope.pollReady(), performance.now() + 5000);
  // The genuine pre-preparation HELLO is the immutable historical origin.
  // READY is observed separately above. A live unfinished preparation must
  // still refuse a fresh ordinary-controller birth projection.
  assert.throws(() => readNativeControllerPreparationBirth(controller.preparationBirth), {
    code: 'RECOVERY_REQUIRED', message: 'original ordinary controller preparation birth is not ready',
  });
  const report: OriginalPreparingExit = { identity, input: input.identity, recipe,
    controller: controllerBirth };
  // A positive READY was obtained from the real existing protocol. Exit closes
  // the original driver domain; it never calls FINISH/CANCEL or invents joins.
  await new Promise<void>((resolve, reject) => process.send!(report, error => error ? reject(error) : resolve()));
  process.exit(0);
}

async function qualifyPreparingGitSuccessor(selected: { stateVolume: string }, installation: import('../../../src/sandbox/linux-worker.js').LinuxWorkerInstallation,
  toolchain: NativeSuccessorConfiguration['toolchain'], resources: SandboxResourceSpec) {
  const root = await mkdtemp(path.join(selected.stateVolume, 'cliq-native-preparing-successor-'));
  await chmod(root, 0o700);
  const casRoot = path.join(root, KERNEL_CAS_DIRECTORY); await mkdir(casRoot, { mode: 0o700 });
  const artifacts = new ActualArtifactCatalog(new ContentAddressedStore(casRoot));
  const data = preparingGitNativeInputData(canonicalSha256([root, 'repository-data']), resources);
  const leaf = await joinResourceOperations(data.map(bytes => artifacts.publishBytes(bytes, 'application/octet-stream', 'native-component-data')));
  const config: NativeSuccessorConfiguration = { root, installation, toolchain, resources, metadataRef: leaf[0]!.ref };
  const child = fork(new URL('./preparing-git-native.ts', import.meta.url), ['--native-preparing-original-exit'],
    { execArgv: ['--import', 'tsx'], stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let output = '', diagnostic = ''; child.stdout!.on('data', (b: Buffer) => { output = (output + b.toString()).slice(-4096); });
  child.stderr!.on('data', (b: Buffer) => { diagnostic = (diagnostic + b.toString()).slice(-4096); });
  const exited = once(child, 'exit');
  let lock: HeldStateOwnerLock | undefined, reservation: HeldWorkerReservation | undefined;
  let input: import('../../../src/state/native-owner.js').HeldRetainedPreparingGitInput | undefined;
  let launcher: Awaited<ReturnType<typeof openLinuxWorkerLauncher>> | undefined, controller: LinuxWorkerController | undefined;
  let primary: { error: unknown } | undefined, result: object | undefined, startedAt = 0, elapsedMs = 0; const failures: unknown[] = [];
  const messageAbort = new AbortController();
  const pending = once(child, 'message', { signal: AbortSignal.any([messageAbort.signal, AbortSignal.timeout(30_000)]) });
  // Observe both branches immediately: an early real child exit is a failure,
  // not a thirty-second wait or an unobserved timeout rejection.
  const received = Promise.race([pending.then(value => ({ kind: 'message' as const, value })),
    exited.then(status => ({ kind: 'exit' as const, status }))]);
  try {
    child.send(config);
    const first = await received;
    assert.equal(first.kind, 'message', diagnostic || output || 'original driver exited before real READY');
    if (first.kind !== 'message') throw new Error('original driver did not return its real READY observation');
    const [value] = first.value, original = value as OriginalPreparingExit;
    assert(original?.identity && original.input && original.recipe && original.controller, diagnostic || output);
    const status = await exited; assert.equal(status[0], 0, diagnostic || output); assert.equal(status[1], null);
    assert.equal(original.input.originalSupervisorPid, child.pid);
    const controllerDeadline = performance.now() + 2000;
    for (;;) {
      let absent = false;
      try {
        const stat = await readFile(`/proc/${original.controller.identity.pid}/stat`, 'utf8');
        const ticks = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/u)[19];
        absent = `linux-proc-start-ticks:${ticks}` !== original.controller.identity.processStartToken;
      } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') absent = true; else throw error; }
      if (absent) break;
      assert(performance.now() < controllerDeadline, 'the actual original controller did not exit within 2 seconds'); await setImmediate();
    }
    const native = await loadNativeStateOwner(); lock = native.acquireLock(root, false);
    reservation = lock.openWorkerReservation(original.input.launchId, original.input.spawnNonceDigest, original.input.reservation);
    input = openRetainedPreparingGitInput(lock, reservation, { runId: original.input.runId, generationId: original.input.generationId,
      launchId: original.input.launchId, spawnNonceDigest: original.input.spawnNonceDigest, activationNonceDigest: original.input.activationNonceDigest,
      generationCreationNonceDigest: original.input.generationCreationNonceDigest, generationRef: original.input.generationRef,
      inputIntentRef: original.input.inputIntentRef }, original.input.generation,
    { pid: original.input.originalSupervisorPid, processStartToken: original.input.originalSupervisorStartToken });
    launcher = await openLinuxWorkerLauncher(installation); controller = await launcher.startController();
    startedAt = performance.now();
    const receipt = await controller.cleanupRetainedPreparingGit({ input, recipe: original.recipe });
    const actual = readNativeRetainedPreparingGitRetirement(receipt);
    assert.equal(actual.observation.origin, 'original_birth_current_checker'); assert.equal(actual.observation.completed, 0);
    assert([5, 6, 7, 8, 9, 10].includes(actual.observation.lastBirthPhase));
    assert.equal(actual.observation.originalSupervisorPid, child.pid);
    assert.equal(actual.observation.originalControllerPid, original.controller.identity.pid);
    assert.equal(actual.observation.originalControllerStartToken, original.controller.identity.processStartToken);
    input.close(); reservation.close(); assertRetainedPreparingGitInputOwner(lock, input);
    const generation = observeRetainedPreparingGeneration(lock, original.identity, 1, receipt);
    const observed = readRetainedPreparingGenerationRetirement(lock, generation, receipt);
    assert.equal(observed.observedState.kind, 'unverified_preparation');
    const quarantine = lock.quarantineGeneration(original.identity, 1);
    assert.equal(quarantine.originalLocatorAbsent, true); assert.equal(quarantine.directoryFsyncComplete, true);
    result = { scenario: 'preparing-ready-original-exit-current-checker', originalDriverExited: true,
      originalControllerDead: true, retirement: actual.observation, checker: actual.checker,
      generation: observed, reservationJoined: true, quarantine,
      scope: 'native resource component only; no SQL StateOwner, accepted Run, original completion or final worker BIND' };
  } catch (error) { primary = { error }; }
  finally {
    messageAbort.abort(); await pending.catch(() => undefined);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    try { await exited; } catch (error) { failures.push(error); }
    if (controller) try { await controller.close(); } catch (error) { failures.push(error); }
    if (launcher) try { await launcher.close(); } catch (error) { failures.push(error); }
    for (const owned of [input, reservation, lock]) if (owned) try { owned.close(); } catch (error) { failures.push(error); }
    if (startedAt) elapsedMs = performance.now() - startedAt;
    // The owned fixture removal is test teardown. It occurs only after every
    // real producer/runtime/reader/lock join and the unchanged deadline check.
    if (!primary && !failures.length && startedAt && elapsedMs < 2000) await rm(root, { recursive: true });
  }
  if (failures.length) throw new ResourceRetirementError('native successor component did not actually join',
    new AggregateError([...(primary ? [primary.error] : []), ...failures]));
  if (primary) throw primary.error; assert(result); assert(startedAt);
  assert(elapsedMs < 2000, 'all current cleanup/runtime/readers/gen/quarantine/lock joins must stay within 2 seconds');
  return { ...result, elapsedMs };
}

if (process.argv[1] === fileURLToPath(import.meta.url) && process.argv[2] === '--native-preparing-original-exit') {
  const [value] = await once(process, 'message', { signal: AbortSignal.timeout(30_000) });
  await nativeOriginalReadyExit(value as NativeSuccessorConfiguration);
}
