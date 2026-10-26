// Real CAS + Ed25519 data regression only. No StateOwner, accepted Run,
// OperationGrant capability, process, native receipt or physical proof exists.
import assert from 'node:assert/strict';
import { mkdtemp, rm, rename } from 'node:fs/promises';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import { digestOmitting } from '../kernel/identity.js';
import type { InvocationJournalEntry, ToolContractManifestV1, WorkspaceGenerationStateV1 } from '../kernel/types.js';
import type { ToolOperationGrantV1, ToolRequestV1, ToolTargetV1 } from '../kernel/tool-authorization.js';
import type { SandboxLaunchSpecV1 } from '../kernel/execution.js';
import type { ToolCallInputV1 } from '../protocol/agent-ir.js';
import { testFixture } from '../model/testing/fixtures.js';
import { builtinInputContracts } from '../tools/builtin-inputs.js';
import { ArtifactCatalog } from './artifacts.js';
import { ContentAddressedStore } from './cas.js';
import { signedVerifierAuthority } from './testing/verifier-authority.js';
import { fixtureSandboxProfile } from './testing/worker-launch.js';
import { LINUX_VERIFIER_RECIPE } from '../sandbox/linux-worker.js';
import { hasOnlySettledPrivateToolUnknowns, readPrivateRollbackClaim } from './private-tool-rollback.js';
import { ResourceRetirementError } from './errors.js';

async function fixture(tool: 'read' | 'ls' | 'find' | 'grep' | 'bash') {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-script-rollback-data-'));
  const cas = new ContentAddressedStore(directory), artifacts = new ArtifactCatalog(cas);
  const signed = await signedVerifierAuthority({ builtinScriptBytes: Buffer.from('// inert signed data; never execute\n') });
  for (const object of signed.objects) await artifacts.publishBytes(object.bytes, 'application/octet-stream', 'offline-data');
  const bundleRef = (await artifacts.publishCanonical(signed.bundle, 'cliq-runtime-bundle-v1')).ref;
  const builtin = builtinInputContracts[tool], script = signed.bundle.entries.find(entry => entry.entryId === 'builtin_tools')!;
  const inputSchemaRef = (await artifacts.publishCanonical(builtin.inputSchema, 'cliq-tool-input-schema-v1')).ref;
  const execution = { kind: 'builtin_script' as const, adapterId: 'builtin_tools' as const, adapterVersion: '1' as const,
    adapterCodeDigest: script.digest, guestToolchainManifestRef: signed.manifestRef, guestToolchainManifestDigest: signed.manifest.manifestDigest,
    toolId: 'node' as const, executionPath: '/usr/bin/node' as const, executableDigest: signed.manifest.node.digest };
  const contract = { name: tool, version: '1', description: 'inert rollback fixture', access: builtin.access,
    replayClass: builtin.replayClass, inputSchemaRef, inputSchemaDigest: inputSchemaRef, execution };
  const manifest: ToolContractManifestV1 = { schemaVersion: 1, format: 'cliq-tool-contracts-v1', entries: [contract], manifestDigest: '' };
  manifest.manifestDigest = digestOmitting(manifest, 'manifestDigest');
  const manifestRef = (await artifacts.publishCanonical(manifest, manifest.format)).ref;
  const assembly = testFixture().assembly;
  assembly.tools = { manifestRef, manifestDigest: manifest.manifestDigest };
  Object.assign(assembly.runtime, { runtimeBundleRef: bundleRef, runtimeBundleManifestDigest: signed.bundle.manifestDigest,
    guestToolchainManifestRef: signed.manifestRef, guestToolchainManifestDigest: signed.manifest.manifestDigest });
  assembly.assemblyDigest = digestOmitting(assembly, 'assemblyDigest');
  const assemblyRef = (await artifacts.publishCanonical(assembly, assembly.format)).ref;
  const input = tool === 'bash' ? { command: 'printf original' } : tool === 'find' ? { path: '.', name: '*.ts' }
    : tool === 'grep' ? { path: '.', pattern: 'original' } : { path: 'original.txt' };
  const call: ToolCallInputV1 = { schemaVersion: 1, format: 'cliq-tool-call-input-v1', callId: 'original-call', index: 0, toolName: tool,
    observedInputRef: canonicalSha256('inert observation'), observedInputDigest: canonicalSha256('inert observation semantics'),
    disposition: 'resolved', value: input, inputSchemaRef, inputSchemaDigest: inputSchemaRef, inputDigest: '' };
  call.inputDigest = digestOmitting(call, 'inputDigest');
  const inputRef = (await artifacts.publishCanonical(call, call.format)).ref;
  const target: ToolTargetV1 = { schemaVersion: 1, format: 'cliq-tool-target-v1', runId: 'data-run',
    workspaceIdentityRef: canonicalSha256('inert workspace'), workspaceIdentityDigest: canonicalSha256('inert workspace digest'),
    toolManifestRef: manifestRef, toolManifestDigest: manifest.manifestDigest, toolName: tool,
    toolContractDigest: canonicalSha256(contract), execution, targetDigest: '' };
  target.targetDigest = digestOmitting(target, 'targetDigest');
  const targetRef = (await artifacts.publishCanonical(target, target.format)).ref;
  const request: ToolRequestV1 = { schemaVersion: 1, format: 'cliq-tool-request-v1', runId: 'data-run', opId: 'original-op',
    frontierRef: canonicalSha256('inert frontier'), assemblyRef, batchItemId: 'original-batch', callId: call.callId, callIndex: 0,
    toolName: tool, inputRef, inputDigest: call.inputDigest, targetRef, targetDigest: target.targetDigest, requestDigest: '' };
  request.requestDigest = digestOmitting(request, 'requestDigest');
  const requestRef = (await artifacts.publishCanonical(request, request.format)).ref;
  // This is an inert retained claim projection. The outer production reader
  // separately reproduces the complete policy/grant; no capability is minted.
  const grant = { requestRef, targetRef, subject: { replayClass: builtin.replayClass }, grantDigest: '' } as ToolOperationGrantV1;
  grant.grantDigest = digestOmitting(grant, 'grantDigest');
  const grantRef = (await artifacts.publishCanonical(grant, 'offline-grant-data')).ref;
  const generationRef = canonicalSha256('inert original generation'), parentRef = canonicalSha256('inert parent containment');
  const owner = { kind: 'run_invocation' as const, runId: request.runId, intendedLeaseEpoch: 1, workerLaunchId: 'original-worker',
    opId: request.opId, attempt: 0, dispatchId: 'original-dispatch' };
  const at = '2026-10-26T00:00:00.000Z';
  const plan = { schemaVersion: 1, format: 'cliq-process-containment-plan-v1', owner,
    filesystemBinding: { kind: 'run-generation', generationRef }, parentContainmentRef: parentRef,
    launchNonceDigest: canonicalSha256('inert original nonce'), backend: { kind: 'linux', cgroupPath: '/cliq/data/original',
      cgroupNameReservationDigest: canonicalSha256('inert reservation'), pidNamespaceReservationId: 'original-namespace', subreaperStartToken: '1' },
    createdAt: at, planDigest: '' };
  plan.planDigest = digestOmitting(plan, 'planDigest');
  const planRef = (await artifacts.publishCanonical(plan, plan.format)).ref;
  const runtime = { runtimeBundleRef: bundleRef, runtimeBundleManifestDigest: signed.bundle.manifestDigest, sandboxBackend: 'linux_namespace' as const,
    launcher: { executableId: 'inert-launcher', executableDigest: canonicalSha256('inert launcher') }, toolchain: {
      kind: 'guest_toolchain' as const, guestToolchainManifestRef: signed.manifestRef, guestToolchainManifestDigest: signed.manifest.manifestDigest,
      guestImageRef: signed.manifest.guestImageRef, guestImageDigest: signed.manifest.guestImageDigest }, runtimeDigest: '' };
  runtime.runtimeDigest = digestOmitting(runtime, 'runtimeDigest');
  const profile = fixtureSandboxProfile();
  const spec: Extract<SandboxLaunchSpecV1, { owner: { kind: 'run_invocation' } }> = { schemaVersion: 1, format: 'cliq-sandbox-launch-v1',
    owner, purpose: 'tool', runtime, executable: { kind: 'guest_toolchain', guestToolchainManifestRef: signed.manifestRef,
      guestToolchainManifestDigest: signed.manifest.manifestDigest, toolId: 'node', role: 'tool', executionPath: '/usr/bin/node', executableDigest: signed.manifest.node.digest },
    processInvocation: { kind: 'run_request', purpose: 'tool', recipe: 'cliq-builtin-tools-v1', privateGitProtection: 'existing_read_only', requestRef, requestDigest: request.requestDigest,
      targetRef, targetDigest: target.targetDigest, argvCwdSource: 'trusted_recipe_decode_of_request_and_target',
      stdio: { stdin: 'closed', stdout: 'captured', stderr: 'captured', extraFileDescriptors: 'authenticated_operation_channel_only' } },
    environment: LINUX_VERIFIER_RECIPE.environment, filesystem: { kind: 'run_generation', generationRef,
      access: tool === 'bash' ? 'read_write' : 'read_only', sourceProjectionRef: canonicalSha256('inert projection'), independentGit: true },
    mounts: [], mountsDigest: canonicalSha256([]), sandboxProfileRef: canonicalSha256(profile), sandboxProfileDigest: profile.profileDigest,
    resources: profile.resources, resourcesDigest: canonicalSha256(profile.resources), containmentPlanRef: planRef, containmentPlanDigest: plan.planDigest,
    operationGrantRef: grantRef, requestRef, requestDigest: request.requestDigest, targetRef, targetDigest: target.targetDigest,
    parentWorkerContainmentRef: parentRef, createdAt: at, launchSpecDigest: '' };
  spec.launchSpecDigest = digestOmitting(spec, 'launchSpecDigest');
  const specRef = (await artifacts.publishCanonical(spec, spec.format)).ref;
  const prepared: InvocationJournalEntry = { runId: request.runId, seq: 1, opId: request.opId, opKind: 'tool', attempt: 0, leaseEpoch: 1,
    phase: 'prepared', target: targetRef, requestRef, grantRef, replayClass: builtin.replayClass,
    budgetDelta: { modelTokens: 0, costMicros: 0, toolCalls: 1, repairAttempts: 0 }, timestamp: at };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: owner.dispatchId, sandboxLaunchSpecRef: specRef };
  const unknown: InvocationJournalEntry = { ...claim, seq: 3, phase: 'unknown', budgetSettlementRef: canonicalSha256('inert full original settlement') };
  const generation = { generationRef } as WorkspaceGenerationStateV1;
  return { directory, artifacts, signed, spec, prepared, claim, unknown, generation,
    read: () => readPrivateRollbackClaim(artifacts, prepared, claim, unknown, generation) };
}

for (const tool of ['read', 'ls', 'find', 'grep', 'bash'] as const) test(`fixed ${tool} rollback retains UNKNOWN and its original pessimistic settlement without redispatch`, async () => {
  const value = await fixture(tool);
  try {
    const before = structuredClone(value.unknown);
    assert(hasOnlySettledPrivateToolUnknowns([value.prepared, value.claim, value.unknown]));
    const closed = await value.read(); assert.equal(closed.request.toolName, tool);
    assert.deepEqual(value.unknown, before); assert.equal(value.unknown.phase, 'unknown');
    assert(closed.spec.filesystem.kind === 'run_generation');
    assert.equal(closed.spec.filesystem.access, tool === 'bash' ? 'read_write' : 'read_only');
    for (const mutate of [
      (spec: typeof value.spec) => { if (spec.filesystem.kind === 'run_generation') spec.filesystem.access = tool === 'bash' ? 'read_only' : 'read_write'; },
      (spec: typeof value.spec) => { if (spec.executable.kind === 'guest_toolchain') spec.executable.executableDigest = canonicalSha256('foreign Node'); },
      (spec: typeof value.spec) => { delete (spec.processInvocation as { privateGitProtection?: unknown }).privateGitProtection; },
      (spec: typeof value.spec) => { (spec.processInvocation as { privateGitProtection?: unknown }).privateGitProtection = 'read_write'; },
      (spec: typeof value.spec) => { if (spec.processInvocation.kind === 'run_request' && spec.processInvocation.purpose === 'tool') spec.processInvocation.recipe = 'cliq-tool-launch-v1'; }
    ]) {
      const changed = structuredClone(value.spec); mutate(changed); changed.launchSpecDigest = digestOmitting(changed, 'launchSpecDigest');
      const artifact = await value.artifacts.publishCanonical(changed, changed.format), old = value.claim.sandboxLaunchSpecRef;
      value.claim.sandboxLaunchSpecRef = artifact.ref;
      await assert.rejects(value.read()); value.claim.sandboxLaunchSpecRef = old;
    }
    const scriptRef = value.signed.bundle.entries.find(entry => entry.entryId === 'builtin_tools')!.digest;
    const scriptPath = path.join(value.directory, scriptRef), saved = `${scriptPath}.original`;
    await rename(scriptPath, saved);
    try { await assert.rejects(value.read()); } finally { await rename(saved, scriptPath); }
    assert.deepEqual(value.unknown, before);
    await assert.rejects(readPrivateRollbackClaim(value.artifacts, value.prepared, value.claim,
      { ...value.unknown, budgetSettlementRef: undefined }, value.generation));
    assert.equal(hasOnlySettledPrivateToolUnknowns([value.prepared, value.claim,
      { ...value.unknown, budgetDelta: { ...value.unknown.budgetDelta, toolCalls: 0 } }]), false);
  } finally { await rm(value.directory, { recursive: true, force: true }); }
});

test('script rollback data rewalk preserves a real consumed-descriptor close failure as retirement uncertainty', async t => {
  const value = await fixture('read'), before = structuredClone(value.unknown);
  const script = value.signed.bundle.entries.find(entry => entry.entryId === 'builtin_tools')!;
  const originalOpen = fs.open, failure = Object.assign(new Error('owned actual read close failure'), { code: 'EIO' });
  let actualCloses = 0;
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    if (args[0] === path.join(value.directory, script.digest)) {
      const close = handle.close.bind(handle);
      handle.close = async () => { await close(); actualCloses++; throw failure; };
    }
    return handle;
  });
  try {
    await assert.rejects(value.read(), error => error instanceof ResourceRetirementError && error.cause === failure);
    assert.equal(actualCloses, 1); assert.deepEqual(value.unknown, before);
  } finally { await rm(value.directory, { recursive: true, force: true }); }
});
