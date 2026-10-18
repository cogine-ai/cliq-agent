import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { chmod, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting, identityHash } from '../../kernel/identity.js';
import type { FrozenIgnoreRulesV1, SourceManifest, SourceProjectionSpec, ToolContractManifestV1,
  WorkspaceEntryManifest, WorkspaceIdentityV1 } from '../../kernel/types.js';
import type { RunPolicySnapshotV1 } from '../../kernel/tool-authorization.js';
import { priceTableDigest } from '../../model/pricing.js';
import { reseal, testFixture } from '../../model/testing/fixtures.js';
import { BUILTIN_POLICY_RULES, modeDecisions } from '../../policy/tool-policy.js';
import type { ModelTextV1 } from '../../protocol/agent-ir.js';
import { sampleCanonicalNow } from '../../state/canonical-time.js';
import { openStateStore, publishInProcessChannel } from '../../state/store.js';
import { activateFixtureWorker, admissionKey, uuidv7 } from '../../state/testing/fixtures.js';
import { batch } from '../../state/testing/tool-calls.js';
import { quiescedToolCheckpoint } from '../../state/testing/tool-effects.js';
import { fixtureSandboxProfile } from '../../state/testing/worker-launch.js';
import { builtinInputContracts } from '../../tools/builtin-inputs.js';
import { signedLinuxWorkerTestRuntime } from './worker-runtime.js';
import { publishOfflineModelEndpoint } from '../../state/testing/model-endpoint.js';
import { readRetainedVerifierToolchain } from '../../state/guest-toolchain.js';
import { composeVerifierSpec } from '../../state/verifier-admission.js';
import type { VerifierRequest } from '../../kernel/control-submit.js';

/** Campaign setup only. Its model prefix and first worker retirement are
 * explicitly offline retained fixtures, never native execution evidence.
 * The later StateStore.loadRunExecution path must create and inspect the real
 * signed processes, generation, edit effect and complete containment death. */
export async function createLinuxWorkerCampaignFixture(input: {
  installationRoot: string; cgroupParent: string; stateVolume: string; label: string; paddingBytes?: number;
  edit?: { contents: Uint8Array; oldText: string; newText: string };
  resultLimits?: Pick<SourceProjectionSpec, 'maxChangedPaths' | 'maxChangedBytes'>;
  verifier?: { guestImageRoot: string; script: Uint8Array; sourceExecutable?: Uint8Array;
    timeoutMs?: number; outputLimitBytes?: number; maxOpenFiles?: number };
}) {
  if (process.platform !== 'linux') throw new Error('Linux worker campaign requires Linux; no skipped qualification');
  const stateRoot = await mkdtemp(path.join(input.stateVolume, 's-'));
  const workspace = await mkdtemp(path.join(input.stateVolume, 'w-'));
  await chmod(stateRoot, 0o700); await chmod(workspace, 0o700);
  const original = Buffer.concat([input.edit ? Buffer.from(input.edit.contents) : Buffer.from('before\n'),
    Buffer.alloc(input.paddingBytes ?? 0, 0x78)]);
  await writeFile(path.join(workspace, 'a'), original, { mode: 0o644 });
  if (input.verifier) await writeFile(path.join(workspace, 'check.test.mjs'), input.verifier.script, { mode: 0o644 });
  if (input.verifier?.sourceExecutable) await writeFile(path.join(workspace, 'untrusted-elf'), input.verifier.sourceExecutable, { mode: 0o755 });
  const authority = testFixture();
  const builtin = builtinInputContracts.edit;
  const selected = [{ name: builtin.name, description: 'Edit the private file once', inputSchema: builtin.inputSchema,
    inputSchemaRef: canonicalSha256(builtin.inputSchema), inputSchemaDigest: canonicalSha256(builtin.inputSchema), replayClass: builtin.replayClass }];
  const manifest: ToolContractManifestV1 = { schemaVersion: 1, format: 'cliq-tool-contracts-v1', entries: [{
    name: builtin.name, version: '1', description: selected[0].description, access: builtin.access,
    inputSchemaRef: selected[0].inputSchemaRef, inputSchemaDigest: selected[0].inputSchemaDigest,
    replayClass: builtin.replayClass, execution: { kind: 'builtin', adapterId: 'edit', adapterVersion: '1', adapterCodeDigest: '' }
  }], manifestDigest: '' };
  const sandbox = fixtureSandboxProfile();
  Object.assign(sandbox.resources, { maxProcesses: 32, memoryBytes: 256 * 1024 ** 2, cpuQuotaMicrosPerSecond: 100000,
    maxOpenFiles: input.verifier?.maxOpenFiles ?? 128, maxSingleFileBytes: (input.verifier ? 256 : 16) * 1024 ** 2,
    maxGenerationBytes: 256 * 1024 ** 2 });
  sandbox.profileDigest = digestOmitting(sandbox, 'profileDigest');
  const signed = await signedLinuxWorkerTestRuntime({ installationRoot: input.installationRoot,
    assembly: authority.assembly, tools: manifest.entries, sandboxProfile: sandbox,
    ...(input.verifier ? { guestImageRoot: input.verifier.guestImageRoot } : {}) });
  manifest.manifestDigest = digestOmitting(manifest, 'manifestDigest');
  authority.assembly.provider.negotiation.exposedToolNames = ['edit'];
  assert.equal(builtin.replayClass, 'manual');
  authority.assembly.retry.tools = [{ toolName: 'edit', replayClass: 'manual',
    maxDispatchedAttempts: 1, postAttemptDelaysMs: [] }];
  const runtimeAuthority = { bundle: signed.bundle, releaseKeys: signed.releaseKeys,
    execution: { installationRoot: input.installationRoot, cgroupParent: input.cgroupParent } };
  const store = await openStateStore(stateRoot, runtimeAuthority);
  try {
    if (signed.guest) {
      for (const object of signed.guest.objects) {
        const published = await store.artifacts.publishBytes(object.bytes, 'application/octet-stream', 'actual-signed-guest-member');
        assert.equal(published.ref, object.ref);
      }
      const image = await open(signed.guest.imagePath, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const published = await store.artifacts.publishChunks(image.createReadStream({ autoClose: false, start: 0 }),
          'application/octet-stream', 'cliq-guest-image-raw-ext4-v1', signed.guest.manifest.guestImageByteCount);
        assert.equal(published.ref, signed.guest.manifest.guestImageRef);
        assert.equal(published.byteLength, signed.guest.manifest.guestImageByteCount);
      } finally { await image.close(); }
    }
    const { principalId, ...channel } = await publishInProcessChannel(store);
    const session = await store.createSession({ principalId, ...channel, requestId: uuidv7(),
      admissionKey: admissionKey(`${input.label}-session`), workspacePath: workspace });
    const workspaceIdentity = await store.artifacts.readCanonical<WorkspaceIdentityV1>(session.session.workspaceIdentityRef);
    const endpoint = await publishOfflineModelEndpoint({ artifacts: store.artifacts, principalId,
      bundle: signed.bundle, trustStorePem: signed.trustStorePem, createdAt: sampleCanonicalNow() });
    const credentials = endpoint.credentialRefs;
    authority.assembly.provider.endpoint = endpoint.endpoint;
    authority.material.capabilityEvidence.value.endpointIdentityDigest = endpoint.endpoint.endpointIdentityDigest;
    authority.material.priceTable!.value.endpointIdentityDigest = endpoint.endpoint.endpointIdentityDigest;
    authority.material.verifyProviderEndpoint = input => input.provider === authority.assembly.provider.name &&
      input.model === authority.assembly.provider.model && canonicalSha256(input.endpoint) === canonicalSha256(endpoint.endpoint) &&
      canonicalSha256(input.credentialGrantRefs) === canonicalSha256(credentials);
    authority.assembly.provider.credentialGrantRefs = credentials;
    authority.material.additionalCredentialGrantRefs = [];
    authority.runSpecCredentialGrantRefs = credentials;
    await store.artifacts.publishCanonical(builtin.inputSchema, 'cliq-tool-input-schema-v1');
    const contracts = await store.artifacts.publishCanonical(manifest, manifest.format);
    authority.assembly.tools = { manifestRef: contracts.ref, manifestDigest: manifest.manifestDigest };
    authority.material.resolveVerifiedTools = reference => reference.manifestRef === contracts.ref &&
      reference.manifestDigest === manifest.manifestDigest ? selected : null;
    const text: ModelTextV1 = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: 'Use tools carefully.', byteCount: 20, textDigest: '' };
    text.textDigest = digestOmitting(text, 'textDigest');
    const system = await store.artifacts.publishCanonical(text, text.format);
    const instructions = { schemaVersion: 1, format: 'cliq-workspace-instructions-v1', entries: [], manifestDigest: '' };
    instructions.manifestDigest = digestOmitting(instructions, 'manifestDigest');
    const instructionsRef = (await store.artifacts.publishCanonical(instructions, instructions.format)).ref;
    Object.assign(authority.assembly.instructions, { systemPromptRef: system.ref, systemPromptDigest: text.textDigest,
      workspaceInstructionsRef: instructionsRef, workspaceInstructionsDigest: instructions.manifestDigest });
    for (const part of [authority.material.compactionEnvelope.systemInstruction, authority.material.compactionEnvelope.userPrefix,
      authority.material.compactionEnvelope.userSuffix, authority.material.compactionEnvelope]) {
      await store.artifacts.publishCanonical(part.value, part.value.format);
    }
    await store.artifacts.publishCanonical(signed.profile, signed.profile.format);
    const createdAt = sampleCanonicalNow(), validThrough = new Date(Date.parse(createdAt) + 180_000).toISOString();
    authority.assembly.createdAt = createdAt;
    const capability = authority.material.capabilityEvidence.value;
    Object.assign(capability, { observedAt: createdAt, validThrough });
    if (capability.source.kind !== 'signed_catalog') throw new Error('campaign expects offline signed-catalog model fixture');
    capability.source.runtimeBundleRef = authority.assembly.runtime.runtimeBundleRef;
    capability.evidenceDigest = digestOmitting(capability, 'evidenceDigest');
    authority.material.capabilityEvidence.ref = canonicalSha256(capability);
    Object.assign(authority.assembly.provider.negotiation, { capabilityEvidenceRef: authority.material.capabilityEvidence.ref,
      capabilityDigest: capability.evidenceDigest });
    const prices = authority.material.priceTable!;
    Object.assign(prices.value, { validFrom: createdAt, validThrough });
    prices.value.tableDigest = priceTableDigest(prices.value); prices.ref = canonicalSha256(prices.value);
    if (authority.assembly.provider.pricing.kind !== 'trusted_price_table') throw new Error('campaign expects offline price fixture');
    Object.assign(authority.assembly.provider.pricing, { priceTableRef: prices.ref, priceTableDigest: prices.value.tableDigest, validThrough });
    await store.artifacts.publishCanonical(prices.value, prices.value.format);
    reseal(authority);
    const assemblyRef = (await store.artifacts.publishCanonical(authority.assembly, authority.assembly.format)).ref;
    const rules: FrozenIgnoreRulesV1 = { schemaVersion: 1, format: 'cliq-frozen-ignore-rules-v1',
      matcherVersion: 'cliq-git-wildmatch-v1', sources: [], rules: [], rulesDigest: '' };
    rules.rulesDigest = digestOmitting(rules, 'rulesDigest');
    const rulesRef = (await store.artifacts.publishCanonical(rules, rules.format)).ref;
    const projection: SourceProjectionSpec = { schemaVersion: 1, matcherVersion: 'cliq-exact-path-v1', frozenIgnoreRulesRef: rulesRef,
      frozenIgnoreRulesDigest: rules.rulesDigest, explicitIncludes: [], explicitExcludes: [],
      maxChangedPaths: input.resultLimits?.maxChangedPaths ?? 1000,
      maxChangedBytes: input.resultLimits?.maxChangedBytes ?? 16 * 1024 ** 2, projectionDigest: '' };
    projection.projectionDigest = digestOmitting(projection, 'projectionDigest');
    const projectionRef = (await store.artifacts.publishCanonical(projection, 'cliq-source-projection-v1')).ref;
    // Capture this declared one-file, non-Git test workspace. No fake snapshot
    // or death observation is used by the productive execution that follows.
    assert.deepEqual(await readFile(path.join(workspace, 'a')), original);
    const blob = await store.artifacts.publishBytes(original, 'application/octet-stream', 'cliq-workspace-file-v1');
    const sourceEntries: WorkspaceEntryManifest['entries'] = [{ kind: 'file', path: 'a', mode: 0o644, size: original.length, blobRef: blob.ref }];
    if (input.verifier) {
      const script = await store.artifacts.publishBytes(input.verifier.script, 'application/octet-stream', 'cliq-workspace-file-v1');
      sourceEntries.push({ kind: 'file', path: 'check.test.mjs', mode: 0o644, size: input.verifier.script.length, blobRef: script.ref });
      if (input.verifier.sourceExecutable) {
        const executable = await store.artifacts.publishBytes(input.verifier.sourceExecutable, 'application/octet-stream', 'cliq-workspace-file-v1');
        sourceEntries.push({ kind: 'file', path: 'untrusted-elf', mode: 0o755, size: input.verifier.sourceExecutable.length, blobRef: executable.ref });
      }
    }
    const entries: WorkspaceEntryManifest = { schemaVersion: 1, format: 'cliq-workspace-entries-v1', entries: sourceEntries,
      entryCount: sourceEntries.length, byteCount: original.length + (input.verifier?.script.length ?? 0) +
        (input.verifier?.sourceExecutable?.length ?? 0), treeDigest: '' };
    entries.treeDigest = canonicalSha256({ schemaVersion: 1, format: entries.format, entries: entries.entries });
    const entriesRef = (await store.artifacts.publishCanonical(entries, entries.format)).ref;
    const source: SourceManifest = { schemaVersion: 1, format: 'cliq-source-manifest-v1', role: 'base',
      workspaceIdentityDigest: workspaceIdentity.identityDigest, entriesRef, sourceProjectionRef: projectionRef,
      sourceProjectionDigest: projection.projectionDigest, frozenIgnoreRulesRef: rulesRef, frozenIgnoreRulesDigest: rules.rulesDigest,
      treeDigest: entries.treeDigest, manifestDigest: '' };
    source.manifestDigest = digestOmitting(source, 'manifestDigest');
    const sourceRef = (await store.artifacts.publishCanonical(source, source.format)).ref;
    const verifierRequests: VerifierRequest[] = [];
    if (input.verifier) {
      assert.ok(signed.guest);
      const identity = await publishInProcessChannel(store);
      const core = { protocolVersion: 1, method: 'authorization.create', requestId: uuidv7(), decision: {
        kind: 'execution_identity_read', purpose: 'verifier', target: { kind: 'guest_toolchain',
          guestToolchainManifestId: signed.guest.manifestId, toolId: 'node' } } };
      const created = await store.createAuthorization({ ...core, requestDigest: canonicalSha256(core) }, identity);
      verifierRequests.push({ id: 'actual-node-tests', version: '1', required: true, executable: { kind: 'toolchain', toolId: 'node' },
        argv: [{ kind: 'non_secret_literal', value: '--test' }, { kind: 'non_secret_literal', value: '--test-concurrency=1' },
          { kind: 'non_secret_literal', value: 'check.test.mjs' }], cwd: '.', env: {}, writableEphemeralPaths: [],
        identityReadGrantId: created.response.result.grant.grantId, timeoutMs: input.verifier.timeoutMs ?? 10_000,
        retries: 0, outputLimitBytes: input.verifier.outputLimitBytes ?? 65_536 });
    }
    const composed = composeVerifierSpec({ requests: verifierRequests, assembly: authority.assembly, sourceProjectionRef: projectionRef,
      ...(signed.guest ? { toolchain: await readRetainedVerifierToolchain(store.artifacts, { bundle: signed.bundle,
        releaseKeys: signed.releaseKeys, guestToolchainManifestRef: signed.guest.manifestRef }) } : {}) });
    for (const artifact of composed.artifacts) assert.equal((await store.artifacts.publishCanonical(artifact.value, artifact.format)).ref, artifact.ref);
    const verifierRef = composed.specRef;
    const mode = input.verifier ? 'yolo' : 'accept-edits';
    const policy: RunPolicySnapshotV1 = { schemaVersion: 1, format: 'cliq-run-policy-v1', principalId,
      workspaceIdentityDigest: workspaceIdentity.identityDigest, mode, engine: signed.engine,
      toolManifestRef: contracts.ref, toolManifestDigest: manifest.manifestDigest, decisions: modeDecisions(mode),
      decisionRules: [...BUILTIN_POLICY_RULES], repositoryRequestRefs: [], createdAt: sampleCanonicalNow(), policyDigest: '' };
    policy.policyDigest = digestOmitting(policy, 'policyDigest');
    const admitted = await store.admitRun({ principalId, ...channel, requestId: uuidv7(), admissionKey: admissionKey(`${input.label}-run`),
      sessionId: session.session.id, expectedContextRevision: 1, workspacePath: workspace, objective: 'Edit the private file exactly once',
      allowUnverified: !input.verifier, credentialGrantRefs: credentials, budgets: { wallTimeMs: 120_000 }, assemblyRef,
      sourceProjectionRef: projectionRef, frozenIgnoreRulesRef: rulesRef, baseWorkspaceManifestRef: sourceRef, verifierSpecRef: verifierRef,
      ...(input.verifier ? { verifierRequests } : {}),
      policyRef: (await store.artifacts.publishCanonical(policy, policy.format)).ref,
      sandboxProfileRef: (await store.artifacts.publishCanonical(sandbox, sandbox.format)).ref });
    const queued = { stateRoot, workspace, store, principalId, channelIdentityRef: channel.channelIdentityRef,
      runtimeAuthority, runId: admitted.run.id, runRevision: admitted.run.revision };
    const active = await activateFixtureWorker(queued, `offline-${input.label}`);
    const agent = await store.loadAgentRun({ runId: queued.runId, material: authority.material, releaseKeys: signed.releaseKeys });
    const fixture = { ...queued, ...active, authority, agent, signed };
    await batch(fixture, [{ name: 'edit', input: { path: 'a',
      old_text: input.edit?.oldText ?? 'before', new_text: input.edit?.newText ?? 'after' } }]);
    const beforeSeal = await store.readRecoveryClosure(queued.runId);
    const checkpointId = identityHash('cliq-offline-campaign-prefix-checkpoint-v1', queued.runId);
    const prefixProof = await quiescedToolCheckpoint(fixture, checkpointId);
    const checkpointing = await store.readRecoveryClosure(queued.runId);
    const offlineGeneration = checkpointing.workspaceGenerations.find(row => row.generationRef === active.generationRef)!;
    await store.sealWorkerGeneration({ launchId: active.launchId, expectedRunRevision: beforeSeal.run.revision,
      expectedGenerationRowVersion: offlineGeneration.rowVersion, quiesceId: 'tool-test-quiesce', checkpointId,
      contextManifestRef: beforeSeal.latestCheckpoint.contextManifestRef, workspaceStateRef: prefixProof.checkpoint.workspaceStateRef,
      snapshotEvidenceRef: prefixProof.checkpoint.snapshotEvidenceRef, snapshotEvidenceDigest: prefixProof.snapshot.evidenceDigest,
      retirementEvidenceRef: prefixProof.checkpoint.retirementEvidenceRef, checkpointReason: 'auto' });
    assert.equal(store.getRun(queued.runId).status, 'queued');
    assert.equal(store.getRun(queued.runId).activeWorkerLaunchId, undefined);
    return { ...fixture, original, sessionId: session.session.id,
      async dispose() { await store.close(); await rm(stateRoot, { recursive: true, force: true }); await rm(workspace, { recursive: true, force: true }); } };
  } catch (error) {
    await store.close(); await rm(stateRoot, { recursive: true, force: true }); await rm(workspace, { recursive: true, force: true }); throw error;
  }
}
