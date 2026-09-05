import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting } from '../../kernel/identity.js';
import type { ToolContractManifestV1, RunSpec } from '../../kernel/types.js';
import type { ModelTextV1 } from '../../protocol/agent-ir.js';
import { reseal, testFixture } from '../../model/testing/fixtures.js';
import { createActiveFixture, disposeFixture } from './fixtures.js';
import { builtinInputContracts } from '../../tools/builtin-inputs.js';
import { signedToolBundle } from './tool-authority.js';
import { BUILTIN_POLICY_RULES, modeDecisions } from '../../policy/tool-policy.js';
import type { RunPolicySnapshotV1 } from '../../kernel/tool-authorization.js';
import { sampleCanonicalNow } from '../canonical-time.js';

/** Real CAS + SQLite/lease, with offline signed-authority verification fixtures; no provider or tool I/O. */
export async function createAgentFixture(label: string, budgets?: Partial<RunSpec['budgets']>, options: {
  tools?: Array<keyof typeof builtinInputContracts>; mode?: RunPolicySnapshotV1['mode'];
  rules?: RunPolicySnapshotV1['decisionRules']; outputSchema?: unknown;
} = {}) {
  const authority = testFixture();
  const builtins = (options.tools ?? ['read']).map((name) => builtinInputContracts[name]);
  const selected = builtins.map((builtin) => ({ name: builtin.name, description: `Use ${builtin.name}`, inputSchema: builtin.inputSchema,
    inputSchemaRef: canonicalSha256(builtin.inputSchema), inputSchemaDigest: canonicalSha256(builtin.inputSchema), replayClass: builtin.replayClass }));
  authority.assembly.provider.negotiation.exposedToolNames = selected.map((tool) => tool.name).sort();
  authority.assembly.retry.tools = selected.map((tool) => tool.replayClass === 'retry'
    ? { toolName: tool.name, replayClass: 'retry', maxDispatchedAttempts: 3, postAttemptDelaysMs: [500, 2000] }
    : { toolName: tool.name, replayClass: 'manual', maxDispatchedAttempts: 1, postAttemptDelaysMs: [] });
  let signed: Awaited<ReturnType<typeof signedToolBundle>> | undefined;
  const credentials: string[] = [];
  const fixture = await createActiveFixture(label, { budgets, credentialGrantRefs: credentials, assembly: async (store) => {
    const grant = await store.artifacts.publishCanonical({ format: 'cliq-offline-credential-fixture-v1' }, 'cliq-offline-credential-fixture-v1');
    credentials.push(grant.ref);
    authority.assembly.provider.credentialGrantRefs = credentials;
    authority.material.additionalCredentialGrantRefs = [];
    authority.runSpecCredentialGrantRefs = credentials;
    for (const tool of selected) await store.artifacts.publishCanonical(tool.inputSchema, 'cliq-tool-input-schema-v1');
    if (options.outputSchema !== undefined) await store.artifacts.publishCanonical(options.outputSchema, 'cliq-tool-output-schema-v1');
    const manifest: ToolContractManifestV1 = { schemaVersion: 1, format: 'cliq-tool-contracts-v1', entries: selected.map((tool, index) => ({
      name: tool.name, version: '1', description: tool.description, access: builtins[index]!.access, inputSchemaRef: tool.inputSchemaRef,
      inputSchemaDigest: tool.inputSchemaDigest, replayClass: tool.replayClass, execution: { kind: 'builtin', adapterId: tool.name,
        adapterVersion: '1', adapterCodeDigest: canonicalSha256({ adapter: tool.name }) },
      ...(options.outputSchema === undefined ? {} : { outputSchemaRef: canonicalSha256(options.outputSchema), outputSchemaDigest: canonicalSha256(options.outputSchema) })
    })), manifestDigest: '' };
    manifest.manifestDigest = digestOmitting(manifest, 'manifestDigest');
    const root = await store.artifacts.publishCanonical(manifest, manifest.format);
    authority.assembly.tools = { manifestRef: root.ref, manifestDigest: manifest.manifestDigest };
    authority.material.resolveVerifiedTools = (reference) => reference.manifestRef === root.ref && reference.manifestDigest === manifest.manifestDigest ? selected : null;
    const text: ModelTextV1 = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8: 'Use tools carefully.', byteCount: 20, textDigest: '' };
    text.textDigest = digestOmitting(text, 'textDigest');
    const system = await store.artifacts.publishCanonical(text, text.format);
    const workspace = { schemaVersion: 1, format: 'cliq-workspace-instructions-v1', entries: [], manifestDigest: '' };
    workspace.manifestDigest = digestOmitting(workspace, 'manifestDigest');
    const instructions = await store.artifacts.publishCanonical(workspace, workspace.format);
    Object.assign(authority.assembly.instructions, { systemPromptRef: system.ref, systemPromptDigest: text.textDigest,
      workspaceInstructionsRef: instructions.ref, workspaceInstructionsDigest: workspace.manifestDigest });
    const envelope = authority.material.compactionEnvelope;
    for (const part of [envelope.systemInstruction, envelope.userPrefix, envelope.userSuffix, envelope]) {
      await store.artifacts.publishCanonical(part.value, part.value.format);
    }
    if (options.mode !== undefined) {
      signed = await signedToolBundle(store.artifacts, authority.assembly, manifest.entries);
      const capability = authority.material.capabilityEvidence.value;
      if (capability.source.kind === 'signed_catalog') capability.source.runtimeBundleRef = authority.assembly.runtime.runtimeBundleRef;
      capability.evidenceDigest = digestOmitting(capability, 'evidenceDigest');
      authority.material.capabilityEvidence.ref = canonicalSha256(capability);
      authority.assembly.provider.negotiation.capabilityEvidenceRef = authority.material.capabilityEvidence.ref;
      authority.assembly.provider.negotiation.capabilityDigest = capability.evidenceDigest;
    }
    reseal(authority);
    return (await store.artifacts.publishCanonical(authority.assembly, authority.assembly.format)).ref;
  }, ...(options.mode === undefined ? {} : { policy: async (store, identity) => {
    const policy: RunPolicySnapshotV1 = { schemaVersion: 1, format: 'cliq-run-policy-v1', principalId: identity.ownerPrincipalId,
      workspaceIdentityDigest: identity.identityDigest, mode: options.mode!, engine: signed!.engine,
      toolManifestRef: authority.assembly.tools.manifestRef, toolManifestDigest: authority.assembly.tools.manifestDigest,
      decisions: modeDecisions(options.mode!), decisionRules: [...BUILTIN_POLICY_RULES, ...(options.rules ?? [])],
      repositoryRequestRefs: [...new Set((options.rules ?? []).filter((rule) => rule.source === 'repository_request').map((rule) => rule.sourceRef!))].sort(),
      createdAt: sampleCanonicalNow(), policyDigest: '' };
    policy.policyDigest = digestOmitting(policy, 'policyDigest');
    return (await store.artifacts.publishCanonical(policy, policy.format)).ref;
  } }) });
  try {
    const agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: authority.material, releaseKeys: signed?.releaseKeys });
    return { ...fixture, authority, agent, signed };
  } catch (error) { await disposeFixture(fixture); throw error; }
}
