import { canonicalSha256 } from '../../kernel/canonical.js';
import { digestOmitting } from '../../kernel/identity.js';
import type { ToolContractManifestV1, RunSpec } from '../../kernel/types.js';
import type { ModelTextV1 } from '../../protocol/agent-ir.js';
import { reseal, testFixture } from '../../model/testing/fixtures.js';
import { createActiveFixture } from './fixtures.js';

/** Real CAS + SQLite/lease, with offline signed-authority verification fixtures; no provider or tool I/O. */
export async function createAgentFixture(label: string, budgets?: Partial<RunSpec['budgets']>) {
  const authority = testFixture();
  const selected = authority.material.resolveVerifiedTools(authority.assembly.tools)!;
  const credentials: string[] = [];
  const fixture = await createActiveFixture(label, { budgets, credentialGrantRefs: credentials, assembly: async (store) => {
    const grant = await store.artifacts.publishCanonical({ format: 'cliq-offline-credential-fixture-v1' }, 'cliq-offline-credential-fixture-v1');
    credentials.push(grant.ref);
    authority.assembly.provider.credentialGrantRefs = credentials;
    authority.material.additionalCredentialGrantRefs = [];
    authority.runSpecCredentialGrantRefs = credentials;
    for (const tool of selected) await store.artifacts.publishCanonical(tool.inputSchema, 'cliq-tool-input-schema-v1');
    const manifest: ToolContractManifestV1 = { schemaVersion: 1, format: 'cliq-tool-contracts-v1', entries: selected.map((tool) => ({
      name: tool.name, version: '1', description: tool.description, access: 'read', inputSchemaRef: tool.inputSchemaRef,
      inputSchemaDigest: tool.inputSchemaDigest, replayClass: 'retry', execution: { kind: 'builtin', adapterId: tool.name,
        adapterVersion: '1', adapterCodeDigest: canonicalSha256({ adapter: tool.name }) }
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
    reseal(authority);
    return (await store.artifacts.publishCanonical(authority.assembly, authority.assembly.format)).ref;
  } });
  const agent = await fixture.store.loadAgentRun({ runId: fixture.runId, material: authority.material });
  return { ...fixture, authority, agent };
}
