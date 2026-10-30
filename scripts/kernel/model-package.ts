// Build-time material for the existing fixed Linux model/tool recipe. These
// bytes still require the ordinary signed bundle and installed authority gates.
import { canonicalJsonBytes, canonicalSha256 } from '../../src/kernel/canonical.js';
import { identityHash, normalizeBoundedText, sha256Bytes } from '../../src/kernel/identity.js';
import type { CompactionPromptEnvelopeMaterial, CompactionPromptEnvelopeV1 } from '../../src/model/request.js';
import type { RuntimeBundleManifest } from '../../src/policy/runtime-authority.js';
import type { ModelTextV1 } from '../../src/protocol/agent-ir.js';
import { builtinInputContracts } from '../../src/tools/builtin-inputs.js';
import { buildInstalledToolContracts } from '../../src/tools/installed-contracts.js';

export type InstalledModelPackageEntry = {
  entryId: string; role: string; relativePath: string; executable: boolean; bytes: Buffer;
};
export type InstalledModelScriptMaterial = Parameters<typeof buildInstalledToolContracts>[0]['scripts'];

function text(utf8: string): { ref: string; value: ModelTextV1; bytes: Buffer } {
  const core = { schemaVersion: 1 as const, format: 'cliq-model-text-v1' as const,
    utf8, byteCount: Buffer.byteLength(utf8, 'utf8') };
  const value: ModelTextV1 = { ...core, textDigest: canonicalSha256(core) };
  const bytes = canonicalJsonBytes(value);
  return { ref: sha256Bytes(bytes), value, bytes };
}

/** Shared by real-provider package builds and owned endpoint qualification.
 * No endpoint, credential, observation or price is inferred from these data.
 * The same literal tools and prompts enter the same signed install recipe. */
export function buildInstalledModelPackageEntries(model: Readonly<{ provider: 'openai-compatible'; model: string }>,
  brokerBytes: Buffer, editBytes: Buffer, scripts?: InstalledModelScriptMaterial) {
  if (model.provider !== 'openai-compatible' || normalizeBoundedText(model.model, 1, 512) !== model.model)
    throw new TypeError('model package requires the fixed compatible provider and an exact model name');
  if (!Buffer.isBuffer(brokerBytes) || !brokerBytes.length || !Buffer.isBuffer(editBytes) || !editBytes.length)
    throw new TypeError('model package requires the actual broker and edit bytes');
  const inputSchemaBytes = canonicalJsonBytes(builtinInputContracts.edit.inputSchema);
  const inputSchemaRef = sha256Bytes(inputSchemaBytes);
  const compiled = buildInstalledToolContracts({ edit: { entryId: 'edit', version: '1', role: 'tool_adapter',
    relativePath: 'workers/cliq-linux-edit', executable: true, digest: sha256Bytes(editBytes), byteCount: editBytes.length },
    ...(scripts ? { scripts } : {}) });
  const tools = compiled.manifest, entry = tools.entries.find(entry => entry.name === 'edit')!;
  const toolBytes = canonicalJsonBytes(tools);
  const system = text(scripts ? 'Use the declared tools in the private workspace. Respect per-action permissions. Ask request_input when user information is needed. Report results and uncertainty faithfully.'
    : 'Use the builtin edit tool only for authorized changes to the private workspace. Report the result faithfully.');
  const systemInstruction = text('Summarize the recorded context faithfully; return Markdown and no tool calls.');
  const userPrefix = text('Recorded context to summarize:\n\n');
  const userSuffix = text('\n\nPreserve the objective, completed work, constraints, and unresolved work.');
  const envelopeCore = { schemaVersion: 1 as const, format: 'cliq-compaction-prompt-envelope-v1' as const,
    systemInstructionRef: systemInstruction.ref, systemInstructionDigest: systemInstruction.value.textDigest,
    userPrefixRef: userPrefix.ref, userPrefixDigest: userPrefix.value.textDigest,
    sourcePlaceholder: '{{CLIQ_SOURCE_CONTEXT_UTF8}}' as const,
    userSuffixRef: userSuffix.ref, userSuffixDigest: userSuffix.value.textDigest,
    resultContract: { toolsAllowed: false as const, requiredStopReason: 'end' as const,
      mediaType: 'text/markdown; charset=utf-8' as const, summaryFormat: 'cliq-context-summary-markdown-v1' as const } };
  const envelope: CompactionPromptEnvelopeV1 = { ...envelopeCore, envelopeDigest: canonicalSha256(envelopeCore) };
  const envelopeBytes = canonicalJsonBytes(envelope), envelopeRef = sha256Bytes(envelopeBytes);
  const members = [systemInstruction, userPrefix, userSuffix].sort((left, right) => left.ref < right.ref ? -1 : 1);
  const entries: InstalledModelPackageEntry[] = [
    { entryId: 'openai-compatible-broker-v1', role: 'provider_adapter', relativePath: 'native/linux-x64/linux-model-broker.node',
      executable: true, bytes: brokerBytes },
    ...compiled.schemas.map(({ name, schema }) => ({ entryId: `installed-${name}-input-schema`, role: 'schema',
      relativePath: `schemas/${name}-input.json`, executable: false, bytes: canonicalJsonBytes(schema) })),
    { entryId: 'installed-tool-contracts', role: 'schema', relativePath: 'schemas/tool-contracts.json', executable: false, bytes: toolBytes },
    { entryId: 'installed-model-system-prompt', role: 'system_prompt', relativePath: 'prompts/model-system.json', executable: false, bytes: system.bytes },
    { entryId: 'installed-model-compaction-prompt', role: 'compaction_prompt', relativePath: 'prompts/model-compaction.json', executable: false, bytes: envelopeBytes },
    ...members.map(member => ({ entryId: identityHash('runtime-bundle-object-v1', member.ref), role: 'bundle_object',
      relativePath: `objects/sha256/${member.ref.slice(0, 2)}/${member.ref}`, executable: false, bytes: member.bytes })),
  ];
  const structuredArtifacts: RuntimeBundleManifest['structuredArtifacts'] = [
    { kind: 'compaction_prompt', artifactId: 'installed-model-compaction', rootEntryId: 'installed-model-compaction-prompt',
      artifactRef: envelopeRef, semanticDigest: envelope.envelopeDigest, memberRefs: members.map(member => member.ref),
      provider: model.provider, model: model.model },
    { kind: 'system_prompt', artifactId: 'installed-model-system', rootEntryId: 'installed-model-system-prompt',
      artifactRef: system.ref, semanticDigest: system.value.textDigest, memberRefs: [], provider: model.provider, model: model.model },
  ];
  const compaction: CompactionPromptEnvelopeMaterial = { ref: envelopeRef, value: envelope,
    systemInstruction: { ref: systemInstruction.ref, value: systemInstruction.value },
    userPrefix: { ref: userPrefix.ref, value: userPrefix.value }, userSuffix: { ref: userSuffix.ref, value: userSuffix.value } };
  return { entries, structuredArtifacts, system, compaction, tools: { ref: sha256Bytes(toolBytes), value: tools },
    inputSchemaRef, toolContractDigest: canonicalSha256(entry) };
}
