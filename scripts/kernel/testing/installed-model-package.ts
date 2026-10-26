// Qualification-only extension of the actual installed package recipe. Its
// signed claims describe an owned HTTPS fixture, never a production provider.
import assert from 'node:assert/strict';
import { sign, X509Certificate, type KeyObject } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import type { EndpointRegistrationV1 } from '../../../src/kernel/credential-authority.js';
import { assertArtifactRef, digestOmitting, identityHash, normalizeBoundedText, parseCanonicalTime, sha256Bytes } from '../../../src/kernel/identity.js';
import type { NormalizedModelCapabilityClaimsV1 } from '../../../src/model/capabilities.js';
import type { InstalledModelAuthorityClosureV1, SignedModelCatalogEntryV1 } from '../../../src/model/installed-authority.js';
import { priceTableDigest, type ModelPriceTableV1, type ModelTokenComponents } from '../../../src/model/pricing.js';
import type { CompactionPromptEnvelopeMaterial, CompactionPromptEnvelopeV1 } from '../../../src/model/request.js';
import type { RuntimeBundleManifest } from '../../../src/policy/runtime-authority.js';
import type { ModelTextV1 } from '../../../src/protocol/agent-ir.js';
import { builtinInputContracts } from '../../../src/tools/builtin-inputs.js';
import { buildInstalledToolContracts } from '../../../src/tools/installed-contracts.js';
import type { GuestToolchainManifest } from '../../../src/kernel/execution.js';

export type InstalledModelPackageFixture = Readonly<{
  provider: 'openai-compatible'; model: string;
  target: Readonly<{ hostAscii: '127.0.0.1'; port: number; basePath: string }>;
  tls: Readonly<{ serverNameAscii: string; caPem: Buffer; spkiSha256Pins: readonly string[] }>;
  claims: NormalizedModelCapabilityClaimsV1;
  requestTokenCeiling: ModelTokenComponents;
  validFrom: string; validThrough: string;
}>;
export type InstalledModelPackageEntry = {
  entryId: string; role: string; relativePath: string; executable: boolean; bytes: Buffer;
};

function text(utf8: string): { ref: string; value: ModelTextV1; bytes: Buffer } {
  const core = { schemaVersion: 1 as const, format: 'cliq-model-text-v1' as const,
    utf8, byteCount: Buffer.byteLength(utf8, 'utf8') };
  const value: ModelTextV1 = { ...core, textDigest: canonicalSha256(core) };
  const bytes = canonicalJsonBytes(value);
  return { ref: sha256Bytes(bytes), value, bytes };
}

/** Literal prompt and actual builtin contract bytes; no model fixture callback,
 * prebuilt Run/frontier, activation, retained proof or authority factory. */
export function installedModelPackageEntries(fixture: InstalledModelPackageFixture, brokerBytes: Buffer, editBytes: Buffer,
  scripts?: { entry: RuntimeBundleManifest['entries'][number]; supervisor: RuntimeBundleManifest['entries'][number];
    guest: { manifestRef: string; manifest: GuestToolchainManifest } }) {
  assert.equal(fixture.provider, 'openai-compatible');
  assert.equal(fixture.target.hostAscii, '127.0.0.1', 'model fixture may contact only its owned loopback HTTPS server');
  assert(Number.isSafeInteger(fixture.target.port) && fixture.target.port >= 1 && fixture.target.port <= 65535);
  assert.equal(normalizeBoundedText(fixture.model, 1, 512), fixture.model);
  assert.equal(normalizeBoundedText(fixture.tls.serverNameAscii, 1, 512), fixture.tls.serverNameAscii);
  assert(Buffer.isBuffer(fixture.tls.caPem) && fixture.tls.caPem.byteLength <= 1024 * 1024);
  new X509Certificate(fixture.tls.caPem);
  assert(fixture.tls.spkiSha256Pins.length > 0);
  fixture.tls.spkiSha256Pins.forEach(assertArtifactRef);
  assert.equal(new Set(fixture.tls.spkiSha256Pins).size, fixture.tls.spkiSha256Pins.length);
  assert(parseCanonicalTime(fixture.validFrom) < parseCanonicalTime(fixture.validThrough));
  assert(Buffer.isBuffer(brokerBytes) && brokerBytes.byteLength > 0);
  assert(Buffer.isBuffer(editBytes) && editBytes.byteLength > 0);

  const builtin = builtinInputContracts.edit;
  const inputSchemaBytes = canonicalJsonBytes(builtin.inputSchema);
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
      provider: fixture.provider, model: fixture.model },
    { kind: 'system_prompt', artifactId: 'installed-model-system', rootEntryId: 'installed-model-system-prompt',
      artifactRef: system.ref, semanticDigest: system.value.textDigest, memberRefs: [], provider: fixture.provider, model: fixture.model },
  ];
  const compaction: CompactionPromptEnvelopeMaterial = { ref: envelopeRef, value: envelope,
    systemInstruction: { ref: systemInstruction.ref, value: systemInstruction.value },
    userPrefix: { ref: userPrefix.ref, value: userPrefix.value }, userSuffix: { ref: userSuffix.ref, value: userSuffix.value } };
  return { entries, structuredArtifacts, system, compaction, tools: { ref: sha256Bytes(toolBytes), value: tools },
    inputSchemaRef, toolContractDigest: canonicalSha256(entry) };
}

/** Sign only after the complete Bundle ref and endpoint TLS identity exist.
 * The caller supplies its same ephemeral package-signing key, not runtime keys. */
export async function writeInstalledModelAuthority(input: {
  packageRoot: string; bundle: RuntimeBundleManifest; privateKey: KeyObject;
  fixture: InstalledModelPackageFixture; material: ReturnType<typeof installedModelPackageEntries>;
}) {
  const { bundle, fixture } = input;
  const runtimeBundleRef = canonicalSha256(bundle);
  const trust = bundle.entries.find(entry => entry.entryId === 'default_https_trust_store');
  const adapter = bundle.entries.find(entry => entry.entryId === 'openai-compatible-broker-v1');
  assert(trust && !trust.executable && trust.role === 'trust_store');
  assert(adapter && adapter.executable && adapter.role === 'provider_adapter');
  const target: EndpointRegistrationV1['target'] = { scheme: 'https', ...fixture.target, redirectPolicy: 'reject_all' };
  const tls: EndpointRegistrationV1['tls'] = { serverNameAscii: fixture.tls.serverNameAscii, minimumVersion: 'TLSv1.3',
    trustStoreRuntimeBundleRef: runtimeBundleRef, trustStoreRuntimeBundleManifestDigest: bundle.manifestDigest,
    trustStoreEntryId: 'default_https_trust_store', trustStoreRef: trust.digest, trustStoreDigest: trust.digest,
    spkiSha256Pins: [...fixture.tls.spkiSha256Pins].sort() };
  const tlsPolicyDigest = canonicalSha256(tls), endpointIdentityDigest = canonicalSha256({ target, tlsPolicyDigest });
  const objects = new Map<string, { bytes: Buffer; kind: InstalledModelAuthorityClosureV1['objects'][number]['kind'] }>();
  const retain = (bytes: Buffer, kind: InstalledModelAuthorityClosureV1['objects'][number]['kind']) => {
    const ref = sha256Bytes(bytes), previous = objects.get(ref);
    if (previous) { assert.equal(previous.kind, kind); assert.deepEqual(previous.bytes, bytes); }
    else objects.set(ref, { bytes, kind });
    return ref;
  };
  const signature = (domain: string, digest: string) => retain(sign(null, Buffer.from(`${domain}\0${digest}`, 'utf8'), input.privateKey), 'ed25519_signature');
  const catalogCore = { schemaVersion: 1 as const, format: 'cliq-signed-model-catalog-entry-v1' as const,
    signerKeyId: bundle.publisherKeyId, signatureAlgorithm: 'ed25519' as const, runtimeBundleRef,
    runtimeBundleManifestDigest: bundle.manifestDigest, provider: fixture.provider, model: fixture.model, endpointIdentityDigest,
    adapter: { adapterId: adapter.entryId, version: adapter.version, codeDigest: adapter.digest },
    claims: { ...fixture.claims }, validFrom: fixture.validFrom, validThrough: fixture.validThrough };
  const catalogEntryDigest = canonicalSha256(catalogCore);
  const catalog: SignedModelCatalogEntryV1 = { ...catalogCore, catalogEntryDigest,
    signatureRef: signature('cliq-model-catalog-entry-v1', catalogEntryDigest) };
  const catalogRef = retain(canonicalJsonBytes(catalog), 'model_catalog_entry');
  // This owned fixture server has no billing mechanism. The signed full token
  // vector is substantiated by its actual bounded request/response contract;
  // these rates and claims confer no actual-provider qualification.
  const priceTable: ModelPriceTableV1 = { schemaVersion: 1, format: 'cliq-model-price-table-v1', signerKeyId: bundle.publisherKeyId,
    signatureAlgorithm: 'ed25519', signatureRef: '', provider: fixture.provider, model: fixture.model, endpointIdentityDigest,
    currency: 'USD', unit: 'micros_per_million_tokens', prices: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    requestTokenCeiling: { ...fixture.requestTokenCeiling }, validFrom: fixture.validFrom, validThrough: fixture.validThrough, tableDigest: '' };
  priceTable.tableDigest = priceTableDigest(priceTable);
  priceTable.signatureRef = signature('cliq-model-price-table-v1', priceTable.tableDigest);
  const priceTableRef = retain(canonicalJsonBytes(priceTable), 'model_price_table');
  const inventory = [...objects].sort(([left], [right]) => left < right ? -1 : 1)
    .map(([artifactRef, object]) => ({ artifactRef, byteCount: object.bytes.byteLength, kind: object.kind }));
  const closureCore = { schemaVersion: 1 as const, format: 'cliq-installed-model-authority-v1' as const,
    publisherKeyId: bundle.publisherKeyId, signatureAlgorithm: 'ed25519' as const, runtimeBundleRef,
    runtimeBundleManifestDigest: bundle.manifestDigest, objects: inventory };
  const closureDigest = canonicalSha256(closureCore);
  const closure: InstalledModelAuthorityClosureV1 = { ...closureCore, closureDigest,
    signature: sign(null, Buffer.from(`cliq-installed-model-authority-v1\0${closureDigest}`, 'utf8'), input.privateKey).toString('base64') };
  await writeFile(path.join(input.packageRoot, 'model-authority.json'), canonicalJsonBytes(closure), { flag: 'wx', mode: 0o400 });
  for (const [ref, object] of objects) {
    const directory = path.join(input.packageRoot, 'model-objects/sha256', ref.slice(0, 2));
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(path.join(directory, ref), object.bytes, { flag: 'wx', mode: 0o400 });
  }
  return { diagnosticOnly: true as const, actualProviderQualified: false as const, actualProviderCostQualified: false as const,
    endpoint: { target, tls, tlsPolicyDigest, endpointIdentityDigest },
    catalog: { ref: catalogRef, value: catalog }, priceTable: { ref: priceTableRef, value: priceTable },
    closure: { ref: canonicalSha256(closure), value: closure },
    system: { ref: input.material.system.ref, value: input.material.system.value }, compaction: input.material.compaction,
    tools: input.material.tools, inputSchemaRef: input.material.inputSchemaRef, toolContractDigest: input.material.toolContractDigest };
}
