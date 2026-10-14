// Trusted installed assembly production. Public clients select ids, never any
// of these refs, callbacks, keys, clocks or descriptor/authority owners.
import { setImmediate } from 'node:timers/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256, normalizeCanonicalText } from '../kernel/canonical.js';
import type { NormalizedRunSubmitRequest } from '../kernel/control-submit.js';
import { decodeEndpointCredentialGrantBinding, decodeEndpointRegistration,
  type EndpointCredentialGrantBinding, type EndpointRegistrationV1 } from '../kernel/credential-authority.js';
import type { SourceInspectionAttemptV1 } from '../kernel/execution.js';
import { addCanonicalDuration, assertArtifactRef, digestOmitting, normalizeBoundedText, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { RunAssemblyV1, ToolContractManifestV1, VerifierSpec, WorkspaceIdentityV1 } from '../kernel/types.js';
import type { ModelCapabilityEvidenceV1 } from '../model/capabilities.js';
import { immutableSnapshot } from '../model/immutable.js';
import { verifyRetainedModelAuthorityPair, type SignedModelCatalogEntryV1 } from '../model/installed-authority.js';
import type { ModelPriceTableV1 } from '../model/pricing.js';
import { compactionEnvelopeEstimate } from '../model/request.js';
import { decodeRetainedRunAssembly, validateRunAssembly, type RunAssemblyValidationMaterial } from '../model/run-assembly.js';
import { BUILTIN_POLICY_RULES, modeDecisions } from '../policy/tool-policy.js';
import { exactKeys, policyProfile, requireEqual, verifyToolRuntimeAuthority } from '../policy/runtime-authority.js';
import type { RunPolicySnapshotV1 } from '../kernel/tool-authorization.js';
import type { ModelTextV1 } from '../protocol/agent-ir.js';
import { verifyModelText } from '../model/attempt.js';
import { LINUX_WORKER_RECIPE } from '../sandbox/linux-worker.js';
import { builtinInputContracts } from '../tools/builtin-inputs.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { validateControlChannelClosure, type AuthenticatedControlIdentity } from './control-channel.js';
import { decodeSourceManifest, decodeWorkspaceIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxProfile } from './execution-closure.js';
import { loadInstalledCredentialPlatform, withHeldInstalledRuntime, type HeldInstalledRuntime, type InstalledRuntimeBorrow } from './installed-runtime.js';
import { installedSandboxProfile } from './installed-sandbox-profile.js';
import { assertHeldWorkspaceRoot, heldWorkspaceRootPath, type HeldWorkspaceCursor, type HeldWorkspaceEntry, type HeldWorkspaceRoot, type NativeStateOwner } from './native-owner.js';
import { readSession, readSessionPrincipalId } from './rows.js';
import { readSourceInspectionAttempt, readSourceInspectionOriginalRequest } from './source-inspection.js';
import { normalizeRunSubmitRequest, readRetainedSourceInspectionTarget, runSubmitIntentDigest } from './source-target.js';
import { assertWorkspaceSourceTrust, holdWorkspaceSourceTrust } from './source-trust.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { assertActiveStateOwner, type StateOwnerContext } from './state-owner.js';
import type { AdmitRunInput } from './reducers/admission.js';

type RetiredSource = Extract<SourceInspectionAttemptV1, { phase: 'retired' }>;
type InstructionEntry = { canonicalRootRelativePath: string; directoryDepth: number;
  fileDescriptor: { deviceId: string; fileId: string; ownerUid: number; mode: 384 | 420; linkCount: 1 };
  rawBytesRef: string; rawBytesDigest: string; rawByteCount: number; sourceEntryDigest: string };
type InstructionSource = { schemaVersion: 1; format: 'cliq-workspace-instruction-source-v1'; workspaceIdentityRef: string;
  workspaceIdentityDigest: string; entries: InstructionEntry[]; capturedAt: string; sourceDigest: string };
type InstructionManifest = { schemaVersion: 1; format: 'cliq-workspace-instructions-v1'; workspaceIdentityDigest: string;
  instructionSourceRef: string; instructionSourceDigest: string; rendering: 'cliq-all-scopes-labeled-instructions-v1';
  entries: Array<{ order: number; canonicalRootRelativePath: string; appliesToSubtree: true; directoryDepth: number;
    instructionSourceEntryDigest: string; contentRef: string; contentDigest: string }>; manifestDigest: string };

export type AssembledInstalledRun = Readonly<{
  assemblyRef: string; assembly: RunAssemblyV1; policyRef: string; sandboxProfileRef: string; verifierSpecRef: string;
  credentialGrantRefs: readonly string[]; sourceProjectionRef: string; frozenIgnoreRulesRef: string; baseWorkspaceManifestRef: string;
  material: RunAssemblyValidationMaterial; admittedAt: string; deadlineAt: string;
}>;
type AdmissionBinding = { driver: SqliteDriver; owner: StateOwnerContext; selected: HeldInstalledRuntime;
  identity: AuthenticatedControlIdentity; normalized: ReturnType<typeof normalizeRunSubmitRequest>; source: RetiredSource;
  native: NativeStateOwner; workspace: Extract<WorkspaceIdentityV1, { kind: 'live' }>;
  input: AdmitRunInput; admittedAt: string; deadlineAt: string };
const admissions = new WeakMap<AssembledInstalledRun, AdmissionBinding>();
/** Fixed refusal projection, not authority or a caller-selectable error code. */
export class InstalledRunAuthorityError extends KernelStorageError {
  constructor(readonly refusalCode: 'MODEL_CAPABILITY_UNKNOWN' | 'MODEL_COST_UNKNOWN' | 'RUN_ASSEMBLY_INVALID') {
    super('INVALID_REQUEST', 'installed Run model authority was refused'); this.name = 'InstalledRunAuthorityError';
  }
}
function invalid(message: string): never { throw new KernelStorageError('INVALID_REQUEST', message); }
function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
const same = (left: unknown, right: unknown) => canonicalJsonBytes(left).equals(canonicalJsonBytes(right));

/** Reject unsupported fixed-recipe intent before source/instruction capture.
 * Generic normalization retains the wider resource contract for other recipes. */
export function assertInstalledRunRecipe(request: NormalizedRunSubmitRequest): asserts request is NormalizedRunSubmitRequest & {
  model: Exclude<NormalizedRunSubmitRequest['model'], { provider: 'ollama' }>;
} {
  if (request.model.provider !== 'openai-compatible' || request.verifiers.length || request.dependency.mode !== 'none' ||
      request.registeredMcpServerIds.length || request.skillIds.length || request.sourceIncludes.length ||
      request.sandboxResources.maxProcesses < 8)
    invalid('installed Run selects an unsupported model, execution resource, verifier, dependency, MCP, skill or source inclusion');
}

function closeOwned(resources: readonly { close(): void }[], error?: unknown): void {
  const failures: unknown[] = [];
  for (const resource of [...resources].reverse()) { try { resource.close(); } catch (failure) { failures.push(failure); } }
  if (failures.length) throw new ResourceRetirementError('installed instruction descriptors did not retire',
    new AggregateError(error === undefined ? failures : [error, ...failures]));
}

/** Trust authorizes this independent declarative capture, never source/tool
 * permission. No legacy loader/config/extension code is evaluated. */
async function captureInstructions(root: HeldWorkspaceRoot, artifacts: ArtifactCatalog,
  workspace: Extract<WorkspaceIdentityV1, { kind: 'live' }>, workspaceIdentityRef: string, signal?: AbortSignal) {
  assertHeldWorkspaceRoot(root);
  if (heldWorkspaceRootPath(root) !== workspace.canonicalRootPath || !same(root.identity, workspace.rootIdentity))
    mismatch('instruction root differs from the authenticated Session');
  const resources: Array<{ close(): void }> = [], cursors: HeldWorkspaceCursor[] = [], selected: HeldWorkspaceEntry[] = [];
  const entries: InstructionEntry[] = [], rendered = new Map<string, { ref: string; digest: string }>();
  let inventory = 0, bytes = 0, failure: unknown;
  const recheck = () => {
    signal?.throwIfAborted(); assertHeldWorkspaceRoot(root);
    cursors.forEach(cursor => cursor.assertComplete()); selected.forEach(entry => entry.assertHeld());
  };
  try {
    const cursor = root.openSnapshot(); resources.push(cursor); cursors.push(cursor);
    const stack = [cursor];
    while (stack.length) {
      await setImmediate(); signal?.throwIfAborted();
      const current = stack[stack.length - 1], entry = current.next();
      if (!entry) { current.assertComplete(); stack.pop(); continue; }
      if (++inventory > 100000) { resources.push(entry); invalid('instruction metadata exceeds its scan bound'); }
      if (normalizeBoundedText(entry.path, 1, 4096) !== entry.path || entry.path.includes('\\') ||
          entry.path.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255)) {
        resources.push(entry); invalid('instruction path is not exact canonical root-relative text');
      }
      const instruction = entry.path === 'AGENTS.md' || entry.path.endsWith('/AGENTS.md');
      if (entry.identity.deviceId !== root.identity.deviceId) { resources.push(entry); invalid('instruction scan cannot cross an external filesystem'); }
      if (entry.kind === 'directory') {
        resources.push(entry); selected.push(entry);
        const child = entry.openDirectory(); resources.push(child); cursors.push(child); stack.push(child); continue;
      }
      if (!instruction) { entry.close(); continue; }
      resources.push(entry); selected.push(entry);
      if (entry.kind !== 'file' || entry.identity.ownerUid !== root.identity.ownerUid ||
          ![0o600, 0o644].includes(entry.mode) || entry.linkCount !== 1 || !Number.isSafeInteger(entry.byteCount) ||
          entry.byteCount < 0 || (bytes += entry.byteCount) > 1048576 || entries.length >= 64)
        invalid('instruction file ownership, mode, links or byte/count bounds are invalid');
      const reader = entry.openFile(); resources.push(reader); const chunks: Buffer[] = [];
      for (;;) { await setImmediate(); signal?.throwIfAborted(); const chunk = reader.readChunk(); if (chunk === null) break; chunks.push(chunk); }
      reader.assertHeld(); entry.assertHeld();
      const raw = Buffer.concat(chunks), utf8 = new TextDecoder('utf-8', { fatal: true }).decode(raw);
      if (raw.length !== entry.byteCount || normalizeCanonicalText(utf8.replace(/\r\n?/gu, '\n')) !== utf8)
        invalid('instruction bytes changed or are not canonical NFC/LF text');
      const rawArtifact = await artifacts.publishBytes(raw, 'application/octet-stream', 'cliq-workspace-file-v1');
      const text: ModelTextV1 = { schemaVersion: 1, format: 'cliq-model-text-v1', utf8, byteCount: raw.length, textDigest: '' };
      text.textDigest = digestOmitting(text, 'textDigest'); verifyModelText(text);
      const content = await artifacts.publishCanonical(text, text.format);
      const core = { canonicalRootRelativePath: entry.path, directoryDepth: entry.path.split('/').length - 1,
        fileDescriptor: { deviceId: entry.identity.deviceId, fileId: entry.identity.fileId, ownerUid: entry.identity.ownerUid,
          mode: entry.mode as 384 | 420, linkCount: 1 as const }, rawBytesRef: rawArtifact.ref,
        rawBytesDigest: sha256Bytes(raw), rawByteCount: raw.length };
      entries.push({ ...core, sourceEntryDigest: canonicalSha256(core) }); rendered.set(entry.path, { ref: content.ref, digest: text.textDigest });
    }
    recheck(); entries.sort((left, right) => Buffer.compare(Buffer.from(left.canonicalRootRelativePath), Buffer.from(right.canonicalRootRelativePath)));
    const source: InstructionSource = { schemaVersion: 1, format: 'cliq-workspace-instruction-source-v1', workspaceIdentityRef,
      workspaceIdentityDigest: workspace.identityDigest, entries, capturedAt: sampleCanonicalNow(), sourceDigest: '' };
    source.sourceDigest = digestOmitting(source, 'sourceDigest');
    const sourceArtifact = await artifacts.publishCanonical(source, source.format); recheck();
    const manifest: InstructionManifest = { schemaVersion: 1, format: 'cliq-workspace-instructions-v1', workspaceIdentityDigest: workspace.identityDigest,
      instructionSourceRef: sourceArtifact.ref, instructionSourceDigest: source.sourceDigest, rendering: 'cliq-all-scopes-labeled-instructions-v1',
      entries: [...entries].sort((left, right) => left.directoryDepth - right.directoryDepth ||
        Buffer.compare(Buffer.from(left.canonicalRootRelativePath), Buffer.from(right.canonicalRootRelativePath)))
        .map((entry, order) => ({ order, canonicalRootRelativePath: entry.canonicalRootRelativePath, appliesToSubtree: true,
          directoryDepth: entry.directoryDepth, instructionSourceEntryDigest: entry.sourceEntryDigest,
          contentRef: rendered.get(entry.canonicalRootRelativePath)!.ref, contentDigest: rendered.get(entry.canonicalRootRelativePath)!.digest })), manifestDigest: '' };
    manifest.manifestDigest = digestOmitting(manifest, 'manifestDigest');
    const published = await artifacts.publishCanonical(manifest, manifest.format); recheck(); return { ref: published.ref, value: immutableSnapshot(manifest) };
  } catch (error) { failure = error; throw error; } finally { closeOwned(resources, failure); }
}

function selectedModel(installed: InstalledRuntimeBorrow, provider: string, model: string, endpoint: EndpointRegistrationV1) {
  const matches = installed.modelAuthority?.models.filter(candidate => candidate.catalog.value.provider === provider &&
    candidate.catalog.value.model === model && candidate.catalog.value.endpointIdentityDigest === endpoint.endpointIdentityDigest) ?? [];
  if (matches.length !== 1 || matches[0]!.catalog.value.claims.streaming)
    throw new InstalledRunAuthorityError('MODEL_CAPABILITY_UNKNOWN');
  return matches[0]!;
}

/** Retained data only. Never reopen the live workspace to choose instruction
 * scopes after admission or restart. Every rendered byte has a closed source. */
async function readInstructions(artifacts: ArtifactCatalog, assembly: RunAssemblyV1, principalId: string): Promise<InstructionManifest> {
  const manifest = await readCanonicalArtifact<InstructionManifest>(artifacts, assembly.instructions.workspaceInstructionsRef);
  if (!exactKeys(manifest, ['schemaVersion', 'format', 'workspaceIdentityDigest', 'instructionSourceRef',
      'instructionSourceDigest', 'rendering', 'entries', 'manifestDigest']) || manifest.schemaVersion !== 1 ||
      manifest.format !== 'cliq-workspace-instructions-v1' || manifest.rendering !== 'cliq-all-scopes-labeled-instructions-v1' ||
      manifest.manifestDigest !== assembly.instructions.workspaceInstructionsDigest ||
      manifest.manifestDigest !== digestOmitting(manifest, 'manifestDigest') || !Array.isArray(manifest.entries) || manifest.entries.length > 64)
    mismatch('installed retained instruction manifest is not its exact closed projection');
  const source = await readCanonicalArtifact<InstructionSource>(artifacts, manifest.instructionSourceRef);
  if (!exactKeys(source, ['schemaVersion', 'format', 'workspaceIdentityRef', 'workspaceIdentityDigest', 'entries', 'capturedAt', 'sourceDigest']) ||
      source.schemaVersion !== 1 || source.format !== 'cliq-workspace-instruction-source-v1' ||
      source.sourceDigest !== manifest.instructionSourceDigest || source.sourceDigest !== digestOmitting(source, 'sourceDigest') ||
      source.workspaceIdentityDigest !== manifest.workspaceIdentityDigest || !Array.isArray(source.entries) || source.entries.length !== manifest.entries.length)
    mismatch('installed instruction source does not bind its all-and-only projection');
  parseCanonicalTime(source.capturedAt);
  if (source.capturedAt > assembly.createdAt) mismatch('installed instruction capture follows its assembly');
  const workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, source.workspaceIdentityRef));
  if (workspace.kind !== 'live' || workspace.ownerPrincipalId !== principalId || workspace.identityDigest !== source.workspaceIdentityDigest)
    mismatch('installed instruction source belongs to another workspace or principal');
  let previous: Buffer | undefined, totalBytes = 0;
  for (const entry of source.entries) {
    if (!exactKeys(entry, ['canonicalRootRelativePath', 'directoryDepth', 'fileDescriptor', 'rawBytesRef', 'rawBytesDigest', 'rawByteCount', 'sourceEntryDigest']) ||
        typeof entry.canonicalRootRelativePath !== 'string' || normalizeBoundedText(entry.canonicalRootRelativePath, 1, 4096) !== entry.canonicalRootRelativePath ||
        entry.canonicalRootRelativePath.includes('\\') || entry.canonicalRootRelativePath.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255) ||
        (entry.canonicalRootRelativePath !== 'AGENTS.md' && !entry.canonicalRootRelativePath.endsWith('/AGENTS.md')) ||
        entry.directoryDepth !== entry.canonicalRootRelativePath.split('/').length - 1 ||
        !exactKeys(entry.fileDescriptor, ['deviceId', 'fileId', 'ownerUid', 'mode', 'linkCount']) ||
        entry.fileDescriptor.deviceId !== workspace.rootIdentity.deviceId || entry.fileDescriptor.ownerUid !== workspace.rootIdentity.ownerUid ||
        typeof entry.fileDescriptor.fileId !== 'string' || normalizeBoundedText(entry.fileDescriptor.fileId, 1, 512) !== entry.fileDescriptor.fileId ||
        ![384, 420].includes(entry.fileDescriptor.mode) || entry.fileDescriptor.linkCount !== 1 ||
        !Number.isSafeInteger(entry.rawByteCount) || entry.rawByteCount < 0 || (totalBytes += entry.rawByteCount) > 1048576 ||
        entry.sourceEntryDigest !== digestOmitting(entry, 'sourceEntryDigest')) mismatch('installed instruction source entry is invalid');
    assertArtifactRef(entry.rawBytesRef); assertArtifactRef(entry.rawBytesDigest);
    const path = Buffer.from(entry.canonicalRootRelativePath);
    if (previous && Buffer.compare(previous, path) >= 0) mismatch('installed instruction source paths are not unique byte-sorted paths');
    previous = path;
  }
  const ordered = [...source.entries].sort((left, right) => left.directoryDepth - right.directoryDepth ||
    Buffer.compare(Buffer.from(left.canonicalRootRelativePath), Buffer.from(right.canonicalRootRelativePath)));
  for (let index = 0; index < ordered.length; index++) {
    const selected = ordered[index]!, rendered = manifest.entries[index]!;
    if (!exactKeys(rendered, ['order', 'canonicalRootRelativePath', 'appliesToSubtree', 'directoryDepth', 'instructionSourceEntryDigest', 'contentRef', 'contentDigest']) ||
        rendered.order !== index || rendered.appliesToSubtree !== true || rendered.canonicalRootRelativePath !== selected.canonicalRootRelativePath ||
        rendered.directoryDepth !== selected.directoryDepth || rendered.instructionSourceEntryDigest !== selected.sourceEntryDigest)
      mismatch('installed instruction rendering substituted or reordered a frozen scope');
    const raw = await artifacts.readBytes(selected.rawBytesRef), content = await readCanonicalArtifact<ModelTextV1>(artifacts, rendered.contentRef);
    verifyModelText(content);
    const utf8 = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    if (raw.length !== selected.rawByteCount || sha256Bytes(raw) !== selected.rawBytesDigest ||
        normalizeCanonicalText(utf8.replace(/\r\n?/gu, '\n')) !== utf8 || content.utf8 !== utf8 ||
        content.textDigest !== rendered.contentDigest || content.byteCount !== raw.length)
      mismatch('installed instruction content differs from its complete captured bytes');
  }
  return immutableSnapshot(manifest);
}

async function materialFor(installed: InstalledRuntimeBorrow, artifacts: ArtifactCatalog, assembly: RunAssemblyV1): Promise<RunAssemblyValidationMaterial> {
  if (assembly.provider.name !== 'openai-compatible' || assembly.provider.endpoint.kind !== 'registered' ||
      assembly.provider.negotiation.streaming || assembly.mcpServers.length || assembly.instructions.skills.length)
    invalid('installed assembly selects an unsupported model, MCP or skill recipe');
  const endpoint = decodeEndpointRegistration(await readCanonicalArtifact(artifacts, assembly.provider.endpoint.endpointRegistrationRef));
  const trust = installed.bundle.entries.find(entry => entry.entryId === endpoint.tls.trustStoreEntryId);
  if (!trust || trust.role !== 'trust_store' || trust.executable || endpoint.tls.trustStoreRuntimeBundleRef !== installed.bundleDigest ||
      endpoint.tls.trustStoreRuntimeBundleManifestDigest !== installed.bundle.manifestDigest ||
      endpoint.tls.trustStoreRef !== trust.digest || endpoint.tls.trustStoreDigest !== trust.digest ||
      !endpoint.purposes.includes('model_endpoint')) mismatch('installed endpoint substitutes its signed TLS authority');
  const trustBytes = await artifacts.readBytes(trust.digest);
  if (trustBytes.length !== trust.byteCount || sha256Bytes(trustBytes) !== trust.digest) mismatch('installed endpoint trust-store bytes changed');
  const capability = await readCanonicalArtifact<ModelCapabilityEvidenceV1>(artifacts, assembly.provider.negotiation.capabilityEvidenceRef);
  if (capability.source.kind !== 'signed_catalog' || assembly.provider.pricing.kind !== 'trusted_price_table')
    mismatch('retained installed model authority is not its admitted signed catalog/price pair');
  const catalogRef = capability.source.catalogEntryRef, priceRef = assembly.provider.pricing.priceTableRef;
  const retainedCatalog = await readCanonicalArtifact<SignedModelCatalogEntryV1>(artifacts, catalogRef);
  const retainedPrice = await readCanonicalArtifact<ModelPriceTableV1>(artifacts, priceRef);
  assertArtifactRef(retainedCatalog.signatureRef); assertArtifactRef(retainedPrice.signatureRef);
  const objects = new Map([[catalogRef, canonicalJsonBytes(retainedCatalog)], [priceRef, canonicalJsonBytes(retainedPrice)]]);
  for (const reference of [retainedCatalog.signatureRef, retainedPrice.signatureRef])
    objects.set(reference, await artifacts.readBytes(reference));
  const model = verifyRetainedModelAuthorityPair({ bundle: installed.bundle, releaseKeys: installed.releaseKeys,
    catalogEntryRef: catalogRef, priceTableRef: priceRef, objects }), catalog = model.catalog.value;
  if (catalog.adapter.adapterId !== 'openai-compatible-broker-v1' || catalog.adapter.version !== '1') mismatch('installed provider adapter recipe is unsupported');
  requireEqual(assembly.provider.adapter, catalog.adapter, 'installed provider adapter');
  const tools = await readCanonicalArtifact<ToolContractManifestV1>(artifacts, assembly.tools.manifestRef);
  const toolEntry = installed.bundle.entries.find(entry => entry.digest === assembly.tools.manifestRef);
  if (!toolEntry || toolEntry.role !== 'schema' || toolEntry.executable || tools.format !== 'cliq-tool-contracts-v1' ||
      tools.schemaVersion !== 1 || !exactKeys(tools, ['schemaVersion', 'format', 'entries', 'manifestDigest']) ||
      digestOmitting(tools, 'manifestDigest') !== tools.manifestDigest || tools.entries.length !== 1)
    mismatch('installed tool manifest is not the exact signed builtin contract');
  const entry = tools.entries[0]!, builtin = builtinInputContracts.edit;
  const edit = installed.bundle.entries.find(entry => entry.entryId === LINUX_WORKER_RECIPE.editId);
  if (!edit || edit.role !== 'tool_adapter' || !edit.executable || entry.name !== builtin.name || entry.version !== builtin.version ||
      entry.access !== builtin.access || entry.replayClass !== builtin.replayClass || entry.execution.kind !== 'builtin' ||
      !same(entry.execution, { kind: 'builtin', adapterId: edit.entryId, adapterVersion: edit.version, adapterCodeDigest: edit.digest }) ||
      !exactKeys(entry, ['name', 'version', 'description', 'access', 'inputSchemaRef', 'inputSchemaDigest', 'replayClass', 'execution']))
    mismatch('installed tool contract differs from the fixed actual edit adapter');
  const schema = await readCanonicalArtifact(artifacts, entry.inputSchemaRef);
  const schemaEntry = installed.bundle.entries.find(candidate => candidate.digest === entry.inputSchemaRef);
  if (!schemaEntry || schemaEntry.role !== 'schema' || schemaEntry.executable || !same(schema, builtin.inputSchema) ||
      entry.inputSchemaDigest !== canonicalSha256(builtin.inputSchema)) mismatch('installed edit input schema differs from the fixed builtin');
  const verifiedTools = immutableSnapshot([{ name: entry.name, description: entry.description, inputSchemaRef: entry.inputSchemaRef,
    inputSchemaDigest: entry.inputSchemaDigest, inputSchema: schema, replayClass: entry.replayClass }]);
  const system = installed.structured.systemPrompts.find(prompt => prompt.provider === assembly.provider.name && prompt.model === assembly.provider.model);
  const compaction = installed.structured.compactionPrompts.find(prompt => prompt.provider === assembly.provider.name && prompt.model === assembly.provider.model);
  if (!system || !compaction || system.ref !== assembly.instructions.systemPromptRef || system.value.textDigest !== assembly.instructions.systemPromptDigest ||
      compaction.material.ref !== assembly.context.compactionPromptEnvelopeRef) mismatch('installed assembly substitutes signed prompt identity');
  const instructions = await readInstructions(artifacts, assembly, endpoint.ownerPrincipalId);
  const credentialRefs = [...assembly.provider.credentialGrantRefs];
  for (const ref of credentialRefs) {
    const binding = decodeEndpointCredentialGrantBinding(await readCanonicalArtifact(artifacts, ref));
    if (binding.ownerPrincipalId !== endpoint.ownerPrincipalId || binding.purpose !== 'model_endpoint' ||
        binding.endpointRegistrationRef !== assembly.provider.endpoint.endpointRegistrationRef || binding.endpointIdentityDigest !== endpoint.endpointIdentityDigest ||
        binding.tlsPolicyDigest !== endpoint.tlsPolicyDigest) mismatch('installed model credential closure is for another principal or endpoint');
  }
  const references = [
    { kind: 'runtime_bundle', ref: installed.bundleDigest, digest: installed.bundle.manifestDigest },
    { kind: 'tool_contract_manifest', ref: assembly.tools.manifestRef, digest: tools.manifestDigest },
    { kind: 'system_prompt', ref: system.ref, digest: system.value.textDigest },
    { kind: 'compaction_prompt_envelope', ref: compaction.material.ref, digest: compaction.material.value.envelopeDigest },
    { kind: 'workspace_instructions', ref: assembly.instructions.workspaceInstructionsRef, digest: instructions.manifestDigest },
  ];
  return Object.freeze({ capabilityEvidence: immutableSnapshot({ ref: assembly.provider.negotiation.capabilityEvidenceRef, value: capability }),
    resolveVerifiedCapabilityClaims: source => source.kind === 'signed_catalog' && source.runtimeBundleRef === installed.bundleDigest &&
      source.catalogEntryRef === model.catalog.ref && source.catalogEntryDigest === catalog.catalogEntryDigest ? catalog.claims : null,
    priceTable: immutableSnapshot(model.priceTable), verifyLocalZeroCostAuthority: () => false,
    resolvePriceTableAuthority: table => same(table, model.priceTable.value) ? model.priceTable.value.signatureRef : null,
    compactionEnvelope: compaction.material,
    resolveVerifiedTools: reference => same(reference, assembly.tools) ? verifiedTools : null,
    additionalCredentialGrantRefs: [], verifyReference: reference => references.some(expected => same(expected, reference)),
    verifyProviderAdapter: candidate => same(candidate, { adapter: catalog.adapter, runtimeBundleRef: installed.bundleDigest,
      runtimeBundleManifestDigest: installed.bundle.manifestDigest }),
    verifyProviderEndpoint: candidate => same(candidate, { provider: catalog.provider, model: catalog.model, endpoint: assembly.provider.endpoint,
      credentialGrantRefs: credentialRefs, capabilitySource: capability.source }) &&
      assembly.provider.endpoint.kind === 'registered' && assembly.provider.endpoint.endpointIdentityDigest === endpoint.endpointIdentityDigest &&
      assembly.provider.endpoint.tlsPolicyDigest === endpoint.tlsPolicyDigest,
  } satisfies RunAssemblyValidationMaterial);
}

export async function loadInstalledRunMaterial(input: { selected: HeldInstalledRuntime; artifacts: ArtifactCatalog; assemblyRef: string }) {
  return withHeldInstalledRuntime(input.selected, async installed => {
    await installed.revalidate();
    const assembly = decodeRetainedRunAssembly(await readCanonicalArtifact(input.artifacts, input.assemblyRef));
    if (assembly.runtime.runtimeBundleRef !== installed.bundleDigest || assembly.runtime.runtimeBundleManifestDigest !== installed.bundle.manifestDigest)
      mismatch('retained Run requires a different installed runtime');
    const material = await materialFor(installed, input.artifacts, assembly); await installed.revalidate(); return material;
  });
}

export async function assembleInstalledRun(input: {
  selected: HeldInstalledRuntime; driver: SqliteDriver; owner: StateOwnerContext; artifacts: ArtifactCatalog;
  identity: AuthenticatedControlIdentity; request: NormalizedRunSubmitRequest; originalRequest: object; source: RetiredSource;
  endpoint: EndpointRegistrationV1; credentialBindings: readonly EndpointCredentialGrantBinding[]; controlledHome: string;
}, signal?: AbortSignal): Promise<AssembledInstalledRun> {
  const { selected, driver, owner, artifacts, controlledHome } = input;
  const currentOriginal = normalizeRunSubmitRequest(input.originalRequest);
  const { identity, request, source, endpoint, credentialBindings } = immutableSnapshot({ identity: input.identity,
    request: input.request, source: input.source, endpoint: decodeEndpointRegistration(input.endpoint),
    credentialBindings: input.credentialBindings.map(decodeEndpointCredentialGrantBinding) });
  if (!same(currentOriginal.request, request)) mismatch('installed producer did not receive the exact normalized current public frame');
  assertInstalledRunRecipe(request);
  const remote = request.model;
  await validateControlChannelClosure(artifacts, owner, identity); assertActiveStateOwner(driver, owner); signal?.throwIfAborted();
  const session = readSession(driver, request.sessionId), workspace = decodeWorkspaceIdentity(await readCanonicalArtifact(artifacts, session.workspaceIdentityRef));
  if (readSessionPrincipalId(driver, session.id) !== identity.principalId || session.contextRevision !== request.expectedContextRevision ||
      workspace.kind !== 'live' || workspace.ownerPrincipalId !== identity.principalId || workspace.canonicalRootPath !== request.workspacePath)
    mismatch('installed assembly does not belong to the authenticated Session and workspace');
  const key = { principalId: identity.principalId, admissionKey: request.admissionKey, admissionIntentDigest: runSubmitIntentDigest(identity.principalId, request) };
  const retained = readSourceInspectionAttempt(driver, key);
  if (!retained || retained.phase !== 'retired' || retained.outcome.kind !== 'captured' || !same(retained, source) || source.outcome.kind !== 'captured')
    mismatch('installed admission requires the exact committed captured and retired source');
  const capturedSourceRef = source.outcome.sourceManifestRef;
  const target = await readCanonicalArtifact<import('../kernel/execution.js').SourceInspectionTargetV1>(artifacts, source.targetRef);
  const original = normalizeRunSubmitRequest(await readCanonicalArtifact(artifacts, target.originalRequestRef));
  if (runSubmitIntentDigest(identity.principalId, original.request) !== key.admissionIntentDigest || original.originalRequestDigest !== target.originalRequestDigest)
    mismatch('installed assembly substituted the original inline request domain');
  const sourceManifest = decodeSourceManifest(await readCanonicalArtifact(artifacts, capturedSourceRef));
  if (sourceManifest.workspaceIdentityDigest !== workspace.identityDigest || sourceManifest.manifestDigest !== source.outcome.sourceManifestDigest || sourceManifest.git)
    mismatch('installed source closure differs from the authenticated non-Git capture');
  const held = await withHeldInstalledRuntime(selected, async installed => {
    await installed.revalidate(); const active = assertActiveStateOwner(driver, owner);
    if (active.runtimeBundleRef !== installed.bundleDigest || target.runtimeBundleRef !== installed.bundleDigest ||
        active.runtimeBundleManifestDigest !== installed.bundle.manifestDigest) mismatch('installed assembly and capture have another runtime owner');
    await readRetainedSourceInspectionTarget(artifacts, source, readSourceInspectionOriginalRequest(driver, source.inspectionId),
      { bundle: installed.bundle, releaseKeys: installed.releaseKeys, sandboxProfile: decodeSandboxProfile(await readCanonicalArtifact(artifacts, target.sandboxProfileRef)) });
    const native = await installed.loadStateOwner(); await installed.revalidate(); return native;
  });
  const platform = await loadInstalledCredentialPlatform(selected), user = platform.currentUser();
  if (path.join(user.home, '.cliq') !== controlledHome) mismatch('installed instruction home is not the actual platform controlled home');
  const resources: Array<{ close(): void }> = []; let failure: unknown;
  let instructions: Awaited<ReturnType<typeof captureInstructions>>;
  try {
    const home = held.openWorkspaceRoot(controlledHome); resources.push(home);
    const trust = await holdWorkspaceSourceTrust(home, request.workspacePath, signal); resources.push(trust);
    assertWorkspaceSourceTrust(trust, request.workspacePath);
    const root = held.openWorkspaceRoot(request.workspacePath); resources.push(root);
    instructions = await captureInstructions(root, artifacts, workspace, session.workspaceIdentityRef, signal);
    assertWorkspaceSourceTrust(trust, request.workspacePath);
  } catch (error) { failure = error; throw error; } finally { closeOwned(resources, failure); }
  const admittedAt = sampleCanonicalNow(), deadlineAt = addCanonicalDuration(admittedAt, request.budgets.wallTimeMs);
  return withHeldInstalledRuntime(selected, async installed => {
    await installed.revalidate(); await validateControlChannelClosure(artifacts, owner, identity); assertActiveStateOwner(driver, owner);
    const model = selectedModel(installed, remote.provider, remote.model, endpoint), catalog = model.catalog.value;
    if (catalog.claims.streaming) throw new InstalledRunAuthorityError('MODEL_CAPABILITY_UNKNOWN');
    if (endpoint.ownerPrincipalId !== identity.principalId || endpoint.endpointRegistrationId !== remote.endpoint.endpointRegistrationId ||
        !endpoint.purposes.includes('model_endpoint') || endpoint.createdAt > admittedAt ||
        endpoint.tls.trustStoreRuntimeBundleRef !== installed.bundleDigest || endpoint.tls.trustStoreRuntimeBundleManifestDigest !== installed.bundle.manifestDigest)
      mismatch('installed endpoint is not the exact principal-bound model TLS authority');
    if (catalog.validFrom > admittedAt || catalog.validThrough < deadlineAt) throw new InstalledRunAuthorityError('MODEL_CAPABILITY_UNKNOWN');
    if (model.priceTable.value.validFrom > admittedAt || model.priceTable.value.validThrough < deadlineAt)
      throw new InstalledRunAuthorityError('MODEL_COST_UNKNOWN');
    if (!credentialBindings.length || credentialBindings.length !== remote.modelCredentialGrantIds.length ||
        new Set(credentialBindings.map(binding => binding.credentialGrantId)).size !== credentialBindings.length)
      mismatch('installed credential ids and frozen model bindings differ');
    const endpointArtifact = await artifacts.publishCanonical(endpoint, endpoint.format), credentialGrantRefs: string[] = [];
    for (const binding of credentialBindings) {
      if (!remote.modelCredentialGrantIds.includes(binding.credentialGrantId) || binding.ownerPrincipalId !== identity.principalId ||
          binding.purpose !== 'model_endpoint' || binding.endpointRegistrationRef !== endpointArtifact.ref ||
          binding.endpointIdentityDigest !== endpoint.endpointIdentityDigest || binding.tlsPolicyDigest !== endpoint.tlsPolicyDigest ||
          binding.createdAt > admittedAt || (binding.expiresAt && binding.expiresAt < deadlineAt)) mismatch('installed credential binding cannot authorize the complete Run interval');
      credentialGrantRefs.push((await artifacts.publishCanonical(binding, 'cliq-endpoint-credential-grant-binding-v1')).ref);
    }
    credentialGrantRefs.sort();
    const capability: ModelCapabilityEvidenceV1 = { schemaVersion: 1, format: 'cliq-model-capability-evidence-v1',
      provider: catalog.provider, model: catalog.model, endpointIdentityDigest: catalog.endpointIdentityDigest, adapter: catalog.adapter,
      source: { kind: 'signed_catalog', runtimeBundleRef: installed.bundleDigest, catalogEntryRef: model.catalog.ref, catalogEntryDigest: catalog.catalogEntryDigest },
      ...catalog.claims, observedAt: admittedAt, validThrough: catalog.validThrough, evidenceDigest: '' };
    capability.evidenceDigest = digestOmitting(capability, 'evidenceDigest');
    const capabilityArtifact = await artifacts.publishCanonical(capability, capability.format);
    const toolCandidates = installed.bundle.entries.filter(entry => entry.role === 'schema' && !entry.executable).map(entry => {
      const bytes = installed.objects.get(entry.digest); return bytes && JSON.parse(bytes.toString('utf8')) as { format?: string };
    }).filter((value): value is ToolContractManifestV1 => value?.format === 'cliq-tool-contracts-v1');
    if (toolCandidates.length !== 1) mismatch('installed runtime lacks its unique signed builtin tool manifest');
    const tools = toolCandidates[0]!, toolRef = canonicalSha256(tools);
    const system = installed.structured.systemPrompts.find(prompt => prompt.provider === catalog.provider && prompt.model === catalog.model);
    const compaction = installed.structured.compactionPrompts.find(prompt => prompt.provider === catalog.provider && prompt.model === catalog.model);
    const worker = installed.bundle.entries.find(entry => entry.entryId === LINUX_WORKER_RECIPE.workerId);
    if (!system || !compaction || !worker || worker.role !== 'worker' || !worker.executable) mismatch('installed Run lacks its exact signed prompt or worker recipe');
    const c = catalog.claims.contextLimitTokens, o = Math.min(catalog.claims.maxOutputTokens, Math.floor(c / 4));
    const h = c - o, s = Math.min(8192, Math.floor(c / 8)), k = compactionEnvelopeEstimate(compaction.material);
    const assembly: RunAssemblyV1 = { schemaVersion: 1, format: 'cliq-run-assembly-v1', provider: { name: catalog.provider, model: catalog.model,
      endpoint: { kind: 'registered', registrationKind: endpoint.registrationKind, endpointRegistrationRef: endpointArtifact.ref,
        endpointIdentityDigest: endpoint.endpointIdentityDigest, tlsPolicyDigest: endpoint.tlsPolicyDigest }, credentialGrantRefs,
      adapter: catalog.adapter, negotiation: { mode: capability.nativeToolCalling ? 'native-tools' : 'text-only',
        capabilityEvidenceRef: capabilityArtifact.ref, capabilityDigest: capability.evidenceDigest, ...catalog.claims,
        exposedToolNames: capability.nativeToolCalling ? tools.entries.map(entry => entry.name) : [] },
      pricing: { kind: 'trusted_price_table', priceTableRef: model.priceTable.ref, priceTableDigest: model.priceTable.value.tableDigest,
        calculationAlgorithm: 'cliq-price-ceil-v1', maxRunCostMicros: request.budgets.costMicros, validThrough: model.priceTable.value.validThrough,
        provenanceRef: model.priceTable.value.signatureRef } }, mcpServers: [], tools: { manifestRef: toolRef, manifestDigest: tools.manifestDigest },
      instructions: { systemPromptRef: system.ref, systemPromptDigest: system.value.textDigest, workspaceInstructionsRef: instructions.ref,
        workspaceInstructionsDigest: instructions.value.manifestDigest, skills: [] },
      runtime: { runtimeBundleRef: installed.bundleDigest, runtimeBundleManifestDigest: installed.bundle.manifestDigest,
        workerExecutableId: worker.entryId, workerExecutableDigest: worker.digest, sandboxBackend: 'linux_namespace' },
      retry: { model: { maxDispatchedAttempts: 3, maxZeroByteTransportRetriesPerAttempt: 0, postAttemptDelaysMs: [500, 2000] },
        tools: tools.entries.map(entry => ({ toolName: entry.name, replayClass: 'manual', maxDispatchedAttempts: 1, postAttemptDelaysMs: [] })) },
      context: { compactionPromptEnvelopeRef: compaction.material.ref, compactionPromptEnvelopeDigest: compaction.material.value.envelopeDigest,
        contextLimitTokens: c, reservedOutputTokens: o, hardPromptTokens: h, triggerThresholdTokens: Math.min(Number(7n * BigInt(c) / 10n), h - 8192),
        protectedRecentTokens: Math.min(32768, Math.floor(c / 4)), summaryTokenCap: s, compactionEnvelopeTokens: k,
        sourceInputTokenCap: Math.min(Math.floor(c / 2), c - s - k), maxSummaryBytes: 262144 }, createdAt: admittedAt, assemblyDigest: '' };
    assembly.assemblyDigest = digestOmitting(assembly, 'assemblyDigest');
    const material = await materialFor(installed, artifacts, assembly), assemblyRef = canonicalSha256(assembly);
    const valid = validateRunAssembly({ assemblyRef, assembly, admittedAt, deadlineAt, maxRunCostMicros: request.budgets.costMicros,
      runSpecCredentialGrantRefs: credentialGrantRefs, material });
    if (!valid.ok) throw new InstalledRunAuthorityError(valid.code);
    const profile = policyProfile(), profileEntry = installed.bundle.entries.find(entry => entry.role === 'policy_engine')!;
    const policy: RunPolicySnapshotV1 = { schemaVersion: 1, format: 'cliq-run-policy-v1', principalId: identity.principalId,
      workspaceIdentityDigest: workspace.identityDigest, mode: request.policyMode,
      engine: { id: 'cliq-policy-v1', version: profileEntry.version, runtimeBundleRef: installed.bundleDigest,
        profileEntryId: profileEntry.entryId, profileRef: profileEntry.digest, profileDigest: profile.profileDigest },
      toolManifestRef: toolRef, toolManifestDigest: tools.manifestDigest, decisions: modeDecisions(request.policyMode),
      decisionRules: [...BUILTIN_POLICY_RULES], repositoryRequestRefs: [], createdAt: admittedAt, policyDigest: '' };
    policy.policyDigest = digestOmitting(policy, 'policyDigest');
    verifyToolRuntimeAuthority({ assembly, policy, bundle: installed.bundle, profile, tools: tools.entries, releaseKeys: installed.releaseKeys });
    const sandbox = installedSandboxProfile(request.sandboxResources);
    const verifier: VerifierSpec = { schemaVersion: 1, format: 'cliq-verifier-spec-v1', verifiers: [], specDigest: '' };
    verifier.specDigest = digestOmitting(verifier, 'specDigest');
    await artifacts.publishCanonical(assembly, assembly.format);
    const policyRef = (await artifacts.publishCanonical(policy, policy.format)).ref;
    const sandboxProfileRef = (await artifacts.publishCanonical(sandbox, sandbox.format)).ref;
    const verifierSpecRef = (await artifacts.publishCanonical(verifier, verifier.format)).ref;
    await installed.revalidate(); await validateControlChannelClosure(artifacts, owner, identity); assertActiveStateOwner(driver, owner);
    const result: AssembledInstalledRun = Object.freeze({ assemblyRef, assembly: immutableSnapshot(assembly), policyRef, sandboxProfileRef, verifierSpecRef,
      credentialGrantRefs: Object.freeze(credentialGrantRefs), sourceProjectionRef: sourceManifest.sourceProjectionRef,
      frozenIgnoreRulesRef: sourceManifest.frozenIgnoreRulesRef, baseWorkspaceManifestRef: capturedSourceRef, material, admittedAt, deadlineAt });
    admissions.set(result, { driver, owner, selected, identity, normalized: currentOriginal, source, native: held, workspace,
      input: immutableSnapshot({ ...identity, requestId: request.requestId, admissionKey: request.admissionKey, sessionId: request.sessionId,
        expectedContextRevision: request.expectedContextRevision, workspacePath: request.workspacePath, objective: request.objective,
        assemblyRef, policyRef, sandboxProfileRef, verifierSpecRef, credentialGrantRefs, budgets: request.budgets,
        allowUnverified: request.allowUnverified, sourceProjectionRef: sourceManifest.sourceProjectionRef,
        frozenIgnoreRulesRef: sourceManifest.frozenIgnoreRulesRef, baseWorkspaceManifestRef: capturedSourceRef }), admittedAt, deadlineAt });
    return result;
  });
}

/** Genuine-brand-first admission friend. Data objects, proxies and callbacks
 * cannot select an alternate public request digest or installed capture. */
export function readInstalledRunAdmission(prepared: AssembledInstalledRun, driver: SqliteDriver,
  owner: StateOwnerContext, identity: AuthenticatedControlIdentity, connection: SqliteConnection | SqliteDriver = driver): Readonly<Pick<AdmissionBinding,
    'input' | 'normalized' | 'source' | 'admittedAt' | 'deadlineAt'>> {
  const binding = admissions.get(prepared);
  if (!binding || binding.driver !== driver || binding.owner !== owner || !same(binding.identity, identity))
    mismatch('installed admission token has no matching authenticated producer');
  assertActiveStateOwner(connection, owner);
  const key = { principalId: identity.principalId, admissionKey: binding.normalized.request.admissionKey,
    admissionIntentDigest: runSubmitIntentDigest(identity.principalId, binding.normalized.request) };
  if (!same(readSourceInspectionAttempt(connection, key), binding.source)) mismatch('installed admission source cut changed');
  const session = readSession(connection, binding.normalized.request.sessionId);
  if (readSessionPrincipalId(connection, session.id) !== identity.principalId || session.contextRevision !== binding.normalized.request.expectedContextRevision)
    mismatch('installed admission Session cut changed');
  return immutableSnapshot({ input: binding.input, normalized: binding.normalized, source: binding.source,
    admittedAt: binding.admittedAt, deadlineAt: binding.deadlineAt });
}

/** Admission friend using the already-held installed native implementation.
 * No named development addon, injected factory or reentrant runtime borrow. */
export function recheckInstalledRunWorkspace(prepared: AssembledInstalledRun, driver: SqliteDriver,
  owner: StateOwnerContext, identity: AuthenticatedControlIdentity, connection: SqliteConnection | SqliteDriver = driver): void {
  readInstalledRunAdmission(prepared, driver, owner, identity, connection);
  const binding = admissions.get(prepared)!;
  const root = binding.native.openWorkspaceRoot(binding.workspace.canonicalRootPath); let failure: unknown;
  try {
    assertHeldWorkspaceRoot(root);
    if (!same(root.identity, binding.workspace.rootIdentity) || heldWorkspaceRootPath(root) !== binding.workspace.canonicalRootPath || root.repositoryDirectory)
      mismatch('installed admission workspace root changed after trusted capture');
    root.assertHeld();
  } catch (error) { failure = error; throw error; } finally { closeOwned([root], failure); }
}
