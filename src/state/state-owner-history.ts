import { readRuntimeUpgradeBoundary } from './runtime-upgrade-history.js';
import type { SignedSchemaConversionV1 } from '../kernel/runtime-upgrade.js';
import { readSignedSchemaConversion, readSignedKernelSchema } from './signed-schema.js';
// Retained data only. This reader never acquires a lock, observes a process or
// supplies authority for a live observation. Owning callers retain those gates.
import { canonicalSha256 } from '../kernel/canonical.js';
import { KERNEL_CAS_DIRECTORY, KERNEL_SQLITE_APPLICATION_ID, KERNEL_STATE_SCHEMA_VERSION } from '../config.js';
import { assertArtifactRef, digestOmitting, identityHash, normalizeAbsolutePath, requiredSafeInteger } from '../kernel/identity.js';
import type { PlatformProcessIdentityV1, StateOwnerAcquisitionEvidenceV1,
  StateOwnerRecordV1, StateOwnerTransitionEvidenceV1, StateLockIdentityV1, StateRootIdentityV1, KernelGenerationIdentityV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeRetainedInstalledModelAuthorityClosure, validateRetainedInstalledModelAuthorityData } from '../model/installed-authority.js';
import { exactKeys, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { readCanonicalArtifact } from './agent-context.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodePlatformProcessIdentity, decodeStateLockIdentity, decodeStateRootIdentity,
  decodeStateOwnerAcquisitionEvidence, decodeStateOwnerTransitionEvidence } from './decoders.js';
import { KernelStorageError } from './errors.js';
import { decodeSandboxRootProfile } from './execution-closure.js';
import { checkCanonicalBytes, validateInstalledStructuredArtifacts, validateTrustStore } from './installed-artifacts.js';
import { kernelSchemaBirthRecipe } from './schema.js';
import type { SqliteConnection, SqliteDriver } from './sqlite-driver.js';
import { readStateOwner } from './state-owner.js';
import { decodeGuestToolchainManifest, guestToolchainMembers, guestToolchainRoots } from './guest-toolchain.js';
import { GUEST_EXTRACTOR_RECIPE } from '../sandbox/guest-toolchain.js';
import { hostPlatform } from './workspace-identity.js';
import { bundledSkillMemberRoles, bundledSkillRoots, validateBundledSkillReferences } from './bundled-skills.js';
import { decodeBundledSkillClosure, SKILL_RESOURCE_BYTES, type BundledSkillClosureV1 } from '../kernel/skill.js';
import { isNpmAdapterEntry, isNpmDataEntry } from '../sandbox/dependency-recipe.js';

type Entry = { owner: StateOwnerRecordV1; process: PlatformProcessIdentityV1;
  acquisition: StateOwnerAcquisitionEvidenceV1; transition?: StateOwnerTransitionEvidenceV1 };
export type RetainedStateOwnerHistory = Readonly<{
  throughEpoch: number; entries: readonly Entry[];
  lockIdentity: StateLockIdentityV1; rootIdentity: StateRootIdentityV1;
  /** Only the extra frame needed to close a terminal takeover at the cut end. */
  successorWitness?: Readonly<Entry>;
  assertUnchanged(connection: SqliteConnection): void;
}>;
function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', message); }

type BirthMember = { artifactRef: string; byteCount: number };
/** Same fixed data bounds/roles as the original installer. No standalone executable is a
 * CAS edge, and no current selection or self-selected signing key is read. */
async function readInstalledSeed(artifacts: ArtifactCatalog, first: Entry,
  generation: Extract<KernelGenerationIdentityV1, { origin: 'fresh_installed' }>, members: readonly BirthMember[]): Promise<void> {
  const smallBytes = 1_048_576, trustBytes = 16 * smallBytes;
  const dataRoles = new Set(['policy_engine', 'sandbox_root_profile', 'system_prompt', 'compaction_prompt', 'bundle_object', 'guest_toolchain', 'schema', 'trust_store', 'skill_bundle']);
  const inventory = new Map(members.map(member => [member.artifactRef, member.byteCount]));
  const expected = new Map<string, number>(), buffers = new Map<string, Buffer>();
  const requireMember = (ref: string, byteCount: number) => {
    assertArtifactRef(ref);
    if (!Number.isSafeInteger(byteCount) || byteCount < 0 || inventory.get(ref) !== byteCount ||
        (expected.has(ref) && expected.get(ref) !== byteCount)) invalid('retained installed genesis omits or substitutes a required seed member');
    expected.set(ref, byteCount);
  };
  const read = async (ref: string, byteCount: number, limit: number) => {
    requireMember(ref, byteCount);
    if (byteCount > limit) invalid('retained installed seed member exceeds its original recipe bound');
    const cached = buffers.get(ref); if (cached) return cached;
    const chunks: Buffer[] = [];
    for await (const chunk of artifacts.readChunks(ref, byteCount)) chunks.push(Buffer.from(chunk));
    const bytes = Buffer.concat(chunks);
    if (bytes.length !== byteCount) invalid('retained installed seed member byte count differs');
    buffers.set(ref, bytes); return bytes;
  };
  const bundleRef = first.owner.runtimeBundleRef, bundleSize = inventory.get(bundleRef);
  if (bundleSize === undefined) invalid('retained installed genesis has no original RuntimeBundle');
  const bundle = checkCanonicalBytes(await read(bundleRef, bundleSize, smallBytes)) as RuntimeBundleManifest;
  if (!bundle || typeof bundle !== 'object' || !Array.isArray(bundle.entries) || !Array.isArray(bundle.structuredArtifacts) ||
      canonicalSha256(bundle) !== bundleRef || bundle.manifestDigest !== first.owner.runtimeBundleManifestDigest)
    invalid('retained installed genesis RuntimeBundle differs');
  const data = bundle.entries.filter(entry => dataRoles.has(entry.role) || entry.role === 'tool_adapter' && !entry.executable);
  for (const entry of data) {
    if (entry.executable) invalid('retained installed seed data entry is executable');
    requireMember(entry.digest, entry.byteCount);
  }
  const guests = [];
  for (const root of guestToolchainRoots(bundle)) {
    const size = inventory.get(root.artifactRef);
    if (size === undefined) invalid('retained installed genesis lacks its original guest manifest');
    const manifest = decodeGuestToolchainManifest(checkCanonicalBytes(await read(root.artifactRef, size, smallBytes)));
    guestToolchainMembers(bundle, root.artifactRef, manifest); guests.push(manifest);
  }
  const guestImages = new Set(guests.map(manifest => manifest.guestImageRef));
  const guestSignatures = new Set(guests.map(manifest => manifest.signatureRef));
  const skillClosures = new Map<string, Readonly<BundledSkillClosureV1>>();
  for (const root of bundledSkillRoots(bundle)) {
    const size = inventory.get(root.artifactRef); if (size === undefined) invalid('retained installed genesis lacks an original skill closure');
    skillClosures.set(root.artifactRef, decodeBundledSkillClosure(checkCanonicalBytes(await read(root.artifactRef, size, smallBytes))));
  }
  const skillMembers = bundledSkillMemberRoles(bundle, skillClosures);
  const source = generation.modelAuthoritySource;
  if (!source || typeof source !== 'object' || (source.kind === 'none'
    ? !exactKeys(source, ['kind'])
    : source.kind !== 'present' || !exactKeys(source, ['kind', 'closureRef', 'closureDigest'])))
    invalid('retained installed genesis has no exact original model-authority source');
  let companion: ReturnType<typeof decodeRetainedInstalledModelAuthorityClosure> | undefined;
  if (source.kind === 'present') {
    assertArtifactRef(source.closureRef); assertArtifactRef(source.closureDigest);
    const count = inventory.get(source.closureRef);
    if (count === undefined) invalid('retained installed genesis lacks its original companion');
    companion = decodeRetainedInstalledModelAuthorityClosure(checkCanonicalBytes(await read(source.closureRef, count, smallBytes)), { bundle });
    if (companion.closureDigest !== source.closureDigest) invalid('retained installed genesis companion digest differs');
    for (const object of companion.objects) requireMember(object.artifactRef, object.byteCount);
  }
  if (expected.size !== inventory.size) invalid('retained installed genesis has missing or extra original seed objects');
  for (const entry of data) {
    if (isNpmDataEntry(entry)) {
      for await (const _chunk of artifacts.readChunks(entry.digest, entry.byteCount)) { /* Complete fixed signed image; no per-file CAS expansion. */ }
      continue;
    }
    if (guestImages.has(entry.digest)) {
      if (entry.byteCount < 1 || entry.byteCount > GUEST_EXTRACTOR_RECIPE.maxImageBytes)
        invalid('retained installed guest image exceeds its original recipe bound');
      for await (const _chunk of artifacts.readChunks(entry.digest, entry.byteCount)) { /* Complete original image, never a metadata-only digest. */ }
      continue;
    }
    if (skillMembers.resources.has(entry.digest) && !skillMembers.instructions.has(entry.digest) && !guestSignatures.has(entry.digest)) {
      if (entry.byteCount > SKILL_RESOURCE_BYTES) invalid('retained installed skill resource exceeds its original bound');
      for await (const _chunk of artifacts.readChunks(entry.digest, entry.byteCount)) { /* Complete original data, never an executable identity. */ }
      continue;
    }
    const bytes = await read(entry.digest, entry.byteCount, guestSignatures.has(entry.digest) ? 64 : entry.role === 'trust_store' ? trustBytes : smallBytes);
    if (guestSignatures.has(entry.digest)) {
      if (bytes.length !== 64) invalid('retained installed guest signature is not complete');
      continue;
    }
    if (skillMembers.instructions.has(entry.digest)) {
      // SKILL.md is source text, not canonical JSON. The common structured
      // consumer below rederives its exact instruction from complete bytes.
    } else if (entry.role === 'tool_adapter') {
      if (!isNpmAdapterEntry(entry) && (entry.entryId !== 'builtin_tools' || entry.version !== '1' || entry.relativePath !== 'adapters/builtin-tools.mjs' || bytes.length < 1))
        invalid('retained installed tool script differs from its fixed original data role');
    } else if (entry.role === 'trust_store') validateTrustStore(bytes);
    else {
      const value = checkCanonicalBytes(bytes);
      if (entry.role === 'sandbox_root_profile') decodeSandboxRootProfile(value);
    }
  }
  await validateBundledSkillReferences(skillClosures, async (ref, byteCount) => {
    const retained = buffers.get(ref); if (retained) return retained;
    requireMember(ref, byteCount);
    if (byteCount > SKILL_RESOURCE_BYTES) invalid('retained skill textual resource exceeds its original bound');
    const chunks: Buffer[] = []; let count = 0;
    for await (const chunk of artifacts.readChunks(ref, byteCount)) { count += chunk.length; if (count > byteCount) invalid('retained skill resource length changed'); chunks.push(Buffer.from(chunk)); }
    if (count !== byteCount) invalid('retained skill resource is incomplete');
    return Buffer.concat(chunks);
  });
  validateInstalledStructuredArtifacts(bundle, buffers);
  if (companion) {
    const objects = new Map<string, Buffer>();
    for (const object of companion.objects) objects.set(object.artifactRef,
      await read(object.artifactRef, object.byteCount, object.kind === 'ed25519_signature' ? 64 : 65_536));
    validateRetainedInstalledModelAuthorityData({ closure: companion, bundle, objects });
  }
  // These checks only rewalk the source-authenticated retained data. The
  // opening/owning installation gate independently authenticates trusted keys.
}

/** Only the two actually implemented birth origins and exact known schemas. This is
 * historical rehashing, not another pristine-namespace or migration bootstrap. */
async function readGenesis(artifacts: ArtifactCatalog, first: Entry, lock: StateLockIdentityV1,
  runtimeKind: 'schema' | 'signed', conversion?: SignedSchemaConversionV1): Promise<void> {
  if (first.acquisition.kind !== 'genesis') invalid('StateOwner history has no exact genesis');
  const acquisition = first.acquisition;
  const generation = await readCanonicalArtifact<KernelGenerationIdentityV1>(artifacts, acquisition.kernelGenerationIdentityRef);
  if (generation.origin !== 'fresh_empty' && generation.origin !== 'fresh_installed') invalid('unsupported retained StateOwner genesis origin');
  const recipe = kernelSchemaBirthRecipe(generation.stateSchemaVersion);
  if (conversion && generation.stateSchemaVersion !== 7) invalid('signed conversion cannot reinterpret another original birth version');
  if (runtimeKind === 'schema') {
    if (generation.origin !== 'fresh_empty' || generation.pristineSchemaManifestRef !== first.owner.runtimeBundleRef ||
        generation.pristineSchemaManifestDigest !== first.owner.runtimeBundleManifestDigest)
      invalid('retained schema-only genesis differs from its original runtime schema');
  } else if (generation.stateSchemaVersion !== KERNEL_STATE_SCHEMA_VERSION && !(
      generation.stateSchemaVersion === 7 && conversion?.source.runtimeBundleRef === first.owner.runtimeBundleRef &&
      conversion.source.runtimeBundleManifestDigest === first.owner.runtimeBundleManifestDigest &&
      conversion.source.schemaManifestRef === generation.pristineSchemaManifestRef &&
      conversion.source.schemaManifestDigest === generation.pristineSchemaManifestDigest &&
      conversion.source.schemaDigest === generation.pristineSchemaDigest)) {
    // Existing signed births have no exact historical signed-schema source.
    // A supported DDL recipe or broad compatibility range cannot supply it.
    invalid('retained signed schema upgrade requires its original schema authority');
  }
  if (!exactKeys(generation, ['schemaVersion', 'format', 'generationId', 'stateRootIdentityRef', 'stateRootIdentityDigest',
    'databaseImageRef', 'databaseImageDigest', 'databaseIdentityDigest', 'databaseContentDigest', 'casNamespaceManifestRef',
    'casNamespaceManifestDigest', 'casNamespaceId', 'casRootDigest', 'stateSchemaVersion', 'generationDigest', 'origin',
    'pristineSchemaManifestRef', 'pristineSchemaManifestDigest', 'pristineSchemaDigest',
    ...(generation.origin === 'fresh_installed' ? ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'modelAuthoritySource'] : [])]) ||
      generation.schemaVersion !== 1 || generation.format !== 'cliq-kernel-generation-identity-v1' ||
      generation.generationDigest !== acquisition.kernelGenerationIdentityDigest ||
      generation.generationDigest !== digestOmitting(generation, 'generationDigest') ||
      generation.stateRootIdentityRef !== lock.stateRootIdentityRef || generation.stateRootIdentityDigest !== lock.stateRootIdentityDigest ||
      generation.pristineSchemaDigest !== recipe.schemaDigest)
    invalid('retained StateOwner genesis is outside the implemented birth recipe');
  for (const key of ['databaseImageRef', 'databaseImageDigest', 'databaseIdentityDigest', 'databaseContentDigest',
    'casNamespaceManifestRef', 'casNamespaceManifestDigest', 'casRootDigest', 'pristineSchemaManifestRef',
    'pristineSchemaManifestDigest', 'pristineSchemaDigest'] as const) assertArtifactRef(generation[key]);
  const installed = generation.origin === 'fresh_installed';
  if (generation.generationId !== (installed
    ? identityHash('cliq-kernel-generation-v1', lock.stateRootIdentityDigest, 'fresh_installed', first.owner.runtimeBundleRef)
    : identityHash('cliq-kernel-generation-v1', lock.stateRootIdentityDigest, 'fresh_empty')) ||
      (installed && (generation.runtimeBundleRef !== first.owner.runtimeBundleRef ||
        generation.runtimeBundleManifestDigest !== first.owner.runtimeBundleManifestDigest))) invalid('retained StateOwner genesis identity drifted');
  const schema = await readCanonicalArtifact<Record<string, unknown>>(artifacts, generation.pristineSchemaManifestRef);
  if (!exactKeys(schema, ['schemaVersion', 'format', 'applicationId', 'userVersion', 'schemaDigest', 'manifestDigest']) ||
      schema.schemaVersion !== 1 || schema.format !== 'cliq-kernel-schema-manifest-v1' ||
      schema.applicationId !== KERNEL_SQLITE_APPLICATION_ID || schema.userVersion !== recipe.userVersion ||
      schema.schemaDigest !== generation.pristineSchemaDigest || schema.manifestDigest !== generation.pristineSchemaManifestDigest ||
      schema.manifestDigest !== digestOmitting(schema, 'manifestDigest')) invalid('retained StateOwner pristine schema does not match');
  const database = await readCanonicalArtifact<Record<string, unknown>>(artifacts, generation.databaseImageRef);
  if (!exactKeys(database, ['schemaVersion', 'format', 'applicationId', 'userVersion', 'contentDigest']) ||
      database.schemaVersion !== 1 || database.format !== 'cliq-kernel-empty-database-v1' ||
      database.applicationId !== KERNEL_SQLITE_APPLICATION_ID || database.userVersion !== recipe.userVersion ||
      database.contentDigest !== recipe.emptyDatabaseContentDigest || database.contentDigest !== generation.databaseContentDigest ||
      generation.databaseImageDigest !== generation.databaseImageRef || generation.databaseIdentityDigest !== generation.databaseImageRef)
    invalid('retained StateOwner empty database birth does not match');
  const namespace = await readCanonicalArtifact<Record<string, unknown>>(artifacts, generation.casNamespaceManifestRef);
  if (!exactKeys(namespace, ['schemaVersion', 'format', 'snapshotBoundary', 'namespaceId', 'stateRootIdentityRef',
    'stateRootIdentityDigest', 'canonicalRootRelativePath', 'ownerUid', 'deviceId', 'directoryFileId', 'mode', 'entries',
    'objectCount', 'totalBytes', 'rootDigest', 'manifestDigest']) || namespace.schemaVersion !== 1 ||
      namespace.format !== 'cliq-cas-namespace-manifest-v1' || namespace.snapshotBoundary !== 'generation_birth' ||
      namespace.namespaceId !== identityHash('cliq-cas-namespace-v1', lock.stateRootIdentityDigest, 'cas') ||
      namespace.namespaceId !== generation.casNamespaceId || namespace.stateRootIdentityRef !== lock.stateRootIdentityRef ||
      namespace.stateRootIdentityDigest !== lock.stateRootIdentityDigest || namespace.canonicalRootRelativePath !== KERNEL_CAS_DIRECTORY ||
      namespace.ownerUid !== lock.ownerUid || namespace.mode !== 448 ||
      typeof namespace.deviceId !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(namespace.deviceId) ||
      typeof namespace.directoryFileId !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(namespace.directoryFileId) ||
      !Array.isArray(namespace.entries) || namespace.objectCount !== namespace.entries.length ||
      namespace.rootDigest !== canonicalSha256(namespace.entries) || namespace.rootDigest !== generation.casRootDigest ||
      namespace.manifestDigest !== generation.casNamespaceManifestDigest || namespace.manifestDigest !== digestOmitting(namespace, 'manifestDigest'))
    invalid('retained StateOwner CAS birth namespace does not match');
  let total = 0, previous = '';
  for (const entry of namespace.entries as Array<{ artifactRef: string; byteCount: number }>) {
    if (!exactKeys(entry, ['artifactRef', 'byteCount']) || typeof entry.artifactRef !== 'string') invalid('invalid retained birth member');
    assertArtifactRef(entry.artifactRef);
    if (entry.artifactRef <= previous || !Number.isSafeInteger(entry.byteCount) || entry.byteCount < 0 ||
        entry.byteCount > Number.MAX_SAFE_INTEGER - total) invalid('unordered or overflowing retained birth members');
    previous = entry.artifactRef; total += entry.byteCount;
  }
  if (namespace.totalBytes !== total || (!installed && namespace.entries.length !== 0))
    invalid('retained StateOwner genesis CAS source does not match');
  if (generation.origin === 'fresh_installed') await readInstalledSeed(artifacts, first, generation, namespace.entries as BirthMember[]);
}

async function readRuntime(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1): Promise<'schema' | 'signed'> {
  const value = await readCanonicalArtifact<RuntimeBundleManifest & { format?: string }>(artifacts, owner.runtimeBundleRef);
  if (value.format === 'cliq-kernel-schema-manifest-v1') {
    const recipe = kernelSchemaBirthRecipe(Reflect.get(value, 'userVersion'));
    if (!exactKeys(value, ['schemaVersion', 'format', 'applicationId', 'userVersion', 'schemaDigest', 'manifestDigest']) ||
        value.schemaVersion !== 1 || Reflect.get(value, 'applicationId') !== KERNEL_SQLITE_APPLICATION_ID ||
        Reflect.get(value, 'schemaDigest') !== recipe.schemaDigest ||
        value.manifestDigest !== owner.runtimeBundleManifestDigest ||
        value.manifestDigest !== digestOmitting(value, 'manifestDigest') || owner.supervisorEntryId !== 'state-store' ||
        owner.supervisorEntryVersion !== 'm2') invalid('retained schema-only StateOwner runtime does not match');
    return 'schema';
  }
  if (!exactKeys(value, ['schemaVersion', 'bundleVersion', 'controlProtocolRange', 'headlessSchemaRange',
    'stateSchemaRange', 'workerProtocolRange', 'entries', 'structuredArtifacts', 'guestToolchainManifestRefs',
    'publisherKeyId', 'manifestDigest', 'signature']) || value.schemaVersion !== 1 || !Array.isArray(value.entries))
    invalid('retained StateOwner runtime manifest is invalid');
  const { signature: _signature, manifestDigest: _digest, ...core } = value;
  const supervisors = value.entries.filter(entry => entry.role === 'supervisor');
  if (value.manifestDigest !== owner.runtimeBundleManifestDigest || value.manifestDigest !== canonicalSha256(core) ||
      supervisors.length !== 1 || !supervisors[0]!.executable || supervisors[0]!.entryId !== owner.supervisorEntryId ||
      supervisors[0]!.version !== owner.supervisorEntryVersion || supervisors[0]!.digest !== owner.supervisorExecutableDigest)
    invalid('retained StateOwner runtime does not name its exact Supervisor');
  // The actual opening authenticates the selected release keys and bytes.
  // Rehashing this retained manifest never trusts a key from the manifest itself.
  return 'signed';
}

async function readFrame(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1): Promise<Entry> {
  const processIdentity = decodePlatformProcessIdentity(await readCanonicalArtifact(artifacts, owner.processIdentityRef));
  const acquisition = decodeStateOwnerAcquisitionEvidence(await readCanonicalArtifact(artifacts, owner.acquisitionEvidenceRef));
  if (processIdentity.identityDigest !== owner.processIdentityDigest ||
      processIdentity.executableImageDigest !== owner.supervisorExecutableDigest ||
      typeof process.geteuid !== 'function' || processIdentity.ownerUid !== process.geteuid() ||
      processIdentity.platform !== hostPlatform() || processIdentity.observedAt !== owner.acquiredAt ||
      acquisition.evidenceDigest !== owner.acquisitionEvidenceDigest || acquisition.ownerEpoch !== owner.ownerEpoch ||
      acquisition.supervisorInstanceId !== owner.supervisorInstanceId || acquisition.runtimeBundleRef !== owner.runtimeBundleRef ||
      acquisition.runtimeBundleManifestDigest !== owner.runtimeBundleManifestDigest ||
      acquisition.processIdentityRef !== owner.processIdentityRef || acquisition.processIdentityDigest !== owner.processIdentityDigest ||
      acquisition.stateLockIdentityRef !== owner.stateLockIdentityRef || acquisition.stateLockIdentityDigest !== owner.stateLockIdentityDigest ||
      acquisition.instanceNonceDigest !== owner.instanceNonceDigest || acquisition.acquiredAt !== owner.acquiredAt ||
      (owner.ownerEpoch === 1 ? acquisition.kind !== 'genesis' : acquisition.kind === 'genesis' ||
        acquisition.priorOwnerEpoch !== owner.ownerEpoch - 1)) invalid('StateOwner process/acquisition closure does not match');
  return { owner, process: processIdentity, acquisition };
}

/** The original one-frame check used when constructing an already-owned Store context. */
export async function readRetainedStateOwnerProcess(artifacts: ArtifactCatalog, owner: StateOwnerRecordV1): Promise<PlatformProcessIdentityV1> {
  return (await readFrame(artifacts, owner)).process;
}

async function readTransition(artifacts: ArtifactCatalog, prior: Extract<StateOwnerRecordV1, { state: 'terminal' }>,
  successor?: StateOwnerRecordV1): Promise<StateOwnerTransitionEvidenceV1> {
  const transition = decodeStateOwnerTransitionEvidence(await readCanonicalArtifact(artifacts, prior.transitionEvidenceRef));
  if (transition.kind !== prior.terminalReason || transition.evidenceDigest !== prior.transitionEvidenceDigest ||
      transition.priorOwnerEpoch !== prior.ownerEpoch || transition.priorSupervisorInstanceId !== prior.supervisorInstanceId ||
      transition.priorProcessIdentityRef !== prior.processIdentityRef || transition.priorProcessIdentityDigest !== prior.processIdentityDigest ||
      transition.stateLockIdentityRef !== prior.stateLockIdentityRef || transition.stateLockIdentityDigest !== prior.stateLockIdentityDigest ||
      (transition.kind === 'graceful_release'
        ? transition.releasingProcessIdentityRef !== prior.processIdentityRef || transition.releasingProcessIdentityDigest !== prior.processIdentityDigest
        : !successor || transition.successorOwnerEpoch !== successor.ownerEpoch ||
          transition.successorSupervisorInstanceId !== successor.supervisorInstanceId ||
          transition.successorRuntimeBundleRef !== successor.runtimeBundleRef ||
          transition.successorRuntimeBundleManifestDigest !== successor.runtimeBundleManifestDigest ||
          transition.successorProcessIdentityRef !== successor.processIdentityRef ||
          transition.successorProcessIdentityDigest !== successor.processIdentityDigest ||
          transition.successorInstanceNonceDigest !== successor.instanceNonceDigest || transition.observedAt !== successor.acquiredAt))
    invalid('StateOwner transition evidence does not match its prior/successor');
  return transition;
}

function readRows(connection: SqliteConnection, throughEpoch: number): StateOwnerRecordV1[] {
  const rows = connection.prepare('SELECT owner_epoch FROM state_owners WHERE owner_epoch <= ? ORDER BY owner_epoch')
    .all<{ owner_epoch: unknown }>(BigInt(throughEpoch));
  if (rows.length !== throughEpoch) invalid('retained StateOwner history has a missing epoch');
  return rows.map((row, index) => {
    if (requiredSafeInteger(row.owner_epoch, 'retained StateOwner epoch') !== index + 1) invalid('retained StateOwner epochs are not contiguous');
    return readStateOwner(connection, index + 1)!;
  });
}

/** A single consistent SQL prefix followed by immutable artifact rewalks.
 * The synchronous comparator is a CAS guard, never a physical proof. */
export async function readRetainedStateOwnerHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  throughEpoch: number): Promise<RetainedStateOwnerHistory> {
  try { return await readHistory(driver, artifacts, throughEpoch); }
  catch (error) {
    if (error instanceof TypeError || error instanceof SyntaxError)
      throw new KernelStorageError('RECOVERY_REQUIRED', 'retained StateOwner history is not a closed typed graph', { cause: error });
    // Native/resource retirement and actual I/O failures retain their original
    // identity; bad data is not permission to hide uncertainty or retry I/O.
    throw error;
  }
}

async function readHistory(driver: SqliteDriver, artifacts: ArtifactCatalog,
  throughEpoch: number): Promise<RetainedStateOwnerHistory> {
  if (!Number.isSafeInteger(throughEpoch) || throughEpoch < 1) invalid('invalid retained StateOwner history epoch');
  const owners = driver.readSnapshot(connection => {
    const prefix = readRows(connection, throughEpoch), last = prefix.at(-1)!;
    if (last.state === 'terminal' && last.terminalReason === 'superseded_after_owner_death') {
      const witness = readStateOwner(connection, throughEpoch + 1);
      if (!witness) invalid('retained StateOwner takeover has no exact successor witness');
      prefix.push(witness);
    }
    return prefix;
  });
  const casThroughEpoch = owners.length;
  const entries: Entry[] = [];
  for (const owner of owners) entries.push(await readFrame(artifacts, owner));
  const first = entries[0]!.owner;
  const lockIdentity = decodeStateLockIdentity(await readCanonicalArtifact(artifacts, first.stateLockIdentityRef));
  const rootIdentity = decodeStateRootIdentity(await readCanonicalArtifact(artifacts, lockIdentity.stateRootIdentityRef));
  if (lockIdentity.identityDigest !== first.stateLockIdentityDigest ||
      rootIdentity.identityDigest !== lockIdentity.stateRootIdentityDigest ||
      rootIdentity.canonicalAbsolutePath !== normalizeAbsolutePath(rootIdentity.canonicalAbsolutePath) ||
      rootIdentity.ownerUid !== entries[0]!.process.ownerUid || rootIdentity.platform !== entries[0]!.process.platform ||
      lockIdentity.ownerUid !== rootIdentity.ownerUid) invalid('retained StateOwner root/lock does not match');
  const runtimeKind = await readRuntime(artifacts, first);
  const boundaries = entries.filter(entry => entry.acquisition.kind === 'runtime_upgrade');
  if (boundaries.length > 1) invalid('only the exact signed7-to8 boundary is implemented');
  const boundary = boundaries[0];
  const conversionTarget = boundary?.owner.runtimeBundleRef ?? artifacts.runtimeConversionSourceRef();
  let conversion: SignedSchemaConversionV1 | undefined;
  if (runtimeKind === 'signed') {
    const bundle = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, first.runtimeBundleRef);
    if (conversionTarget) {
      const target = await readCanonicalArtifact<RuntimeBundleManifest>(artifacts, conversionTarget);
      conversion = await readSignedSchemaConversion(artifacts, bundle, target, artifacts.releaseTrustRoots());
    } else await readSignedKernelSchema(artifacts, bundle, artifacts.releaseTrustRoots());
  } else if (conversionTarget) invalid('signed conversion cannot replace a schema-only runtime');
  await readGenesis(artifacts, entries[0]!, lockIdentity, runtimeKind, conversion);
  for (const [index, entry] of entries.entries()) {
    const prior = entries[index - 1]?.owner;
    const originalRuntime = prior ?? first;
    const upgrade = entry.acquisition.kind === 'runtime_upgrade';
    if (entry.owner.stateLockIdentityRef !== first.stateLockIdentityRef || entry.owner.stateLockIdentityDigest !== first.stateLockIdentityDigest ||
        (!upgrade && (entry.owner.runtimeBundleRef !== originalRuntime.runtimeBundleRef ||
          entry.owner.runtimeBundleManifestDigest !== originalRuntime.runtimeBundleManifestDigest ||
          entry.owner.supervisorEntryId !== originalRuntime.supervisorEntryId || entry.owner.supervisorEntryVersion !== originalRuntime.supervisorEntryVersion ||
          (runtimeKind === 'signed' && entry.owner.supervisorExecutableDigest !== originalRuntime.supervisorExecutableDigest))) ||
        entry.process.ownerUid !== rootIdentity.ownerUid || entry.process.platform !== rootIdentity.platform)
      invalid('retained StateOwner history changed root/lock/runtime without an exact upgrade');
    if (entry.acquisition.kind === 'runtime_upgrade') {
      if (!prior || entries[0]!.acquisition.kind !== 'genesis') invalid('runtime upgrade lacks its original genesis');
      const upgradeData = await readRuntimeUpgradeBoundary(driver, artifacts, prior, entry.owner, entry.acquisition, entries[0]!.acquisition);
      if (upgradeData.receipt.stateRootIdentityRef !== lockIdentity.stateRootIdentityRef ||
          upgradeData.receipt.stateRootIdentityDigest !== lockIdentity.stateRootIdentityDigest)
        invalid('runtime upgrade substituted its original StateRoot');
      await readRuntime(artifacts, entry.owner);
    }
    if (entry.acquisition.kind !== 'genesis') {
      const acquisition = entry.acquisition;
      if (!prior || prior.state !== 'terminal' || prior.rowDigest !== acquisition.priorTerminalRowDigest ||
          prior.terminalReason !== acquisition.priorTerminalReason || prior.transitionEvidenceRef !== acquisition.priorTransitionEvidenceRef ||
          prior.transitionEvidenceDigest !== acquisition.priorTransitionEvidenceDigest ||
          prior.stateLockIdentityRef !== entry.owner.stateLockIdentityRef || prior.stateLockIdentityDigest !== entry.owner.stateLockIdentityDigest)
        invalid('StateOwner acquisition does not match its retained predecessor');
    }
    if (index < throughEpoch && entry.owner.state === 'terminal')
      entry.transition = await readTransition(artifacts, entry.owner, entries[index + 1]?.owner);
  }
  const retained = immutableSnapshot({ throughEpoch, entries: entries.slice(0, throughEpoch), lockIdentity, rootIdentity,
    ...(entries[throughEpoch] ? { successorWitness: entries[throughEpoch] } : {}) });
  const digest = canonicalSha256(owners);
  return Object.freeze({ ...retained, assertUnchanged(connection: SqliteConnection) {
    if (canonicalSha256(readRows(connection, casThroughEpoch)) !== digest) invalid('retained StateOwner history changed before commit');
  } });
}
