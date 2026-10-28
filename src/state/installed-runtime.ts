import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { setTimeout as upgradeDelay } from 'node:timers/promises';
import { decodeInstalledUpgradeStopObservation } from './credential-platform.js';
import type { InstalledUpgradeSourceV1, InstalledUpgradeIdentityV1, RuntimeUpgradeReceiptV1 } from '../kernel/runtime-upgrade.js';
import type { SupervisorHelloV1 } from '../kernel/control-wire.js';
import { assertControlWireJson, controlWireRecord } from '../kernel/control-wire-data.js';
import type { PublishedArtifact } from './artifacts.js';
import { ArtifactCatalog } from './artifacts.js';
import { readLatestStateOwner } from './state-owner.js';
import { readRetainedStateOwnerHistory } from './state-owner-history.js';
import { openSqliteDriver, openReadOnlySqliteDriver } from './sqlite-driver.js';
import { decodeRuntimeUpgradeReceipt } from './runtime-upgrade-history.js';
import { assertKernelSchemaVersion } from './schema.js';
import { sampleCanonicalNow } from './canonical-time.js';
import { signedKernelSchemaProfile, decodeSignedKernelSchema, schemaConversionProfile, decodeSchemaConversion, kernelSchemaEntries } from './signed-schema.js';
import { BUILTIN_SCRIPT_RECIPE } from '../sandbox/builtin-tool-data.js';
import { isNpmAdapterEntry, isNpmDataEntry } from '../sandbox/dependency-recipe.js';
import type { NativeBuiltinBashToolchain } from '../sandbox/guest-toolchain.js';
import type { NativeBuiltinToolScriptImage, NativeDependencyNpmScriptImage, NativeDependencyNpmDataImage } from '../sandbox/linux-worker.js';
import { createHash, randomBytes } from 'node:crypto';
import { constants, fstatSync, lstatSync, type BigIntStats } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, type FileHandle } from 'node:fs/promises';
import { isMainThread, Worker } from 'node:worker_threads';
import { Module } from 'node:module';
import { isSea } from 'node:sea';
import { setImmediate as yieldImmediate } from 'node:timers/promises';
import { types as utilTypes } from 'node:util';

import { KERNEL_CAS_DIRECTORY, KERNEL_DATABASE_FILENAME } from '../config.js';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, encodeCanonicalTime, identityHash,
  normalizeAbsolutePath, sha256Bytes } from '../kernel/identity.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, PlatformProcessIdentityV1, StateRootIdentityV1, StateOwnerRecordV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import { exactKeys, policyProfile, SINGLE_CAS_STREAMS_LAYOUT, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { ARTIFACT_CHUNK_BYTES, ContentAddressedStore } from './cas.js';
import { publishInstalledCasRoots } from './installed-cas-roots.js';
import { installedUpgradeRetirementFailure, type InstalledRuntimeUpgradePhase } from './installed-upgrade-diagnostics.js';
import { joinResourceOperations, KernelStorageError, ResourceRetirementError } from './errors.js';
import { decodeSandboxRootProfile } from './execution-closure.js';
import { decodeControlChannel, decodeLocalPrincipalIdentity, decodePlatformProcessIdentity, decodeStateRootIdentity } from './decoders.js';
import { checkCanonicalBytes, validateBundle, validateTrustStore, validateInstalledStructuredArtifacts,
  type InstalledStructuredArtifacts } from './installed-artifacts.js';
import { decodeInstalledModelAuthorityClosure, verifyInstalledModelAuthority,
  type VerifiedInstalledModelAuthority } from '../model/installed-authority.js';
import { MODEL_BROKER_ENTRY_ID, MODEL_BROKER_RELATIVE_PATH, InstalledModelBrokerRefusalError,
  type ModelBrokerBinding, type NativeModelBrokerBinding, type NativeModelTransport, type NativeModelNoReleaseFence } from './model-broker-native.js';
import { DEPENDENCY_BROKER_ENTRY_ID, DEPENDENCY_BROKER_RELATIVE_PATH, type DependencyBrokerBinding,
  type NativeDependencyBrokerBinding, type NativeDependencyTransport, type NativeDependencySettlementFence, type NativeDependencyClosed } from './dependency-broker-native.js';
import { runInstalledCredentialAuthority, type HeldCredentialAuthorityLock } from './store.js';
import type { NativeWorkerBinding, NativeWorkerImage, NativeSourceGitInspectorImage } from '../sandbox/linux-worker.js';
import type { CredentialPlatformUser, NativeCredentialInspection, NativeCredentialPlatformBinding, NativeSecretServiceInput } from './credential-platform.js';
import { GUEST_EXTRACTOR_RECIPE, type NativeGuestExtractorBinding, type NativeGuestToolchain, type NativeSourceGitToolchain } from '../sandbox/guest-toolchain.js';
import { decodeBundledSkillClosure, SKILL_RESOURCE_BYTES } from '../kernel/skill.js';
import { bundledSkillMemberRoles, bundledSkillRoots, validateBundledSkillReferences } from './bundled-skills.js';
import { decodeGuestToolchainManifest, guestToolchainExecutables, guestToolchainRoots, validateGuestToolchainMetadata,
  type RetainedVerifierToolchain } from './guest-toolchain.js';
import { acquireHeldInstalledAnchor, checkHeldInstalledUpgradeKeeper, executeHeldInstalledImage, initializeHeldInstalledKeeper, loadHeldStateOwnerImage,
  stateRootIdentityFromDescriptor, withHeldCredentialNativeScope, STATE_OWNER_NATIVE_ENTRY_ID, STATE_OWNER_NATIVE_RELATIVE_PATH,
  type NativeStateOwner, type NativeInstalledUpgradeKeeperCheck } from './native-owner.js';
import { joinInstalledUpgradeSourceControl } from './installed-upgrade-source-control.js';
import { openHeldInstalledControlClient, type HeldInstalledControlClient } from './native-owner.js';
import { noteInstalledWorkRead, observeInstalledWork, noteInstalledInstallPhase } from './installed-work-diagnostics.js';

export type HeldInstalledRuntime = Readonly<{
  bundle: RuntimeBundleManifest;
  bundleDigest: string;
  assertHeld(): Promise<void>;
  close(): Promise<void>;
}>;
/** Same-selection manager reads only. This handle is not an observation or a
 * credential authority; neither native binding nor start/reload/secret APIs
 * escape its original held installation. */
export type InstalledManagerObserver = Readonly<{
  currentUser(): CredentialPlatformUser;
  inspect(unit: string): Promise<unknown>;
}>;
/** A continuously held original containment anchor, not execution authority or
 * a transferable descriptor/PID locator. */
export type HeldInstalledKeeper = Readonly<{ assertHeld(): void; close(): void }>;
/** Supervisor ownership of the verified keeper's original root, not admission
 * authority, a pathname substitute or a transferable numeric descriptor. */
export type HeldInstalledAnchor = Readonly<{ assertHeld(): void; close(): void }>;
/** Internal physical owner. It is minted only in credentialScope and passed
 * directly to the fixed business runner, never returned to caller callbacks. */
export type InstalledCredentialScope = Readonly<{ assertHeld(): void }>;
export type InstalledCredentialProvenance = Readonly<{
  selected: HeldInstalledRuntime; ownerPrincipalId: string;
  rootIdentity: StateRootIdentityV1; processIdentity: PlatformProcessIdentityV1;
  principalIdentity: LocalPrincipalIdentityV1; channelIdentity: LocalControlChannelIdentityV1;
  objects: ReadonlyMap<string, Buffer>; releaseKeys: readonly ReleaseTrustKey[];
}>;
type CredentialPhysicalBinding = { native: NativeStateOwner;
  scope: Readonly<{ generation: string; assertHeld(): void;
    observeProducerLifetime(pid: number, ownerUid: number, processStartToken: string): 'present' | 'dead' }>;
  assertSelection(): void;
  pid: number; processStartToken: string; generation: string; active: boolean;
  provenance: InstalledCredentialProvenance };
const credentialPhysicalScopes = new WeakMap<InstalledCredentialScope, CredentialPhysicalBinding>();
const installedModelNoReleaseFences = new WeakMap<NativeModelNoReleaseFence, {
  native: NativeModelNoReleaseFence; bindingDigest: string; active: boolean; processId: number;
  selected: HeldInstalledRuntime; bundleDigest: string; manifestDigest: string; assertSelection(): void;
}>();

/** Friend validation only. A structural object, closed report or token digest
 * is not the original signed native owner's continuously held release mutex. */
export function assertInstalledModelNoReleaseFence(fence: NativeModelNoReleaseFence, binding: ModelBrokerBinding,
  expected?: { selected: HeldInstalledRuntime; runtimeBundleRef: string; runtimeBundleManifestDigest: string }): void {
  const held = installedModelNoReleaseFences.get(fence);
  if (!held || !held.active || held.processId !== process.pid || held.bindingDigest !== canonicalSha256(binding))
    mismatch('installed model no-release fence is not the original held claim owner');
  if (expected && (held.selected !== expected.selected || held.bundleDigest !== expected.runtimeBundleRef ||
      held.manifestDigest !== expected.runtimeBundleManifestDigest)) mismatch('installed model no-release fence belongs to another signed selection');
  held.assertSelection();
  try { held.native.assertHeld(); }
  catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
      const failure = new ResourceRetirementError('model no-release mutex owner has uncertain retirement', error);
      rememberRetirement(failure); throw failure;
    }
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed model no-release mutex is no longer held');
  }
}

function checkedCredentialPhysicalScope(physical: InstalledCredentialScope): CredentialPhysicalBinding {
  const held = credentialPhysicalScopes.get(physical);
  if (!held || !held.active) mismatch('installed credential physical scope is invalid or ended');
  if (held.pid !== process.pid || held.native.processStartToken() !== held.processStartToken || held.scope.generation !== held.generation)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'credential authority scope belongs to another process or generation');
  held.scope.assertHeld();
  held.assertSelection();
  return held;
}
/** Genuine-brand-first friend operations; neither returns a descriptor/native
 * object nor lets a caller register a structural physical owner. */
export function assertInstalledCredentialScope(physical: InstalledCredentialScope): void {
  checkedCredentialPhysicalScope(physical);
}
export function installedCredentialProvenance(physical: InstalledCredentialScope): InstalledCredentialProvenance {
  return checkedCredentialPhysicalScope(physical).provenance;
}
/** Ordinary recovery only. Retained lifetime input is read by the private
 * business owner; missing executable paths or caller PIDs never prove death. */
export function observeInstalledCredentialProducer(physical: InstalledCredentialScope,
  processIdentity: PlatformProcessIdentityV1): 'present' | 'dead' {
  const binding = checkedCredentialPhysicalScope(physical);
  if (processIdentity.platform !== 'linux' || processIdentity.ownerUid !== binding.provenance.rootIdentity.ownerUid)
    mismatch('credential producer lifetime does not belong to this root');
  try {
    const result = binding.scope.observeProducerLifetime(processIdentity.pid, processIdentity.ownerUid, processIdentity.processStartToken);
    checkedCredentialPhysicalScope(physical);
    return result;
  } catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
      const failure = new ResourceRetirementError('credential producer observation resources did not retire', error);
      rememberRetirement(failure); throw failure;
    }
    throw error;
  }
}

export { commitEndpointAuthority, readEndpointAuthority, readCredentialAuthority } from './store.js';
export type { HeldCredentialAuthorityLock } from './store.js';

type InstalledDirectoryIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
/** Fixed read-only inventory, freshly verified against the original held
 * installation. No callback, native loader, descriptor or execution authority
 * escapes this observation, and its copied metadata is not a future proof. */
export type InstalledRuntimeObservation = Readonly<{
  bundleDigest: string;
  manifestDigest: string;
  bundleVersion: string;
  stateRoot: InstalledDirectoryIdentity & Readonly<{ canonicalPath: string }>;
  casRoot: InstalledDirectoryIdentity;
}>;
/** Trusted startup observation only. No descriptor or independently supplied
 * installation evidence can outlive the callback's held borrow. */
export type InstalledRuntimeBorrow = Readonly<{
  bundle: RuntimeBundleManifest;
  bundleDigest: string;
  releaseKeys: readonly ReleaseTrustKey[];
  stateRoot: InstalledDirectoryIdentity & Readonly<{ canonicalPath: string }>;
  casRoot: InstalledDirectoryIdentity;
  modelAuthority?: VerifiedInstalledModelAuthority;
  structured: InstalledStructuredArtifacts;
  objects: ReadonlyMap<string, Buffer>;
  seed: readonly Readonly<{ artifactRef: string; byteCount: number; mediaType: string; schemaKind: string }>[];
  revalidate(signal?: AbortSignal): Promise<void>;
  loadStateOwner(signal?: AbortSignal): Promise<NativeStateOwner>;
}>;
type InstalledRuntimeBinding = {
  factory: InstalledRuntime;
  borrow<T>(operation: (installed: InstalledRuntimeBorrow) => Promise<T>, signal?: AbortSignal): Promise<T>;
  observe(signal?: AbortSignal): Promise<InstalledRuntimeObservation>;
  execute(role: 'keeper' | 'supervisor' | 'endpoint' | 'credential', command?: string): Promise<never>;
  initializeKeeper(): Promise<HeldInstalledKeeper>;
  acquireAnchor(): Promise<HeldInstalledAnchor>;
  loadWorkerNative(signal?: AbortSignal): Promise<NativeWorkerBinding>;
  loadCredentialPlatform(signal?: AbortSignal): Promise<NativeCredentialPlatformBinding>;
  loadManagerObserver(): Promise<InstalledManagerObserver>;
  assertManagerObservationAvailable(): void;
  loadModelBroker(): Promise<NativeModelBrokerBinding>;
  loadDependencyBroker(): Promise<NativeDependencyBrokerBinding>;
  openControlClient(): Promise<HeldInstalledControlClient>;
  sealWorkerImage(entryId: string): Promise<NativeWorkerImage>;
  sealBuiltinToolScript(signal?: AbortSignal): Promise<NativeBuiltinToolScriptImage>;
  sealDependencyNpmAssets(signal?: AbortSignal): Promise<Readonly<{ script: NativeDependencyNpmScriptImage; data: NativeDependencyNpmDataImage }>>;
  startBuiltinBashToolchain(toolchain: RetainedVerifierToolchain, options: { signal?: AbortSignal }): Promise<NativeBuiltinBashToolchain>;
  sealSourceGitInspector(signal?: AbortSignal): Promise<NativeSourceGitInspectorImage>;
  retainSourceGitRecipe(signal?: AbortSignal): Promise<void>;
  startGuestToolchain(toolchain: RetainedVerifierToolchain, options: { signal?: AbortSignal }): Promise<NativeGuestToolchain>;
  startSourceGitToolchain(toolchain: RetainedVerifierToolchain, options: { signal?: AbortSignal }): Promise<NativeSourceGitToolchain>;
  closeGuestToolchain(job: NativeGuestToolchain): Promise<void>;
  credentialScope<T>(operation: (token: HeldCredentialAuthorityLock) => Promise<T>): Promise<T>;
};
const heldInstalledRuntimes = new WeakMap<HeldInstalledRuntime, InstalledRuntimeBinding>();
const installedRuntimeTrust = new WeakMap<InstalledRuntime, readonly ReleaseTrustKey[]>();
const installedDependencyTransports = new WeakMap<NativeDependencyTransport, {
  original: NativeDependencyTransport; selected: HeldInstalledRuntime; configurationDigest: string; bindingDigest?: string; closed: boolean;
  closure?: NativeDependencyClosed;
  assertCurrent(): void;
}>();
/** Genuine fixed native construction, before the permanent claim binds its
 * sequence. This readonly friend cannot release network or worker execution. */
export function assertInstalledDependencyTransportConfiguration(selected: HeldInstalledRuntime, transport: NativeDependencyTransport,
  configurationBytes: Buffer): void {
  const held = installedDependencyTransports.get(transport);
  if (!held || held.selected !== selected || held.closed || utilTypes.isProxy(configurationBytes) || !Buffer.isBuffer(configurationBytes) ||
      configurationBytes.length < 1 || configurationBytes.length > 1_048_576 || held.configurationDigest !== sha256Bytes(configurationBytes))
    mismatch('dependency claim requires its exact original installed configuration');
  held.assertCurrent();
}

/** Original completed close data survives revocation/selection disposal. It
 * supplies no release/settlement permission and cannot relabel close as ACK. */
export function readInstalledDependencyTransportClosure(selected: HeldInstalledRuntime, transport: NativeDependencyTransport,
  binding: DependencyBrokerBinding): NativeDependencyClosed | undefined {
  const held = installedDependencyTransports.get(transport);
  if (!held || held.selected !== selected || held.bindingDigest !== canonicalSha256(binding))
    mismatch('dependency closure requires its exact original installed owner and claim');
  return held.closure && immutableSnapshot(held.closure);
}
const installedDependencySettlements = new WeakMap<NativeDependencySettlementFence, {
  original: NativeDependencySettlementFence; selected: HeldInstalledRuntime; bindingDigest: string; active: boolean; assertCurrent(): void;
}>();

/** Only the original signed native purpose object crosses the Worker addon
 * boundary. A structural transport, changed claim or closed owner never does. */
export function borrowInstalledDependencyTransport(selected: HeldInstalledRuntime, transport: NativeDependencyTransport, binding: DependencyBrokerBinding): object {
  const held = installedDependencyTransports.get(transport);
  if (!held || held.selected !== selected || held.closed || held.bindingDigest !== canonicalSha256(binding))
    mismatch('dependency scope requires its original installed owner and permanent claim');
  held.assertCurrent(); return held.original;
}
export function assertInstalledDependencySettlement(selected: HeldInstalledRuntime, fence: NativeDependencySettlementFence, binding: DependencyBrokerBinding): void {
  const held = installedDependencySettlements.get(fence);
  if (!held || held.selected !== selected || !held.active || held.bindingDigest !== canonicalSha256(binding))
    mismatch('dependency settlement requires its original joined native owner and exact claim');
  held.assertCurrent(); fence.assertCurrent();
}
let credentialScopeReserved = false;
const heldInstalledAnchors = new WeakMap<HeldInstalledAnchor, { selected: HeldInstalledRuntime;
  withRoot(operation: (fd: number, rootPath: string) => void): void;
  readBirth(): InstalledUpgradeSourceV1['originalKeeper'] }>();

/** Private worker producer bridge. Only synchronous fixed native operations
 * borrow the original root; neither public handle offers a descriptor getter. */
export function withInstalledWorkerRoot(selected: HeldInstalledRuntime, anchor: HeldInstalledAnchor,
  operation: (fd: number, rootPath: string) => void): void {
  if (!heldInstalledRuntimes.has(selected)) mismatch('installed runtime is not a verified held selection');
  const binding = heldInstalledAnchors.get(anchor);
  if (!binding || binding.selected !== selected) mismatch('installed anchor does not belong to this exact held selection');
  binding.withRoot(operation);
}

/** Private fixed-image bridges: original selected FileHandles remain owned by
 * their existing scope; only the new seal is owned by the worker launcher. */
export function loadInstalledWorkerNative(selected: HeldInstalledRuntime, signal?: AbortSignal): Promise<NativeWorkerBinding> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('installed runtime is not a verified held selection');
  return binding.loadWorkerNative(signal);
}
/** These two fixed friends carry no StateOwner/credential lock. The selected
 * producer supplies and retains the actual signed image/root descriptors. */
export function loadInstalledCredentialPlatform(selected: HeldInstalledRuntime, signal?: AbortSignal): Promise<NativeCredentialPlatformBinding> {
  return managerObservationBinding(selected).loadCredentialPlatform(signal);
}
function managerObservationBinding(selected: HeldInstalledRuntime): InstalledRuntimeBinding {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('installed runtime is not a verified held selection');
  healthy();
  // Ordinary callers load before acquiring the credential scope. Enqueueing
  // here during a scope would wait behind its own pending native operation,
  // preventing the public caller from ever reaching the existing Busy gate.
  if (credentialScopeReserved) throw new CredentialScopeBusyError();
  return binding;
}
/** Inert gate for a connection's already-loaded observer. It must run before
 * borrow enqueue, never wait behind its own acquiring/active/draining scope. */
export function assertInstalledManagerObservationAvailable(selected: HeldInstalledRuntime): void {
  managerObservationBinding(selected).assertManagerObservationAvailable();
}
/** Ordinary installed clients may inspect only this selection's two fixed
 * units. The credential backend retains its separate signed-SEA gate. */
export function loadInstalledManagerObserver(selected: HeldInstalledRuntime): Promise<InstalledManagerObserver> {
  return managerObservationBinding(selected).loadManagerObserver();
}
export function loadInstalledModelBroker(selected: HeldInstalledRuntime): Promise<NativeModelBrokerBinding> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('installed runtime is not a verified held selection');
  return binding.loadModelBroker();
}
export function loadInstalledDependencyBroker(selected: HeldInstalledRuntime): Promise<NativeDependencyBrokerBinding> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('dependency transport requires a genuine held installed selection');
  return binding.loadDependencyBroker();
}
function assertInstalledDependencyBrokerProcess(): void {
  if (!isMainThread || !isSea() || process.platform !== 'linux' || process.arch !== 'x64' || process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'dependency transport requires the fixed signed Linux Supervisor process');
}

/** Supported fixed creator-process recipe only, not installation or release
 * authority. Both live dispatch and domain-death production retain this gate. */
export function assertInstalledModelBrokerProcess(): void {
  if (!isMainThread || !isSea() || process.platform !== 'linux' || process.arch !== 'x64' || process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'model broker requires the fixed signed Linux backend');
}
export function openInstalledControlClient(selected: HeldInstalledRuntime): Promise<HeldInstalledControlClient> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('installed runtime is not a verified held selection');
  return binding.openControlClient();
}
export function sealInstalledWorkerImage(selected: HeldInstalledRuntime, entryId: string): Promise<NativeWorkerImage> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('installed runtime is not a verified held selection');
  return binding.sealWorkerImage(entryId);
}
/** Fixed non-executable signed script friend. The native seal has a separate
 * type tag, no descriptor getter, and is not a caller-selected program. */
export function sealInstalledSourceGitInspector(selected: HeldInstalledRuntime, signal?: AbortSignal): Promise<NativeSourceGitInspectorImage> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('source inspection requires a genuine held installed selection');
  return binding.sealSourceGitInspector(signal);
}
/** Audit data only, through the same original installed scope. The two fixed
 * recipe members remain separate host files; CAS bytes cannot execute them. */
export function retainInstalledSourceGitRecipe(selected: HeldInstalledRuntime, signal?: AbortSignal): Promise<void> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('source recipe retention requires a genuine held installed selection');
  return binding.retainSourceGitRecipe(signal);
}

/** Fixed signed data and its distinct native type; never a caller program. */
export function sealInstalledBuiltinToolScript(selected: HeldInstalledRuntime, signal?: AbortSignal): Promise<NativeBuiltinToolScriptImage> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('builtin tool requires a genuine held installed selection');
  return binding.sealBuiltinToolScript(signal);
}
export function sealInstalledDependencyNpmAssets(selected: HeldInstalledRuntime, signal?: AbortSignal):
  Promise<Readonly<{ script: NativeDependencyNpmScriptImage; data: NativeDependencyNpmDataImage }>> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('dependency execution requires its genuine held installed selection');
  return binding.sealDependencyNpmAssets(signal);
}
export function startInstalledBuiltinBashToolchain(selected: HeldInstalledRuntime, toolchain: RetainedVerifierToolchain,
  options: { signal?: AbortSignal } = {}): Promise<NativeBuiltinBashToolchain> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('builtin bash requires a genuine held installed selection');
  return binding.startBuiltinBashToolchain(toolchain, options);
}
export function closeInstalledBuiltinBashToolchain(selected: HeldInstalledRuntime, job: NativeBuiltinBashToolchain): Promise<void> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('builtin bash retirement requires a genuine held installed selection');
  return binding.closeGuestToolchain(job);
}

/** Private fixed extractor bridge. The original imported CAS image remains
 * descriptor-held; native begin owns its asynchronous copy/hash/seal and join. */
export function startInstalledGuestToolchain(selected: HeldInstalledRuntime, toolchain: RetainedVerifierToolchain,
  options: { signal?: AbortSignal } = {}): Promise<NativeGuestToolchain> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('guest extraction requires a genuine held installed selection');
  return binding.startGuestToolchain(toolchain, options);
}
/** Join the original native producer and release its installation registry
 * reference. No copied description, plain object or different selection works. */
export function closeInstalledGuestToolchain(selected: HeldInstalledRuntime, job: NativeGuestToolchain): Promise<void> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('guest retirement requires a genuine held installed selection');
  return binding.closeGuestToolchain(job);
}
/** Fixed same-image Node + Git producer. This cannot reuse a Node-only native
 * tag or let the caller select another executable, path, argv or library. */
export function startInstalledSourceGitToolchain(selected: HeldInstalledRuntime, toolchain: RetainedVerifierToolchain,
  options: { signal?: AbortSignal } = {}): Promise<NativeSourceGitToolchain> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('source Git extraction requires a genuine held installed selection');
  return binding.startSourceGitToolchain(toolchain, options);
}
export function closeInstalledSourceGitToolchain(selected: HeldInstalledRuntime, job: NativeSourceGitToolchain): Promise<void> {
  const binding = heldInstalledRuntimes.get(selected);
  if (!binding) mismatch('source Git retirement requires a genuine held installed selection');
  return binding.closeGuestToolchain(job);
}

export function initializeInstalledKeeper(held: HeldInstalledRuntime): Promise<HeldInstalledKeeper> {
  const binding = heldInstalledRuntimes.get(held);
  if (binding === undefined) mismatch('installed runtime is not a verified held selection');
  return binding.initializeKeeper();
}

export function acquireInstalledAnchor(held: HeldInstalledRuntime): Promise<HeldInstalledAnchor> {
  const binding = heldInstalledRuntimes.get(held);
  if (binding === undefined) mismatch('installed runtime is not a verified held selection');
  return binding.acquireAnchor();
}

/** Look up the producer's private brand before observing any caller property.
 * Structural objects, proxies and clones cannot impersonate a held selection. */
export function withHeldInstalledRuntime<T>(held: HeldInstalledRuntime,
  operation: (installed: InstalledRuntimeBorrow) => Promise<T>, signal?: AbortSignal): Promise<T> {
  const binding = heldInstalledRuntimes.get(held);
  if (binding === undefined) mismatch('installed runtime is not a verified held selection');
  return binding.borrow(operation, signal);
}

/** This fixed observation does not wait for an authority callback which may
 * itself be awaiting the observing client's response. Business borrows remain
 * serialized; all actual observation work still belongs to their held Scope. */
export function readInstalledRuntimeObservation(held: HeldInstalledRuntime,
  signal?: AbortSignal): Promise<InstalledRuntimeObservation> {
  const binding = heldInstalledRuntimes.get(held);
  if (binding === undefined) mismatch('installed runtime is not a verified held selection');
  return binding.observe(signal);
}

export class CredentialScopeBusyError extends TypeError {
  readonly controlError = Object.freeze({ schemaVersion: 1, code: 'RATE_LIMITED', retryable: true,
    retryAfterMs: 1000, messageCode: 'run.credential_scope_busy' } as const);
  constructor() {
    super('ordinary credential entry cannot be called while a scope is acquiring, active or draining');
    this.name = 'CredentialScopeBusyError';
  }
}

/** Ordinary same-user credential-store scope. Preoccupy the whole process
 * before enqueue: recursion or a second factory cannot wait on its own tail.
 * This token carries physical ownership, not an authentication decision. */
export function withCredentialAuthorityLock<T>(held: HeldInstalledRuntime,
  operation: (token: HeldCredentialAuthorityLock) => Promise<T>): Promise<T> {
  const binding = heldInstalledRuntimes.get(held);
  if (!binding) mismatch('installed runtime is not a verified held selection');
  healthy();
  if (credentialScopeReserved) throw new CredentialScopeBusyError();
  if (typeof operation !== 'function') throw new TypeError('credential scope requires a callback');
  credentialScopeReserved = true;
  const release = () => { if (!retirementFailure) credentialScopeReserved = false; };
  try {
    return binding.credentialScope(operation).finally(release);
  } catch (error) { release(); throw error; }
}

type InstalledRuntime = Readonly<{
  installInitial(target: { packageRoot: string; stateRoot: string }): Promise<{ bundleDigest: string; manifestDigest: string }>;
  openSelected(stateRoot: string): Promise<HeldInstalledRuntime>;
  /** Bootstrap-only terminal operation. No StateOwner/control/worker may have
   * been acquired; the signed entry point enforces this fixed startup order. */
  executeSelected(held: HeldInstalledRuntime, role: 'keeper' | 'supervisor' | 'endpoint' | 'credential', command?: string): Promise<never>;
}>;
type Directory = { handle: FileHandle; info: BigIntStats; parent?: Directory; name: string; private: boolean };
type InstalledFile = { handle: FileHandle; info: BigIntStats; parent: Directory; name: string; digest?: string };
type VerifiedPackage = { root: Directory; manifest: InstalledFile; bundle: RuntimeBundleManifest;
  bundleDigest: string; manifestBytes: Buffer; entries: Map<string, InstalledFile>; roots: Map<string, Buffer>;
  streamedRoots: Map<string, InstalledFile>;
  singleCasPaths: ReadonlySet<string>; delegatedPaths: ReadonlySet<string>; delegatedRefs: ReadonlySet<string>;
  structured: InstalledStructuredArtifacts; modelAuthority?: VerifiedInstalledModelAuthority;
  companionFiles: InstalledFile[] };
function streamedInstalledSchemaKind(signed: VerifiedPackage, ref: string): string {
  const declared = signed.structured.objects.filter(object => object.artifactRef === ref);
  if (declared.length !== 1 || !['cliq-guest-image-raw-ext4-v1', 'cliq-skill-source-file-v1', 'cliq-npm-data-image-v1'].includes(declared[0]!.schemaKind))
    mismatch('installed streamed data has no exact supported original member kind');
  return declared[0]!.schemaKind;
}
function requireSingleCasBundle(bundle: RuntimeBundleManifest): void {
  if (bundle.schemaVersion !== 2 || bundle.installedLayout !== SINGLE_CAS_STREAMS_LAYOUT)
    mismatch('new installed execution requires its signed single-CAS layout');
}
// Only the fixed schema7 upgrade controller may reopen the original physical
// layout. A public caller cannot supply this module-private identity, and no
// process-global compatibility mode can leak into a concurrent selection.
const originalUpgradeLayout = Symbol('original installed upgrade source');
function noteUpgradePhase(observer: ((phase: InstalledRuntimeUpgradePhase) => void) | undefined, phase: InstalledRuntimeUpgradePhase): void {
  try { observer?.(phase); } catch { /* Fixed diagnostics cannot replace an original upgrade result or refusal. */ }
}

const SMALL_BYTES = 1_048_576;
const TRUST_BYTES = 16 * SMALL_BYTES;
// Bound each IO batch without caching integrity: every verification still reads
// and hashes all bytes, checks exact EOF and joins the original physical owner.
const CHUNK_BYTES = 1_048_576;
// Descriptor retirement is process authority, not the lifetime of a factory or
// selected handle. A fresh factory must not erase an uncertain close.
let retirementFailure: ResourceRetirementError | undefined;

function mismatch(message: string, cause?: unknown): never {
  throw new KernelStorageError('ARTIFACT_MISMATCH', message, cause === undefined ? undefined : { cause });
}
function healthy(): void { if (retirementFailure) throw retirementFailure; }
function supportedPlatform(): void {
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime requires Linux descriptor-relative filesystem operations');
}
function rememberRetirement(error: unknown): void {
  if (error instanceof ResourceRetirementError) retirementFailure ??= error;
}
function effectiveUid(): bigint {
  if (typeof process.geteuid !== 'function') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed runtime requires effective-user identity');
  return BigInt(process.geteuid());
}
function childPath(directory: Directory, name: string): string {
  supportedPlatform();
  return `/proc/self/fd/${directory.handle.fd}/${name}`;
}
function sameDirectory(left: BigIntStats, right: BigIntStats): boolean {
  return ['dev', 'ino', 'uid', 'gid', 'mode'].every(key => left[key as keyof BigIntStats] === right[key as keyof BigIntStats]);
}
function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return ['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs']
    .every(key => left[key as keyof BigIntStats] === right[key as keyof BigIntStats]);
}
function checkDirectory(info: BigIntStats, privateRoot: boolean): void {
  if (!info.isDirectory() || (privateRoot ? info.uid !== effectiveUid() || (info.mode & 0o7777n) !== 0o700n :
    info.uid !== 0n && info.uid !== effectiveUid())) mismatch('installed runtime directory ownership, type or mode is invalid');
}
function checkFile(info: BigIntStats, mode: number, byteCount?: number): void {
  if (!info.isFile() || info.uid !== effectiveUid() || info.nlink !== 1n || (info.mode & 0o7777n) !== BigInt(mode) ||
      info.size > BigInt(Number.MAX_SAFE_INTEGER) || (byteCount !== undefined && info.size !== BigInt(byteCount))) {
    mismatch('installed runtime file ownership, type, link count, size or mode is invalid');
  }
}

/** Own every opened descriptor immediately. Ownership is consumed before close,
 * including failed closes; a reused numeric fd is never retried. */
class Scope {
  readonly directories: Directory[] = [];
  private readonly handles = new Set<FileHandle>();
  private readonly verifications = new Set<Promise<void>>();
  private closePromise?: Promise<void>;

  own(handle: FileHandle): FileHandle { this.handles.add(handle); return handle; }
  take(handle: FileHandle): FileHandle {
    if (this.closePromise || !this.handles.delete(handle)) mismatch('installed execution image is not owned by its live scope');
    return handle;
  }
  async retire(handle: FileHandle): Promise<void> {
    if (!this.handles.delete(handle)) return;
    try { await handle.close(); }
    catch (cause) {
      const error = new ResourceRetirementError('installed runtime descriptor retirement failed', cause);
      rememberRetirement(error); throw error;
    }
  }
  async reuseCasFile(file: InstalledFile, parent: Directory, ref: string, byteCount: number): Promise<InstalledFile> {
    if (this.closePromise || !this.handles.has(file.handle) || file.parent !== parent || file.name !== ref || file.digest !== ref)
      mismatch('installed CAS member is not the same live physical holder');
    checkFile(file.info, 0o400, byteCount); await assertFile(file); return file;
  }
  close(): Promise<void> {
    return this.closePromise ??= (async () => {
      // Accepted borrows still finish. Successful jobs join their actual sync
      // reads, not the idle executor. Close then owns a FIFO executor-exit
      // barrier before any original descriptor may retire.
      const batches = await Promise.allSettled([...this.verifications]);
      const executor = await Promise.allSettled([retireDiscardPool()]);
      const handles = [...this.handles].reverse();
      const results = await Promise.allSettled(handles.map(handle => this.retire(handle)));
      const failures = [...batches.filter(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError),
        ...executor, ...results].filter((result): result is PromiseRejectedResult => result.status === 'rejected');
      if (failures.length) throw retirementFailure ??
        (failures.find(result => result.reason instanceof ResourceRetirementError) ?? failures[0]!).reason;
    })();
  }
  verifyDiscard(files: readonly InstalledFile[], signal?: AbortSignal): Promise<void> {
    if (this.closePromise) return Promise.reject(new KernelStorageError('ARTIFACT_MISMATCH', 'installed runtime scope is closed'));
    const pending = verifyDiscardFiles(files, signal);
    // Ownership precedes the permit, including queued cancellation. A success
    // joins its original reads; the Scope's close barrier joins idle Workers.
    this.verifications.add(pending);
    void pending.then(() => this.verifications.delete(pending), () => this.verifications.delete(pending));
    return pending;
  }
  async assertDirectory(directory: Directory): Promise<void> {
    const held = await directory.handle.stat({ bigint: true });
    const named = await lstat(directory.parent ? childPath(directory.parent, directory.name) : '/', { bigint: true });
    checkDirectory(held, directory.private); checkDirectory(named, directory.private);
    if (!sameDirectory(directory.info, held) || !sameDirectory(held, named)) mismatch('installed runtime directory changed');
  }
  async assertDirectories(): Promise<void> {
    healthy();
    for (const directory of this.directories) await this.assertDirectory(directory);
  }
  assertMetadata(files: readonly InstalledFile[]): void {
    healthy();
    for (const directory of this.directories) {
      const held = fstatSync(directory.handle.fd, { bigint: true });
      const named = lstatSync(directory.parent ? childPath(directory.parent, directory.name) : '/', { bigint: true });
      checkDirectory(held, directory.private); checkDirectory(named, directory.private);
      if (!sameDirectory(directory.info, held) || !sameDirectory(held, named)) mismatch('installed runtime directory changed');
    }
    for (const file of files) {
      const held = fstatSync(file.handle.fd, { bigint: true });
      const named = lstatSync(childPath(file.parent, file.name), { bigint: true });
      if (!sameFile(file.info, held) || !sameFile(held, named)) mismatch('installed runtime signed file metadata changed');
    }
  }
  async directory(parent: Directory, name: string, create = false): Promise<Directory> {
    await this.assertDirectory(parent);
    const known = this.directories.find(directory => directory.parent === parent && directory.name === name);
    if (known) { await this.assertDirectory(known); return known; }
    const filename = childPath(parent, name);
    if (create) await mkdir(filename, { mode: 0o700 });
    const named = await lstat(filename, { bigint: true });
    checkDirectory(named, true);
    const handle = this.own(await open(filename, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    const info = await handle.stat({ bigint: true });
    checkDirectory(info, true);
    if (!sameDirectory(named, info)) mismatch('installed runtime directory changed while opening');
    const directory = { handle, info, parent, name, private: true };
    this.directories.push(directory);
    await this.assertDirectory(parent);
    return directory;
  }
  async root(filename: string, create = false): Promise<Directory> {
    const normalized = normalizeAbsolutePath(filename);
    if (normalized !== filename) mismatch('installed runtime root must be a canonical absolute path');
    const handle = this.own(await open('/', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    let directory: Directory = { handle, info: await handle.stat({ bigint: true }), name: '/', private: false };
    checkDirectory(directory.info, false); this.directories.push(directory);
    const components = filename.split('/').slice(1);
    for (let index = 0; index < components.length; index++) {
      const name = components[index]!;
      await this.assertDirectory(directory);
      const filename = childPath(directory, name);
      const last = index === components.length - 1;
      if (last && create) await mkdir(filename, { mode: 0o700 });
      const named = await lstat(filename, { bigint: true });
      checkDirectory(named, last);
      const handle = this.own(await open(filename, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
      const info = await handle.stat({ bigint: true }); checkDirectory(info, last);
      if (!sameDirectory(named, info)) mismatch('installed runtime root component changed while opening');
      const next: Directory = { handle, info, parent: directory, name, private: last };
      this.directories.push(next); directory = next;
    }
    await this.assertDirectories();
    return directory;
  }
  async parent(root: Directory, relative: string, create = false): Promise<{ parent: Directory; name: string }> {
    const components = relative.split('/');
    let parent = root;
    for (const component of components.slice(0, -1)) {
      const known = this.directories.find(directory => directory.parent === parent && directory.name === component);
      parent = known ? known : await this.directory(parent, component, create);
    }
    return { parent, name: components.at(-1)! };
  }
  async file(root: Directory, relative: string, mode: number, byteCount?: number, digest?: string): Promise<InstalledFile> {
    const { parent, name } = await this.parent(root, relative);
    await this.assertDirectory(parent);
    const filename = childPath(parent, name);
    const named = await lstat(filename, { bigint: true }); checkFile(named, mode, byteCount);
    const handle = this.own(await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK));
    const info = await handle.stat({ bigint: true }); checkFile(info, mode, byteCount);
    if (!sameFile(named, info)) mismatch('installed runtime file changed while opening');
    const file = { handle, info, parent, name, digest };
    await assertFile(file); await this.assertDirectory(parent);
    return file;
  }
}

async function assertFile(file: InstalledFile): Promise<void> {
  healthy();
  const held = await file.handle.stat({ bigint: true });
  const named = await lstat(childPath(file.parent, file.name), { bigint: true });
  if (!sameFile(file.info, held) || !sameFile(held, named)) mismatch('installed runtime held file or its independent path changed');
}
async function* chunks(file: InstalledFile, signal?: AbortSignal): AsyncGenerator<Buffer> {
  signal?.throwIfAborted();
  await assertFile(file);
  signal?.throwIfAborted();
  const hash = createHash('sha256');
  const count = Number(file.info.size);
  let position = 0;
  while (position < count) {
    signal?.throwIfAborted();
    const buffer = Buffer.allocUnsafe(Math.min(CHUNK_BYTES, count - position));
    const { bytesRead } = await file.handle.read(buffer, 0, Math.min(buffer.length, count - position), position);
    noteInstalledWorkRead(bytesRead);
    signal?.throwIfAborted();
    if (!bytesRead) mismatch('installed runtime file ended before its signed byte count');
    const bytes = buffer.subarray(0, bytesRead); hash.update(bytes); position += bytesRead;
    yield bytes;
  }
  const extra = await file.handle.read(Buffer.allocUnsafe(1), 0, 1, position);
  noteInstalledWorkRead(extra.bytesRead);
  signal?.throwIfAborted();
  if (extra.bytesRead) mismatch('installed runtime file exceeds its signed byte count');
  await assertFile(file);
  signal?.throwIfAborted();
  if (file.digest !== undefined && hash.digest('hex') !== file.digest) mismatch('installed runtime signed file digest differs');
}
async function readSmall(file: InstalledFile, limit = SMALL_BYTES, signal?: AbortSignal): Promise<Buffer> {
  if (file.info.size > BigInt(limit)) mismatch('installed runtime data exceeds its bounded decoding limit');
  const bytes: Buffer[] = [];
  for await (const chunk of chunks(file, signal)) bytes.push(chunk);
  return Buffer.concat(bytes);
}
// Main-isolate discard work shares a single scratch/Worker budget. Other
// isolates retain the original pipeline and never create additional Workers.
let discardBusy = false;
type DiscardWait = { resolve(release: () => void): void; reject(error: unknown): void; signal?: AbortSignal; abort(): void };
const discardWaits: DiscardWait[] = [];
function grantDiscard(): void {
  if (discardBusy) return;
  const next = discardWaits.shift(); if (!next) return;
  next.signal?.removeEventListener('abort', next.abort);
  if (next.signal?.aborted) { next.reject(next.signal.reason); grantDiscard(); return; }
  discardBusy = true; let released = false;
  next.resolve(() => { if (!released) { released = true; discardBusy = false; grantDiscard(); } });
}
function discardPermit(signal?: AbortSignal): Promise<() => void> {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const wait: DiscardWait = { resolve, reject, ...(signal ? { signal } : {}), abort() {
      const index = discardWaits.indexOf(wait);
      if (index >= 0) { discardWaits.splice(index, 1); reject(signal!.reason); }
    } };
    discardWaits.push(wait); signal?.addEventListener('abort', wait.abort, { once: true }); grantDiscard();
  });
}
const INSTALLED_HASH_WORKER_SOURCE = String.raw`
const { createHash } = require('node:crypto');
const { fstatSync, readSync } = require('node:fs');
const { parentPort, workerData } = require('node:worker_threads');
if (![2,4].includes(workerData.laneCount) || !Number.isInteger(workerData.lane) ||
  workerData.lane < 0 || workerData.lane >= workerData.laneCount ||
  !(workerData.control instanceof SharedArrayBuffer) || workerData.control.byteLength !== 8 + 8 * workerData.laneCount)
  throw new Error('fixed hash worker configuration is invalid');
const stop = new Int32Array(workerData.control, 0, 1);
const counts = new BigInt64Array(workerData.control, 8, workerData.laneCount);
const scratch = Buffer.allocUnsafe(1048576 / workerData.laneCount);
const fields = ['dev','ino','size','uid','gid','mode','nlink','mtimeNs','ctimeNs'];
const check = file => { const actual = fstatSync(file.fd, { bigint: true });
  if (!fields.every(key => String(actual[key]) === file.info[key])) throw 'metadata'; };
const cancel = () => { if (Atomics.load(stop, 0)) throw 'cancelled'; };
const verify = file => {
  try {
    cancel(); check(file); const hash = createHash('sha256'); let at = 0;
    while (at < file.byteCount) {
      cancel(); const bytes = readSync(file.fd, scratch, 0, Math.min(scratch.length, file.byteCount - at), at);
      Atomics.add(counts, workerData.lane, BigInt(bytes)); if (!bytes) throw 'short'; cancel();
      hash.update(bytes === scratch.length ? scratch : scratch.subarray(0, bytes)); at += bytes;
    }
    cancel(); const extra = readSync(file.fd, scratch, 0, 1, at);
    Atomics.add(counts, workerData.lane, BigInt(extra)); if (extra) throw 'long'; cancel();
    check(file); return { id: file.id, code: 'ok', digest: hash.digest('hex') };
  } catch (error) { return { id: file.id,
    code: ['metadata','cancelled','short','long'].includes(error) ? error : 'read' }; }
};
parentPort.on('message', file => {
  if (file.kind === 'close') { parentPort.close(); return; }
  // All real reads/EOF/stat have returned and the verifier frame is gone.
  // Clear its task (including the borrowed FD) before sending the inert ACK.
  const reply = verify(file); file = undefined; parentPort.postMessage(reply);
});
`;
type HashReply = { id: number; code: 'ok' | 'metadata' | 'cancelled' | 'short' | 'long' | 'read'; digest?: string };
type HashLane = { worker: Worker; exited: boolean; exit: Promise<void>; pending?: { id: number; resolve(reply?: HashReply): void } };
const hashWorkerFailure = () => new KernelStorageError('ARTIFACT_MISMATCH', 'installed runtime hash worker failed');
function throwHashFailure(failures: readonly unknown[], signal?: AbortSignal): never {
  const retirement = failures.findIndex(error => error instanceof ResourceRetirementError);
  const substantive = failures.findIndex(error => !signal?.aborted || error !== signal.reason);
  throw failures[retirement >= 0 ? retirement : substantive >= 0 ? substantive : 0];
}
let hashJobId = 0;
/** One process-private executor, exclusively accessed under discardPermit.
 * Only threads/code/scratch survive a successful job; never an FD, hash,
 * observation, result or cancelled job. No Worker is unref'ed. */
class DiscardPool {
  private readonly control: SharedArrayBuffer;
  private readonly stop: Int32Array;
  private readonly counts: BigInt64Array;
  private readonly counted: bigint[];
  private readonly lanes: HashLane[] = [];
  private readonly failures: unknown[] = [];
  private currentFailures?: unknown[];
  private closing = false;
  constructor(readonly laneCount: 2 | 4) {
    this.control = new SharedArrayBuffer(8 + 8 * laneCount);
    this.stop = new Int32Array(this.control, 0, 1); this.counts = new BigInt64Array(this.control, 8, laneCount);
    this.counted = Array<bigint>(laneCount).fill(0n);
  }
  private abort = () => { Atomics.store(this.stop, 0, 1); };
  private fail(error: unknown): void {
    this.failures.push(error); this.currentFailures?.push(error); this.abort();
  }
  private assertHealthy(): void { if (this.failures.length) throwHashFailure(this.failures); }
  private account(): void {
    for (let index = 0; index < this.laneCount; index++) {
      const current = Atomics.load(this.counts, index), delta = current - this.counted[index]!;
      if (delta) noteInstalledWorkRead(Number(delta)); this.counted[index] = current;
    }
  }
  start(): void {
    for (let index = 0; index < this.laneCount; index++) {
      const worker = new Worker(INSTALLED_HASH_WORKER_SOURCE, { eval: true, env: {}, execArgv: [], argv: [],
        resourceLimits: { maxOldGenerationSizeMb: 16, maxYoungGenerationSizeMb: 4, codeRangeSizeMb: 2, stackSizeMb: 1 },
        workerData: { control: this.control, lane: index, laneCount: this.laneCount } });
      const lane: HashLane = { worker, exited: false, exit: new Promise<void>(resolve => worker.once('exit', code => {
        lane.exited = true;
        if (code !== 0 || !this.closing || lane.pending) this.fail(hashWorkerFailure());
        lane.pending?.resolve(); delete lane.pending; resolve();
      })) };
      this.lanes.push(lane);
      // These routers belong to this executor, never to a previous R's local
      // arrays/listeners. An idle failure remains visible to the next R/close.
      worker.on('error', () => this.fail(hashWorkerFailure()));
      worker.on('message', (reply: unknown) => {
        if (!reply || typeof reply !== 'object' || Object.getPrototypeOf(reply) !== Object.prototype) {
          this.fail(hashWorkerFailure()); lane.pending?.resolve(); delete lane.pending; return;
        }
        const data = Object.getOwnPropertyDescriptors(reply), id = data.id?.value, code = data.code?.value;
        const keys = Object.keys(data).sort().join(',');
        if (!lane.pending || id !== lane.pending.id || !['ok', 'metadata', 'cancelled', 'short', 'long', 'read'].includes(code) ||
          Object.values(data).some(value => !('value' in value)) || keys !== (code === 'ok' ? 'code,digest,id' : 'code,id') ||
          code === 'ok' && (typeof data.digest?.value !== 'string' || !/^[a-f0-9]{64}$/u.test(data.digest.value))) {
          this.fail(hashWorkerFailure()); lane.pending?.resolve(); delete lane.pending; return;
        }
        lane.pending.resolve(reply as HashReply); delete lane.pending;
      });
    }
  }
  async verify(files: readonly InstalledFile[], signal?: AbortSignal): Promise<void> {
    const failures: unknown[] = []; let next = 0, verified = 0;
    this.assertHealthy();
    this.currentFailures = failures;
    const fail = (error: unknown) => { failures.push(error); this.abort(); };
    signal?.addEventListener('abort', this.abort, { once: true });
    try {
      signal?.throwIfAborted();
      const run = async (lane: HashLane) => {
        while (!Atomics.load(this.stop, 0) && next < files.length) {
          const file = files[next++]!;
          try {
            signal?.throwIfAborted(); await assertFile(file); signal?.throwIfAborted();
            if (hashJobId >= Number.MAX_SAFE_INTEGER) throw hashWorkerFailure();
            const id = ++hashJobId;
            const reply = await new Promise<HashReply | undefined>(resolve => {
              lane.pending = { id, resolve };
              try { lane.worker.postMessage({ id, fd: file.handle.fd, byteCount: Number(file.info.size),
                info: Object.fromEntries(['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs']
                  .map(key => [key, String(file.info[key as keyof BigIntStats])])) }); }
              catch (error) { delete lane.pending; fail(error); resolve(undefined); }
            });
            this.account(); if (!reply) break;
            if (reply.code === 'cancelled') {
              if (!Atomics.load(this.stop, 0) && !signal?.aborted && !failures.length) fail(hashWorkerFailure());
              break;
            }
            if (reply.code !== 'ok') mismatch(reply.code === 'metadata' ? 'installed runtime held file or its independent path changed' :
              reply.code === 'short' ? 'installed runtime file ended before its signed byte count' :
              reply.code === 'long' ? 'installed runtime file exceeds its signed byte count' : 'installed runtime original file read failed');
            await assertFile(file);
            // A computed SHA mismatch is already an observed real failure; a
            // simultaneous original abort cannot replace it with cancellation.
            if (file.digest !== undefined && reply.digest !== file.digest) mismatch('installed runtime signed file digest differs');
            signal?.throwIfAborted(); verified++;
          } catch (error) { if (!signal?.aborted || error !== signal.reason) fail(error); else this.abort(); }
        }
      };
      await Promise.all(this.lanes.map(run));
    } finally {
      this.account(); signal?.removeEventListener('abort', this.abort); this.currentFailures = undefined;
    }
    if (failures.length) throwHashFailure(failures, signal);
    this.assertHealthy();
    signal?.throwIfAborted();
    if (verified !== files.length) throw hashWorkerFailure();
    // No job is left in flight. Do not carry old byte counts into a new R or
    // let an indefinitely reused executor accumulate a signed-int64 wrap.
    for (let index = 0; index < this.laneCount; index++) {
      Atomics.store(this.counts, index, 0n); this.counted[index] = 0n;
    }
  }
  async close(): Promise<void> {
    this.abort(); this.closing = true;
    for (const lane of this.lanes) if (!lane.exited) {
      try { lane.worker.postMessage({ kind: 'close' }); } catch (error) { this.fail(error); }
    }
    await Promise.all(this.lanes.map(lane => lane.exit)); this.account(); this.assertHealthy();
  }
}
let discardPool: DiscardPool | undefined;
async function retireDiscardPoolLocked(): Promise<void> {
  const owned = discardPool;
  if (!owned) return;
  try { await owned.close(); } finally { discardPool = undefined; }
}
async function retireDiscardPool(): Promise<void> {
  if (!isMainThread) return;
  const release = await discardPermit();
  try { await retireDiscardPoolLocked(); } finally { release(); }
}
async function verifyDiscardFiles(files: readonly InstalledFile[], signal?: AbortSignal): Promise<void> {
  if (!isMainThread) { for (const file of files) await verifyBytesPipeline(file, signal); return; }
  const release = await discardPermit(signal);
  try {
    const large = files.filter(file => file.info.size >= 8_388_608n);
    if (large.length < 2 && !discardPool) {
      for (const file of files) await verifyBytesPipeline(file, signal);
      return;
    }
    try {
      if (large.length >= 2) {
        const laneCount = large.length >= 4 ? 4 : 2;
        if (discardPool && discardPool.laneCount !== laneCount) await retireDiscardPoolLocked();
        if (!discardPool) { discardPool = new DiscardPool(laneCount); discardPool.start(); }
      }
      // An existing idle pool also owns standalone/small reads. Starting a
      // parent pipeline beside its scratch would exceed one MiB; retiring and
      // recreating healthy threads between full checks is unnecessary. Without
      // a pool, small batches keep the original pipeline. Large-first work
      // balances lanes, and every job still reads/EOF/stats its original FD.
      await discardPool!.verify([...large, ...files.filter(file => file.info.size < 8_388_608n)], signal);
    } catch (error) {
      // A concurrent real executor/retirement failure cannot disappear under
      // the caller's cancellation, including a literally undefined failure.
      const retired = await Promise.allSettled([retireDiscardPoolLocked()]);
      throwHashFailure([error, ...retired.filter((result): result is PromiseRejectedResult => result.status === 'rejected')
        .map(result => result.reason)], signal);
    }
  } finally { release(); }
}
async function verifyBytes(file: InstalledFile, signal?: AbortSignal): Promise<void> {
  await verifyDiscardFiles([file], signal);
}
async function verifyBytesPipeline(file: InstalledFile, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  await assertFile(file);
  signal?.throwIfAborted();
  const hash = createHash('sha256'), count = Number(file.info.size);
  // Discard-only verification may reuse these two private halves. Their total
  // capacity never exceeds the original one-MiB scratch bound. Retaining chunks
  // above continue to own independent buffers and are not pipelined.
  const length = Math.min(CHUNK_BYTES / 2, count);
  const buffers = [Buffer.allocUnsafe(length), Buffer.allocUnsafe(length)];
  let position = 0, index = 0, failed = false, failure: unknown;
  let pending: ReturnType<FileHandle['read']> | undefined;
  const read = (slot: number, at: number) => file.handle.read(buffers[slot]!, 0, Math.min(length, count - at), at).then(result => {
    noteInstalledWorkRead(result.bytesRead); return result;
  });
  try {
    if (count) pending = read(index, position);
    while (pending) {
      const current = pending; pending = undefined;
      const { bytesRead } = await current;
      signal?.throwIfAborted();
      if (!bytesRead) mismatch('installed runtime file ended before its signed byte count');
      const bytes = buffers[index]!.subarray(0, bytesRead); position += bytesRead; index = 1 - index;
      // Only the next positional read is in flight while the completed half is
      // synchronously hashed; no buffer is overwritten before its hash ends.
      if (position < count) pending = read(index, position);
      hash.update(bytes);
    }
  } catch (error) { failed = true; failure = error; throw error; }
  finally {
    // Abort/hash failure never lets the owning borrow or selected.close retire
    // the original FileHandle under an outstanding real read.
    if (pending) {
      if (failed) await joinResourceOperations([Promise.reject(failure), pending] as const);
      else await pending;
    }
  }
  const extra = await file.handle.read(Buffer.allocUnsafe(1), 0, 1, position);
  noteInstalledWorkRead(extra.bytesRead);
  signal?.throwIfAborted();
  if (extra.bytesRead) mismatch('installed runtime file exceeds its signed byte count');
  await assertFile(file);
  signal?.throwIfAborted();
  if (file.digest !== undefined && hash.digest('hex') !== file.digest) mismatch('installed runtime signed file digest differs');
}
async function* artifactChunks(file: InstalledFile, signal?: AbortSignal): AsyncGenerator<Buffer> {
  for await (const bytes of chunks(file, signal))
    for (let offset = 0; offset < bytes.length; offset += ARTIFACT_CHUNK_BYTES)
      yield bytes.subarray(offset, offset + ARTIFACT_CHUNK_BYTES);
}
async function checkPackageGraph(scope: Scope, root: Directory, bundle: RuntimeBundleManifest,
  companion?: VerifiedInstalledModelAuthority, delegatedPaths: ReadonlySet<string> = new Set()): Promise<void> {
  const expected = new Map<string, Set<string>>();
  const companionPaths = companion ? ['model-authority.json', ...companion.closure.objects.map(object =>
    `model-objects/sha256/${object.artifactRef.slice(0, 2)}/${object.artifactRef}`)] : [];
  for (const filename of ['manifest.json', ...bundle.entries.filter(entry => !delegatedPaths.has(entry.relativePath)).map(entry => entry.relativePath), ...companionPaths]) {
    const components = filename.split('/');
    for (let index = 0; index < components.length; index++) {
      const parent = components.slice(0, index).join('/');
      const names = expected.get(parent) ?? new Set<string>(); names.add(components[index]!); expected.set(parent, names);
    }
  }
  for (const [relative, names] of expected) {
    const directory = relative ? (await scope.parent(root, `${relative}/_`)).parent : root;
    await scope.assertDirectory(directory);
    const observed = await readdir(childPath(directory, '.'));
    if (observed.length !== names.size || observed.some(name => !names.has(name))) mismatch('installed runtime graph contains missing or unsigned paths');
    await scope.assertDirectory(directory);
  }
}
async function checkSelectedVersion(scope: Scope, bundles: Directory, bundleDigest: string, retainedDigest?: string): Promise<void> {
  await scope.assertDirectory(bundles);
  const names = await readdir(childPath(bundles, '.'));
  const expected = retainedDigest === undefined ? [bundleDigest] : [retainedDigest, bundleDigest];
  if (names.length !== expected.length || names.some(name => !expected.includes(name)))
    mismatch('installed runtime contains an unregistered version or object');
  await scope.assertDirectory(bundles);
}

/** A separate real historical read, never an executable-image borrow. The
 * caller retains only the small signed source manifest and its namespace
 * expectations; every original entry is opened, completely read and joined
 * inside this fresh scope before current selection may escape. */
async function verifyRetainedSourcePackage(metadataScope: Scope, root: Directory,
  releaseKeys: readonly ReleaseTrustKey[], expectedDigest: string, casRoot: Directory): Promise<Readonly<{
    manifest: InstalledFile; bundle: RuntimeBundleManifest; delegatedPaths: ReadonlySet<string>;
  }>> {
  const manifest = await metadataScope.file(root, 'manifest.json', 0o400, undefined, expectedDigest);
  const bytes = await readSmall(manifest);
  const bundle = validateBundle(checkCanonicalBytes(bytes), releaseKeys);
  const historical = new Scope();
  let delegatedPaths: ReadonlySet<string> = new Set();
  try {
    // Duplicate the actual captured directory, rather than reopen a caller
    // path or keep a retired source file in the current execution scope.
    const originalRoot = await historical.directory(root, '.');
    const originalCas = await historical.directory(casRoot, '.');
    const original = await verifyPackage(historical, originalRoot, releaseKeys, expectedDigest, false, undefined, originalCas);
    delegatedPaths = original.delegatedPaths;
    if (!original.manifestBytes.equals(bytes)) mismatch('retained source metadata changed during its historical read');
    historical.assertMetadata([original.manifest, ...original.entries.values(), ...original.companionFiles]);
    await historical.assertDirectories();
    await metadataScope.assertDirectories();
    await assertFile(manifest);
  } catch (error) {
    await joinResourceOperations([Promise.reject(error), historical.close()]);
    throw error;
  }
  await historical.close();
  await assertFile(manifest); await metadataScope.assertDirectory(root);
  return Object.freeze({ manifest, bundle, delegatedPaths });
}
async function verifyPackage(scope: Scope, root: Directory, releaseKeys: readonly ReleaseTrustKey[], expectedDigest?: string,
  sourceCompanion = false, signal?: AbortSignal, installedCas?: Directory,
  publishedStreams?: ReadonlyMap<string, InstalledFile>): Promise<VerifiedPackage> {
  return observeInstalledWork('package', () => verifyPackageBytes(scope, root, releaseKeys, expectedDigest, sourceCompanion, signal, installedCas, publishedStreams));
}
async function verifyPackageBytes(scope: Scope, root: Directory, releaseKeys: readonly ReleaseTrustKey[], expectedDigest?: string,
  sourceCompanion = false, signal?: AbortSignal, installedCas?: Directory,
  publishedStreams?: ReadonlyMap<string, InstalledFile>): Promise<VerifiedPackage> {
  signal?.throwIfAborted();
  const manifest = await scope.file(root, 'manifest.json', 0o400, undefined, expectedDigest);
  const manifestBytes = await readSmall(manifest, SMALL_BYTES, signal);
  const bundleDigest = sha256Bytes(manifestBytes);
  const bundle = validateBundle(checkCanonicalBytes(manifestBytes), releaseKeys);
  manifest.digest = bundleDigest;
  const entries = new Map<string, InstalledFile>();
  const roots = new Map<string, Buffer>([[bundleDigest, manifestBytes]]);
  const streamedRoots = new Map<string, InstalledFile>();
  const singleCasPaths = new Set<string>(), delegatedPaths = new Set<string>(), delegatedRefs = new Set<string>();
  const inodes = new Set<string>([`${manifest.info.dev}:${manifest.info.ino}`]);
  // Metadata is read before data placement is resolved. Only the exact signed
  // guest-image edges and fixed npm pair may delegate to installed CAS; absence
  // of a package path never chooses a layout or supplies a fallback.
  for (const entry of bundle.entries.filter(entry => entry.role !== 'bundle_object')) {
    signal?.throwIfAborted();
    const file = await scope.file(root, entry.relativePath, entry.executable ? 0o500 : 0o400, entry.byteCount, entry.digest);
    const identity = `${file.info.dev}:${file.info.ino}`;
    if (inodes.has(identity)) mismatch('distinct signed entries alias one installed inode');
    inodes.add(identity); entries.set(entry.entryId, file);
    if (['policy_engine', 'sandbox_root_profile', 'system_prompt', 'compaction_prompt', 'guest_toolchain', 'schema', 'skill_bundle'].includes(entry.role)) {
      if (entry.executable) mismatch('signed structured roots must be data');
      const bytes = await readSmall(file, SMALL_BYTES, signal); const value = checkCanonicalBytes(bytes);
      if (entry.role === 'policy_engine') {
        if (canonicalSha256(value) !== canonicalSha256(policyProfile())) mismatch('signed policy root is not the fixed supported evaluator profile');
      } else if (entry.role === 'sandbox_root_profile') decodeSandboxRootProfile(value);
      roots.set(entry.digest, bytes);
    } else if (entry.role === 'trust_store') {
      const bytes = await readSmall(file, TRUST_BYTES, signal); validateTrustStore(bytes); roots.set(entry.digest, bytes);
    } else if (entry.entryId === BUILTIN_SCRIPT_RECIPE.entryId && entry.role === 'tool_adapter') {
      if (entry.executable !== false || entry.version !== BUILTIN_SCRIPT_RECIPE.version ||
          entry.relativePath !== BUILTIN_SCRIPT_RECIPE.relativePath || entry.byteCount < 1 || entry.byteCount > BUILTIN_SCRIPT_RECIPE.scriptBytes)
        mismatch('builtin tool script is outside its fixed signed data contract');
      roots.set(entry.digest, await readSmall(file, BUILTIN_SCRIPT_RECIPE.scriptBytes, signal));
    } else if (isNpmAdapterEntry(entry)) {
      roots.set(entry.digest, await readSmall(file, SMALL_BYTES, signal));
    } else if (entry.role !== 'bundle_object') await verifyBytes(file, signal);
  }
  const guests = guestToolchainRoots(bundle).map(root => {
    const bytes = roots.get(root.artifactRef);
    if (!bytes) mismatch('installed guest manifest has no complete signed bytes');
    return { ref: root.artifactRef, manifest: decodeGuestToolchainManifest(checkCanonicalBytes(bytes)), bytes };
  });
  const imageRefs = new Set(guests.map(guest => guest.manifest.guestImageRef));
  const signatureRefs = new Set(guests.map(guest => guest.manifest.signatureRef));
  const skillClosures = new Map(bundledSkillRoots(bundle).map(root => [root.artifactRef,
    decodeBundledSkillClosure(checkCanonicalBytes(roots.get(root.artifactRef)!))] as const));
  const skillMembers = bundledSkillMemberRoles(bundle, skillClosures);
  for (const entry of bundle.entries.filter(entry => entry.role === 'bundle_object')) {
    signal?.throwIfAborted();
    const eligible = isNpmDataEntry(entry) || imageRefs.has(entry.digest);
    if (eligible) singleCasPaths.add(entry.relativePath);
    const delegated = installedCas !== undefined && bundle.schemaVersion === 2 &&
      bundle.installedLayout === SINGLE_CAS_STREAMS_LAYOUT && eligible;
    const published = delegated ? publishedStreams?.get(entry.digest) : undefined;
    const file = published ? await scope.reuseCasFile(published, installedCas!, entry.digest, entry.byteCount) :
      await scope.file(delegated ? installedCas! : root, delegated ? entry.digest : entry.relativePath,
        entry.executable ? 0o500 : 0o400, entry.byteCount, entry.digest);
    const identity = `${file.info.dev}:${file.info.ino}`;
    if (inodes.has(identity)) mismatch('distinct signed entries alias one installed inode');
    inodes.add(identity); entries.set(entry.entryId, file);
    if (delegated) { delegatedPaths.add(entry.relativePath); delegatedRefs.add(entry.digest); }
    if (isNpmDataEntry(entry)) {
      // The sole fixed complete official image is a raw signed data edge,
      // never JSON, an executable or thousands of separate CAS members.
      await verifyBytes(file, signal); streamedRoots.set(entry.digest, file);
    } else if (imageRefs.has(entry.digest)) {
      if (entry.executable || entry.byteCount < 1 || entry.byteCount > GUEST_EXTRACTOR_RECIPE.maxImageBytes)
        mismatch('installed guest image exceeds the supported signed recipe bound');
      await verifyBytes(file, signal); streamedRoots.set(entry.digest, file);
    } else if (skillMembers.instructions.has(entry.digest)) {
      roots.set(entry.digest, await readSmall(file, SMALL_BYTES, signal));
    } else if (skillMembers.resources.has(entry.digest)) {
      if (entry.executable || entry.byteCount > SKILL_RESOURCE_BYTES) mismatch('installed skill resource exceeds its signed data bound');
      await verifyBytes(file, signal); streamedRoots.set(entry.digest, file);
    } else {
      const bytes = await readSmall(file, signatureRefs.has(entry.digest) ? 64 : SMALL_BYTES, signal);
      if (!signatureRefs.has(entry.digest)) checkCanonicalBytes(bytes);
      roots.set(entry.digest, bytes);
    }
  }
  await validateBundledSkillReferences(skillClosures, async (ref, byteCount) => {
    const retained = roots.get(ref); if (retained) return retained;
    const declarations = bundle.entries.filter(entry => entry.digest === ref), entry = declarations[0];
    if (declarations.length !== 1 || !entry || entry.role !== 'bundle_object' || entry.executable || entry.byteCount !== byteCount)
      mismatch('skill textual resource has no unique original signed member');
    return readSmall(entries.get(entry.entryId)!, SKILL_RESOURCE_BYTES, signal);
  });
  const structured = validateInstalledStructuredArtifacts(bundle, roots);
  for (const guest of guests) {
    const signature = roots.get(guest.manifest.signatureRef);
    if (!signature || !streamedRoots.has(guest.manifest.guestImageRef)) mismatch('installed guest closure is incomplete');
    validateGuestToolchainMetadata(bundle, guest.ref, guest.bytes, signature, releaseKeys);
  }
  const companionFiles: InstalledFile[] = [];
  let modelAuthority: VerifiedInstalledModelAuthority | undefined;
  if (sourceCompanion) {
    await scope.assertDirectory(root);
    const names = await readdir(childPath(root, '.'));
    await scope.assertDirectory(root);
    if (names.includes('model-authority.json')) {
      const file = await scope.file(root, 'model-authority.json', 0o400);
      const bytes = await readSmall(file, SMALL_BYTES, signal);
      try {
        const closure = decodeInstalledModelAuthorityClosure(checkCanonicalBytes(bytes), { bundle, releaseKeys });
        file.digest = sha256Bytes(bytes); companionFiles.push(file); roots.set(file.digest, bytes);
        const objects = new Map<string, Buffer>();
        for (const object of closure.objects) {
          signal?.throwIfAborted();
          const member = await scope.file(root, `model-objects/sha256/${object.artifactRef.slice(0, 2)}/${object.artifactRef}`,
            0o400, object.byteCount, object.artifactRef);
          const identity = `${member.info.dev}:${member.info.ino}`;
          if (inodes.has(identity)) mismatch('installed model members alias another signed inode');
          inodes.add(identity); companionFiles.push(member);
          const bytes = await readSmall(member, 65536, signal);
          objects.set(object.artifactRef, bytes); roots.set(object.artifactRef, bytes);
        }
        modelAuthority = verifyInstalledModelAuthority({ closure, bundle, releaseKeys, objects });
        if (modelAuthority.closureRef !== file.digest) mismatch('installed model closure complete identity differs');
      } catch (cause) { if (signal?.aborted && cause === signal.reason) throw cause; mismatch('installed model companion verification failed', cause); }
    }
  }
  await checkPackageGraph(scope, root, bundle, modelAuthority, delegatedPaths); await scope.assertDirectories();
  signal?.throwIfAborted();
  return { root, manifest, bundle, bundleDigest, manifestBytes, entries, roots, streamedRoots, singleCasPaths, delegatedPaths, delegatedRefs, structured, companionFiles,
    ...(modelAuthority ? { modelAuthority } : {}) };
}

async function readInstalledCompanionFromCas(scope: Scope, casRoot: Directory, signed: VerifiedPackage,
  modelAuthorityRef: string, releaseKeys: readonly ReleaseTrustKey[]): Promise<InstalledFile[]> {
  const casFiles: InstalledFile[] = [];
  try {
    const file = await scope.file(casRoot, modelAuthorityRef, 0o400, undefined, modelAuthorityRef);
    const bytes = await readSmall(file); casFiles.push(file); signed.roots.set(modelAuthorityRef, bytes);
    const closure = decodeInstalledModelAuthorityClosure(checkCanonicalBytes(bytes), { bundle: signed.bundle, releaseKeys });
    const objects = new Map<string, Buffer>();
    for (const object of closure.objects) {
      const member = await scope.file(casRoot, object.artifactRef, 0o400, object.byteCount, object.artifactRef);
      const bytes = await readSmall(member, 65536); casFiles.push(member);
      objects.set(object.artifactRef, bytes); signed.roots.set(object.artifactRef, bytes);
    }
    signed.modelAuthority = verifyInstalledModelAuthority({ closure, bundle: signed.bundle, releaseKeys, objects });
    if (signed.modelAuthority.closureRef !== modelAuthorityRef) mismatch('selected model closure complete identity differs');
  } catch (cause) { mismatch('selected installed model companion verification failed', cause); }
  return casFiles;
}

async function writeChunks(scope: Scope, root: Directory, relative: string, source: AsyncIterable<Buffer>, mode: number): Promise<void> {
  const { parent, name } = await scope.parent(root, relative, true);
  await scope.assertDirectory(parent);
  const handle = scope.own(await open(childPath(parent, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600));
  let position = 0;
  for await (const bytes of source) {
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, position);
      if (!bytesWritten) mismatch('installed runtime copy made no progress');
      offset += bytesWritten; position += bytesWritten;
    }
  }
  await handle.chmod(mode); await handle.sync();
  await scope.retire(handle); await scope.assertDirectory(parent);
}
async function* bytesSource(bytes: Buffer): AsyncGenerator<Buffer> { yield bytes; }
async function syncDirectories(scope: Scope): Promise<void> {
  for (const directory of [...scope.directories].reverse()) {
    await scope.assertDirectory(directory); await directory.handle.sync(); await scope.assertDirectory(directory);
  }
}
async function absent(parent: Directory, name: string): Promise<void> {
  try { await lstat(childPath(parent, name)); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
  mismatch('initial runtime installation refuses an existing selection or version');
}
async function finish<T>(scope: Scope, operation: () => Promise<T>): Promise<T> {
  let result: T | undefined;
  let failure: unknown;
  try { result = await operation(); } catch (error) { rememberRetirement(error); failure = error; }
  try { await scope.close(); } catch (error) { rememberRetirement(error); throw error; }
  if (failure !== undefined) throw failure;
  healthy(); return result as T;
}

/** Trusted composition only: production supplies compiled release roots here.
 * Neither install nor selection accepts caller overrides, execution callbacks,
 * arbitrary loaders, StateStore authority or an upgrade/adoption operation. */
export function createInstalledRuntime(input: { releaseKeys: readonly ReleaseTrustKey[] }): InstalledRuntime {
  supportedPlatform();
  healthy();
  if (!exactKeys(input, ['releaseKeys'])) mismatch('installed runtime accepts only trusted composition keys');
  const releaseKeys = immutableSnapshot(input.releaseKeys);
  if (!Array.isArray(releaseKeys) || !releaseKeys.length || releaseKeys.some(key => !exactKeys(key, ['keyId', 'publicKeyPem']) ||
      typeof key.keyId !== 'string' || !key.keyId || typeof key.publicKeyPem !== 'string' || !key.publicKeyPem) ||
      new Set(releaseKeys.map(key => key.keyId)).size !== releaseKeys.length) mismatch('installed runtime requires fixed unambiguous trusted composition keys');
  const runtime: InstalledRuntime = Object.freeze({
    executeSelected(this: InstalledRuntime, held: HeldInstalledRuntime, role: 'keeper' | 'supervisor' | 'endpoint' | 'credential', command?: string): Promise<never> {
      // Reject receiver/brand/factory/primitive role before touching a caller
      // property, queue, or descriptor. Invalid calls do not consume a handle.
      if (this !== runtime) mismatch('installed runtime factory receiver is not its trusted instance');
      const binding = heldInstalledRuntimes.get(held);
      if (!binding || binding.factory !== runtime) mismatch('installed execution requires this factory\'s genuine held selection');
      if (role !== 'keeper' && role !== 'supervisor' && role !== 'endpoint' && role !== 'credential') mismatch('installed execution requires a fixed primitive role');
      if (role === 'credential' ? typeof command !== 'string' || !command.length || command.length > 87382 || !/^[A-Za-z0-9_-]+$/u.test(command)
        : command !== undefined) mismatch('installed execution requires bounded credential metadata only for the fixed credential role');
      if (!isMainThread) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed execution requires the main thread');
      healthy();
      return binding.execute(role, command);
    },
    async installInitial(this: InstalledRuntime, target: { packageRoot: string; stateRoot: string }) {
      supportedPlatform();
      if (this !== runtime) mismatch('installed runtime factory receiver is not its trusted instance');
      healthy();
      if (!exactKeys(target, ['packageRoot', 'stateRoot'])) mismatch('initial runtime installation requires only fixed package and StateRoot locators');
      const { packageRoot, stateRoot } = target;
      const sourceScope = new Scope();
      const destination = new Scope();
      const installed = await finish(destination, async () => {
        let signed: VerifiedPackage;
        try {
          noteInstalledInstallPhase('source_verify');
          const sourceRoot = await sourceScope.root(packageRoot);
          signed = await verifyPackage(sourceScope, sourceRoot, releaseKeys, undefined, true);
          requireSingleCasBundle(signed.bundle);
          noteInstalledInstallPhase('destination_layout');
          const state = await destination.root(stateRoot, true);
          const root = await destination.directory(state, 'runtime', true);
          const casRoot = await destination.directory(state, KERNEL_CAS_DIRECTORY, true);
          const bundles = await destination.directory(root, 'bundles', true);
          const stage = await destination.directory(bundles, `.stage-${randomBytes(16).toString('hex')}`, true);
          noteInstalledInstallPhase('signed_entries_copy');
          let copiedEntries = 0;
          for (const entry of signed.bundle.entries) {
            if (signed.singleCasPaths.has(entry.relativePath)) continue;
            await writeChunks(destination, stage, entry.relativePath, chunks(signed.entries.get(entry.entryId)!), entry.executable ? 0o500 : 0o400);
            noteInstalledInstallPhase('signed_entries_copy', ++copiedEntries);
          }
          noteInstalledInstallPhase('manifest_bootstrap_copy');
          await writeChunks(destination, stage, 'manifest.json', bytesSource(signed.manifestBytes), 0o400);
          noteInstalledInstallPhase('manifest_bootstrap_copy', 1);
          const supervisor = signed.bundle.entries.find(entry => entry.role === 'supervisor')!;
          await writeChunks(destination, root, 'bootstrap', chunks(signed.entries.get(supervisor.entryId)!), 0o500);
          noteInstalledInstallPhase('manifest_bootstrap_copy', 2);
          // Existing CAS publication owns its durability protocol; all supported
          // complete roots precede durable selection, with no second ledger.
          const cas = new ContentAddressedStore(childPath(casRoot, '.'));
          const casFiles: InstalledFile[] = [];
          noteInstalledInstallPhase('cas_roots_publish');
          let publishedRoots = 0;
          const roots = [...signed.roots];
          for (let offset = 0; offset < roots.length; offset += 4) {
            const group = roots.slice(offset, offset + 4);
            // Each original root retains its scope checks. Only up to four
            // complete publications share the existing four CAS barriers.
            for (const _ of group) await destination.assertDirectories();
            await publishInstalledCasRoots(cas, group);
            for (const [ref, bytes] of group) {
              await destination.assertDirectories();
              casFiles.push(await destination.file(casRoot, ref, 0o400, bytes.length, ref));
              noteInstalledInstallPhase('cas_roots_publish', ++publishedRoots);
            }
          }
          noteInstalledInstallPhase('cas_streams_publish');
          let publishedStreams = 0;
          for (const [ref, file] of signed.streamedRoots) {
            await destination.assertDirectories();
            const result = await cas.publishChunks(artifactChunks(file), Number(file.info.size));
            if (result.ref !== ref || BigInt(result.byteLength) !== file.info.size)
              mismatch('installed streamed data CAS publication changed its complete identity');
            await destination.assertDirectories();
            casFiles.push(await destination.file(casRoot, ref, 0o400, result.byteLength, ref));
            noteInstalledInstallPhase('cas_streams_publish', ++publishedStreams);
          }
          noteInstalledInstallPhase('destination_verify');
          await verifyPackage(destination, stage, releaseKeys, signed.bundleDigest, false, undefined, casRoot,
            new Map(casFiles.map(file => [file.name, file])));
          noteInstalledInstallPhase('bootstrap_verify');
          await verifyBytes(await destination.file(root, 'bootstrap', 0o500, supervisor.byteCount, supervisor.digest));
          noteInstalledInstallPhase('source_final_verify');
          await checkPackageGraph(sourceScope, sourceRoot, signed.bundle, signed.modelAuthority);
          await sourceScope.assertDirectories();
          let sourceFilesVerified = 0;
          for (const file of [signed.manifest, ...signed.entries.values(), ...signed.companionFiles]) {
            await verifyBytes(file); noteInstalledInstallPhase('source_final_verify', ++sourceFilesVerified);
          }
          noteInstalledInstallPhase('cas_final_verify');
          let casFilesVerified = 0;
          for (const file of casFiles) {
            await verifyBytes(file); noteInstalledInstallPhase('cas_final_verify', ++casFilesVerified);
          }
          noteInstalledInstallPhase('directory_sync');
          await syncDirectories(destination);
          noteInstalledInstallPhase('directory_sync', destination.directories.length);
          // Retire source authority before publishing a selection. Source
          // deletion after this point cannot change installed identity.
          noteInstalledInstallPhase('source_join');
          await sourceScope.close(); healthy();
          noteInstalledInstallPhase('bundle_publish');
          await absent(bundles, signed.bundleDigest);
          await rename(childPath(bundles, stage.name), childPath(bundles, signed.bundleDigest));
          stage.name = signed.bundleDigest;
          await bundles.handle.sync(); await destination.assertDirectories();
          noteInstalledInstallPhase('selection_publish');
          await absent(root, 'active.json');
          const temporary = `.tmp-active-${randomBytes(16).toString('hex')}`;
          await writeChunks(destination, root, temporary, bytesSource(canonicalJsonBytes({ schemaVersion: 1,
            bundleDigest: signed.bundleDigest, ...(signed.modelAuthority ? { modelAuthorityRef: signed.modelAuthority.closureRef } : {}) })), 0o600);
          healthy(); await rename(childPath(root, temporary), childPath(root, 'active.json'));
          await root.handle.sync(); await destination.assertDirectories();
          noteInstalledInstallPhase('destination_join');
          return { bundleDigest: signed.bundleDigest, manifestDigest: signed.bundle.manifestDigest };
        } catch (error) {
          rememberRetirement(error);
          await sourceScope.close(); throw error;
        }
      });
      noteInstalledInstallPhase('complete_joined');
      return installed;
    },
    async openSelected(this: InstalledRuntime, stateRoot: string, originalLayout?: typeof originalUpgradeLayout): Promise<HeldInstalledRuntime> {
      supportedPlatform();
      if (this !== runtime) mismatch('installed runtime factory receiver is not its trusted instance');
      if (originalLayout !== undefined && originalLayout !== originalUpgradeLayout) mismatch('installed layout context is not its original upgrade source');
      healthy();
      const scope = new Scope();
      try {
        const state = await scope.root(stateRoot);
        const root = await scope.directory(state, 'runtime');
        const bundles = await scope.directory(root, 'bundles');
        const casRoot = await scope.directory(state, KERNEL_CAS_DIRECTORY);
        const active = await scope.file(root, 'active.json', 0o600);
        const activeBytes = await readSmall(active);
        const selection = checkCanonicalBytes(activeBytes) as { schemaVersion: number; bundleDigest: string; modelAuthorityRef?: string; upgradeReceiptRef?: string };
        if (!selection || typeof selection !== 'object' || Array.isArray(selection) ||
            !exactKeys(selection, ['schemaVersion', 'bundleDigest', ...(Object.hasOwn(selection, 'modelAuthorityRef') ? ['modelAuthorityRef'] : []),
              ...(Object.hasOwn(selection, 'upgradeReceiptRef') ? ['upgradeReceiptRef'] : [])]) ||
            selection.schemaVersion !== 1) mismatch('installed runtime selection has an invalid closed shape');
        try { assertArtifactRef(selection.bundleDigest); if (selection.modelAuthorityRef !== undefined) assertArtifactRef(selection.modelAuthorityRef);
          if (selection.upgradeReceiptRef !== undefined) assertArtifactRef(selection.upgradeReceiptRef); }
        catch (cause) { mismatch('installed runtime selection has an invalid complete reference', cause); }
        active.digest = sha256Bytes(activeBytes);
        const registeredUpgrade = selection.upgradeReceiptRef === undefined ? undefined :
          await readRegisteredInstalledUpgrade(stateRoot, releaseKeys, selection.upgradeReceiptRef);
        if (registeredUpgrade && (registeredUpgrade.targetRuntimeBundleRef !== selection.bundleDigest ||
            registeredUpgrade.installation.kind === 'not_installed' ||
            registeredUpgrade.installation.targetModelAuthorityRef !== selection.modelAuthorityRef)) mismatch('selection differs from its registered upgrade');
        await checkSelectedVersion(scope, bundles, selection.bundleDigest, registeredUpgrade?.sourceRuntimeBundleRef);
        const version = await scope.directory(bundles, selection.bundleDigest);
        const signed = await verifyPackage(scope, version, releaseKeys, selection.bundleDigest, false, undefined, casRoot);
        if (originalLayout === undefined) requireSingleCasBundle(signed.bundle);
        const supervisor = signed.bundle.entries.find(entry => entry.role === 'supervisor')!;
        const bootstrap = await scope.file(root, 'bootstrap', 0o500, supervisor.byteCount, supervisor.digest);
        const retainedMetadataFiles: InstalledFile[] = [];
        const retainedGraphs: Array<{ directory: Directory; bundle: RuntimeBundleManifest; delegatedPaths: ReadonlySet<string> }> = [];
        if (registeredUpgrade) {
          const source = registeredUpgrade.installation;
          if (source.kind === 'not_installed') mismatch('installed selection cannot use a noninstalled receipt');
          assertUpgradeObjectIdentity(root, source.runtimeIdentity);
          assertUpgradeObjectIdentity(version, source.targetBundleIdentity);
          assertUpgradeObjectIdentity(active, source.stagedActiveIdentity);
          assertUpgradeObjectIdentity(bootstrap, source.stagedBootstrapIdentity);
          const originalStage = await scope.directory(root, source.stageName);
          assertUpgradeObjectIdentity(originalStage, source.stageIdentity);
          if ((await readdir(childPath(originalStage, '.'))).length !== 0) mismatch('published upgrade stage contains unregistered objects');
          const retainedVersion = await scope.directory(bundles, registeredUpgrade.sourceRuntimeBundleRef);
          const retained = await verifyRetainedSourcePackage(scope, retainedVersion, releaseKeys, registeredUpgrade.sourceRuntimeBundleRef, casRoot);
          retainedMetadataFiles.push(retained.manifest);
          retainedGraphs.push({ directory: retainedVersion, bundle: retained.bundle, delegatedPaths: retained.delegatedPaths });
        }

        const casFiles: InstalledFile[] = [];
        for (const [ref, bytes] of signed.roots) casFiles.push(await scope.file(casRoot, ref, 0o400, bytes.length, ref));
        for (const [ref, image] of signed.streamedRoots)
          if (!signed.delegatedRefs.has(ref)) casFiles.push(await scope.file(casRoot, ref, 0o400, Number(image.info.size), ref));
        const installedStreams = new Map<string, InstalledFile>();
        for (const [ref, image] of signed.streamedRoots) {
          const physical = signed.delegatedRefs.has(ref) ? image : casFiles.find(file => file.digest === ref);
          if (!physical) mismatch('installed stream lacks its original physical CAS holder');
          installedStreams.set(ref, physical);
        }
        if (selection.modelAuthorityRef !== undefined)
          casFiles.push(...await readInstalledCompanionFromCas(scope, casRoot, signed, selection.modelAuthorityRef, releaseKeys));
        let closed = false;
        const guestShutdown = new AbortController();
        const observationShutdown = new AbortController();
        const observationJobs = new Set<Promise<InstalledRuntimeObservation>>();
        let observationRetirement: ResourceRetirementError | undefined;
        let poisoned: unknown, hasPoisoned = false;
        let tail = Promise.resolve();
        let closePromise: Promise<void> | undefined;
        let workerNative: NativeWorkerBinding | undefined;
        let credentialPlatform: NativeCredentialPlatformBinding | undefined;
        let credentialPlatformNative: NativeCredentialPlatformBinding | undefined;
        let managerObserver: InstalledManagerObserver | undefined;
        let modelBroker: NativeModelBrokerBinding | undefined;
        let dependencyBroker: NativeDependencyBrokerBinding | undefined;
        let guestExtractor: NativeGuestExtractorBinding | undefined;
        const platformJobs = new Set<Promise<unknown>>();
        const brokerTransports = new Set<NativeModelTransport | NativeDependencyTransport>();
        const guestJobs = new Set<NativeGuestToolchain>();
        const guestJoins = new Map<NativeGuestToolchain, Promise<void>>();
        const retiredGuestJobs = new WeakSet<NativeGuestToolchain>();
        const closeGuestToolchain = (job: NativeGuestToolchain): Promise<void> => {
          if (retiredGuestJobs.has(job)) return Promise.resolve();
          if (!guestJobs.has(job)) return Promise.reject(new KernelStorageError('ARTIFACT_MISMATCH', 'guest retirement is not owned by this selection'));
          const joining = guestJoins.get(job);
          if (joining) return joining;
          const pending = Promise.resolve().then(() => job.close()).then(() => {
            guestJobs.delete(job); guestJoins.delete(job); retiredGuestJobs.add(job);
          }, error => {
            const failure = error instanceof ResourceRetirementError ? error : new ResourceRetirementError('installed guest extractor did not retire', error);
            rememberRetirement(failure); throw failure;
          });
          guestJoins.set(job, pending); return pending;
        };
        const assertSelection = () => {
          if (hasPoisoned) throw poisoned;
          try { scope.assertMetadata([active, signed.manifest, bootstrap, ...signed.entries.values(), ...casFiles, ...retainedMetadataFiles]); }
          catch (error) { rememberRetirement(error); poisoned = error; hasPoisoned = true; throw error; }
        };
        const revalidate = (signal?: AbortSignal) => observeInstalledWork('revalidate', async () => {
          signal?.throwIfAborted();
          healthy(); await scope.assertDirectories();
          signal?.throwIfAborted();
          await scope.verifyDiscard([active, signed.manifest, bootstrap, ...signed.entries.values(), ...casFiles, ...retainedMetadataFiles], signal);
          await checkPackageGraph(scope, version, signed.bundle, undefined, signed.delegatedPaths);
          for (const retained of retainedGraphs) await checkPackageGraph(scope, retained.directory, retained.bundle, undefined, retained.delegatedPaths);
          signal?.throwIfAborted();
          await checkSelectedVersion(scope, bundles, signed.bundleDigest, registeredUpgrade?.sourceRuntimeBundleRef); await scope.assertDirectories();
          signal?.throwIfAborted();
        });
        await revalidate();
        const checkedRevalidate = async (signal?: AbortSignal) => {
          if (hasPoisoned) throw poisoned;
          try { await revalidate(signal); }
          catch (error) {
            // Cancellation joins the same held descriptors; it is not an
            // integrity failure. Never suppress a different concurrent error.
            if (!signal?.aborted || error !== signal.reason) { rememberRetirement(error); poisoned = error; hasPoisoned = true; }
            throw error;
          }
        };
        const joinObservations = async (): Promise<void> => {
          const results = await Promise.allSettled([...observationJobs]);
          const failed = results.find(result => result.status === 'rejected' && result.reason instanceof ResourceRetirementError);
          if (failed?.status === 'rejected') throw failed.reason;
          // A completed observation may have left the live set before close.
          // Its retirement uncertainty must still dominate ordinary failures.
          if (observationRetirement) throw observationRetirement;
        };
        const loadSelectedNative = async (signal?: AbortSignal): Promise<NativeStateOwner> => {
          await checkedRevalidate(signal);
          const entry = signed.bundle.entries.find(entry => entry.entryId === STATE_OWNER_NATIVE_ENTRY_ID);
          const file = signed.entries.get(STATE_OWNER_NATIVE_ENTRY_ID);
          if (!entry || !file || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
              entry.relativePath !== STATE_OWNER_NATIVE_RELATIVE_PATH || entry.byteCount <= 0 || entry.byteCount > TRUST_BYTES)
            mismatch('installed StateOwner requires its fixed signed native entry');
          const native = await loadHeldStateOwnerImage(file.handle, signed.bundle);
          await checkedRevalidate(signal);
          return native;
        };
        const enqueue = <T>(operation: () => Promise<T>): Promise<T> => {
          if (closed) mismatch('installed runtime handle is closed');
          const pending = tail.then(operation);
          tail = pending.then(() => undefined, () => undefined);
          return pending;
        };
        // Both clients retain the same signed addon and original FD. Only the
        // full credential entry below can expose its mutating operations.
        const loadCredentialPlatformNative = (): NativeCredentialPlatformBinding => {
          assertSelection();
          if (!credentialPlatformNative) {
            const entry = signed.bundle.entries.find(value => value.entryId === 'linux_credential_platform');
            const file = signed.entries.get('linux_credential_platform');
            if (!entry || !file || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
                entry.relativePath !== 'native/linux-x64/linux-credential-platform.node')
              mismatch('fixed signed credential platform module is missing');
            const loaded = new Module('cliq-installed-linux-credential-platform');
            process.dlopen(loaded, `/proc/self/fd/${file.handle.fd}`);
            const native = loaded.exports as NativeCredentialPlatformBinding;
            if (native.interfaceVersion !== 2 || typeof native.secretService !== 'function' || typeof native.userManager !== 'function' ||
                typeof native.currentUser !== 'function')
              mismatch('unsupported installed credential platform interface');
            credentialPlatformNative = native;
          }
          assertSelection();
          return credentialPlatformNative;
        };
        const refusePlatformOperation = (error: unknown): never => {
          if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
            const failure = new ResourceRetirementError('credential platform resources did not retire', error);
            rememberRetirement(failure); throw failure;
          }
          // Only fixed native status codes survive. Remote/native messages,
          // payloads and stacks never become retained observation data.
          const value = error as { code?: unknown; platformCode?: unknown } | null;
          const platformCode = value?.code === 'ERR_CLIQ_CREDENTIAL_PLATFORM' &&
            (value.platformCode === 'delete_denied' || value.platformCode === 'delete_failed')
            ? value.platformCode : 'platform_store_unavailable';
          throw new KernelStorageError('RECOVERY_REQUIRED', 'installed credential platform rejected an operation',
            { cause: Object.freeze({ platformCode }) });
        };
        const trackPlatformOperation = <T>(pending: Promise<T>): Promise<T> => {
          const job = pending.then(result => { assertSelection(); return result; }, refusePlatformOperation);
          platformJobs.add(job);
          void job.finally(() => platformJobs.delete(job)).catch(() => {});
          return job;
        };
        const identity = (directory: Directory): InstalledDirectoryIdentity => Object.freeze({
          deviceId: directory.info.dev.toString(), fileId: directory.info.ino.toString(), ownerUid: Number(directory.info.uid),
        });
        const observation = Object.freeze({
          bundle: signed.bundle, bundleDigest: signed.bundleDigest,
          releaseKeys,
          stateRoot: Object.freeze({ ...identity(state), canonicalPath: stateRoot }),
          casRoot: identity(casRoot),
          structured: signed.structured,
          get objects(): ReadonlyMap<string, Buffer> { return new Map([...signed.roots].map(([ref, bytes]) => [ref, Buffer.from(bytes)])); },
          ...(signed.modelAuthority ? { modelAuthority: signed.modelAuthority } : {}),
          seed: Object.freeze([...signed.roots].map(([artifactRef, bytes]) => {
            const role = signed.bundle.entries.find(entry => entry.digest === artifactRef)?.role;
            const companionKind = signed.modelAuthority?.closure.objects.find(object => object.artifactRef === artifactRef)?.kind;
            const schemaKind = artifactRef === signed.bundleDigest ? 'cliq-runtime-bundle-v1' :
              artifactRef === signed.modelAuthority?.closureRef ? 'cliq-installed-model-authority-v1' :
              companionKind === 'ed25519_signature' ? 'cliq-ed25519-signature-v1' :
              companionKind === 'model_catalog_entry' ? 'cliq-signed-model-catalog-entry-v1' :
              companionKind === 'model_price_table' ? 'cliq-model-price-table-v1' :
              signed.structured.objects.find(object => object.artifactRef === artifactRef)?.schemaKind ?? (
              role === 'tool_adapter' && signed.bundle.entries.some(entry => entry.entryId === BUILTIN_SCRIPT_RECIPE.entryId && entry.digest === artifactRef)
                ? 'cliq-builtin-tool-script-v1' :
              role === 'tool_adapter' && signed.bundle.entries.some(entry => entry.digest === artifactRef && isNpmAdapterEntry(entry))
                ? 'cliq-npm-dependency-script-v1' :
              role === 'schema' ? 'cliq-installed-schema-v1' :
              role === 'policy_engine' ? 'cliq-policy-engine-profile-v1' :
              role === 'sandbox_root_profile' ? 'cliq-sandbox-root-profile-v1' :
              role === 'trust_store' ? 'cliq-https-trust-store-v1' : mismatch('installed seed contains an unsupported object'));
            return Object.freeze({ artifactRef, byteCount: bytes.length,
              mediaType: schemaKind === 'cliq-builtin-tool-script-v1' || schemaKind === 'cliq-skill-source-file-v1' || schemaKind === 'cliq-npm-dependency-script-v1' || role === 'trust_store' || companionKind === 'ed25519_signature' || schemaKind === 'cliq-ed25519-signature-v1'
                ? 'application/octet-stream' : 'application/json', schemaKind });
          }).concat([...signed.streamedRoots].map(([artifactRef, file]) => ({ artifactRef, byteCount: Number(file.info.size),
            mediaType: 'application/octet-stream', schemaKind: streamedInstalledSchemaKind(signed, artifactRef) })))
            .sort((left, right) => left.artifactRef < right.artifactRef ? -1 : left.artifactRef > right.artifactRef ? 1 : 0)),
        });
        const selected: HeldInstalledRuntime = Object.freeze({
          bundle: signed.bundle, bundleDigest: signed.bundleDigest,
          async assertHeld(this: HeldInstalledRuntime): Promise<void> {
            if (this !== selected) mismatch('installed runtime handle receiver is not its held instance');
            return enqueue(checkedRevalidate);
          },
          close(this: HeldInstalledRuntime): Promise<void> {
            if (this !== selected) return Promise.reject(new KernelStorageError('ARTIFACT_MISMATCH', 'installed runtime handle receiver is not its held instance'));
            closed = true;
            guestShutdown.abort();
            observationShutdown.abort();
            return closePromise ??= (async () => {
              // Every preparation already has its actual closeable owner.
              // Cancel before joining producers, without acquiring the
              // credential lock those pending producers may still hold.
              const transportJoins = [...brokerTransports].map(transport => transport.close());
              const guestClosures = [...guestJobs].map(closeGuestToolchain);
              const [transports, guests, observations] = await Promise.all([Promise.allSettled(transportJoins),
                Promise.allSettled(guestClosures), Promise.allSettled([joinObservations()])]);
              await tail;
              const producers = await Promise.allSettled([...platformJobs]);
              const remaining = await Promise.allSettled([...platformJobs]);
              const failed = [...producers, ...transports, ...guests, ...observations, ...remaining].find(result => result.status === 'rejected' &&
                result.reason instanceof ResourceRetirementError);
              if (failed?.status === 'rejected') throw failed.reason;
              if (brokerTransports.size !== 0) {
                const failure = new ResourceRetirementError('installed model transports did not all retire', undefined);
                rememberRetirement(failure); throw failure;
              }
              if (guestJobs.size !== 0) {
                const failure = new ResourceRetirementError('installed guest extractors did not all retire', undefined);
                rememberRetirement(failure); throw failure;
              }
              await scope.close();
            })();
          },
        });
        heldInstalledRuntimes.set(selected, {
          factory: runtime,
          observe(signal) {
            if (closed) mismatch('installed runtime handle is closed');
            const combined = signal ? AbortSignal.any([signal, observationShutdown.signal]) : observationShutdown.signal;
            // Register before starting any work: even reentrant shutdown from
            // a trusted diagnostic subscriber must join this exact operation.
            const pending = Promise.resolve().then(async () => {
              await checkedRevalidate(combined);
              return immutableSnapshot({ bundleDigest: signed.bundleDigest,
                manifestDigest: signed.bundle.manifestDigest, bundleVersion: signed.bundle.bundleVersion,
                stateRoot: { ...identity(state), canonicalPath: stateRoot }, casRoot: identity(casRoot) });
            }).catch(error => {
              if (error instanceof ResourceRetirementError) observationRetirement ??= error;
              throw error;
            });
            observationJobs.add(pending);
            void pending.finally(() => observationJobs.delete(pending)).catch(() => undefined);
            return pending;
          },
          assertManagerObservationAvailable() {
            if (closed) mismatch('installed runtime handle is closed');
            assertSelection();
          },
          credentialScope(operation) {
            return enqueue(async () => {
              if (!isMainThread || !isSea() || process.versions.node !== '24.21.0')
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'credential authority requires the fixed signed installed backend');
              const native = await loadSelectedNative();
              const processImage = await native.observeCurrentProcess();
              const image = signed.entries.get(STATE_OWNER_NATIVE_ENTRY_ID)!;
              const rootIdentity = stateRootIdentityFromDescriptor(stateRoot, {
                deviceId: state.info.dev.toString(), fileId: state.info.ino.toString(), ownerUid: Number(state.info.uid),
              });
              if (processImage.pid !== process.pid || processImage.processStartToken !== native.processStartToken() ||
                  processImage.uid !== rootIdentity.ownerUid || BigInt(processImage.uid) !== effectiveUid() ||
                  processImage.executableImageDigest !== supervisor.digest)
                mismatch('credential authority process differs from its signed same-user selection');
              const now = encodeCanonicalTime(Date.now());
              const processIdentity: PlatformProcessIdentityV1 = {
                schemaVersion: 1, format: 'cliq-platform-process-identity-v1', platform: 'linux',
                pid: processImage.pid, processStartToken: processImage.processStartToken, ownerUid: processImage.uid,
                executableImageDigest: processImage.executableImageDigest, observedAt: now, identityDigest: '',
              };
              processIdentity.identityDigest = digestOmitting(processIdentity, 'identityDigest');
              const ownerPrincipalId = identityHash('cliq-local-principal-v1', rootIdentity.identityDigest, 'linux', processImage.uid);
              const principalIdentity: LocalPrincipalIdentityV1 = {
                schemaVersion: 1, format: 'cliq-local-principal-identity-v1', platform: 'linux',
                stateRootIdentityRef: canonicalSha256(rootIdentity), stateRootIdentityDigest: rootIdentity.identityDigest,
                effectiveUid: processImage.uid, principalId: ownerPrincipalId, identityDigest: '',
              };
              principalIdentity.identityDigest = digestOmitting(principalIdentity, 'identityDigest');
              const channelIdentity: LocalControlChannelIdentityV1 = {
                schemaVersion: 1, format: 'cliq-local-control-channel-identity-v1', client: 'cli',
                principalIdentityRef: canonicalSha256(principalIdentity), principalIdentityDigest: principalIdentity.identityDigest,
                principalId: ownerPrincipalId, transport: { kind: 'in_process',
                  processIdentityRef: canonicalSha256(processIdentity), processIdentityDigest: processIdentity.identityDigest },
                openedAt: now, channelNonceDigest: sha256Bytes(randomBytes(32)), channelIdentityDigest: '',
              };
              channelIdentity.channelIdentityDigest = digestOmitting(channelIdentity, 'channelIdentityDigest');
              decodeStateRootIdentity(rootIdentity); decodePlatformProcessIdentity(processIdentity);
              decodeLocalPrincipalIdentity(principalIdentity); decodeControlChannel(channelIdentity);
              const trust = signed.bundle.entries.find(entry => entry.entryId === 'default_https_trust_store');
              const trustBytes = trust && signed.roots.get(trust.digest);
              if (!trust || trust.role !== 'trust_store' || trust.executable || !trustBytes)
                mismatch('credential authority requires the fixed signed default HTTPS trust store');
              // Retain only this private authentication/TLS closure. Ordinary
              // reads do not publish it; the business transaction decides that.
              const objects = new Map<string, Buffer>([[signed.bundleDigest, signed.manifestBytes], [trust.digest, trustBytes]]);
              // The current genuine package's fixed schema/conversion data can
              // audit old credential provenance. It does not transfer those
              // old endpoint/TLS bindings to productive current operations.
              for (const entry of kernelSchemaEntries(signed.bundle)) {
                const bytes = signed.roots.get(entry.digest);
                if (!bytes || bytes.length !== entry.byteCount || sha256Bytes(bytes) !== entry.digest)
                  mismatch('credential history schema source is missing or changed');
                objects.set(entry.digest, bytes);
              }
              for (const identity of [rootIdentity, processIdentity, principalIdentity, channelIdentity]) {
                const bytes = canonicalJsonBytes(identity);
                objects.set(sha256Bytes(bytes), bytes);
              }
              return withHeldCredentialNativeScope(native, {
                image: image.handle, root: state.handle, rootIdentity: state.info, stateRoot,
              }, async credential => {
                await checkedRevalidate(); credential.assertHeld();
                const physical: InstalledCredentialScope = Object.freeze({ assertHeld() {
                  if (this !== physical) throw new TypeError('invalid installed credential physical scope receiver');
                  assertInstalledCredentialScope(physical);
                } });
                const binding: CredentialPhysicalBinding = { native, scope: credential, assertSelection, pid: process.pid,
                  processStartToken: native.processStartToken(), generation: credential.generation, active: true,
                  provenance: Object.freeze({ selected, ownerPrincipalId, rootIdentity, processIdentity,
                    principalIdentity, channelIdentity, objects, releaseKeys }) };
                credentialPhysicalScopes.set(physical, binding);
                try {
                  const result = await runInstalledCredentialAuthority(physical, operation);
                  await checkedRevalidate(); credential.assertHeld();
                  return result;
                } finally { binding.active = false; }
              });
            }).catch(error => { rememberRetirement(error); throw error; });
          },
          loadWorkerNative(signal) {
            return enqueue(async () => {
              await checkedRevalidate(signal);
              if (!workerNative) {
                const entry = signed.bundle.entries.find(value => value.entryId === 'linux_worker_native');
                const file = signed.entries.get('linux_worker_native');
                if (!entry || !file || entry.role !== 'platform_helper' || !entry.executable)
                  mismatch('signed worker native module is missing');
                const loaded = new Module('cliq-installed-linux-worker-native');
                process.dlopen(loaded, `/proc/self/fd/${file.handle.fd}`);
                const native = loaded.exports as NativeWorkerBinding;
                if (native.interfaceVersion !== 3 || typeof native.sealImage !== 'function' ||
                    typeof native.sealImageBuffer !== 'function' || typeof native.openController !== 'function')
                  mismatch('unsupported installed native worker interface');
                workerNative = native;
              }
              await checkedRevalidate(signal);
              return workerNative;
            });
          },
          loadCredentialPlatform(signal) {
            return enqueue(async () => {
              if (!isMainThread || !isSea() || process.platform !== 'linux' || process.arch !== 'x64' || process.versions.node !== '24.21.0')
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'credential platform requires the fixed signed Linux backend');
              await checkedRevalidate(signal);
              if (!credentialPlatform) {
                const native = loadCredentialPlatformNative();
                const refused = refusePlatformOperation, track = trackPlatformOperation;
                const invoke = <T>(operation: () => Promise<T>): Promise<T> => {
                  if (closed) mismatch('installed runtime handle is closed');
                  assertSelection();
                  return track(Promise.resolve().then(operation));
                };
                const secretService = ((input: NativeSecretServiceInput): Promise<unknown> => {
                  if (input.kind !== 'inspect') return invoke(() => input.kind === 'create_compare'
                    ? observeInstalledWork('create_compare', () => native.secretService(input))
                    : native.secretService(input));
                  if (closed) mismatch('installed runtime handle is closed');
                  assertSelection();
                  let original: NativeCredentialInspection;
                  try { original = native.secretService(input); }
                  catch (error) { return refused(error); }
                  // Publish the actual owner synchronously, before a caller can
                  // request shutdown. A .then alone would discard cancellation.
                  const result = track(original) as NativeCredentialInspection;
                  if (typeof original.cancelAndJoin !== 'function') {
                    const failure = new ResourceRetirementError('credential inspection lacks its original native cancellation owner', undefined);
                    rememberRetirement(failure); throw failure;
                  }
                  let joining: Promise<void> | undefined;
                  Object.defineProperty(result, 'cancelAndJoin', { value: function (this: NativeCredentialInspection, ...args: unknown[]) {
                    if (this !== result || args.length) throw new TypeError('credential inspection cancellation requires its original owner and no fields');
                    if (joining) return joining;
                    const failedJoin = (error: unknown): never => {
                      const failure = error instanceof ResourceRetirementError ? error
                        : new ResourceRetirementError('credential inspection cancellation did not retire', error);
                      rememberRetirement(failure); throw failure;
                    };
                    let nativeJoin: Promise<void>;
                    try { nativeJoin = original.cancelAndJoin(); }
                    catch (error) { nativeJoin = Promise.reject(error); }
                    joining = nativeJoin.then(() => result.then(() => undefined, error => {
                      // Ordinary observation refusal is not a failed physical
                      // join. Retirement uncertainty always remains sticky.
                      if (error instanceof ResourceRetirementError) throw error;
                    }), failedJoin);
                    platformJobs.add(joining);
                    void joining.finally(() => platformJobs.delete(joining!)).catch(() => {});
                    return joining;
                  } });
                  return result;
                }) as NativeCredentialPlatformBinding['secretService'];
                credentialPlatform = Object.freeze({ interfaceVersion: 2 as const,
                  secretService,
                  userManager: input => invoke(() => native.userManager(input)),
                  currentUser: () => {
                    assertSelection();
                    try { const user = native.currentUser(); assertSelection(); return user; }
                    catch (error) {
                      if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
                        const failure = new ResourceRetirementError('credential platform resources did not retire', error);
                        rememberRetirement(failure); throw failure;
                      }
                      throw error;
                    }
                  } });
              }
              await checkedRevalidate(signal);
              return credentialPlatform;
            });
          },
          loadManagerObserver() {
            return enqueue(async () => {
              const [major, minor] = process.versions.node.split('.').map(Number);
              if (!isMainThread || process.platform !== 'linux' || process.arch !== 'x64' ||
                  !(major > 22 || (major === 22 && minor >= 13)))
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed manager observation requires Linux x64 and Node >=22.13');
              await checkedRevalidate();
              const native = loadCredentialPlatformNative();
              if (!managerObserver) {
                const root = stateRootIdentityFromDescriptor(stateRoot, identity(state));
                const units = new Set([`cliq-${root.identityDigest}-keeper.service`, `cliq-${root.identityDigest}-supervisor.service`]);
                const assertObserver = (receiver: unknown, extraArguments: number) => {
                  if (receiver !== managerObserver || extraArguments) throw new TypeError('installed manager observation requires its original receiver and exact fields');
                  if (closed) mismatch('installed runtime handle is closed');
                  if (credentialScopeReserved) throw new CredentialScopeBusyError();
                  healthy(); assertSelection();
                };
                managerObserver = Object.freeze({
                  currentUser(this: InstalledManagerObserver, ...args: unknown[]) {
                    assertObserver(this, args.length);
                    let user: CredentialPlatformUser;
                    try { user = native.currentUser(); }
                    catch (error) { return refusePlatformOperation(error); }
                    assertSelection(); return immutableSnapshot(user);
                  },
                  inspect(this: InstalledManagerObserver, unit: string, ...args: unknown[]) {
                    try {
                      assertObserver(this, args.length);
                      // Primitive fixed literals only: objects/accessors,
                      // arbitrary units, reload, start and secret inputs never
                      // reach the actual native manager operation.
                      if (typeof unit !== 'string' || !units.has(unit)) throw new TypeError('installed manager observation requires a fixed selected unit');
                      // The actual job is registered before returning, with
                      // the same metadata checks and physical join as the full
                      // platform. Never enqueue behind its awaiting borrow.
                      return trackPlatformOperation(Promise.resolve().then(() => native.userManager({ kind: 'inspect', unit })));
                    } catch (error) { return Promise.reject(error); }
                  },
                });
              }
              await checkedRevalidate();
              return managerObserver;
            });
          },
          loadDependencyBroker() {
            return enqueue(async () => {
              assertInstalledDependencyBrokerProcess(); await checkedRevalidate();
              if (!dependencyBroker) {
                const entry = signed.bundle.entries.find(value => value.entryId === DEPENDENCY_BROKER_ENTRY_ID);
                const file = signed.entries.get(DEPENDENCY_BROKER_ENTRY_ID);
                if (!entry || !file || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
                    entry.relativePath !== DEPENDENCY_BROKER_RELATIVE_PATH || entry.byteCount < 1 || entry.byteCount > TRUST_BYTES)
                  mismatch('fixed signed dependency registry broker is missing');
                const loaded = new Module('cliq-installed-linux-dependency-broker');
                process.dlopen(loaded, `/proc/self/fd/${file.handle.fd}`);
                const native = loaded.exports as NativeDependencyBrokerBinding;
                if (native.interfaceVersion !== 1 || typeof native.prepareDependencyTransport !== 'function' ||
                    native.maximumOwnerDataBytes !== 67_108_864 || !Number.isSafeInteger(native.descriptorPageStorageBytes) ||
                    native.descriptorPageStorageBytes < 1 || native.descriptorPageStorageBytes > 1_048_576 ||
                    !Number.isSafeInteger(native.fixedOwnerStorageBytes) || native.fixedOwnerStorageBytes < 1 ||
                    native.fixedOwnerStorageBytes > native.maximumOwnerDataBytes)
                  mismatch('unsupported fixed dependency registry broker interface');
                dependencyBroker = Object.freeze({ interfaceVersion: 1 as const, maximumOwnerDataBytes: 67_108_864 as const,
                  descriptorPageStorageBytes: native.descriptorPageStorageBytes, fixedOwnerStorageBytes: native.fixedOwnerStorageBytes,
                  prepareDependencyTransport(configurationBytes, trustStoreBytes) {
                    if (closed) mismatch('installed dependency selection is closed'); assertSelection();
                    if (utilTypes.isProxy(configurationBytes) || !Buffer.isBuffer(configurationBytes) || configurationBytes.length < 1 ||
                        configurationBytes.length > 1_048_576 || utilTypes.isProxy(trustStoreBytes) || !Buffer.isBuffer(trustStoreBytes) ||
                        trustStoreBytes.length < 1 || trustStoreBytes.length > 16_777_216)
                      mismatch('dependency native configuration and signed trust root must be bounded original buffers');
                    const configuration = Buffer.from(configurationBytes), trust = Buffer.from(trustStoreBytes);
                    let original: NativeDependencyTransport;
                    try { original = native.prepareDependencyTransport(configuration, trust); }
                    catch (error) {
                      const code = utilTypes.isNativeError(error) && !utilTypes.isProxy(error) ? Object.getOwnPropertyDescriptor(error, 'code') : undefined;
                      if (code && 'value' in code && code.value === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
                        const failure = new ResourceRetirementError('dependency broker construction did not retire', undefined);
                        rememberRetirement(failure); throw failure;
                      }
                      throw new KernelStorageError('RECOVERY_REQUIRED', 'installed dependency broker refused construction');
                    }
                    let transport!: NativeDependencyTransport;
                    let joining: Promise<Awaited<ReturnType<typeof original.close>>> | undefined;
                    let fenceRetained = false, resourcesJoined = false;
                    const fences = new Set<NativeDependencySettlementFence>();
                    const current = () => { if (closed) mismatch('installed dependency selection is closed'); assertSelection(); };
                    const binding = { original, selected, configurationDigest: sha256Bytes(configuration), closed: false, assertCurrent: current } as
                      NonNullable<ReturnType<typeof installedDependencyTransports.get>>;
                    const fail = (error: unknown, retiring: boolean): never => {
                      let retirement = retiring;
                      try { retirement ||= original.observeFailure(error).brokerCode === 'resource_retirement'; } catch { /* No plain-error provenance. */ }
                      if (retirement) {
                        const failure = error instanceof ResourceRetirementError ? error : new ResourceRetirementError('dependency broker resources did not actually join', undefined);
                        rememberRetirement(failure); throw failure;
                      }
                      // Preserve only the native purpose-tagged Error itself.
                      // Its fixed observation is decoded by this exact owner.
                      try { original.observeFailure(error); } catch {
                        throw new KernelStorageError('RECOVERY_REQUIRED', 'installed dependency broker refused an operation');
                      }
                      throw error;
                    };
                    const sync = <T>(operation: () => T, retiring = false): T => {
                      if (!retiring) current();
                      try { return operation(); } catch (error) { return fail(error, retiring); }
                    };
                    const invoke = <T>(operation: () => Promise<T>, retiring = false): Promise<T> => {
                      if (!retiring) current();
                      let pending: Promise<T>;
                      try { pending = operation(); } catch (error) { pending = Promise.reject(error); }
                      const job = pending.then(value => { if (!retiring) current(); return value; }, error => fail(error, retiring));
                      platformJobs.add(job); void job.finally(() => platformJobs.delete(job)).catch(() => {}); return job;
                    };
                    // Observe immediately: a rejected synchronous page followed
                    // by close must not leave an unhandled unsealed-ready task.
                    const prepared = original.ready.then(() => { current(); assertArtifactRef(original.brokerFenceTokenDigest); }, error => fail(error, false));
                    const ready = prepared.catch(async error => { await transport.close(); throw error; });
                    transport = Object.freeze({ brokerFenceTokenDigest: original.brokerFenceTokenDigest, ready,
                      registerPackagePage: bytes => sync(() => original.registerPackagePage(bytes)),
                      sealPackagePlan: () => sync(() => original.sealPackagePlan()),
                      retainDispatchFence() { sync(() => original.retainDispatchFence()); fenceRetained = true; },
                      bindInvocation(bytes) {
                        sync(() => original.bindInvocation(bytes));
                        binding.bindingDigest = sha256Bytes(bytes);
                      },
                      connect: (bytes, index, attempt) => invoke(() => original.connect(bytes, index, attempt)),
                      releaseGet: (bytes, index, attempt) => invoke(() => original.releaseGet(bytes, index, attempt)),
                      observeFailure: error => original.observeFailure(error),
                      sealPackageInputs: bytes => invoke(() => original.sealPackageInputs(bytes)),
                      releaseProcess: bytes => sync(() => original.releaseProcess(bytes)),
                      acquireSettlementFence(bytes) {
                        const originalFence = sync(() => original.acquireSettlementFence(bytes));
                        let fence!: NativeDependencySettlementFence;
                        const held = { original: originalFence, selected, bindingDigest: sha256Bytes(bytes), active: true, assertCurrent: () => assertSelection() };
                        fence = Object.freeze({ ...originalFence,
                          assertCurrent() {
                            const fixed = installedDependencySettlements.get(fence);
                            if (!fixed?.active) mismatch('dependency settlement is no longer held');
                            fixed.assertCurrent(); sync(() => fixed.original.assertCurrent(), true);
                          },
                          close() {
                            if (!held.active) return;
                            sync(() => originalFence.close(), true); held.active = false; fences.delete(fence);
                          },
                        });
                        installedDependencySettlements.set(fence, held); fences.add(fence); return fence;
                      },
                      beginAcknowledgeProcessResult: bytes => sync(() => original.beginAcknowledgeProcessResult(bytes), true),
                      pollProcessResultAcknowledged: () => sync(() => original.pollProcessResultAcknowledged(), true),
                      releaseDispatchFence() {
                        if (fences.size) {
                          const failure = new ResourceRetirementError('dependency settlement mutex still has its original borrower', undefined);
                          rememberRetirement(failure); throw failure;
                        }
                        sync(() => original.releaseDispatchFence(), true); fenceRetained = false;
                        if (resourcesJoined) brokerTransports.delete(transport);
                      },
                      close: () => joining ??= invoke(async () => {
                        binding.closed = true;
                        const value = await original.close();
                        const booleans = ['networkStarted', 'requestStarted', 'processClaimed', 'processJoined', 'processResultAcknowledged',
                          'processResultCustodyRetired', 'dispatchFenceRetained', 'settlementFenceBorrowed'] as const;
                        if (!exactKeys(value, ['kind', 'brokerFenceTokenDigest', 'tokenRevoked', ...booleans, 'connectionCount', 'requestCount',
                          'transferredBytes', 'processResultCustodyOrigin']) || value.kind !== 'dependency_transport_closed' ||
                            value.brokerFenceTokenDigest !== original.brokerFenceTokenDigest || value.tokenRevoked !== true ||
                            booleans.some(key => typeof value[key] !== 'boolean') ||
                            ['connectionCount', 'requestCount', 'transferredBytes'].some(key => !Number.isSafeInteger(value[key as 'connectionCount']) || value[key as 'connectionCount'] < 0) ||
                            value.connectionCount > 600_000 || value.requestCount > value.connectionCount || value.transferredBytes > 20 * 1_073_741_824 ||
                            !['none', 'acknowledged', 'controller_joined'].includes(value.processResultCustodyOrigin) ||
                            value.processClaimed && (!value.processJoined || !value.processResultCustodyRetired) ||
                            value.processResultAcknowledged !== (value.processResultCustodyOrigin === 'acknowledged') ||
                            value.processResultCustodyRetired !== (value.processResultCustodyOrigin !== 'none') ||
                            value.dispatchFenceRetained !== fenceRetained || value.settlementFenceBorrowed !== (fences.size !== 0))
                          throw new ResourceRetirementError('dependency broker closure lacks its complete original joins', undefined);
                        binding.closure = immutableSnapshot(value);
                        resourcesJoined = true; if (!fenceRetained) brokerTransports.delete(transport); return value;
                      }, true),
                    });
                    installedDependencyTransports.set(transport, binding); brokerTransports.add(transport);
                    platformJobs.add(ready); void ready.finally(() => platformJobs.delete(ready)).catch(() => {});
                    return transport;
                  },
                });
              }
              await checkedRevalidate(); return dependencyBroker;
            });
          },
          loadModelBroker() {
            return enqueue(async () => {
              assertInstalledModelBrokerProcess();
              await checkedRevalidate();
              if (!modelBroker) {
                const entry = signed.bundle.entries.find(value => value.entryId === MODEL_BROKER_ENTRY_ID);
                const file = signed.entries.get(MODEL_BROKER_ENTRY_ID);
                if (!entry || !file || entry.role !== 'provider_adapter' || !entry.executable || entry.version !== '1' ||
                    entry.relativePath !== MODEL_BROKER_RELATIVE_PATH)
                  mismatch('fixed signed model broker adapter is missing');
                const loaded = new Module('cliq-installed-linux-model-broker');
                process.dlopen(loaded, `/proc/self/fd/${file.handle.fd}`);
                const native = loaded.exports as NativeModelBrokerBinding;
                if (native.interfaceVersion !== 3 || typeof native.prepareModelTransport !== 'function')
                  mismatch('unsupported installed model broker interface');
                const refused = (error: unknown): never => {
                  if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
                    const failure = new ResourceRetirementError('model broker resources did not retire', undefined);
                    rememberRetirement(failure); throw failure;
                  }
                  if ((error as { code?: unknown; brokerCode?: unknown } | null)?.code === 'ERR_CLIQ_MODEL_BROKER' &&
                      (error as { brokerCode?: unknown }).brokerCode === 'broker_response_refused') throw new InstalledModelBrokerRefusalError();
                  throw new KernelStorageError('RECOVERY_REQUIRED', 'installed model broker refused an operation');
                };
                const invoke = <T>(operation: () => Promise<T>, retiring = false): Promise<T> => {
                  if (closed && !retiring) mismatch('installed runtime handle is closed');
                  if (!retiring) assertSelection();
                  // Enter the native queue synchronously after the caller's
                  // final SQL cut; do not insert a microtask before release.
                  let pending: Promise<T>;
                  try { pending = operation(); }
                  catch (error) { pending = Promise.reject(error); }
                  const job = pending.then(result => {
                    if (!retiring) assertSelection(); return result;
                  }, refused);
                  platformJobs.add(job);
                  void job.finally(() => platformJobs.delete(job)).catch(() => {});
                  return job;
                };
                modelBroker = Object.freeze({ interfaceVersion: 3 as const,
                  prepareModelTransport(input) {
                    if (closed) mismatch('installed runtime handle is closed');
                    assertSelection();
                    let original: NativeModelTransport;
                    try { original = native.prepareModelTransport(input); }
                    catch (error) { return refused(error); }
                    let transport!: NativeModelTransport;
                    let retirement: Promise<Awaited<ReturnType<typeof original.close>>> | undefined;
                    let fenceRetained = false, resourcesJoined = false;
                    const fences = new Set<NativeModelNoReleaseFence>();
                    // Promise handlers run only after this synchronous call
                    // has registered the owner below. In particular, no
                    // selection check can strand a newly minted native owner.
                    const prepared = original.ready.then(undefined, refused).then(() => {
                      if (closed) mismatch('installed runtime handle is closed');
                      assertSelection();
                      assertArtifactRef(original.brokerFenceTokenDigest);
                    });
                    const owned = prepared.catch(async error => {
                      // A validation or preparation refusal cannot expose a
                      // free failure before its actual native owner joins.
                      await transport.close();
                      throw error;
                    });
                    transport = Object.freeze({
                      brokerFenceTokenDigest: original.brokerFenceTokenDigest, ready: owned,
                      retainDispatchFence() {
                        if (closed) mismatch('installed runtime handle is closed'); assertSelection();
                        try { original.retainDispatchFence(); fenceRetained = true; }
                        catch (error) { return refused(error); }
                      },
                      acquireNoReleaseFence(binding) {
                        if (!fenceRetained || !resourcesJoined) mismatch('installed model no-release fence lacks its original joined resource owner');
                        binding = immutableSnapshot(binding);
                        let nativeFence: NativeModelNoReleaseFence;
                        try { nativeFence = original.acquireNoReleaseFence(binding); }
                        catch (error) { return refused(error); }
                        let fence!: NativeModelNoReleaseFence;
                        const held = { native: nativeFence, bindingDigest: canonicalSha256(binding), active: true, processId: process.pid,
                          selected, bundleDigest: signed.bundleDigest, manifestDigest: signed.bundle.manifestDigest, assertSelection };
                        fence = Object.freeze({
                          assertHeld() { assertInstalledModelNoReleaseFence(fence, binding); },
                          close() {
                            if (!held.active) return;
                            try { nativeFence.close(); }
                            catch (error) {
                              const failure = new ResourceRetirementError('model no-release mutex owner did not retire', error);
                              rememberRetirement(failure); throw failure;
                            }
                            held.active = false; fences.delete(fence);
                          },
                        });
                        installedModelNoReleaseFences.set(fence, held); fences.add(fence); return fence;
                      },
                      releaseDispatchFence() {
                        if (fences.size) {
                          const failure = new ResourceRetirementError('model no-release mutex still has an owning guard', undefined);
                          rememberRetirement(failure); throw failure;
                        }
                        try { original.releaseDispatchFence(); }
                        catch (error) { return refused(error); }
                        fenceRetained = false;
                        if (resourcesJoined) brokerTransports.delete(transport);
                      },
                      connect: binding => invoke(() => original.connect(binding)),
                      releaseBody: binding => invoke(() => original.releaseBody(binding)),
                      close: () => retirement ??= invoke(async () => {
                        const result = await original.close();
                        if (!exactKeys(result, ['kind', 'brokerFenceTokenDigest', 'bodyBytesDigest', 'networkStarted', 'requestStarted',
                          'tokenRevoked', 'matchingActiveReleaseCount']) || result.kind !== 'broker_transport_closed' ||
                            result.brokerFenceTokenDigest !== original.brokerFenceTokenDigest || result.bodyBytesDigest !== input.bodyBytesDigest ||
                            typeof result.networkStarted !== 'boolean' || typeof result.requestStarted !== 'boolean' ||
                            result.tokenRevoked !== true || result.matchingActiveReleaseCount !== 0) {
                          const failure = new ResourceRetirementError('model broker closure is incomplete', undefined);
                          rememberRetirement(failure); throw failure;
                        }
                        resourcesJoined = true;
                        if (!fenceRetained) brokerTransports.delete(transport); return result;
                      }, true),
                    });
                    brokerTransports.add(transport);
                    platformJobs.add(owned);
                    void owned.finally(() => platformJobs.delete(owned)).catch(() => {});
                    return transport;
                  },
                });
              }
              await checkedRevalidate(); return modelBroker;
            });
          },
          openControlClient() {
            return enqueue(async () => {
              const native = await loadSelectedNative();
              const image = signed.entries.get(supervisor.entryId)!;
              const client = openHeldInstalledControlClient(native, { root: state.handle, rootIdentity: state.info,
                stateRoot, image: image.handle, imageIdentity: image.info });
              try { await checkedRevalidate(); client.assertHeld(); return client; }
              catch (error) {
                try { client.close(); } catch (failure) {
                  const retirement = new ResourceRetirementError('installed control client did not retire', new AggregateError([error, failure]));
                  rememberRetirement(retirement); throw retirement;
                }
                throw error;
              }
            });
          },
          sealWorkerImage(entryId) {
            return enqueue(async () => {
              await checkedRevalidate();
              const roles: Record<string, string> = { linux_worker_controller: 'platform_helper',
                linux_bubblewrap: 'platform_helper', linux_worker: 'worker', edit: 'tool_adapter' };
              const entry = signed.bundle.entries.find(value => value.entryId === entryId);
              const file = signed.entries.get(entryId);
              if (!workerNative || !Object.hasOwn(roles, entryId) || !entry || !file ||
                  entry.role !== roles[entryId] || !entry.executable)
                mismatch('executable is not in the signed installed worker recipe');
              const sealed = workerNative.sealImage(file.handle.fd);
              try { await checkedRevalidate(); return sealed; }
              catch (error) {
                try { sealed.close(); }
                catch (failure) {
                  const retirement = new ResourceRetirementError('installed worker image did not retire',
                    new AggregateError([error, failure]));
                  rememberRetirement(retirement); throw retirement;
                }
                throw error;
              }
            });
          },
          retainSourceGitRecipe(signal) {
            return enqueue(async () => {
              await checkedRevalidate(signal);
              const cas = new ContentAddressedStore(childPath(casRoot, '.'));
              for (const entryId of ['source_git_inspector', 'linux_worker_controller']) {
                const entry = signed.bundle.entries.find(value => value.entryId === entryId), file = signed.entries.get(entryId);
                const inspector = entryId === 'source_git_inspector';
                if (!entry || !file || entry.role !== 'platform_helper' || entry.byteCount < 1 ||
                    (inspector ? entry.version !== '1' || entry.executable !== false ||
                      entry.relativePath !== 'helpers/source-git-inspector.mjs' || entry.byteCount > SMALL_BYTES
                      : !entry.executable || entry.byteCount > TRUST_BYTES))
                  mismatch('source recipe retention requires its exact supported signed members');
                signal?.throwIfAborted(); assertSelection();
                const published = await cas.publishChunks(artifactChunks(file, signal), entry.byteCount);
                if (published.ref !== entry.digest || published.byteLength !== entry.byteCount)
                  mismatch('retained source recipe differs from its original installed bytes');
                signal?.throwIfAborted(); assertSelection();
              }
              await checkedRevalidate(signal);
            });
          },
          sealSourceGitInspector(signal) {
            return enqueue(async () => {
              await checkedRevalidate(signal);
              const entry = signed.bundle.entries.find(value => value.entryId === 'source_git_inspector');
              const file = signed.entries.get('source_git_inspector');
              if (!workerNative || workerNative.sourceInterfaceVersion !== 1 || !entry || !file ||
                  entry.role !== 'platform_helper' || entry.version !== '1' || entry.executable !== false ||
                  entry.relativePath !== 'helpers/source-git-inspector.mjs' || entry.byteCount < 1 || entry.byteCount > 1024 * 1024)
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'the fixed signed source inspector is not installed');
              signal?.throwIfAborted();
              const sealed = workerNative.sealSourceGitInspector(file.handle.fd);
              try {
                if (sealed.identity.sha256 !== entry.digest || sealed.identity.byteCount !== entry.byteCount)
                  mismatch('sealed source inspector differs from its exact signed bytes');
                await checkedRevalidate(signal); return sealed;
              }
              catch (error) {
                try { sealed.close(); }
                catch (failure) {
                  const retirement = new ResourceRetirementError('installed source inspector seal did not retire', new AggregateError([error, failure]));
                  rememberRetirement(retirement); throw retirement;
                }
                throw error;
              }
            });
          },
          sealBuiltinToolScript(signal) {
            return enqueue(async () => {
              await checkedRevalidate(signal);
              const entry = signed.bundle.entries.find(value => value.entryId === BUILTIN_SCRIPT_RECIPE.entryId);
              const file = signed.entries.get(BUILTIN_SCRIPT_RECIPE.entryId);
              if (!workerNative || workerNative.builtinToolInterfaceVersion !== 2 || !entry || !file ||
                  entry.role !== 'tool_adapter' || entry.version !== '1' || entry.executable !== false ||
                  entry.relativePath !== BUILTIN_SCRIPT_RECIPE.relativePath || entry.byteCount < 1 || entry.byteCount > 1024 * 1024)
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'the fixed signed builtin tool script is not installed');
              signal?.throwIfAborted();
              const sealed = workerNative.sealBuiltinToolScript(file.handle.fd);
              try {
                if (sealed.identity.sha256 !== entry.digest || sealed.identity.byteCount !== entry.byteCount)
                  mismatch('sealed builtin tool script differs from its exact signed bytes');
                await checkedRevalidate(signal); return sealed;
              }
              catch (error) {
                try { sealed.close(); }
                catch (failure) {
                  const retirement = new ResourceRetirementError('installed builtin tool script seal did not retire', new AggregateError([error, failure]));
                  rememberRetirement(retirement); throw retirement;
                }
                throw error;
              }
            });
          },
          sealDependencyNpmAssets(signal) {
            return enqueue(async () => {
              await checkedRevalidate(signal);
              const scriptEntry = signed.bundle.entries.find(isNpmAdapterEntry), dataEntry = signed.bundle.entries.find(isNpmDataEntry);
              if (!workerNative || workerNative.dependencyInterfaceVersion !== 1 ||
                  typeof workerNative.sealDependencyNpmScript !== 'function' || typeof workerNative.sealDependencyNpmData !== 'function' ||
                  !scriptEntry || !dataEntry)
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'the fixed signed dependency npm assets are not installed');
              const scriptFile = signed.entries.get(scriptEntry.entryId), dataFile = signed.entries.get(dataEntry.entryId);
              if (!scriptFile || !dataFile) mismatch('dependency npm assets are missing from the complete signed closure');
              let script: NativeDependencyNpmScriptImage | undefined, data: NativeDependencyNpmDataImage | undefined;
              try {
                signal?.throwIfAborted();
                script = workerNative.sealDependencyNpmScript(scriptFile.handle.fd);
                if (script.identity.sha256 !== scriptEntry.digest || script.identity.byteCount !== scriptEntry.byteCount)
                  mismatch('dependency adapter seal differs from its complete original signed bytes');
                data = workerNative.sealDependencyNpmData(dataFile.handle.fd);
                if (data.identity.sha256 !== dataEntry.digest || data.identity.byteCount !== dataEntry.byteCount)
                  mismatch('dependency npm data seal differs from its complete original signed bytes');
                await checkedRevalidate(signal);
                return Object.freeze({ script, data });
              } catch (error) {
                const failures: unknown[] = [];
                for (const image of [script, data]) if (image) try { image.close(); } catch (failure) { failures.push(failure); }
                if (failures.length) {
                  const failure = new ResourceRetirementError('dependency npm asset seals did not actually retire', new AggregateError([error, ...failures]));
                  rememberRetirement(failure); throw failure;
                }
                throw error;
              }
            });
          },
          startGuestToolchain(toolchain, options) {
            return enqueue(async () => {
              const signal = options.signal ? AbortSignal.any([options.signal, guestShutdown.signal]) : guestShutdown.signal;
              const current = () => {
                signal.throwIfAborted(); healthy();
                if (closed) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed guest extraction is closing');
                assertSelection();
              };
              current();
              if (!isMainThread || !isSea() || process.arch !== 'x64' || process.versions.node !== '24.21.0')
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'guest extraction requires the fixed signed Linux backend');
              await checkedRevalidate(signal); current();
              const bytes = signed.roots.get(toolchain.manifestRef);
              if (!bytes) mismatch('guest extraction is not in the selected signed closure');
              const manifest = decodeGuestToolchainManifest(checkCanonicalBytes(bytes));
              const signature = signed.roots.get(manifest.signatureRef);
              if (!signature) mismatch('guest extraction has no retained signature');
              const expected = validateGuestToolchainMetadata(signed.bundle, toolchain.manifestRef, bytes, signature, releaseKeys);
              if (canonicalSha256(expected) !== canonicalSha256(toolchain) || manifest.architecture !== 'x86_64' ||
                  manifest.guestImageByteCount > GUEST_EXTRACTOR_RECIPE.maxImageBytes)
                mismatch('guest extraction substitutes the pinned fixed recipe');
              const image = installedStreams.get(manifest.guestImageRef);
              if (!image) mismatch('guest extraction lacks its original imported CAS image');
              if (!guestExtractor) {
                const entry = signed.bundle.entries.find(entry => entry.entryId === GUEST_EXTRACTOR_RECIPE.entryId);
                const file = signed.entries.get(GUEST_EXTRACTOR_RECIPE.entryId);
                if (!entry || !file || entry.role !== 'platform_helper' || !entry.executable || entry.version !== GUEST_EXTRACTOR_RECIPE.version ||
                    entry.relativePath !== GUEST_EXTRACTOR_RECIPE.relativePath || entry.byteCount < 1 || entry.byteCount > TRUST_BYTES)
                  mismatch('fixed signed guest extractor is missing');
                const loaded = new Module('cliq-installed-linux-guest-extractor');
                process.dlopen(loaded, `/proc/self/fd/${file.handle.fd}`);
                const native = loaded.exports as NativeGuestExtractorBinding;
                if (native.interfaceVersion !== 1 || typeof native.begin !== 'function') mismatch('unsupported installed guest extractor interface');
                guestExtractor = native;
              }
              current();
              const job = guestExtractor.begin(image.handle.fd, { imageDigest: manifest.guestImageDigest, imageByteCount: manifest.guestImageByteCount,
                architecture: 'x86_64', nodePath: manifest.node.canonicalGuestPath, nodeDigest: manifest.node.digest,
                pinnedExecutables: guestToolchainExecutables(manifest).map(entry => ({ path: entry.canonicalGuestPath, digest: entry.digest })) });
              // Register immediately after native begin: even post-check failure
              // or Store shutdown must cancel and join this exact original job.
              guestJobs.add(job);
              try {
                current();
                while (!job.pollReady()) { current(); await yieldImmediate(); }
                current();
                const description = job.describe();
                if (description.imageDigest !== manifest.guestImageRef || description.nodePath !== manifest.node.canonicalGuestPath ||
                    description.nodeDigest !== manifest.node.digest || description.files.length < 1 || description.files.length > GUEST_EXTRACTOR_RECIPE.maxMappedFiles)
                  mismatch('native guest extraction differs from the retained manifest');
                await checkedRevalidate(signal); current(); return job;
              } catch (error) { await closeGuestToolchain(job); throw error; }
            });
          },
          startSourceGitToolchain(toolchain, options) {
            return enqueue(async () => {
              const signal = options.signal ? AbortSignal.any([options.signal, guestShutdown.signal]) : guestShutdown.signal;
              const current = () => {
                signal.throwIfAborted(); healthy();
                if (closed) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed source Git extraction is closing');
                assertSelection();
              };
              current();
              if (!isMainThread || !isSea() || process.platform !== 'linux' || process.arch !== 'x64' || process.versions.node !== '24.21.0')
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'source Git extraction requires the fixed signed Linux backend');
              await checkedRevalidate(signal); current();
              const bytes = signed.roots.get(toolchain.manifestRef);
              if (!bytes) mismatch('source Git extraction is not in the selected signed closure');
              const manifest = decodeGuestToolchainManifest(checkCanonicalBytes(bytes));
              const signature = signed.roots.get(manifest.signatureRef);
              if (!signature) mismatch('source Git extraction has no retained signature');
              const expected = validateGuestToolchainMetadata(signed.bundle, toolchain.manifestRef, bytes, signature, releaseKeys);
              if (canonicalSha256(expected) !== canonicalSha256(toolchain) || manifest.architecture !== 'x86_64' ||
                  manifest.node.canonicalGuestPath !== '/usr/bin/node' || manifest.git.canonicalGuestPath !== '/usr/bin/git' ||
                  manifest.guestImageByteCount > GUEST_EXTRACTOR_RECIPE.maxImageBytes)
                mismatch('source Git extraction substitutes the pinned fixed recipe');
              const image = installedStreams.get(manifest.guestImageRef);
              if (!image) mismatch('source Git extraction lacks its original imported CAS image');
              if (!guestExtractor) {
                const entry = signed.bundle.entries.find(value => value.entryId === GUEST_EXTRACTOR_RECIPE.entryId);
                const file = signed.entries.get(GUEST_EXTRACTOR_RECIPE.entryId);
                if (!entry || !file || entry.role !== 'platform_helper' || !entry.executable || entry.version !== GUEST_EXTRACTOR_RECIPE.version ||
                    entry.relativePath !== GUEST_EXTRACTOR_RECIPE.relativePath || entry.byteCount < 1 || entry.byteCount > TRUST_BYTES)
                  mismatch('fixed signed guest extractor is missing');
                const loaded = new Module('cliq-installed-linux-guest-extractor');
                process.dlopen(loaded, `/proc/self/fd/${file.handle.fd}`);
                const native = loaded.exports as NativeGuestExtractorBinding;
                if (native.interfaceVersion !== 1 || typeof native.begin !== 'function') mismatch('unsupported installed guest extractor interface');
                guestExtractor = native;
              }
              if (typeof guestExtractor.beginSourceGit !== 'function')
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'fixed signed source Git extractor is unavailable');
              current();
              const job = guestExtractor.beginSourceGit(image.handle.fd, { imageDigest: manifest.guestImageDigest, imageByteCount: manifest.guestImageByteCount,
                architecture: 'x86_64', nodePath: manifest.node.canonicalGuestPath, nodeDigest: manifest.node.digest,
                pinnedExecutables: guestToolchainExecutables(manifest).map(entry => ({ path: entry.canonicalGuestPath, digest: entry.digest })) });
              guestJobs.add(job);
              try {
                current();
                while (!job.pollReady()) { current(); await yieldImmediate(); }
                current();
                const description = job.describe();
                if (description.imageDigest !== manifest.guestImageRef || description.nodePath !== manifest.node.canonicalGuestPath ||
                    description.nodeDigest !== manifest.node.digest || description.gitPath !== manifest.git.canonicalGuestPath ||
                    description.gitDigest !== manifest.git.digest || description.files.length < 2 || description.files.length > GUEST_EXTRACTOR_RECIPE.maxMappedFiles ||
                    !description.files.some(file => file.path === description.nodePath && file.digest === description.nodeDigest) ||
                    !description.files.some(file => file.path === description.gitPath && file.digest === description.gitDigest))
                  mismatch('native source Git extraction differs from both retained executable roots');
                await checkedRevalidate(signal); current(); return job;
              } catch (error) { await closeGuestToolchain(job); throw error; }
            });
          },
          startBuiltinBashToolchain(toolchain, options) {
            return enqueue(async () => {
              const signal = options.signal ? AbortSignal.any([options.signal, guestShutdown.signal]) : guestShutdown.signal;
              const current = () => {
                signal.throwIfAborted(); healthy();
                if (closed) throw new KernelStorageError('RECOVERY_REQUIRED', 'installed builtin bash extraction is closing');
                assertSelection();
              };
              current();
              if (!isMainThread || !isSea() || process.platform !== 'linux' || process.arch !== 'x64' || process.versions.node !== '24.21.0')
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'builtin bash extraction requires the fixed signed Linux backend');
              await checkedRevalidate(signal); current();
              const bytes = signed.roots.get(toolchain.manifestRef);
              if (!bytes) mismatch('builtin bash extraction is not in the selected signed closure');
              const manifest = decodeGuestToolchainManifest(checkCanonicalBytes(bytes));
              const signature = signed.roots.get(manifest.signatureRef);
              if (!signature) mismatch('builtin bash extraction has no retained signature');
              const expected = validateGuestToolchainMetadata(signed.bundle, toolchain.manifestRef, bytes, signature, releaseKeys);
              if (canonicalSha256(expected) !== canonicalSha256(toolchain) || manifest.architecture !== 'x86_64' ||
                  manifest.node.canonicalGuestPath !== '/usr/bin/node' || manifest.git.canonicalGuestPath !== '/usr/bin/git' ||
                  manifest.guestImageByteCount > GUEST_EXTRACTOR_RECIPE.maxImageBytes)
                mismatch('builtin bash extraction substitutes the pinned fixed recipe');
              const bash = manifest.admittedExecutables.find(entry => entry.logicalName === 'bash');
              if (!bash || bash.canonicalGuestPath !== '/bin/bash' ||
                  manifest.admittedExecutables.filter(entry => entry.logicalName === 'bash').length !== 1)
                mismatch('builtin bash has no exact signed admitted Bash executable');
              const image = installedStreams.get(manifest.guestImageRef);
              if (!image) mismatch('builtin bash extraction lacks its original imported CAS image');
              if (!guestExtractor) {
                const entry = signed.bundle.entries.find(value => value.entryId === GUEST_EXTRACTOR_RECIPE.entryId);
                const file = signed.entries.get(GUEST_EXTRACTOR_RECIPE.entryId);
                if (!entry || !file || entry.role !== 'platform_helper' || !entry.executable || entry.version !== GUEST_EXTRACTOR_RECIPE.version ||
                    entry.relativePath !== GUEST_EXTRACTOR_RECIPE.relativePath || entry.byteCount < 1 || entry.byteCount > TRUST_BYTES)
                  mismatch('fixed signed guest extractor is missing');
                const loaded = new Module('cliq-installed-linux-guest-extractor');
                process.dlopen(loaded, `/proc/self/fd/${file.handle.fd}`);
                const native = loaded.exports as NativeGuestExtractorBinding;
                if (native.interfaceVersion !== 1 || typeof native.begin !== 'function') mismatch('unsupported installed guest extractor interface');
                guestExtractor = native;
              }
              if (typeof guestExtractor.beginBuiltinBash !== 'function')
                throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'fixed signed builtin bash extractor is unavailable');
              current();
              const job = guestExtractor.beginBuiltinBash(image.handle.fd, { imageDigest: manifest.guestImageDigest, imageByteCount: manifest.guestImageByteCount,
                architecture: 'x86_64', nodePath: manifest.node.canonicalGuestPath, nodeDigest: manifest.node.digest,
                pinnedExecutables: guestToolchainExecutables(manifest).map(entry => ({ path: entry.canonicalGuestPath, digest: entry.digest })) });
              guestJobs.add(job);
              try {
                current();
                while (!job.pollReady()) { current(); await yieldImmediate(); }
                current();
                const description = job.describe();
                if (description.imageDigest !== manifest.guestImageRef || description.nodePath !== manifest.node.canonicalGuestPath ||
                    description.nodeDigest !== manifest.node.digest || description.gitPath !== manifest.git.canonicalGuestPath ||
                    description.gitDigest !== manifest.git.digest || description.bashPath !== bash.canonicalGuestPath ||
                    description.bashDigest !== bash.digest || description.files.length < 3 || description.files.length > GUEST_EXTRACTOR_RECIPE.maxMappedFiles ||
                    !description.files.some(file => file.path === description.nodePath && file.digest === description.nodeDigest) ||
                    !description.files.some(file => file.path === description.gitPath && file.digest === description.gitDigest) ||
                    !description.files.some(file => file.path === description.bashPath && file.digest === description.bashDigest))
                  mismatch('native builtin bash extraction differs from both retained executable roots');
                await checkedRevalidate(signal); current(); return job;
              } catch (error) { await closeGuestToolchain(job); throw error; }
            });
          },
          closeGuestToolchain,
          acquireAnchor(): Promise<HeldInstalledAnchor> {
            return enqueue(async () => {
              const native = await loadSelectedNative();
              const file = signed.entries.get(supervisor.entryId)!;
              let ready: InstalledFile;
              try { ready = await scope.file(root, 'keeper.ready', 0o600, 40); }
              catch (error) {
                if (error instanceof ResourceRetirementError) throw error;
                mismatch('installed keeper locator is unavailable', error);
              }
              if (ready.info.gid !== BigInt(process.getegid!())) mismatch('installed keeper locator has a different group');
              const locator = await readSmall(ready);
              ready.digest = sha256Bytes(locator);
              const anchor = acquireHeldInstalledAnchor(native, {
                stateRoot, root: state.info, image: file.info, bundleDigest: signed.bundleDigest,
                relativePath: supervisor.relativePath, locator,
              });
              try {
                await verifyBytes(ready); await checkedRevalidate();
                await scope.retire(ready.handle);
                healthy(); anchor.assertHeld();
                const held: HeldInstalledAnchor = Object.freeze({
                  assertHeld() {
                    if (this !== held) throw new TypeError('invalid installed anchor handle');
                    try { healthy(); anchor.assertHeld(); } catch (error) { rememberRetirement(error); throw error; }
                  },
                  close() {
                    if (this !== held) throw new TypeError('invalid installed anchor handle');
                    try { anchor.close(); } catch (error) { rememberRetirement(error); throw error; }
                  },
                });
                heldInstalledAnchors.set(held, { selected, readBirth() {
                  if (closed || hasPoisoned) mismatch('installed keeper birth lost its original selected lifetime');
                  healthy(); anchor.assertHeld();
                  const birth = Object.freeze({ pid: locator.readUInt32LE(8),
                    processStartToken: `linux-proc-start-ticks:${locator.readBigUInt64LE(16)}`,
                    locatorDigest: sha256Bytes(locator), bootIdentityHex: locator.subarray(24).toString('hex'), observedAt: sampleCanonicalNow(),
                    readyIdentity: upgradeDirectoryIdentity(ready) });
                  anchor.assertHeld(); return birth;
                }, withRoot(operation) {
                  if (closed) mismatch('installed runtime handle is closed');
                  if (hasPoisoned) throw poisoned;
                  try { healthy(); anchor.withRoot(operation); }
                  catch (error) { rememberRetirement(error); throw error; }
                } });
                return held;
              } catch (error) {
                rememberRetirement(error);
                await joinResourceOperations([Promise.reject(error), Promise.resolve().then(() => {
                  try { anchor.close(); } catch (failure) { rememberRetirement(failure); throw failure; }
                })] as const);
                throw error;
              }
            }).catch(error => { rememberRetirement(error); throw error; });
          },
          initializeKeeper(): Promise<HeldInstalledKeeper> {
            return enqueue(async () => {
              const native = await loadSelectedNative();
              const file = signed.entries.get(supervisor.entryId)!;
              const keeper = initializeHeldInstalledKeeper(native, {
                stateRoot, root: state.info, image: file.info, bundleDigest: signed.bundleDigest,
                relativePath: supervisor.relativePath,
              });
              try {
                await checkedRevalidate();
                keeper.assertHeld();
                // Only a private locator for the native-owned original pin;
                // neither these bytes nor the file carry execution authority.
                const locator = keeper.readyLocator();
                if (!Buffer.isBuffer(locator) || locator.length !== 40) mismatch('installed keeper returned an invalid locator');
                const temporary = `.tmp-keeper-${randomBytes(16).toString('hex')}`;
                await writeChunks(scope, root, temporary, bytesSource(locator), 0o600);
                const ready = await scope.file(root, temporary, 0o600, 40, sha256Bytes(locator));
                if (ready.info.gid !== BigInt(process.getegid!())) mismatch('installed keeper locator has a different group');
                await verifyBytes(ready);
                keeper.assertHeld(); await scope.assertDirectories();
                await rename(childPath(root, temporary), childPath(root, 'keeper.ready'));
                // A legitimate rename may change ctime. Keep the original FD
                // and bind all other fields before freezing its new full stat.
                const published = await ready.handle.stat({ bigint: true });
                if (!['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs']
                  .every(key => ready.info[key as keyof BigIntStats] === published[key as keyof BigIntStats]))
                  mismatch('installed keeper locator changed during publication');
                ready.name = 'keeper.ready'; ready.info = published;
                await root.handle.sync(); await scope.assertDirectories();
                await verifyBytes(ready);
                await scope.retire(ready.handle);
                healthy(); keeper.assertHeld();
                const held: HeldInstalledKeeper = Object.freeze({
                  assertHeld() {
                    if (this !== held) throw new TypeError('invalid installed keeper handle');
                    try { healthy(); keeper.assertHeld(); } catch (error) { rememberRetirement(error); throw error; }
                  },
                  close() {
                    if (this !== held) throw new TypeError('invalid installed keeper handle');
                    // Sticky uncertainty revokes new authority, not cleanup.
                    try { keeper.close(); } catch (error) { rememberRetirement(error); throw error; }
                  },
                });
                return held;
              } catch (error) {
                rememberRetirement(error);
                // A minted native resource cannot escape a failed post-init
                // installation check. Join retirement; uncertainty wins.
                await joinResourceOperations([Promise.reject(error), Promise.resolve().then(() => {
                  try { keeper.close(); } catch (failure) { rememberRetirement(failure); throw failure; }
                })] as const);
                throw error;
              }
            }).catch(error => { rememberRetirement(error); throw error; });
          },
          execute(role, command): Promise<never> {
            if (closed) mismatch('installed runtime handle is closed');
            closed = true; // Consume synchronously; join existing borrows first.
            observationShutdown.abort();
            const pending = tail.then(async (): Promise<never> => {
              let image: FileHandle | undefined;
              let failure: unknown;
              try {
                await joinObservations();
                const native = await loadSelectedNative();
                const file = signed.entries.get(supervisor.entryId)!;
                // The original FileHandle stays strongly owned by this terminal
                // operation. C borrows it; no numeric-fd ownership handoff.
                image = scope.take(file.handle);
                await scope.close();
                executeHeldInstalledImage(native, image, {
                  stateRoot, root: state.info, bootstrap: bootstrap.info,
                  image: file.info, bundleDigest: signed.bundleDigest,
                  relativePath: supervisor.relativePath, role, command,
                });
              } catch (error) { rememberRetirement(error); failure = error; }
              const retireImage = async () => {
                const owned = image; image = undefined; // Never retry a numeric fd.
                if (!owned) return;
                try { await owned.close(); }
                catch (cause) {
                  const error = new ResourceRetirementError('installed execution image descriptor did not retire',
                    new AggregateError([failure, cause]));
                  rememberRetirement(error); throw error;
                }
              };
              // Pre-terminal refusal still joins every known descriptor. A
              // retirement failure wins over an ordinary validation error.
              await joinResourceOperations([Promise.reject(failure), scope.close(), retireImage()] as const);
              throw new Error('installed terminal execution unexpectedly returned');
            });
            tail = pending.then(() => undefined, () => undefined);
            closePromise = pending.then(() => undefined, error => {
              if (error instanceof ResourceRetirementError) throw error;
            });
            void closePromise.catch(() => undefined);
            return pending;
          },
          borrow<T>(operation: (installed: InstalledRuntimeBorrow) => Promise<T>, signal?: AbortSignal): Promise<T> {
            return enqueue(async () => {
              await checkedRevalidate(signal);
              let active = true;
              const revalidations: Promise<void>[] = [];
              const installed: InstalledRuntimeBorrow = Object.freeze({
                ...observation,
                revalidate(checkSignal?: AbortSignal): Promise<void> {
                  if (!active) mismatch('installed runtime borrow has ended');
                  const pending = checkedRevalidate(signal && checkSignal ? AbortSignal.any([signal, checkSignal]) : signal ?? checkSignal);
                  revalidations.push(pending);
                  // The borrow owns joining even a caller-unawaited check.
                  void pending.catch(() => undefined);
                  return pending;
                },
                loadStateOwner(loadSignal?: AbortSignal): Promise<NativeStateOwner> {
                  if (!active) mismatch('installed runtime borrow has ended');
                  const pending = loadSelectedNative(signal && loadSignal ? AbortSignal.any([signal, loadSignal]) : signal ?? loadSignal);
                  // The borrow owns joining even an unawaited loader. Its sole
                  // file-owning Scope cannot close before this operation ends.
                  const joined = pending.then(() => undefined);
                  revalidations.push(joined);
                  void joined.catch(() => undefined);
                  return pending;
                },
              });
              const result = Promise.resolve().then(() => operation(installed));
              await result.then(() => undefined, () => undefined);
              active = false;
              // Join every check, preserving retirement uncertainty over an
              // ordinary callback or validation error.
              return (await joinResourceOperations([result, ...revalidations] as const))[0];
            });
          },
        });
        return selected;
      } catch (error) {
        rememberRetirement(error); await scope.close(); throw error;
      }
    },
  });
  installedRuntimeTrust.set(runtime, releaseKeys);
  return runtime;
}

/** The private stage owns actual directories/files, not a structural package
 * description. It is never an installed execution or StateOwner capability. */
export type HeldInstalledRuntimeUpgrade = Readonly<{ close(): Promise<void> }>;
type UpgradeCredentialLifetime = Readonly<{ assertHeld(): void;
  observeProducerLifetime(pid: number, ownerUid: number, processStartToken: string): 'present' | 'dead' }>;
export type InstalledUpgradeTransaction = Readonly<{
  stateRoot: string; bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[];
  native: NativeStateOwner; seed: readonly PublishedArtifact[]; source: InstalledUpgradeSourceV1;
  supervisorBirth: PlatformProcessIdentityV1;
  supervisorOwner: StateOwnerRecordV1;
  /** Fixed inert conversion boundary, never a decision or physical witness. */
  notePhase?(phase: InstalledRuntimeUpgradePhase): void;
  assertCurrent(): Promise<void>;
  assertCommit(): void;
  assertOldProcessesDead(): void;
  prepareSelection(receiptRef: string): Promise<void>;
  publishSelection(receiptRef: string, receipt: RuntimeUpgradeReceiptV1): Promise<void>;
}>;
type InstalledUpgradeBinding = {
  prepared: InstalledUpgradeTransaction;
  run<T>(operation: () => Promise<T>): Promise<T>;
  publish(receiptRef: string, receipt: RuntimeUpgradeReceiptV1): Promise<void>;
  stop(): Promise<void>;
  active(): boolean;
  notePhase?(phase: InstalledRuntimeUpgradePhase): void;
};
const installedUpgradeStages = new WeakMap<HeldInstalledRuntimeUpgrade, InstalledUpgradeBinding>();
// An uncertain native pager/inspection retirement keeps its original source
// descriptors strongly reachable until process exit. A WeakMap cycle alone
// would allow FileHandle finalizers to close them beneath that owner.
const unretiredInstalledUpgradeStages = new Set<HeldInstalledRuntimeUpgrade>();
/** Internal friend: a cloned/foreign/closed stage cannot supply physical proof.
 * This is available only inside the owning upgrade transaction's real scope. */
export function readHeldInstalledUpgradeTransaction(stage: HeldInstalledRuntimeUpgrade): InstalledUpgradeTransaction {
  const binding = installedUpgradeStages.get(stage);
  if (!binding || !binding.active()) mismatch('upgrade requires its genuine active prepared stage and credential exclusion');
  return binding.prepared;
}

function upgradeDirectoryIdentity(directory: { info: BigIntStats }): InstalledUpgradeIdentityV1 {
  return { deviceId: String(directory.info.dev), fileId: String(directory.info.ino), ownerUid: Number(directory.info.uid),
    ownerGid: Number(directory.info.gid), mode: Number(directory.info.mode & 0o7777n) };
}

/** Preparation is inert: original selection/version remain authoritative. The
 * original live keeper is authenticated before any death source is captured. */
export async function stageInstalledRuntimeUpgrade(selected: HeldInstalledRuntime, packageRoot: string,
  signal?: AbortSignal, observePhase?: (phase: InstalledRuntimeUpgradePhase) => void): Promise<HeldInstalledRuntimeUpgrade> {
  if (!heldInstalledRuntimes.has(selected)) mismatch('upgrade needs the genuinely selected original installation');
  signal?.throwIfAborted();
  noteUpgradePhase(observePhase, 'stage_original');
  const scope = new Scope(), sourceScope = new Scope();
  let keeperCheck: NativeInstalledUpgradeKeeperCheck | undefined;
  try {
    return await withHeldInstalledRuntime(selected, async original => {
      signal?.throwIfAborted();
      const stateRoot = original.stateRoot.canonicalPath, state = await scope.root(stateRoot), runtime = await scope.directory(state, 'runtime');
      if (String(state.info.dev) !== original.stateRoot.deviceId || String(state.info.ino) !== original.stateRoot.fileId)
        mismatch('upgrade StateRoot differs from the original selection');
      const bundles = await scope.directory(runtime, 'bundles'), casRoot = await scope.directory(state, KERNEL_CAS_DIRECTORY);
      if (bundles.info.dev !== runtime.info.dev) mismatch('upgrade requires its original bundle publication filesystem');
      const oldVersion = await scope.directory(bundles, original.bundleDigest);
      const oldSigned = await verifyPackage(scope, oldVersion, original.releaseKeys, original.bundleDigest, false, signal, casRoot);
      const oldActive = await scope.file(runtime, 'active.json', 0o600), oldActiveBytes = await readSmall(oldActive);
      oldActive.digest = sha256Bytes(oldActiveBytes);
      const oldSupervisor = oldSigned.bundle.entries.find(entry => entry.role === 'supervisor')!;
      const oldBootstrap = await scope.file(runtime, 'bootstrap', 0o500, oldSupervisor.byteCount, oldSupervisor.digest);
      const oldKeeperReady = await scope.file(runtime, 'keeper.ready', 0o600, 40);
      const keeperLocator = await readSmall(oldKeeperReady); oldKeeperReady.digest = sha256Bytes(keeperLocator);
      if ([oldActive, oldBootstrap, oldKeeperReady].some(file => file.info.dev !== runtime.info.dev))
        mismatch('upgrade requires its original runtime publication filesystem');
      if (oldKeeperReady.info.gid !== state.info.gid) mismatch('upgrade original keeper locator has another group');
      await verifyBytes(oldKeeperReady);
      const originalFiles = [oldActive, oldBootstrap, oldKeeperReady, oldSigned.manifest, ...oldSigned.entries.values(), ...oldSigned.companionFiles];
      await verifyBytes(oldBootstrap);
      noteUpgradePhase(observePhase, 'stage_source');
      const packageDirectory = await sourceScope.root(packageRoot), signed = await verifyPackage(sourceScope, packageDirectory, original.releaseKeys, undefined, true, signal);
      requireSingleCasBundle(signed.bundle);
      if (signed.bundleDigest === original.bundleDigest) mismatch('upgrade must select its exact distinct signed target');
      if (signed.bundle.headlessSchemaRange.min > 3 || signed.bundle.headlessSchemaRange.max < 3)
        mismatch('complete installed upgrade requires its signed schema3 client interface');
      const schemaEntry = signed.bundle.entries.find(entry => entry.entryId === 'kernel_schema');
      const conversionEntry = signed.bundle.entries.find(entry => entry.entryId === 'schema_conversion');
      if (!schemaEntry || !conversionEntry || schemaEntry.role !== 'schema' || conversionEntry.role !== 'schema') mismatch('upgrade target omits full signed schema/conversion');
      decodeSignedKernelSchema(checkCanonicalBytes(signed.roots.get(schemaEntry.digest)!));
      decodeSchemaConversion(checkCanonicalBytes(signed.roots.get(conversionEntry.digest)!), original.bundle);
      const expectedSchema = signedKernelSchemaProfile(), expectedConversion = schemaConversionProfile(original.bundle);
      if (schemaEntry.digest !== canonicalSha256(expectedSchema) || conversionEntry.digest !== canonicalSha256(expectedConversion))
        mismatch('upgrade target substituted its full signed schema sources');
      const targetSupervisor = signed.bundle.entries.find(entry => entry.role === 'supervisor')!;
      const controller = signed.entries.get(targetSupervisor.entryId)!;
      noteUpgradePhase(observePhase, 'source_control');
      await verifyBytes(controller, signal);
      await joinInstalledUpgradeSourceControl(controller.handle, stateRoot, original.bundleDigest, signal);
      await verifyBytes(controller, signal); await sourceScope.assertDirectories(); await original.revalidate(signal);
      const stage = await scope.directory(runtime, `.upgrade-${randomBytes(16).toString('hex')}`, true);
      const version = await scope.directory(stage, 'package', true);
      for (const entry of signed.bundle.entries) {
        signal?.throwIfAborted();
        if (signed.singleCasPaths.has(entry.relativePath)) continue;
        await writeChunks(scope, version, entry.relativePath, chunks(signed.entries.get(entry.entryId)!, signal), entry.executable ? 0o500 : 0o400);
      }
      await writeChunks(scope, version, 'manifest.json', bytesSource(signed.manifestBytes), 0o400);
      // Match the existing installed graph: companion bytes are durably
      // rooted in CAS, never added as unsigned installed package paths.
      await writeChunks(scope, stage, 'bootstrap', chunks(signed.entries.get(targetSupervisor.entryId)!, signal), 0o500);
      const newBootstrap = await scope.file(stage, 'bootstrap', 0o500, targetSupervisor.byteCount, targetSupervisor.digest);
      await verifyBytes(newBootstrap);
      // The active file is born here, before the receipt's inode binding. Its
      // exact receipt-dependent bytes are filled and synced before SQL commit.
      await scope.assertDirectory(stage);
      const activeHandle = scope.own(await open(childPath(stage, 'active.json'), constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600));
      const activeBirth = await activeHandle.stat({ bigint: true });
      checkFile(activeBirth, 0o600, 0);
      if (!sameFile(activeBirth, await lstat(childPath(stage, 'active.json'), { bigint: true }))) mismatch('upgrade active birth changed');
      await activeHandle.sync();
      const newActive: InstalledFile = { handle: activeHandle, info: activeBirth, parent: stage, name: 'active.json' };
      noteUpgradePhase(observePhase, 'stage_cas');
      const cas = new ContentAddressedStore(childPath(casRoot, '.')), seed: PublishedArtifact[] = [], casFiles: InstalledFile[] = [];
      const roots = [...signed.roots];
      for (let offset = 0; offset < roots.length; offset += 4) {
        const group = roots.slice(offset, offset + 4);
        for (const _member of group) { signal?.throwIfAborted(); await scope.assertDirectories(); }
        const published = await publishInstalledCasRoots(cas, group);
        for (let index = 0; index < group.length; index++) {
          const [ref, bytes] = group[index]!;
          if (published[index]!.ref !== ref || published[index]!.byteLength !== bytes.length) mismatch('upgrade CAS root changed');
          await scope.assertDirectories(); const member = await scope.file(casRoot, ref, 0o400, bytes.length, ref);
          await verifyBytes(member); casFiles.push(member);
          const skillRaw = signed.structured.objects.some(object => object.artifactRef === ref && object.schemaKind === 'cliq-skill-source-file-v1');
          seed.push({ ref, byteLength: bytes.length, mediaType: skillRaw ? 'application/octet-stream' : 'application/json',
            schemaKind: skillRaw ? 'cliq-skill-source-file-v1' : 'cliq-installed-upgrade-seed-v1' });
        }
      }
      for (const [ref, image] of signed.streamedRoots) {
        signal?.throwIfAborted(); await scope.assertDirectories();
        const published = await cas.publishChunks(artifactChunks(image), Number(image.info.size));
        if (published.ref !== ref || BigInt(published.byteLength) !== image.info.size) mismatch('upgrade CAS stream changed');
        await scope.assertDirectories(); const member = await scope.file(casRoot, ref, 0o400, published.byteLength, ref);
        await verifyBytes(member); casFiles.push(member);
        seed.push({ ref, byteLength: published.byteLength, mediaType: 'application/octet-stream', schemaKind: streamedInstalledSchemaKind(signed, ref) });
      }
      const staged = await verifyPackage(scope, version, original.releaseKeys, signed.bundleDigest, false, signal, casRoot,
        new Map(casFiles.map(file => [file.name, file])));
      await checkPackageGraph(sourceScope, packageDirectory, signed.bundle, signed.modelAuthority);
      for (const file of [signed.manifest, ...signed.entries.values(), ...signed.companionFiles]) { signal?.throwIfAborted(); await verifyBytes(file, signal); }
      for (const file of casFiles) { signal?.throwIfAborted(); await verifyBytes(file, signal); }
      await syncDirectories(scope); await original.revalidate(signal);
      noteUpgradePhase(observePhase, 'stage_native');
      const nativeEntry = staged.bundle.entries.find(entry => entry.entryId === STATE_OWNER_NATIVE_ENTRY_ID)!;
      const nativeFile = staged.entries.get(nativeEntry.entryId)!;
      const native = await loadHeldStateOwnerImage(nativeFile.handle, staged.bundle);
      keeperCheck = checkHeldInstalledUpgradeKeeper(native, { stateRoot, root: state.info, image: oldSigned.entries.get(oldSupervisor.entryId)!.info,
        bundleDigest: original.bundleDigest, relativePath: oldSupervisor.relativePath, locator: keeperLocator,
        packageRoot, packageIdentity: packageDirectory.info, controllerRelativePath: targetSupervisor.relativePath, controllerImage: controller.info });
      await verifyBytes(oldKeeperReady); await verifyBytes(controller, signal); await original.revalidate(signal);
      keeperCheck.assertCurrent();
      // Pure birth metadata from the current native check, not an old held
      // Anchor. The closed V2 installation source records these actual facts,
      // never a claim to inherit or hold an original native Anchor token.
      const originalKeeper: InstalledUpgradeSourceV1['originalKeeper'] = Object.freeze({ pid: keeperLocator.readUInt32LE(8),
        processStartToken: `linux-proc-start-ticks:${keeperLocator.readBigUInt64LE(16)}`,
        locatorDigest: sha256Bytes(keeperLocator), bootIdentityHex: keeperLocator.subarray(24).toString('hex'), observedAt: sampleCanonicalNow(),
        readyIdentity: upgradeDirectoryIdentity(oldKeeperReady) });
      keeperCheck.assertCurrent(); keeperCheck.close(); keeperCheck = undefined;
      await sourceScope.close();
      noteUpgradePhase(observePhase, 'stage_owner_history');
      const artifacts = new ArtifactCatalog(cas, signal, original.releaseKeys).withRuntimeConversionSource(signed.bundleDigest);
      const database = openReadOnlySqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
      let supervisorBirth: PlatformProcessIdentityV1, supervisorOwner: StateOwnerRecordV1;
      try {
        const owner = readLatestStateOwner(database);
        if (!owner || owner.state !== 'active' || owner.runtimeBundleRef !== original.bundleDigest) mismatch('upgrade lost the original active owner source');
        supervisorOwner = owner;
        const history = await readRetainedStateOwnerHistory(database, artifacts, owner.ownerEpoch);
        supervisorBirth = history.entries.at(-1)!.process;
        if (database.prepare("SELECT 1 FROM runs WHERE status NOT IN ('succeeded','completed_unverified','failed','cancelled') LIMIT 1").get())
          mismatch('upgrade refuses to stop an installation with nonterminal Runs');
        database.readSnapshot(connection => history.assertUnchanged(connection));
      } finally { database.close(); }
      const source: InstalledUpgradeSourceV1 = { kind: 'held_installed_stage_v2',
        keeperObservationKind: 'current_checked_original_keeper', stageName: stage.name,
        stageIdentity: upgradeDirectoryIdentity(stage), runtimeIdentity: upgradeDirectoryIdentity(runtime),
        targetBundleIdentity: upgradeDirectoryIdentity(version), originalActiveIdentity: upgradeDirectoryIdentity(oldActive),
        originalBootstrapIdentity: upgradeDirectoryIdentity(oldBootstrap), stagedActiveIdentity: upgradeDirectoryIdentity(newActive),
        stagedBootstrapIdentity: upgradeDirectoryIdentity(newBootstrap),
        sourceBundleDigest: original.bundleDigest, targetBundleDigest: staged.bundleDigest,
        ...(signed.modelAuthority ? { targetModelAuthorityRef: signed.modelAuthority.closureRef } : {}),
        originalActiveDigest: oldActive.digest, originalBootstrapDigest: oldSupervisor.digest, originalKeeper };
      let closed = false, transactionActive = false, credential: UpgradeCredentialLifetime | undefined, selectionRef: string | undefined;
      let running: Promise<unknown> | undefined, closePromise: Promise<void> | undefined, stopPromise: Promise<void> | undefined;
      let activeStop: NativeCredentialInspection | undefined, stopCancellation: Promise<void> | undefined;
      const distinctCasFiles = casFiles.filter(file => !staged.delegatedRefs.has(file.name));
      const assertAlive = () => { if (closed) mismatch('upgrade stage has closed'); signal?.throwIfAborted(); healthy(); };
      const assertBirth = () => {
        assertAlive(); scope.assertMetadata([staged.manifest, newBootstrap, ...staged.entries.values(), ...originalFiles, ...distinctCasFiles]);
        if (upgradeDirectoryIdentity(stage).fileId !== source.stageIdentity.fileId) mismatch('upgrade stage birth changed');
      };
      const prepared: InstalledUpgradeTransaction = Object.freeze({ stateRoot, bundle: staged.bundle, releaseKeys: original.releaseKeys,
        native, seed: Object.freeze(seed), source: immutableSnapshot(source), supervisorBirth: immutableSnapshot(supervisorBirth),
        supervisorOwner: immutableSnapshot(supervisorOwner),
        notePhase: phase => noteUpgradePhase(observePhase, phase),
        async assertCurrent() {
          assertBirth(); await scope.assertDirectories();
          await scope.verifyDiscard([staged.manifest, newBootstrap, ...staged.entries.values(), ...originalFiles, ...distinctCasFiles], signal);
          await checkPackageGraph(scope, version, staged.bundle, undefined, staged.delegatedPaths);
          await checkPackageGraph(scope, oldVersion, oldSigned.bundle, undefined, oldSigned.delegatedPaths); assertBirth();
        },
        assertCommit() {
          if (!transactionActive || !credential) mismatch('upgrade transaction lost its original credential exclusion');
          assertBirth(); credential.assertHeld();
          if (!selectionRef) mismatch('upgrade selection bytes are not durable');
          scope.assertMetadata([newActive]);
        },
        assertOldProcessesDead() {
          if (!transactionActive || !credential) mismatch('upgrade lacks its original process observer');
          credential.assertHeld();
          for (const process of [supervisorBirth, { ...originalKeeper, ownerUid: original.stateRoot.ownerUid }])
            if (credential.observeProducerLifetime(process.pid, process.ownerUid, process.processStartToken) !== 'dead')
              mismatch('upgrade requires genuine old Supervisor and keeper death');
        },
        publishSelection(receiptRef, receipt) {
          const owner = installedUpgradeStages.get(held);
          if (!owner || !owner.active()) mismatch('upgrade publication lost its original transaction owner');
          return owner.publish(receiptRef, receipt);
        },
        async prepareSelection(receiptRef) {
          assertArtifactRef(receiptRef); assertBirth();
          if (selectionRef) { if (selectionRef !== receiptRef) mismatch('upgrade cannot select another receipt'); return; }
          const bytes = canonicalJsonBytes({ schemaVersion: 1, bundleDigest: staged.bundleDigest,
            ...(signed.modelAuthority ? { modelAuthorityRef: signed.modelAuthority.closureRef } : {}), upgradeReceiptRef: receiptRef });
          if (newActive.info.size !== 0n || newActive.digest !== undefined) mismatch('upgrade selection must use its original empty birth');
          const writer = scope.own(await open(childPath(stage, 'active.json'), constants.O_WRONLY | constants.O_NOFOLLOW));
          try {
            if (!sameFile(newActive.info, await writer.stat({ bigint: true }))) mismatch('upgrade active birth was replaced');
            let offset = 0;
            while (offset < bytes.length) { const result = await writer.write(bytes, offset, bytes.length - offset, offset);
              if (!result.bytesWritten) mismatch('upgrade active write made no progress'); offset += result.bytesWritten; }
            await writer.sync();
          } finally { await scope.retire(writer); }
          const info = await newActive.handle.stat({ bigint: true });
          if (info.dev !== newActive.info.dev || info.ino !== newActive.info.ino || info.uid !== newActive.info.uid || info.gid !== newActive.info.gid ||
              info.mode !== newActive.info.mode || info.nlink !== 1n || info.size !== BigInt(bytes.length)) mismatch('upgrade active identity changed during fill');
          newActive.info = info; newActive.digest = sha256Bytes(bytes); await verifyBytes(newActive); await stage.handle.sync();
          selectionRef = receiptRef;
        },
      });
      const held: HeldInstalledRuntimeUpgrade = Object.freeze({ close() {
        if (this !== held) return Promise.reject(new TypeError('invalid upgrade stage receiver'));
        closed = true;
        if (activeStop && !stopCancellation) {
          const failedJoin = (error: unknown): never => {
            const failure = installedUpgradeRetirementFailure(error) ??
              new ResourceRetirementError('installed upgrade native stop cancellation did not join', error);
            rememberRetirement(failure); throw failure;
          };
          // Cancellation is issued synchronously, and even a synchronous
          // native rejection becomes the one retained/joined close producer.
          try { stopCancellation = activeStop.cancelAndJoin().catch(failedJoin); }
          catch (error) { stopCancellation = Promise.reject(error).catch(failedJoin); }
        }
        return closePromise ??= (async () => { await joinResourceOperations([running?.then(() => undefined, error => {
          if (error instanceof ResourceRetirementError) throw error; }), stopCancellation]); await scope.close(); })().catch(error => {
            if (error instanceof ResourceRetirementError) { unretiredInstalledUpgradeStages.add(held); rememberRetirement(error); }
            throw error;
          });
      } });
      installedUpgradeStages.set(held, { prepared, active: () => transactionActive && !closed,
        notePhase: phase => noteUpgradePhase(observePhase, phase),
        stop(): Promise<void> {
          assertAlive();
          noteUpgradePhase(observePhase, 'stop_original');
          return stopPromise ??= (async () => {
            if (!transactionActive || !credential) mismatch('upgrade stop requires its original credential exclusion');
            noteUpgradePhase(observePhase, 'stop_observe_original');
            const { observeInstalledCredentialSupervisor } = await import('./installed-services.js');
            const observed = await observeInstalledCredentialSupervisor(selected, false);
            if (observed.stateRoot !== stateRoot || observed.uid !== Number(state.info.uid) ||
                observed.supervisor.MainPID !== supervisorBirth.pid || observed.keeper.MainPID !== originalKeeper.pid)
              mismatch('upgrade service observation is not the original Supervisor and keeper');
            noteUpgradePhase(observePhase, 'stop_load_platform');
            const platformEntry = staged.bundle.entries.find(entry => entry.entryId === 'linux_credential_platform');
            const platformFile = platformEntry && staged.entries.get(platformEntry.entryId);
            if (!platformEntry || !platformFile || platformEntry.role !== 'platform_helper' || !platformEntry.executable ||
                platformEntry.relativePath !== 'native/linux-x64/linux-credential-platform.node') mismatch('upgrade lacks its fixed signed manager helper');
            await verifyBytes(platformFile);
            const module = new Module('cliq-installed-runtime-upgrade-manager'); process.dlopen(module, `/proc/self/fd/${platformFile.handle.fd}`);
            const platform = module.exports as NativeCredentialPlatformBinding;
            if (platform.interfaceVersion !== 2 || platform.installedUpgradeInterfaceVersion !== 1 || typeof platform.stopInstalledUpgradeUnit !== 'function')
              mismatch('selected upgrade helper lacks its fixed stop interface');
            await verifyBytes(platformFile); assertBirth();
            for (const role of ['supervisor', 'keeper'] as const) {
              const unit = observed[role], process = role === 'supervisor' ? supervisorBirth : originalKeeper;
              if (unit.ActiveState !== 'active' || unit.SubState !== 'running' || unit.MainPID !== unit.ExecMainPID ||
                  !/^[0-9a-f]{32}$/u.test(unit.InvocationID)) mismatch('upgrade stop has no actual original running unit');
              const started = performance.now();
              noteUpgradePhase(observePhase, role === 'supervisor' ? 'stop_supervisor_request' : 'stop_keeper_request');
              activeStop = platform.stopInstalledUpgradeUnit({ rootIdentityDigest: stateRootIdentityFromDescriptor(stateRoot, {
                deviceId: String(state.info.dev), fileId: String(state.info.ino), ownerUid: Number(state.info.uid)
              }).identityDigest, role, pid: process.pid, processStartToken: process.processStartToken, invocationId: unit.InvocationID });
              if (typeof activeStop.cancelAndJoin !== 'function') throw new ResourceRetirementError('upgrade stop has no original native cancellation/join owner', undefined);
              const raw = await activeStop;
              noteUpgradePhase(observePhase, role === 'supervisor' ? 'stop_supervisor_decode' : 'stop_keeper_decode');
              const result = decodeInstalledUpgradeStopObservation(raw); activeStop = undefined;
              if (canonicalSha256(result.bus) !== canonicalSha256(observed.bus) || canonicalSha256(result.manager) !== canonicalSha256(observed.manager) ||
                  result.unit?.Id !== unit.Id || result.unit.ActiveState !== 'inactive' || result.unit.SubState !== 'dead' ||
                  result.unit.MainPID !== 0 || result.unit.ControlPID !== 0) mismatch('upgrade stop lost its original manager or fixed unit');
              noteUpgradePhase(observePhase, role === 'supervisor' ? 'stop_supervisor_death' : 'stop_keeper_death');
              while (credential.observeProducerLifetime(process.pid, observed.uid, process.processStartToken) !== 'dead') {
                if (performance.now() - started >= 2000) mismatch('upgrade original process did not die within the fixed two-second stop limit');
                await upgradeDelay(5); assertAlive();
              }
              if (performance.now() - started >= 2000) mismatch('upgrade actual stop/join exceeded the fixed two-second limit');
            }
          })().catch(error => {
            const failure = installedUpgradeRetirementFailure(error);
            if (failure) { rememberRetirement(failure); throw failure; }
            throw error;
          });
        },
        run<T>(operation: () => Promise<T>): Promise<T> {
          assertAlive(); if (running) return Promise.reject(new TypeError('upgrade stage already has its sole transaction'));
          noteUpgradePhase(observePhase, 'credential_exclusion');
          const pending = withHeldCredentialNativeScope(native, { image: nativeFile.handle, root: state.handle,
            rootIdentity: state.info, stateRoot }, async originalCredential => {
              credential = originalCredential; transactionActive = true;
              try {
                let result!: T;
                let failed = false, failure: unknown;
                try { result = await operation(); }
                catch (error) { failed = true; failure = error; }
                // A concurrent close owns this exact native cancellation.
                // Join it before the credential scope can consider release;
                // its sticky RRE takes precedence over an ordinary failure.
                if (stopCancellation) try {
                  await joinResourceOperations([failed ? Promise.reject(failure) : Promise.resolve(), stopCancellation]);
                } catch (error) { healthy(); throw error; }
                healthy();
                if (failed) throw failure;
                return result;
              } finally { transactionActive = false; credential = undefined; }
            });
          running = pending; return pending;
        },
        async publish(receiptRef, receipt) {
          noteUpgradePhase(observePhase, 'publish_selection');
          assertBirth();
          if (selectionRef !== receiptRef || receipt.installation.kind === 'not_installed' ||
              canonicalSha256(receipt.installation) !== canonicalSha256(source)) mismatch('upgrade publication lacks its registered original stage');
          await prepared.assertCurrent(); await verifyBytes(newActive);
          await verifyBytes(oldActive); await verifyBytes(oldBootstrap);
          await absent(bundles, staged.bundleDigest);
          await rename(childPath(stage, version.name), childPath(bundles, staged.bundleDigest));
          version.parent = bundles; version.name = staged.bundleDigest; await bundles.handle.sync(); await scope.assertDirectories();
          await scope.retire(oldBootstrap.handle);
          await rename(childPath(stage, newBootstrap.name), childPath(runtime, 'bootstrap'));
          newBootstrap.parent = runtime; newBootstrap.name = 'bootstrap';
          const bootstrapRenamed = await newBootstrap.handle.stat({ bigint: true });
          if (!['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs'].every(key =>
              bootstrapRenamed[key as keyof BigIntStats] === newBootstrap.info[key as keyof BigIntStats])) mismatch('upgrade bootstrap changed during authorized rename');
          newBootstrap.info = bootstrapRenamed;
          await verifyBytes(newBootstrap); await runtime.handle.sync();
          await scope.retire(oldActive.handle);
          await rename(childPath(stage, newActive.name), childPath(runtime, 'active.json'));
          newActive.parent = runtime; newActive.name = 'active.json';
          const activeRenamed = await newActive.handle.stat({ bigint: true });
          if (!['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs'].every(key =>
              activeRenamed[key as keyof BigIntStats] === newActive.info[key as keyof BigIntStats])) mismatch('upgrade active changed during authorized rename');
          newActive.info = activeRenamed;
          await verifyBytes(newActive); await runtime.handle.sync(); await scope.assertDirectories();
          // Every issued copy/hash/fsync has joined. The callback still
          // retains the native credential source descriptors until that
          // original native scope closes; stage.close then joins all FDs.
        },
      });
      return held;
    }, signal);
  } catch (error) {
    rememberRetirement(error);
    await joinResourceOperations([Promise.reject(error), sourceScope.close(), scope.close(), Promise.resolve().then(() => keeperCheck?.close())])
      .catch(failure => { rememberRetirement(failure); throw failure; });
    throw error;
  }
}


/** Sole installed orchestration. No caller chooses a manager/unit/PID, supplies
 * retirement facts, or obtains productive authority from a staged package. */
export async function completeInstalledRuntimeUpgrade(stage: HeldInstalledRuntimeUpgrade): Promise<RuntimeUpgradeReceiptV1> {
  const binding = installedUpgradeStages.get(stage);
  if (!binding) mismatch('installed upgrade requires its original held preparation');
  try {
    return await binding.run(async () => {
      await binding.stop();
      binding.notePhase?.('conversion');
      const { upgradeRetiredRuntime } = await import('./runtime-upgrade.js');
      const prepared = binding.prepared;
      const receipt = await upgradeRetiredRuntime({ stateRoot: prepared.stateRoot,
        target: { bundle: prepared.bundle, releaseKeys: prepared.releaseKeys }, installation: stage });
      return receipt;
    });
  } finally { await stage.close(); }
}


function assertUpgradeObjectIdentity(object: { info: BigIntStats }, expected: InstalledUpgradeIdentityV1): void {
  if (canonicalSha256(upgradeDirectoryIdentity(object)) !== canonicalSha256(expected)) mismatch('registered upgrade object was absent or replaced');
}

/** Full retained SQL/CAS/signature graph, without acquiring an owner or creating
 * a missing database. A matching CAS-only receipt is never selected authority. */
async function readRegisteredInstalledUpgrade(stateRoot: string, releaseKeys: readonly ReleaseTrustKey[], receiptRef: string): Promise<RuntimeUpgradeReceiptV1> {
  assertArtifactRef(receiptRef);
  const driver = openReadOnlySqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    assertKernelSchemaVersion(driver, 8);
    const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY)), undefined, releaseKeys);
    const latest = readLatestStateOwner(driver);
    if (!latest) mismatch('registered upgrade has no actual owner history');
    const history = await readRetainedStateOwnerHistory(driver, artifacts, latest.ownerEpoch);
    const boundary = history.entries.find(entry => entry.acquisition.kind === 'runtime_upgrade');
    if (!boundary || boundary.acquisition.kind !== 'runtime_upgrade' || boundary.acquisition.upgradeReceiptRef !== receiptRef)
      mismatch('selection receipt was not registered by the sole upgrade transaction');
    const receipt = decodeRuntimeUpgradeReceipt(await artifacts.readCanonical(receiptRef));
    if (canonicalSha256(receipt) !== receiptRef || receipt.receiptDigest !== boundary.acquisition.upgradeReceiptDigest ||
        receipt.installation.kind === 'not_installed') mismatch('registered installed upgrade receipt differs');
    driver.readSnapshot(connection => history.assertUnchanged(connection));
    return receipt;
  } finally { driver.close(); }
}

async function upgradePathInfo(parent: Directory, name: string): Promise<BigIntStats | undefined> {
  await parent.handle.stat({ bigint: true });
  try { return await lstat(childPath(parent, name), { bigint: true }); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
}
function upgradeIdentityMatches(info: BigIntStats | undefined, expected: InstalledUpgradeIdentityV1): boolean {
  return info !== undefined && canonicalSha256(upgradeDirectoryIdentity({ info })) === canonicalSha256(expected);
}

/** Same-decision recovery only. Missing/replaced births or a live original
 * holder refuse; no package/CAS candidate can allocate another upgrade. */
export async function recoverInstalledRuntimeUpgrade(stateRoot: string, receiptRef: string,
  trustedReleaseKeys: readonly ReleaseTrustKey[], signal?: AbortSignal): Promise<RuntimeUpgradeReceiptV1> {
  signal?.throwIfAborted();
  const releaseKeys = immutableSnapshot(trustedReleaseKeys);
  const receipt = await readRegisteredInstalledUpgrade(stateRoot, releaseKeys, receiptRef);
  if (receipt.installation.kind === 'not_installed') mismatch('recovery requires its original installed stage');
  const registered = receipt.installation, scope = new Scope();
  let held: HeldInstalledRuntimeUpgrade | undefined;
  try {
    const state = await scope.root(stateRoot), runtime = await scope.directory(state, 'runtime'), bundles = await scope.directory(runtime, 'bundles');
    assertUpgradeObjectIdentity(runtime, registered.runtimeIdentity);
    const stage = await scope.directory(runtime, registered.stageName); assertUpgradeObjectIdentity(stage, registered.stageIdentity);
    const localBundle = await upgradePathInfo(stage, 'package'), publishedBundle = await upgradePathInfo(bundles, registered.targetBundleDigest);
    if (localBundle && publishedBundle || !localBundle && !publishedBundle ||
        !upgradeIdentityMatches(localBundle ?? publishedBundle, registered.targetBundleIdentity)) mismatch('registered upgrade bundle birth is missing or replaced');
    const version = localBundle ? await scope.directory(stage, 'package') : await scope.directory(bundles, registered.targetBundleDigest);
    const casRoot = await scope.directory(state, KERNEL_CAS_DIRECTORY);
    const signed = await verifyPackage(scope, version, releaseKeys, registered.targetBundleDigest, false, signal, casRoot);
    requireSingleCasBundle(signed.bundle);
    const originalVersion = await scope.directory(bundles, registered.sourceBundleDigest);
    const original = await verifyPackage(scope, originalVersion, releaseKeys, registered.sourceBundleDigest, false, signal, casRoot);
    const casFiles: InstalledFile[] = [];
    for (const [ref, bytes] of signed.roots) casFiles.push(await scope.file(casRoot, ref, 0o400, bytes.length, ref));
    for (const [ref, image] of signed.streamedRoots)
      if (!signed.delegatedRefs.has(ref)) casFiles.push(await scope.file(casRoot, ref, 0o400, Number(image.info.size), ref));
    if (registered.targetModelAuthorityRef) casFiles.push(...await readInstalledCompanionFromCas(scope, casRoot, signed, registered.targetModelAuthorityRef, releaseKeys));
    for (const file of casFiles) await verifyBytes(file, signal);
    const targetSupervisor = signed.bundle.entries.find(entry => entry.role === 'supervisor')!;
    const sourceSupervisor = original.bundle.entries.find(entry => entry.role === 'supervisor')!;
    const locate = async (name: 'bootstrap' | 'active.json', oldIdentity: InstalledUpgradeIdentityV1,
      targetIdentity: InstalledUpgradeIdentityV1, oldDigest: string, newDigest: string, oldSize?: number, newSize?: number) => {
      const source = await upgradePathInfo(stage, name), destination = await upgradePathInfo(runtime, name);
      if (!destination || source && !upgradeIdentityMatches(source, targetIdentity)) mismatch('registered upgrade file birth is missing or replaced');
      if (upgradeIdentityMatches(destination, targetIdentity)) {
        if (source) mismatch('registered upgrade target has duplicated births');
        const file = await scope.file(runtime, name, name === 'bootstrap' ? 0o500 : 0o600, newSize, newDigest);
        await verifyBytes(file); return { target: file, published: true, old: undefined as InstalledFile | undefined };
      }
      if (!source || !upgradeIdentityMatches(destination, oldIdentity)) mismatch('registered upgrade original destination was replaced');
      const before = await scope.file(runtime, name, name === 'bootstrap' ? 0o500 : 0o600, oldSize, oldDigest);
      const file = await scope.file(stage, name, name === 'bootstrap' ? 0o500 : 0o600, newSize, newDigest);
      await verifyBytes(before); await verifyBytes(file); return { target: file, published: false, old: before };
    };
    const activeBytes = canonicalJsonBytes({ schemaVersion: 1, bundleDigest: receipt.targetRuntimeBundleRef,
      ...(registered.targetModelAuthorityRef ? { modelAuthorityRef: registered.targetModelAuthorityRef } : {}), upgradeReceiptRef: receiptRef });
    const bootstrap = await locate('bootstrap', registered.originalBootstrapIdentity, registered.stagedBootstrapIdentity,
      registered.originalBootstrapDigest, targetSupervisor.digest, sourceSupervisor.byteCount, targetSupervisor.byteCount);
    const active = await locate('active.json', registered.originalActiveIdentity, registered.stagedActiveIdentity,
      registered.originalActiveDigest, sha256Bytes(activeBytes), undefined, activeBytes.length);
    if (active.published && (localBundle || !bootstrap.published)) mismatch('upgrade selection precedes its registered bundle/bootstrap');
    if (active.published) {
      if ((await readdir(childPath(stage, '.'))).length !== 0) mismatch('completed upgrade stage has unregistered objects');
      await scope.close(); return receipt; // Strict read-only idempotence; no owner or Stop is created.
    }
    const keeperReady = await scope.file(runtime, 'keeper.ready', 0o600, 40, registered.originalKeeper.locatorDigest);
    assertUpgradeObjectIdentity(keeperReady, registered.originalKeeper.readyIdentity); await verifyBytes(keeperReady);
    const database = openReadOnlySqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
    let sourceProcess: PlatformProcessIdentityV1, stageProcess: PlatformProcessIdentityV1, supervisorOwner: StateOwnerRecordV1;
    try {
      const sourceOwner = readLatestStateOwner(database);
      if (!sourceOwner) mismatch('upgrade recovery has no original owner chain');
      const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY)), undefined, releaseKeys);
      const history = await readRetainedStateOwnerHistory(database, artifacts, sourceOwner.ownerEpoch);
      sourceProcess = history.entries[receipt.sourceOwnerEpoch - 1]!.process;
      supervisorOwner = history.entries[receipt.sourceOwnerEpoch - 1]!.owner;
      stageProcess = history.entries[receipt.targetOwner.ownerEpoch - 1]!.process;
      database.readSnapshot(connection => history.assertUnchanged(connection));
    } finally { database.close(); }
    const nativeFile = signed.entries.get(STATE_OWNER_NATIVE_ENTRY_ID);
    if (!nativeFile) mismatch('registered target lost its exact native helper');
    const native = await loadHeldStateOwnerImage(nativeFile.handle, signed.bundle);
    const image = await native.observeCurrentProcess();
    if (image.executableImageDigest !== targetSupervisor.digest) mismatch('upgrade recovery must run its actual signed target image');
    let credential: UpgradeCredentialLifetime | undefined, running: Promise<unknown> | undefined, closePromise: Promise<void> | undefined,
      activeBorrow = false, closed = false;
    const files = [signed.manifest, ...signed.entries.values(), ...signed.companionFiles, original.manifest, ...original.entries.values(),
      bootstrap.target, active.target, keeperReady, ...casFiles, ...(bootstrap.old ? [bootstrap.old] : []), ...(active.old ? [active.old] : [])];
    const assertSource = () => { if (closed) mismatch('registered upgrade recovery scope has closed'); signal?.throwIfAborted(); scope.assertMetadata(files); };
    const assertDeath = () => {
      if (!activeBorrow || !credential) mismatch('upgrade recovery lost its original credential exclusion');
      credential.assertHeld();
      for (const source of [sourceProcess, stageProcess, { ...registered.originalKeeper, ownerUid: Number(state.info.uid) }])
        if (credential.observeProducerLifetime(source.pid, source.ownerUid, source.processStartToken) !== 'dead')
          mismatch('registered upgrade original holder or keeper is still alive');
    };
    const prepared: InstalledUpgradeTransaction = Object.freeze({ stateRoot, bundle: signed.bundle, releaseKeys, native,
      seed: [], source: registered, supervisorBirth: sourceProcess, supervisorOwner,
      async assertCurrent() { assertSource(); await scope.assertDirectories(); await scope.verifyDiscard(files, signal);
        await checkPackageGraph(scope, version, signed.bundle, undefined, signed.delegatedPaths);
        await checkPackageGraph(scope, originalVersion, original.bundle, undefined, original.delegatedPaths); assertSource(); },
      assertCommit() { assertSource(); assertDeath(); }, assertOldProcessesDead: assertDeath,
      prepareSelection(ref) { if (ref !== receiptRef) return Promise.reject(new TypeError('recovery cannot prepare another decision')); return Promise.resolve(); },
      publishSelection(ref, originalReceipt) {
        if (ref !== receiptRef || canonicalSha256(originalReceipt) !== canonicalSha256(receipt)) mismatch('recovery cannot select another upgrade');
        return installedUpgradeStages.get(held!)!.publish(ref, originalReceipt);
      },
    });
    held = Object.freeze({ close() { if (this !== held) return Promise.reject(new TypeError('invalid recovered upgrade receiver'));
      closed = true; return closePromise ??= (async () => {
        await running?.then(() => undefined, error => { if (error instanceof ResourceRetirementError) throw error; }); await scope.close();
      })().catch(error => { if (error instanceof ResourceRetirementError) { unretiredInstalledUpgradeStages.add(held!); rememberRetirement(error); }
        throw error; }); } });
    installedUpgradeStages.set(held, { prepared, active: () => activeBorrow && !closed,
      stop: async () => { assertDeath(); },
      run<T>(operation: () => Promise<T>): Promise<T> {
        if (running || closed) return Promise.reject(new TypeError('registered recovery owns one original completion'));
        const pending = withHeldCredentialNativeScope(native, { image: nativeFile.handle, root: state.handle, rootIdentity: state.info, stateRoot }, async originalScope => {
          credential = originalScope; activeBorrow = true;
          try { assertDeath(); return await operation(); } finally { activeBorrow = false; credential = undefined; }
        }); running = pending; return pending;
      },
      async publish(ref, originalReceipt) {
        if (ref !== receiptRef || canonicalSha256(originalReceipt) !== canonicalSha256(receipt)) mismatch('registered recovery decision changed');
        await prepared.assertCurrent(); assertDeath();
        if (localBundle) {
          await absent(bundles, signed.bundleDigest);
          await rename(childPath(stage, version.name), childPath(bundles, signed.bundleDigest));
          version.parent = bundles; version.name = signed.bundleDigest; await bundles.handle.sync();
        }
        const publish = async (part: typeof bootstrap, name: 'bootstrap' | 'active.json') => {
          if (part.published) return;
          await scope.assertDirectories(); await verifyBytes(part.target); if (part.old) { await verifyBytes(part.old); await scope.retire(part.old.handle); }
          const before = part.target.info;
          await rename(childPath(stage, name), childPath(runtime, name)); part.target.parent = runtime; part.target.name = name;
          const current = await part.target.handle.stat({ bigint: true });
          if (!['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs'].every(key => before[key as keyof BigIntStats] === current[key as keyof BigIntStats]))
            mismatch('registered recovery object changed during its authorized rename');
          part.target.info = current; await verifyBytes(part.target); await runtime.handle.sync();
        };
        await publish(bootstrap, 'bootstrap'); await publish(active, 'active.json'); await scope.assertDirectories();
      },
    });
    return await completeInstalledRuntimeUpgrade(held);
  } catch (error) {
    if (error instanceof ResourceRetirementError && held) {
      unretiredInstalledUpgradeStages.add(held); rememberRetirement(error); throw error;
    }
    await joinResourceOperations([Promise.reject(error), scope.close()]); throw error;
  }
}


/** Data-only match against the already verified expected signed bundle. A
 * HELLO summary is not a signature, held installation or retirement proof. */
export function assertInstalledUpgradeHelloBundle(summary: SupervisorHelloV1['activeRuntimeBundle'], bundle: RuntimeBundleManifest): void {
  assertControlWireJson(summary); assertControlWireJson(bundle);
  controlWireRecord(summary, ['schemaVersion', 'runtimeBundleRef', 'bundleDigest', 'bundleVersion']);
  const completeRef = canonicalSha256(bundle);
  if (summary.schemaVersion !== 1 || summary.runtimeBundleRef !== completeRef || summary.bundleDigest !== completeRef ||
      summary.bundleVersion !== bundle.bundleVersion)
    mismatch('upgrade HELLO differs from its exact expected signed runtime');
}

/** Fixed readonly child friend. The private original layout context never
 * escapes; only the existing authenticated HELLO is inspected and joined. */
export async function verifyInstalledUpgradeOriginalControl(runtime: InstalledRuntime, stateRoot: string,
  sourceBundleRef: string, signal?: AbortSignal): Promise<void> {
  if (!installedRuntimeTrust.has(runtime)) mismatch('original control check requires its genuine runtime composition');
  if (!isMainThread || !isSea() || process.platform !== 'linux' || process.arch !== 'x64' || process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'original control check requires its fixed readonly SEA purpose');
  if (normalizeAbsolutePath(stateRoot) !== stateRoot) mismatch('original control check requires its canonical StateRoot');
  assertArtifactRef(sourceBundleRef); signal?.throwIfAborted();
  const original = await (runtime.openSelected as (this: InstalledRuntime, root: string,
    layout: typeof originalUpgradeLayout) => Promise<HeldInstalledRuntime>).call(runtime, stateRoot, originalUpgradeLayout);
  try {
    if (original.bundleDigest !== sourceBundleRef) mismatch('original control check selected another signed source');
    const { openInstalledControlSession } = await import('../control/session.js');
    const session = await openInstalledControlSession(original);
    try { signal?.throwIfAborted(); assertInstalledUpgradeHelloBundle(session.hello.activeRuntimeBundle, original.bundle); }
    finally { await session.close(); }
  } finally { await original.close(); }
}

/** One production administrative workflow under the same compiled roots. It
 * never accepts a trust root, unit, process locator or recovery fact from argv.
 * Productive execution starts only through the existing installed services. */
export async function upgradeInstalledRuntime(runtime: InstalledRuntime, stateRoot: string, packageRoot: string,
  signal?: AbortSignal, observePhase?: (phase: InstalledRuntimeUpgradePhase) => void): Promise<RuntimeUpgradeReceiptV1> {
  const releaseKeys = installedRuntimeTrust.get(runtime);
  if (!releaseKeys) mismatch('upgrade requires the original trusted runtime composition');
  if (normalizeAbsolutePath(stateRoot) !== stateRoot || normalizeAbsolutePath(packageRoot) !== packageRoot)
    mismatch('upgrade requires canonical installation and package locators');
  signal?.throwIfAborted();
  noteUpgradePhase(observePhase, 'read_schema');
  let receiptRef: string | undefined;
  const database = openReadOnlySqliteDriver(path.join(stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    const version = database.prepare('SELECT user_version FROM pragma_user_version').get<{ user_version: bigint }>()!.user_version;
    if (version === 8n) {
      const artifacts = new ArtifactCatalog(new ContentAddressedStore(path.join(stateRoot, KERNEL_CAS_DIRECTORY)), signal, releaseKeys);
      const latest = readLatestStateOwner(database);
      if (!latest) mismatch('schema8 upgrade recovery has no original owner');
      const history = await readRetainedStateOwnerHistory(database, artifacts, latest.ownerEpoch);
      const boundary = history.entries.find(entry => entry.acquisition.kind === 'runtime_upgrade');
      if (!boundary || boundary.acquisition.kind !== 'runtime_upgrade') mismatch('upgrade cannot convert an unrelated schema8 birth');
      database.readSnapshot(connection => history.assertUnchanged(connection)); receiptRef = boundary.acquisition.upgradeReceiptRef;
    } else if (version !== 7n) mismatch('only the exact signed7-to8 installed upgrade is implemented');
  } finally { database.close(); }
  let receipt: RuntimeUpgradeReceiptV1;
  if (receiptRef) { noteUpgradePhase(observePhase, 'recover_selection'); receipt = await recoverInstalledRuntimeUpgrade(stateRoot, receiptRef, releaseKeys, signal); }
  else {
    noteUpgradePhase(observePhase, 'source_open');
    const original = await (runtime.openSelected as (this: InstalledRuntime, root: string,
      layout: typeof originalUpgradeLayout) => Promise<HeldInstalledRuntime>).call(runtime, stateRoot, originalUpgradeLayout);
    try {
      // A prior precommit attempt may have stopped these original services.
      // Only schema7 reaches this branch: start the same verified fixed units
      // and authenticate real old-runtime READY before capturing a new stage.
      const { observeInstalledCredentialSupervisor } = await import('./installed-services.js');
      noteUpgradePhase(observePhase, 'source_services');
      await observeInstalledCredentialSupervisor(original, true);
      signal?.throwIfAborted();
      const stage = await stageInstalledRuntimeUpgrade(original, packageRoot, signal, observePhase);
      const abort = () => { void stage.close().catch(rememberRetirement); };
      signal?.addEventListener('abort', abort, { once: true });
      try { signal?.throwIfAborted(); receipt = await completeInstalledRuntimeUpgrade(stage); }
      finally { signal?.removeEventListener('abort', abort); await stage.close(); }
    } finally { await original.close(); }
  }
  signal?.throwIfAborted();
  noteUpgradePhase(observePhase, 'target_open');
  const selected = await runtime.openSelected(stateRoot);
  try {
    if (selected.bundleDigest !== receipt.targetRuntimeBundleRef || selected.bundle.manifestDigest !== receipt.targetRuntimeBundleManifestDigest)
      mismatch('upgrade restart selected another runtime');
    const { observeInstalledCredentialSupervisor } = await import('./installed-services.js');
    noteUpgradePhase(observePhase, 'target_services');
    await observeInstalledCredentialSupervisor(selected, true);
    const { openInstalledControlSession } = await import('../control/session.js');
    noteUpgradePhase(observePhase, 'target_control');
    const session = await openInstalledControlSession(selected);
    try {
      assertInstalledUpgradeHelloBundle(session.hello.activeRuntimeBundle, selected.bundle);
    } finally { await session.close(); }
  } finally { await selected.close(); }
  return receipt;
}
