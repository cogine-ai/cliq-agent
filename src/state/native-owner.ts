import type { NativeLocalModelStore } from './local-model-store-native.js';
import { constants, type BigIntStats } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { Module } from 'node:module';
import path from 'node:path';
import { isSea } from 'node:sea';
import { fileURLToPath } from 'node:url';
import { types } from 'node:util';
import { immutableSnapshot } from '../model/immutable.js';
import { setImmediate } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';

import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRecord, controlWireText, controlWireInteger, controlWireRef } from '../kernel/control-wire-data.js';
import { parseJsonStrict } from '../kernel/json.js';
import { decodeOwnedLegacyImportControl, assertOwnedImportControlSuccessor, decodeMigrationAuthorityMarker,
  decodeLegacyMigrationRendezvous, type OwnedLegacyImportControl, type MigrationAuthorityMarker,
  type LegacyMigrationRendezvous } from '../kernel/migration-control.js';
import { decodeKernelRollbackDrainingControl, type KernelRollbackDrainingControlV1 } from '../kernel/kernel-archive-data.js';
import { encodeCurrentMigrationExpectedEntry } from '../kernel/current-migration-inspection-data.js';
import { encodeCurrentArchiveManifestSelection, encodeCurrentArchivePayload, encodeCurrentArchiveCasEntry,
  type CurrentArchiveManifestSelection } from '../kernel/current-kernel-archive-data.js';
import { CompleteKernelArchiveManifestStream } from './kernel-archive-manifest-stream.js';
import type { CompleteKernelArchiveHeader } from './kernel-archive-manifest.js';
import { decodeKernelArchiveCasIdentity, decodeKernelArchiveCasEntry, decodeKernelArchiveDirectoryIdentity,
  KERNEL_ARCHIVE_MAX_MANIFEST_BYTES, KERNEL_ARCHIVE_MAX_BYTES,
  type KernelArchiveCasIdentity, type KernelArchiveCasEntry } from '../kernel/kernel-archive-namespace.js';
import { decodeLegacyAuthMigratedMarker, type LegacyAuthMigratedMarkerV1 } from '../kernel/migration-auth-data.js';
import { decodeOwnedLegacyImportPreparation, decodeOwnedImportInventoryPage,
  type OwnedLegacyImportPreparationV1 } from '../kernel/owned-import-data.js';
import { digestOmitting, identityHash, normalizeAbsolutePath, sha256Bytes } from '../kernel/identity.js';
import type { StateRootIdentityV1, WorkspaceGenerationIdentityV1, WorkspaceIdentityV1, RepositoryIdentityV2 } from '../kernel/types.js';
import type { PublicationArenaRetirementObservation } from '../kernel/publication.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { decodeWorkspaceGenerationIdentity } from './decoders.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { hashHeldProcessImage } from './process-image.js';
import { openSqliteDriver, type SqliteDriver } from './sqlite-driver.js';
import { initializePreparedImportPreview, appendPreparedImportRows, finishPreparedImportPreview,
  updatePreparedImportInputDigests, type PreparedImportBaseline, type PreparedLegacyImportRows } from './prepared-import-candidate.js';
import { readPreparedImportSessionItemsPage, readPreparedImportSessionsPage, readPreparedImportSessionHeader,
  readPreparedImportSessionItemTail, finalizePreparedImportSession,
  type PreparedLegacyItemRow, type PreparedLegacySessionRow } from './prepared-import-candidate.js';
import type { SignedKernelSchemaV1 } from '../kernel/runtime-upgrade.js';
import { decodePublicationRetirementSpans, noteJoinedPublicationRetirement, publicationClaimRetirementDiagnosticKey,
  type PublicationRetirementDispatch, type PublicationRetirementSpans } from './publication-retirement-diagnostics.js';
import type { AdminMcpStdioInputBinding, RunMcpStdioInputBinding, RecoveryMcpStdioInputBinding, McpStdioNativeLifecycle, McpStdioNativeCleanup, McpStdioRecoveryNativeLifecycle, McpStdioRecoveryNativeCleanup } from './mcp-stdio-lifecycle.js';
import type { McpAdminOriginalRetirement } from '../sandbox/mcp-admin-retirement.js';
export type { AdminMcpStdioInputBinding, RunMcpStdioInputBinding, RecoveryMcpStdioInputBinding, McpStdioNativeLifecycle, McpStdioNativeCleanup, McpStdioRecoveryNativeLifecycle, McpStdioRecoveryNativeCleanup } from './mcp-stdio-lifecycle.js';

export const STATE_OWNER_NATIVE_ENTRY_ID = 'state_owner_native';
export const STATE_OWNER_NATIVE_RELATIVE_PATH = `native/${process.platform}-${process.arch}/state-owner.node`;
export const STATE_OWNER_NATIVE_PATH = isSea()
  ? path.join(path.dirname(process.execPath), STATE_OWNER_NATIVE_RELATIVE_PATH)
  : fileURLToPath(new URL(`../../dist/${STATE_OWNER_NATIVE_RELATIVE_PATH}`, import.meta.url));

type DescriptorIdentity = Readonly<{ deviceId: string; fileId: string; ownerUid: number }>;
export type AdminMcpInputBinding = Readonly<{
  adminOperationId: string;
  attempt: number;
  principalId: string;
  nonce: string;
  targetRef: string;
  targetDigest: string;
  probePayloadCoreRef: string;
  probePayloadCoreDigest: string;
  plannedContainmentRef: string;
  plannedContainmentDigest: string;
  sandboxLaunchSpecRef: string;
  sandboxLaunchSpecDigest: string;
}>;
export type HeldAdminMcpInput = Readonly<{
  identity: Readonly<{
    adminOperationId: string;
    attempt: number;
    nonce: string;
    targetRef: string;
    probePayloadCoreRef: string;
    birthIdentity: unknown;
  }>;
  assertHeld(): void;
  close(): void;
}>;
export type AdminMcpNativeLifecycle = Readonly<{
  schemaVersion: 1;
  format: 'cliq-mcp-admin-native-lifecycle-v1';
  binding: AdminMcpInputBinding;
  birthIdentity: DescriptorIdentity;
  privateParentIdentity: DescriptorIdentity;
  originalSupervisor: Readonly<{
    pid: number;
    processStartToken: string;
  }>;
  stateRootIdentity: DescriptorIdentity;
  runtimeIdentity: DescriptorIdentity;
  controller: Readonly<{
    pid: number;
    processStartToken: string;
  }>;
  reservation: Readonly<{
    cgroupName: string;
    cgroupDevice: string;
    cgroupInode: string;
  }>;
  containment: import('../sandbox/mcp-http-admin-native.js').McpAdminScopeObservation | null;
  retirement: import('../sandbox/mcp-http-admin-native.js').McpAdminScopeObservation | null;
  joined: Readonly<{
    deathJoined: boolean;
    outputCustodyRetired: boolean;
    protocolCompleted: boolean;
  }>;
  progressKind: number;
  progressDigest: string;
}>;
type NativeAdminMcpInput = HeldAdminMcpInput;
const adminMcpInputs = new WeakMap<HeldAdminMcpInput, {
  lock: HeldStateOwnerLock;
  native: NativeAdminMcpInput;
  bindingDigest: string;
  processId: number;
  active: boolean;
  mode: 'create' | 'retained' | 'absent';
}>();
function adminMcpInput(lock: HeldStateOwnerLock, input: AdminMcpInputBinding, mode: 'create' | 'retained' | 'absent'): HeldAdminMcpInput {
  assertStateOwnerLock(lock);
  const keys = ['adminOperationId', 'attempt', 'principalId', 'nonce', 'targetRef', 'targetDigest', 'probePayloadCoreRef', 'probePayloadCoreDigest',
    'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest'];
  if (!input || typeof input !== 'object' || types.isProxy(input)) {
    throw new TypeError('invalid original Admin MCP input binding');
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(key => !Object.hasOwn(descriptors, key) ||
    !descriptors[key]!.enumerable || !Object.hasOwn(descriptors[key]!, 'value'))) {
    throw new TypeError('invalid original Admin MCP input binding');
  }
  const binding = Object.freeze(Object.fromEntries(keys.map(key => [key, descriptors[key]!.value]))) as AdminMcpInputBinding;
  if (typeof binding.adminOperationId !== 'string' || binding.adminOperationId.length < 1 || Buffer.byteLength(binding.adminOperationId) > 256 || binding.adminOperationId.includes('\0') ||
    typeof binding.principalId !== 'string' || binding.principalId.length < 1 || Buffer.byteLength(binding.principalId) > 256 || binding.principalId.includes('\0') ||
    !Number.isSafeInteger(binding.attempt) || binding.attempt < 1 || binding.attempt > 3 || typeof binding.nonce !== 'string' || !/^[0-9a-f]{64}$/u.test(binding.nonce) ||
    keys.slice(4).some(key => typeof (binding as unknown as Record<string, unknown>)[key] !== 'string' ||
      !/^[0-9a-f]{64}$/u.test((binding as unknown as Record<string, string>)[key]!))) {
    throw new TypeError('invalid original Admin MCP input binding');
  }
  const owner = publicationLocks.get(lock);
  if (!owner) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'Admin MCP input requires its genuine StateOwner lock');
  }
  let native: NativeAdminMcpInput;
  try {
    native = mode === 'create' ? owner.createAdminMcpInput(binding) : mode === 'retained'
      ? owner.openRetainedAdminMcpInput(binding) : owner.openAbsentAdminMcpInput(binding);
  } catch (error) {
    return workerReservationError(error);
  }
  if (native.identity.adminOperationId !== binding.adminOperationId || native.identity.attempt !== binding.attempt ||
    native.identity.nonce !== binding.nonce || native.identity.targetRef !== binding.targetRef || native.identity.probePayloadCoreRef !== binding.probePayloadCoreRef) {
    try {
      native.close();
    } catch (error) {
      throw new ResourceRetirementError('mismatched native Admin MCP input did not retire', error);
    }
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'native Admin MCP input differs from its exact original intent');
  }
  const held = {
    lock, native, bindingDigest: canonicalSha256(binding), processId: process.pid, active: true, mode
  };
  const handle: HeldAdminMcpInput = Object.freeze({
    identity: immutableSnapshot(native.identity),
    assertHeld() {
      if (this !== handle || !held.active || held.processId !== process.pid) {
        throw new TypeError('invalid original Admin MCP input');
      }
      lock.assertHeld();
      try {
        native.assertHeld();
      } catch (error) {
        workerReservationError(error);
      }
    },
    close() {
      if (this !== handle) {
        throw new TypeError('invalid original Admin MCP input');
      }
      if (!held.active) {
        return;
      }
      try {
        native.close();
        held.active = false;
      } catch (error) {
        workerReservationError(error);
      }
    },
  });
  adminMcpInputs.set(handle, held);
  return handle;
}
export const openAdminMcpInput = (lock: HeldStateOwnerLock, input: AdminMcpInputBinding): HeldAdminMcpInput => adminMcpInput(lock, input, 'create');
export const openRetainedAdminMcpInput = (lock: HeldStateOwnerLock, input: AdminMcpInputBinding): HeldAdminMcpInput => adminMcpInput(lock, input, 'retained');
export const openAbsentAdminMcpInput = (lock: HeldStateOwnerLock, input: AdminMcpInputBinding): HeldAdminMcpInput => adminMcpInput(lock, input, 'absent');
/** C-only tagged friend input; this transfers no caller-selected descriptor. */
export function borrowAdminMcpInputForExecution(lock: HeldStateOwnerLock, input: HeldAdminMcpInput, binding: AdminMcpInputBinding): object {
  const held = adminMcpInputs.get(input);
  if (!held || held.lock !== lock || held.processId !== process.pid || held.bindingDigest !== canonicalSha256(binding) || held.mode !== 'create') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'Admin MCP input differs from its exact original physical owner');
  }
  input.assertHeld();
  return held.native;
}
export function borrowRetainedAdminMcpInputForCleanup(lock: HeldStateOwnerLock, input: HeldAdminMcpInput, binding: AdminMcpInputBinding): object {
  const held = adminMcpInputs.get(input);
  if (!held || held.lock !== lock || held.processId !== process.pid || held.bindingDigest !== canonicalSha256(binding) || held.mode !== 'retained') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'MCP cleanup requires the exact reopened original Admin input');
  }
  input.assertHeld();
  return held.native;
}
/** Pure historical projection from the native original-birth/hash-chain
 * decoder. Neither these audit data nor bytes prove a live domain is dead. */
export function decodeAdminMcpLifecycleData(snapshot: Uint8Array): AdminMcpNativeLifecycle {
  const binding = loaded && nativeBindings.get(loaded.implementation);
  if (!binding?.decodeAdminMcpLifecycle) {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'loaded fixed native Admin MCP data decoder is unavailable');
  }
  const decoded = binding.decodeAdminMcpLifecycle(sourceLifecycleBytes(snapshot));
  if (decoded.schemaVersion !== 1 || decoded.format !== 'cliq-mcp-admin-native-lifecycle-v1') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'native Admin MCP lifecycle projection differs');
  }
  return immutableSnapshot(decoded);
}
export type HeldAdminMcpStdioInput = HeldAdminMcpInput;
export type HeldRunMcpStdioInput = Readonly<{
  identity: Readonly<{ runId: string; launchOpId: string; nonce: string; birthIdentity: DescriptorIdentity; privateParentIdentity: DescriptorIdentity }>;
  assertHeld(): void; close(): void;
}>;
export type HeldRecoveryMcpStdioInput = Readonly<{
  identity: Readonly<{ runId: string; originalOpId: string; nonce: string; birthIdentity: DescriptorIdentity; privateParentIdentity: DescriptorIdentity }>;
  assertHeld(): void; close(): void;
}>;
type StdioInput = Readonly<{ identity: HeldAdminMcpStdioInput['identity'] | HeldRunMcpStdioInput['identity'] | HeldRecoveryMcpStdioInput['identity']; assertHeld(): void; close(): void }>;
const stdioInputs = new WeakMap<StdioInput, { lock: HeldStateOwnerLock; native: StdioInput; bindingDigest: string;
  processId: number; active: boolean; purpose: 'admin' | 'run' | 'recovery'; retained: boolean }>();
const stdioAdminStrings = ['adminOperationId', 'principalId', 'nonce', 'targetRef', 'targetDigest', 'probePayloadCoreRef', 'probePayloadCoreDigest',
  'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest'] as const;
const stdioRunStrings = ['runId', 'principalId', 'launchOpId', 'batchItemId', 'callId', 'workerLaunchId', 'supervisorInstanceId', 'nonce',
  'registryRef', 'manifestDigest', 'toolRequestRef', 'toolRequestDigest', 'requestRef', 'requestDigest', 'targetRef', 'targetDigest', 'grantRef', 'grantDigest',
  'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest'] as const;
const stdioRunNumbers = ['attempt', 'lifecycleSeq', 'callIndex', 'leaseEpoch', 'stateOwnerEpoch', 'callDeadlineMs', 'launchDeadlineMs'] as const;
const stdioRecoveryStrings = ['runId', 'principalId', 'probeKind', 'brokerDispatchId', 'inspectorSupervisorInstanceId', 'originalOpId', 'originalDispatchId', 'effectServerToolName', 'adapterExecutableId', 'profileId', 'statusOperationName', 'previousWaitingSubjectRef', 'waitingSubjectRef', 'reconciliationSubjectDigest', 'probeNonceDigest', 'probeDispatchDigest', 'brokerRequestDigest', 'brokerTargetDigest', 'brokerFenceTokenDigest', 'originalInstanceIdentityRef', 'originalInstanceIdentityDigest', 'registryRevisionRef', 'registryManifestDigest', 'adapterRef', 'adapterDigest', 'adapterExecutableDigest', 'profileDigest', 'statusRequestTemplateRef', 'statusRequestTemplateDigest', 'statusRequestDigest', 'plannedContainmentRef', 'plannedContainmentDigest', 'sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'nonce'] as const;
const stdioRecoveryNumbers = ['probeOrdinal', 'probeStartedAtMs', 'probeDeadlineAtMs', 'inspectorStateOwnerEpoch', 'originalAttempt', 'originalDispatchJournalSeq'] as const;
function stdioInputData(input: AdminMcpStdioInputBinding | RunMcpStdioInputBinding | RecoveryMcpStdioInputBinding, purpose: 'admin' | 'run' | 'recovery') {
  const strings = purpose === 'admin' ? stdioAdminStrings : purpose === 'recovery' ? stdioRecoveryStrings : stdioRunStrings;
  const numbers = purpose === 'admin' ? ['attempt'] : purpose === 'recovery' ? stdioRecoveryNumbers : stdioRunNumbers;
  const keys = [...strings, ...numbers, 'originalSupervisorPid', 'originalSupervisorStartToken'];
  if (!input || typeof input !== 'object' || types.isProxy(input)) throw new TypeError('invalid original MCP stdio input');
  const fields = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields, key) ||
      !fields[key]!.enumerable || !Object.hasOwn(fields[key]!, 'value'))) throw new TypeError('invalid original MCP stdio input');
  const data = Object.fromEntries(keys.map(key => [key, fields[key]!.value])) as Record<string, unknown>;
  const firstDigest = purpose === 'admin' ? 2 : purpose === 'recovery' ? 11 : 7;
  for (let i = 0; i < strings.length; i++) {
    const value = data[strings[i]!];
    if (typeof value !== 'string' || value.includes('\0') || !value || Buffer.from(value).toString() !== value ||
        (i < firstDigest ? Buffer.byteLength(value) > 256 : !/^[0-9a-f]{64}$/u.test(value))) throw new TypeError('invalid original MCP stdio input identity');
  }
  for (const key of numbers) if (!Number.isSafeInteger(data[key]) || (data[key] as number) < (['attempt', 'lifecycleSeq', 'callIndex', 'originalAttempt'].includes(key) ? 0 : 1))
    throw new TypeError('invalid original MCP stdio input number');
  if (purpose === 'recovery' && (
      !['automatic', 'user_requested'].includes(data.probeKind as string) ||
      Buffer.byteLength(data.effectServerToolName as string) > 128 || Buffer.byteLength(data.statusOperationName as string) > 128 ||
      data.effectServerToolName === data.statusOperationName || data.previousWaitingSubjectRef === data.waitingSubjectRef ||
      (data.probeStartedAtMs as number) > Number.MAX_SAFE_INTEGER - 30_000 ||
      data.probeDeadlineAtMs !== (data.probeStartedAtMs as number) + 30_000))
    throw new TypeError('invalid original recovery MCP stdio recipe/deadline');
  if (purpose === 'admin' && ((data.attempt as number) < 1 || (data.attempt as number) > 3) ||
      purpose === 'run' && (data.launchDeadlineMs as number) > (data.callDeadlineMs as number) ||
      !Number.isSafeInteger(data.originalSupervisorPid) || (data.originalSupervisorPid as number) < 1 || (data.originalSupervisorPid as number) > 0x7fffffff ||
      typeof data.originalSupervisorStartToken !== 'string' || !/^linux-proc-start-ticks:[1-9]\d{0,19}$/u.test(data.originalSupervisorStartToken))
    throw new TypeError('invalid original MCP stdio input owner or deadline');
  return { binding: Object.freeze(data), arguments: [...strings.map(key => data[key] as string), ...numbers.map(key => data[key] as number),
    data.originalSupervisorPid as number, data.originalSupervisorStartToken as string] };
}
function openStdioInput(lock: HeldStateOwnerLock, input: AdminMcpStdioInputBinding | RunMcpStdioInputBinding | RecoveryMcpStdioInputBinding,
  purpose: 'admin' | 'run' | 'recovery', retained: boolean): StdioInput {
  assertStateOwnerLock(lock); lock.assertHeld();
  const owner = publicationLocks.get(lock), selected = stdioInputData(input, purpose);
  if (!owner) throw new KernelStorageError('ARTIFACT_MISMATCH', 'stdio input requires its genuine held StateOwner');
  let native: StdioInput;
  try {
    if (purpose === 'recovery' && (typeof owner.createRecoveryMcpStdioInput !== 'function' || typeof owner.openRetainedRecoveryMcpStdioInput !== 'function'))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'loaded fixed recovery stdio input owner is unavailable');
    native = purpose === 'recovery' ? (retained ? owner.openRetainedRecoveryMcpStdioInput!(...selected.arguments) : owner.createRecoveryMcpStdioInput!(...selected.arguments)) : purpose === 'admin' ? (retained ? owner.openRetainedAdminMcpStdioInput(...selected.arguments) : owner.createAdminMcpStdioInput(...selected.arguments)) :
      (retained ? owner.openRetainedRunMcpStdioInput(...selected.arguments) : owner.createRunMcpStdioInput(...selected.arguments));
    native.assertHeld();
  } catch (error) { return workerReservationError(error); }
  const identity = native.identity, data = selected.binding;
  if (identity.nonce !== data.nonce || (purpose === 'recovery' ? !('runId' in identity) || identity.runId !== data.runId || !('originalOpId' in identity) || identity.originalOpId !== data.originalOpId : purpose === 'run' ? !('runId' in identity) || identity.runId !== data.runId || !('launchOpId' in identity) || identity.launchOpId !== data.launchOpId :
      !('adminOperationId' in identity) || identity.adminOperationId !== data.adminOperationId || identity.attempt !== data.attempt ||
      identity.targetRef !== data.targetRef || identity.probePayloadCoreRef !== data.probePayloadCoreRef)) {
    try { native.close(); } catch (error) { throw new ResourceRetirementError('mismatched stdio physical input did not retire', error); }
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'stdio physical input changes its original binding');
  }
  const held = { lock, native, bindingDigest: canonicalSha256(selected.binding), processId: process.pid, active: true, purpose, retained };
  const handle = Object.freeze({ identity: immutableSnapshot(identity),
    assertHeld() {
      if (this !== handle || !held.active || held.processId !== process.pid) throw new TypeError('invalid original stdio input');
      lock.assertHeld(); try { native.assertHeld(); } catch (error) { workerReservationError(error); }
    },
    close() {
      if (this !== handle || held.processId !== process.pid) throw new TypeError('invalid original stdio input');
      if (!held.active) return;
      try { native.close(); held.active = false; } catch (error) { workerReservationError(error); }
    }
  });
  stdioInputs.set(handle, held); return handle;
}
export const openAdminMcpStdioInput = (lock: HeldStateOwnerLock, input: AdminMcpStdioInputBinding): HeldAdminMcpStdioInput =>
  openStdioInput(lock, input, 'admin', false) as HeldAdminMcpStdioInput;
export const openRetainedAdminMcpStdioInput = (lock: HeldStateOwnerLock, input: AdminMcpStdioInputBinding): HeldAdminMcpStdioInput =>
  openStdioInput(lock, input, 'admin', true) as HeldAdminMcpStdioInput;
export const openRunMcpStdioInput = (lock: HeldStateOwnerLock, input: RunMcpStdioInputBinding): HeldRunMcpStdioInput =>
  openStdioInput(lock, input, 'run', false) as HeldRunMcpStdioInput;
export const openRetainedRunMcpStdioInput = (lock: HeldStateOwnerLock, input: RunMcpStdioInputBinding): HeldRunMcpStdioInput =>
  openStdioInput(lock, input, 'run', true) as HeldRunMcpStdioInput;
export const openRecoveryMcpStdioInput = (lock: HeldStateOwnerLock, input: RecoveryMcpStdioInputBinding): HeldRecoveryMcpStdioInput =>
  openStdioInput(lock, input, 'recovery', false) as HeldRecoveryMcpStdioInput;
export const openRetainedRecoveryMcpStdioInput = (lock: HeldStateOwnerLock, input: RecoveryMcpStdioInputBinding): HeldRecoveryMcpStdioInput =>
  openStdioInput(lock, input, 'recovery', true) as HeldRecoveryMcpStdioInput;
export function borrowMcpStdioInput(lock: HeldStateOwnerLock, input: StdioInput, binding: AdminMcpStdioInputBinding | RunMcpStdioInputBinding | RecoveryMcpStdioInputBinding,
  purpose: 'admin' | 'run' | 'recovery', retained: boolean): object {
  const held = stdioInputs.get(input), data = stdioInputData(binding, purpose);
  if (!held || held.lock !== lock || held.purpose !== purpose || held.retained !== retained || held.processId !== process.pid ||
      held.bindingDigest !== canonicalSha256(data.binding)) throw new KernelStorageError('ARTIFACT_MISMATCH', 'stdio input is not its original purpose and physical owner');
  input.assertHeld(); return held.native;
}
export function decodeMcpStdioRecoveryLifecycleData(snapshot: Uint8Array): McpStdioRecoveryNativeLifecycle {
  const binding = loaded && nativeBindings.get(loaded.implementation);
  if (!binding?.decodeMcpStdioRecoveryLifecycle) throw new KernelStorageError('RECOVERY_REQUIRED', 'loaded fixed recovery stdio lifecycle decoder is unavailable');
  const data = binding.decodeMcpStdioRecoveryLifecycle(sourceLifecycleBytes(snapshot));
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-stdio-recovery-native-lifecycle-v1' || data.binding.kind !== 'recovery')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'recovery stdio native lifecycle purpose differs');
  return immutableSnapshot(data);
}
export function decodeMcpStdioRecoveryCleanupData(snapshot: Uint8Array): McpStdioRecoveryNativeCleanup {
  const binding = loaded && nativeBindings.get(loaded.implementation);
  if (!binding?.decodeMcpStdioRecoveryCleanup) throw new KernelStorageError('RECOVERY_REQUIRED', 'loaded fixed recovery stdio cleanup decoder is unavailable');
  const data = binding.decodeMcpStdioRecoveryCleanup(sourceLifecycleBytes(snapshot));
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-stdio-recovery-native-cleanup-v1' || data.originalBinding.kind !== 'recovery')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'recovery stdio native cleanup purpose differs');
  return immutableSnapshot(data);
}
export function decodeMcpStdioLifecycleData(snapshot: Uint8Array): McpStdioNativeLifecycle {
  const binding = loaded && nativeBindings.get(loaded.implementation);
  if (!binding?.decodeMcpStdioLifecycle) throw new KernelStorageError('RECOVERY_REQUIRED', 'loaded fixed stdio lifecycle decoder is unavailable');
  const data = binding.decodeMcpStdioLifecycle(sourceLifecycleBytes(snapshot));
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-stdio-native-lifecycle-v1') throw new KernelStorageError('ARTIFACT_MISMATCH', 'stdio native lifecycle format differs');
  return immutableSnapshot(data);
}
export function decodeMcpStdioCleanupData(snapshot: Uint8Array): McpStdioNativeCleanup {
  const binding = loaded && nativeBindings.get(loaded.implementation);
  if (!binding?.decodeMcpStdioCleanup) throw new KernelStorageError('RECOVERY_REQUIRED', 'loaded fixed stdio cleanup decoder is unavailable');
  const data = binding.decodeMcpStdioCleanup(sourceLifecycleBytes(snapshot));
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-stdio-native-cleanup-v1') throw new KernelStorageError('ARTIFACT_MISMATCH', 'stdio native cleanup format differs');
  return immutableSnapshot(data);
}
/** Complete raw-to-original-source audit only, never a live current receipt. */
export function decodeMcpAdminOriginalRetirementData(snapshot: Uint8Array, originalLifecycle: Uint8Array): McpAdminOriginalRetirement {
  const binding = loaded && nativeBindings.get(loaded.implementation);
  if (!binding?.decodeMcpAdminOriginalRetirement) throw new KernelStorageError('RECOVERY_REQUIRED', 'loaded fixed Admin current retirement decoder is unavailable');
  const data = binding.decodeMcpAdminOriginalRetirement(sourceLifecycleBytes(snapshot), sourceLifecycleBytes(originalLifecycle));
  if (data.schemaVersion !== 1 || data.format !== 'cliq-mcp-admin-original-retirement-v1')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'Admin original current retirement format differs');
  return immutableSnapshot(data);
}
/** Physical birth witness only. It grants neither activation nor death proof. */
export type HeldWorkerReservation = Readonly<{ identity: DescriptorIdentity; assertHeld(): void; close(): void }>;
type NativeWorkerReservation = HeldWorkerReservation & { borrow(): Readonly<{ fd: number; identity: DescriptorIdentity; assertHeld(): void; close(): void }>;
  borrowPreparingGit(tree: object, launchId: string, spawnNonceDigest: string, activationNonceDigest: string,
    creationNonceDigest: string, generationRef: string, inputIntentRef: string): HeldPreparingGitInput;
  borrowPreparingGitCleanup(runId: string, generationId: string, launchId: string, spawnNonceDigest: string, activationNonceDigest: string,
    creationNonceDigest: string, generationRef: string, inputIntentRef: string, generationDeviceId: string, generationFileId: string,
    originalSupervisorPid: number, originalSupervisorStartToken: string): HeldRetainedPreparingGitInput };
const workerReservations = new WeakMap<HeldWorkerReservation,
  { lock: HeldStateOwnerLock; native: NativeWorkerReservation; launchId: string; spawnNonceDigest: string; closed: boolean }>();
function checkedWorkerReservation(launchId: string, spawnNonceDigest: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(launchId) || !/^[0-9a-f]{64}$/u.test(spawnNonceDigest)) {
    throw new KernelStorageError('INVALID_REQUEST', 'worker reservation requires the exact launch and spawn nonce');
  }
  return identityHash('cliq-worker-reservation-v1', launchId, spawnNonceDigest);
}
function workerReservationError(error: unknown): never {
  if (error instanceof KernelStorageError || error instanceof ResourceRetirementError) throw error;
  if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
    throw new ResourceRetirementError('worker reservation descriptors did not retire', error);
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'exact native worker reservation is not held');
}
function wrapWorkerReservation(lock: HeldStateOwnerLock, native: NativeWorkerReservation, launchId: string,
  spawnNonceDigest: string): HeldWorkerReservation {
  const handle: HeldWorkerReservation = Object.freeze({ identity: Object.freeze({ ...native.identity }),
    assertHeld() {
      if (this !== handle) throw new TypeError('invalid worker reservation');
      try { lock.assertHeld(); native.assertHeld(); } catch (error) { workerReservationError(error); }
    },
    close() {
      if (this !== handle) throw new TypeError('invalid worker reservation');
      try { native.close(); workerReservations.get(handle)!.closed = true; } catch (error) { workerReservationError(error); }
    }
  });
  workerReservations.set(handle, { lock, native, launchId, spawnNonceDigest, closed: false });
  return handle;
}
/** Internal descriptor bridge between the two installed native modules. */
export function borrowWorkerReservationForExecution(reservation: HeldWorkerReservation, launchId: string,
  spawnNonceDigest: string) {
  const held = workerReservations.get(reservation);
  if (!held || held.launchId !== launchId || held.spawnNonceDigest !== spawnNonceDigest) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'native witness belongs to a different launch reservation');
  }
  reservation.assertHeld();
  try { return held.native.borrow(); } catch (error) { workerReservationError(error); }
}
/** Only the exact original native close can set this joined state. It closes
 * every duplicate before returning, and any error keeps the StateOwner held. */
export function readWorkerReservationRetirement(lock: HeldStateOwnerLock, reservation: HeldWorkerReservation,
  launchId: string, spawnNonceDigest: string): DescriptorIdentity {
  const held = workerReservations.get(reservation);
  if (!held || held.lock !== lock || held.launchId !== launchId || held.spawnNonceDigest !== spawnNonceDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'reservation retirement substitutes its exact original physical owner');
  lock.assertHeld();
  if (!held.closed) throw new KernelStorageError('RECOVERY_REQUIRED', 'original worker reservation descriptors are not joined');
  return reservation.identity;
}
export type PreparingGitInputBinding = Readonly<{ runId: string; generationId: string; launchId: string;
  spawnNonceDigest: string; activationNonceDigest: string; generationCreationNonceDigest: string; generationRef: string; inputIntentRef: string }>;
export type HeldPreparingGitInput = Readonly<{ identity: PreparingGitInputBinding & Readonly<{ reservation: DescriptorIdentity; generation: DescriptorIdentity;
  originalSupervisorPid: number; originalSupervisorStartToken: string }>;
  assertHeld(): void; close(): void }>;
const preparingGitInputs = new WeakMap<HeldPreparingGitInput, { lock: HeldStateOwnerLock; native: HeldPreparingGitInput }>();
export type HeldRetainedPreparingGitInput = HeldPreparingGitInput;
const retainedPreparingGitInputs = new WeakMap<HeldRetainedPreparingGitInput, { lock: HeldStateOwnerLock; native: HeldRetainedPreparingGitInput }>();
/** Physical same-lock friend only. The StateStore's original preparing cut
 * owns business authority; a client cannot mint or substitute this handle. */
export function openPreparingGitInput(lock: HeldStateOwnerLock, reservation: HeldWorkerReservation, tree: HeldGenerationTree,
  input: PreparingGitInputBinding): HeldPreparingGitInput {
  const held = workerReservations.get(reservation), nativeTree = nativeTrees.get(tree);
  if (!held || held.lock !== lock || !nativeTree) throw new KernelStorageError('ARTIFACT_MISMATCH', 'original preparing Git reservation and generation are required');
  if (!input || typeof input !== 'object' || types.isProxy(input)) throw new TypeError('invalid preparing Git input binding');
  const keys = ['runId', 'generationId', 'launchId', 'spawnNonceDigest', 'activationNonceDigest', 'generationCreationNonceDigest', 'generationRef', 'inputIntentRef'];
  const fields = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields, key) ||
      !fields[key]!.enumerable || !Object.hasOwn(fields[key]!, 'value') || typeof fields[key]!.value !== 'string'))
    throw new TypeError('invalid preparing Git input binding');
  const binding = Object.fromEntries(keys.map(key => [key, fields[key]!.value])) as PreparingGitInputBinding;
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(binding.runId) || !/^[A-Za-z0-9_-]{43}$/u.test(binding.generationId) ||
      binding.launchId !== held.launchId || binding.spawnNonceDigest !== held.spawnNonceDigest)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'original preparing Git reservation differs from its selected launch');
  for (const key of ['activationNonceDigest', 'generationCreationNonceDigest', 'generationRef', 'inputIntentRef'] as const)
    if (!/^[0-9a-f]{64}$/u.test(binding[key])) throw new TypeError('invalid preparing Git input digest');
  lock.assertHeld(); reservation.assertHeld(); tree.assertHeld();
  let native: HeldPreparingGitInput;
  try { native = held.native.borrowPreparingGit(nativeTree, binding.launchId, binding.spawnNonceDigest, binding.activationNonceDigest,
    binding.generationCreationNonceDigest, binding.generationRef, binding.inputIntentRef); }
  catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'original preparing Git input was not acquired', { cause }); }
  const identity = Object.freeze({ ...native.identity, reservation: Object.freeze({ ...native.identity.reservation }), generation: Object.freeze({ ...native.identity.generation }) });
  if (keys.some(key => identity[key as keyof PreparingGitInputBinding] !== binding[key as keyof PreparingGitInputBinding])) {
    try { native.close(); } catch (cause) { throw new ResourceRetirementError('mismatched preparing Git input did not retire', cause); }
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'original preparing Git input differs from its physical generation');
  }
  const handle: HeldPreparingGitInput = Object.freeze({ identity,
    assertHeld() {
      if (this !== handle) throw new TypeError('invalid original preparing Git input');
      lock.assertHeld();
      try { native.assertHeld(); } catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'original preparing Git input is not held', { cause }); }
    },
    close() {
      if (this !== handle) throw new TypeError('invalid original preparing Git input');
      try { native.close(); } catch (cause) { throw new ResourceRetirementError('original preparing Git input did not retire', cause); }
    }
  });
  preparingGitInputs.set(handle, { lock, native }); return handle;
}
/** Only the separately loaded signed native receiver can consume its C tag.
 * No numerical descriptor or caller-selected execution operation is exposed. */
export function borrowPreparingGitInputForExecution(input: HeldPreparingGitInput): object {
  const binding = preparingGitInputs.get(input);
  if (!binding) throw new TypeError('invalid original preparing Git input');
  input.assertHeld(); return binding.native;
}
/** The caller's original preparing graph supplies expected inert identities;
 * only the separately tagged native checker can close the physical prefix. */
export function openRetainedPreparingGitInput(lock: HeldStateOwnerLock, reservation: HeldWorkerReservation,
  input: PreparingGitInputBinding, generation: DescriptorIdentity, supervisor: Readonly<{ pid: number; processStartToken: string }>): HeldRetainedPreparingGitInput {
  const held = workerReservations.get(reservation);
  if (!held || held.lock !== lock || !input || types.isProxy(input) || !generation || types.isProxy(generation) || !supervisor || types.isProxy(supervisor))
    throw new TypeError('retained preparing cleanup requires its original reservation and closed data');
  const keys = ['runId', 'generationId', 'launchId', 'spawnNonceDigest', 'activationNonceDigest', 'generationCreationNonceDigest', 'generationRef', 'inputIntentRef'];
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(key => !Object.hasOwn(descriptors, key) ||
      !Object.hasOwn(descriptors[key]!, 'value') || typeof descriptors[key]!.value !== 'string')) throw new TypeError('invalid retained preparing binding');
  const binding = Object.fromEntries(keys.map(key => [key, descriptors[key]!.value])) as PreparingGitInputBinding;
  const inert = (value: object, expected: readonly string[]) => {
    const fields = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(fields).length !== expected.length || expected.some(key => !Object.hasOwn(fields, key) || !Object.hasOwn(fields[key]!, 'value')))
      throw new TypeError('retained preparing identities require closed own data');
    return Object.fromEntries(expected.map(key => [key, fields[key]!.value]));
  };
  const physical = inert(generation, ['deviceId', 'fileId', 'ownerUid']), process = inert(supervisor, ['pid', 'processStartToken']);
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(binding.runId) || !/^[A-Za-z0-9_-]{43}$/u.test(binding.generationId) ||
      binding.launchId !== held.launchId || binding.spawnNonceDigest !== held.spawnNonceDigest ||
      typeof physical.deviceId !== 'string' || !/^[1-9][0-9]*$/u.test(physical.deviceId) || typeof physical.fileId !== 'string' || !/^[1-9][0-9]*$/u.test(physical.fileId) ||
      physical.ownerUid !== reservation.identity.ownerUid || !Number.isSafeInteger(process.pid) || process.pid < 1 || process.pid > 2_147_483_647 ||
      typeof process.processStartToken !== 'string' || process.processStartToken.length < 1 || process.processStartToken.length > 127)
    throw new TypeError('invalid original retained preparing identities');
  for (const key of ['activationNonceDigest', 'generationCreationNonceDigest', 'generationRef', 'inputIntentRef'] as const)
    if (!/^[0-9a-f]{64}$/u.test(binding[key])) throw new TypeError('invalid retained preparing digest');
  lock.assertHeld(); reservation.assertHeld();
  let native: HeldRetainedPreparingGitInput;
  try { native = held.native.borrowPreparingGitCleanup(binding.runId, binding.generationId, binding.launchId, binding.spawnNonceDigest,
    binding.activationNonceDigest, binding.generationCreationNonceDigest, binding.generationRef, binding.inputIntentRef,
    physical.deviceId, physical.fileId, process.pid, process.processStartToken); }
  catch (cause) {
    if ((cause as NodeJS.ErrnoException | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('retained preparing input construction did not retire', cause);
    throw new KernelStorageError('RECOVERY_REQUIRED', 'retained preparing input was not acquired', { cause });
  }
  const identity = Object.freeze({ ...native.identity, reservation: Object.freeze({ ...native.identity.reservation }), generation: Object.freeze({ ...native.identity.generation }) });
  const handle: HeldRetainedPreparingGitInput = Object.freeze({ identity,
    assertHeld() { if (this !== handle) throw new TypeError('invalid retained preparing input'); lock.assertHeld(); native.assertHeld(); },
    close() { if (this !== handle) throw new TypeError('invalid retained preparing input');
      try { native.close(); } catch (cause) { throw new ResourceRetirementError('retained preparing input did not retire', cause); } }
  });
  retainedPreparingGitInputs.set(handle, { lock, native }); return handle;
}
/** Closed-input provenance only. Cleanup joins consume the native input before
 * the final transaction; its original owning lock must still be the same one. */
export function assertRetainedPreparingGitInputOwner(lock: HeldStateOwnerLock, input: HeldRetainedPreparingGitInput): void {
  const held = retainedPreparingGitInputs.get(input);
  if (!held || held.lock !== lock) throw new TypeError('retained preparing receipt belongs to another physical StateOwner');
  lock.assertHeld();
}

export function borrowRetainedPreparingGitInputForCleanup(input: HeldRetainedPreparingGitInput): object {
  const held = retainedPreparingGitInputs.get(input);
  if (!held) throw new TypeError('invalid cleanup-only preparing input'); input.assertHeld(); return held.native;
}
export type SourceInspectionStagingIdentity = DescriptorIdentity & Readonly<{ mode: 448 }>;
/** Physical source-inspection reservation only, never a Run or execution FD. */
export type HeldSourceInspectionStaging = Readonly<{
  identity: SourceInspectionStagingIdentity;
  assertHeld(): void;
  close(): void;
}>;
export type SourceInspectionStagingRetirement = Readonly<{ kind: 'physical_source_staging_retirement' }>;
type SourceInspectionStagingBinding = Readonly<{
  lock: HeldStateOwnerLock;
  native: NativeSourceInspectionStaging;
  inspectionId: string;
  stagingNonceDigest: string;
  stagingIdentity: SourceInspectionStagingIdentity;
  created: boolean;
}>;
type NativeSourceInspectionStaging = Readonly<{
  identity: DescriptorIdentity;
  assertHeld(): void;
  readPresence(): 'present' | 'absent';
  close(): void;
  retireStep(): boolean;
  assertRetired(): void;
  borrowGitInput(root: HeldWorkspaceRoot, inspectionId: string, stagingNonceDigest: string,
    targetRef: string, inputIntentRef: string): NativeSourceGitInput;
  openGitInput(inspectionId: string, stagingNonceDigest: string, targetRef: string, inputIntentRef: string): NativeSourceGitInput;
  openAbsentGitInput(lifecycle: Buffer, inspectionId: string, stagingNonceDigest: string,
    targetRef: string, inputIntentRef: string): NativeRegisteredAbsentSourceGitInput;
}>;
export type SourceGitInputIdentity = Readonly<{
  inspectionId: string;
  stagingNonceDigest: string;
  targetRef: string;
  inputIntentRef: string;
  birthIdentity: DescriptorIdentity;
}>;
/** Same-attempt physical descriptors and a durable native birth bookmark.
 * This is neither source permission nor a release/continuation capability. */
export type HeldSourceGitInput = Readonly<{
  identity: SourceGitInputIdentity;
  assertHeld(): void;
  close(): void;
}>;
declare const retainedSourceGitInputBrand: unique symbol;
/** Physical cleanup input only. No workspace/root payload or execution borrow
 * exists on this distinct native tag, including when the old root moved. */
export type HeldRetainedSourceGitInput = HeldSourceGitInput & Readonly<{ [retainedSourceGitInputBrand]: true }>;
type NativeSourceGitInput = HeldSourceGitInput;
export type SourceGitNativeLifecycleV2 = Readonly<{
  format: 'cliq-source-native-lifecycle-v2'; lifecycleDigest: string; byteCount: number;
  birthIdentity: DescriptorIdentity;
  inspectionId: string; stagingNonceDigest: string; targetRef: string; inputIntentRef: string;
  stateRoot: DescriptorIdentity & { ownerGid: number; mode: 448 };
  runtime: DescriptorIdentity & { ownerGid: number; mode: 448 };
  sourceParent: DescriptorIdentity & { ownerGid: number; mode: 448 };
  staging: DescriptorIdentity & { ownerGid: number; mode: 448 };
  workspaceDeviceId: string; workspaceFileId: string; gitDeviceId: string; gitFileId: string;
  pidNamespaceId: string | null;
  originalSupervisorPid: number; originalSupervisorStartToken: string;
  controllerRoot: DescriptorIdentity & { ownerGid: number; mode: 448 };
  controllerParent: DescriptorIdentity & { ownerGid: number; mode: 448 };
  controllerLeaf: DescriptorIdentity & { ownerGid: number; mode: 448 };
  controllerLeafName: string; originalControllerPid: number; originalControllerStartToken: string;
  recordCount: number; lastBirthKind: number; reserved: 0 | 1; blocked: 0 | 1; released: 0 | 1; continued: 0 | 1;
  cgroupDeviceId: string | null; cgroupId: string | null; launchNonceDigest: string | null;
  containmentPlanRef: string | null; sandboxLaunchRef: string | null; sandboxLaunchDigest: string | null;
  processes: readonly Readonly<{ role: 'monitor' | 'worker' | 'namespace_init'; pid: number; processStartToken: string }>[];
  snapshotDigest?: string; sourceByteCount?: number; entryCount?: number; shardCount?: number;
}>;
declare const registeredAbsentSourceGitInputBrand: unique symbol;
export type HeldRegisteredAbsentSourceGitInput = Readonly<{
  identity: Omit<SourceGitInputIdentity, 'birthIdentity'> & { snapshotIdentity: DescriptorIdentity };
  assertHeld(): void; close(): void; readonly [registeredAbsentSourceGitInputBrand]: true;
}>;
type NativeRegisteredAbsentSourceGitInput = Omit<HeldRegisteredAbsentSourceGitInput, typeof registeredAbsentSourceGitInputBrand>;
const sourceGitInputs = new WeakMap<HeldSourceGitInput,
  Readonly<{ lock: HeldStateOwnerLock; native: NativeSourceGitInput }>>();
const retainedSourceGitInputs = new WeakMap<HeldRetainedSourceGitInput,
  Readonly<{ lock: HeldStateOwnerLock; native: NativeSourceGitInput }>>();
const registeredAbsentSourceGitInputs = new WeakMap<HeldRegisteredAbsentSourceGitInput,
  Readonly<{ lock: HeldStateOwnerLock; native: NativeRegisteredAbsentSourceGitInput }>>();
const registeredAbsentSourceStagings = new WeakSet<SourceInspectionStagingBinding>();
const sourceStagings = new WeakMap<HeldSourceInspectionStaging, SourceInspectionStagingBinding>();
const sourceRetirements = new WeakMap<SourceInspectionStagingRetirement, SourceInspectionStagingBinding>();
const sourceRetirementTasks = new WeakMap<HeldSourceInspectionStaging, Promise<SourceInspectionStagingRetirement>>();
const sourceRetirementsByLock = new WeakMap<HeldStateOwnerLock, Set<Promise<SourceInspectionStagingRetirement>>>();

function sourceStagingError(error: unknown): never {
  if (error instanceof KernelStorageError) throw error;
  if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
    throw new ResourceRetirementError('source staging resource retirement failed', error);
  }
  throw new KernelStorageError('RECOVERY_REQUIRED', 'source inspection staging identity or reservation is not valid');
}
function checkedSourceInspection(inspectionId: string, stagingNonceDigest: string): string {
  if (typeof inspectionId !== 'string' || typeof stagingNonceDigest !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(inspectionId) || !/^[0-9a-f]{64}$/.test(stagingNonceDigest))
    throw new KernelStorageError('INVALID_REQUEST', 'source staging requires the canonical inspection id and nonce digest');
  return identityHash(inspectionId, stagingNonceDigest);
}
function wrapSourceInspectionStaging(lock: HeldStateOwnerLock, native: NativeSourceInspectionStaging,
  inspectionId: string, stagingNonceDigest: string, created: boolean): HeldSourceInspectionStaging {
  const identity: SourceInspectionStagingIdentity = Object.freeze({ ...native.identity, mode: 448 });
  const staging: HeldSourceInspectionStaging = Object.freeze({ identity,
    assertHeld() {
      if (this !== staging) throw new TypeError('invalid source inspection staging handle');
      try { native.assertHeld(); } catch (error) { sourceStagingError(error); }
    },
    close() {
      if (this !== staging) throw new TypeError('invalid source inspection staging handle');
      try { native.close(); } catch (error) { sourceStagingError(error); }
    }
  });
  sourceStagings.set(staging, Object.freeze({ lock, native, inspectionId, stagingNonceDigest, stagingIdentity: identity, created }));
  return staging;
}
function sourceStagingBinding(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging): SourceInspectionStagingBinding {
  const binding = sourceStagings.get(staging);
  if (!binding || binding.lock !== lock) throw new KernelStorageError('ARTIFACT_MISMATCH', 'source staging was not minted by this exact StateOwner');
  lock.assertHeld();
  return binding;
}
/** Internal native-to-native descriptor friend. It never exports a numerical
 * FD or accepts a replacement workspace, staging, command, or authority. */
export function openHeldSourceGitInput(lock: HeldStateOwnerLock, root: HeldWorkspaceRoot,
  staging: HeldSourceInspectionStaging, input: Readonly<{ targetRef: string; inputIntentRef: string }>): HeldSourceGitInput {
  assertHeldWorkspaceRoot(root);
  const binding = sourceStagingBinding(lock, staging);
  if (!binding.created) throw new KernelStorageError('ARTIFACT_MISMATCH', 'source Git input requires its original new staging');
  staging.assertHeld();
  const refs = sourceGitReferences(input);
  let native: NativeSourceGitInput;
  try { native = binding.native.borrowGitInput(root, binding.inspectionId, binding.stagingNonceDigest, refs.targetRef, refs.inputIntentRef); }
  catch (error) { sourceStagingError(error); }
  const handle = wrapSourceGitInput(lock, native);
  sourceGitInputs.set(handle, Object.freeze({ lock, native }));
  return handle;
}
function sourceGitReferences(input: Readonly<{ targetRef: string; inputIntentRef: string }>) {
  if (input === null || typeof input !== 'object' || types.isProxy(input)) throw new TypeError('invalid source Git input references');
  const fields = Object.getOwnPropertyDescriptors(input), keys = Reflect.ownKeys(fields);
  if (keys.length !== 2 || !Object.hasOwn(fields, 'targetRef') || !Object.hasOwn(fields, 'inputIntentRef') ||
      keys.some(key => typeof key !== 'string') ||
      !['targetRef', 'inputIntentRef'].every(key => Object.hasOwn(fields[key]!, 'value') &&
        typeof fields[key]!.value === 'string' && /^[0-9a-f]{64}$/u.test(fields[key]!.value)))
    throw new TypeError('invalid source Git input references');
  return { targetRef: fields.targetRef!.value as string, inputIntentRef: fields.inputIntentRef!.value as string };
}
function wrapSourceGitInput(lock: HeldStateOwnerLock, native: NativeSourceGitInput): HeldSourceGitInput {
  const identity = Object.freeze({ ...native.identity, birthIdentity: Object.freeze({ ...native.identity.birthIdentity }) });
  const handle: HeldSourceGitInput = Object.freeze({ identity,
    assertHeld() {
      if (this !== handle) throw new TypeError('invalid source Git input');
      try { lock.assertHeld(); native.assertHeld(); }
      catch (error) {
        if (error instanceof ResourceRetirementError) throw error;
        if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
          throw new ResourceRetirementError('source Git input did not retire', error);
        throw new KernelStorageError('RECOVERY_REQUIRED', 'original source Git input is not held');
      }
    },
    close() {
      if (this !== handle) throw new TypeError('invalid source Git input');
      try { native.close(); } catch (error) {
        throw new ResourceRetirementError('source Git input did not retire', error);
      }
    }
  });
  return handle;
}
export function openRetainedSourceGitInput(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging,
  input: Readonly<{ targetRef: string; inputIntentRef: string }>): HeldRetainedSourceGitInput {
  const binding = sourceStagingBinding(lock, staging);
  if (binding.created) throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained source cleanup requires reopened original staging');
  staging.assertHeld(); const refs = sourceGitReferences(input);
  let native: NativeSourceGitInput;
  try { native = binding.native.openGitInput(binding.inspectionId, binding.stagingNonceDigest, refs.targetRef, refs.inputIntentRef); }
  catch (error) { sourceStagingError(error); }
  const handle = wrapSourceGitInput(lock, native) as HeldRetainedSourceGitInput;
  retainedSourceGitInputs.set(handle, Object.freeze({ lock, native })); return handle;
}
/** Cleanup-only native friend. It cannot be passed to reserveSourceGit: the
 * independently loaded native receiver requires the distinct retained tag. */
export function borrowRetainedSourceGitInputForCleanup(input: HeldRetainedSourceGitInput): NativeSourceGitInput {
  const binding = retainedSourceGitInputs.get(input);
  if (!binding) throw new TypeError('invalid retained source Git input');
  input.assertHeld(); return binding.native;
}
/** A complete registered birth is data only. This reader independently runs
 * the native closed decoder, including every original progress checksum. */
function sourceLifecycleBytes(value: Uint8Array): Buffer {
  if (!value || typeof value !== 'object' || types.isProxy(value) || !types.isUint8Array(value))
    throw new TypeError('source lifecycle requires bounded complete bytes');
  const prototype = Object.getPrototypeOf(Uint8Array.prototype);
  const read = (key: string) => Object.getOwnPropertyDescriptor(prototype, key)!.get!.call(value);
  const length: number = read('byteLength');
  if (length < 1 || length > 1_048_576) throw new TypeError('source lifecycle requires bounded complete bytes');
  return Buffer.from(new Uint8Array(read('buffer') as ArrayBuffer, read('byteOffset') as number, length));
}
export function decodeSourceGitNativeLifecycle(snapshot: Uint8Array): SourceGitNativeLifecycleV2 {
  // Reuse only the already genuinely loaded fixed helper. This data audit
  // opens no image, StateRoot, lock or process and establishes no new trust.
  const binding = loaded && nativeBindings.get(loaded.implementation);
  if (!binding?.decodeSourceGitLifecycle)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'the loaded fixed native source decoder is unavailable');
  const bytes = sourceLifecycleBytes(snapshot), data = binding.decodeSourceGitLifecycle(bytes);
  if (data.lifecycleDigest !== sha256Bytes(bytes) || data.byteCount !== bytes.length ||
      data.format !== 'cliq-source-native-lifecycle-v2') throw new KernelStorageError('ARTIFACT_MISMATCH', 'source lifecycle native projection differs');
  return immutableSnapshot(data);
}
export function openRegisteredAbsentSourceGitInput(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging,
  refs: Readonly<{ targetRef: string; inputIntentRef: string }>, lifecycle: Uint8Array): HeldRegisteredAbsentSourceGitInput {
  const binding = sourceStagingBinding(lock, staging);
  if (binding.created) throw new TypeError('registered absent cleanup requires the original retained staging');
  const snapshot = sourceLifecycleBytes(lifecycle);
  const checked = sourceGitReferences(refs), data = decodeSourceGitNativeLifecycle(snapshot);
  if (data.inspectionId !== binding.inspectionId || data.stagingNonceDigest !== binding.stagingNonceDigest ||
      data.targetRef !== checked.targetRef || data.inputIntentRef !== checked.inputIntentRef ||
      data.staging.deviceId !== binding.stagingIdentity.deviceId || data.staging.fileId !== binding.stagingIdentity.fileId ||
      data.staging.ownerUid !== binding.stagingIdentity.ownerUid || data.staging.mode !== 448)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'registered absent lifecycle differs from its retained staging');
  let native: NativeRegisteredAbsentSourceGitInput;
  try { native = binding.native.openAbsentGitInput(snapshot, binding.inspectionId, binding.stagingNonceDigest,
    checked.targetRef, checked.inputIntentRef); } catch (error) { sourceStagingError(error); }
  const identity = Object.freeze({ ...native.identity, snapshotIdentity: Object.freeze({ ...native.identity.snapshotIdentity }) });
  const handle: NativeRegisteredAbsentSourceGitInput = Object.freeze({ identity,
    assertHeld() { if (this !== handle) throw new TypeError('invalid registered absent source input');
      try { lock.assertHeld(); native.assertHeld(); } catch (error) { sourceStagingError(error); } },
    close() { if (this !== handle) throw new TypeError('invalid registered absent source input');
      try { native.close(); } catch (error) { sourceStagingError(error); } }
  });
  const branded = handle as HeldRegisteredAbsentSourceGitInput;
  registeredAbsentSourceGitInputs.set(branded, Object.freeze({ lock, native }));
  registeredAbsentSourceStagings.add(binding); return branded;
}
/** Distinct cleanup-only native tag; fresh reserve() independently refuses it. */
export function borrowRegisteredAbsentSourceGitInputForCleanup(input: HeldRegisteredAbsentSourceGitInput): NativeRegisteredAbsentSourceGitInput {
  const binding = registeredAbsentSourceGitInputs.get(input);
  if (!binding) throw new TypeError('invalid registered absent source input');
  input.assertHeld(); return binding.native;
}
/** Private installed-composition bridge. A matching plain object cannot issue
 * a native scope; the receiver independently checks the C type tag and ABI. */
export function borrowSourceGitInputForExecution(input: HeldSourceGitInput): NativeSourceGitInput {
  const binding = sourceGitInputs.get(input);
  if (!binding) throw new TypeError('invalid source Git input');
  input.assertHeld();
  return binding.native;
}
/** Current same-lock observation only. Retained staging remains cleanup-only;
 * this does not satisfy the distinct created-only admission friend below. */
export function readHeldSourceInspectionStaging(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging):
  Readonly<{ inspectionId: string; stagingNonceDigest: string; stagingIdentity: SourceInspectionStagingIdentity }> {
  const binding = sourceStagingBinding(lock, staging);
  staging.assertHeld();
  return Object.freeze({ inspectionId: binding.inspectionId, stagingNonceDigest: binding.stagingNonceDigest,
    stagingIdentity: binding.stagingIdentity });
}
/** A current native locator observation for cleanup branch selection only.
 * It is no execution, recovery or retirement proof. Both cleanup constructors
 * must independently recheck their original identity after this read. */
export function readSourceInspectionStagingPresence(lock: HeldStateOwnerLock,
  staging: HeldSourceInspectionStaging): 'present' | 'absent' {
  const binding = sourceStagingBinding(lock, staging);
  let observed: 'present' | 'absent';
  try { observed = binding.native.readPresence(); } catch (error) { sourceStagingError(error); }
  if (observed !== 'present' && observed !== 'absent')
    throw new KernelStorageError('RECOVERY_REQUIRED', 'source staging presence was not observed');
  return observed;
}

/** Only a newly created actual reservation can authorize a capturing row. */
export function readSourceInspectionStaging(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging):
  Readonly<{ inspectionId: string; stagingNonceDigest: string; stagingIdentity: SourceInspectionStagingIdentity }> {
  const binding = sourceStagingBinding(lock, staging);
  if (!binding.created) throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained source staging cannot authorize a new reservation');
  staging.assertHeld();
  return Object.freeze({ inspectionId: binding.inspectionId, stagingNonceDigest: binding.stagingNonceDigest,
    stagingIdentity: binding.stagingIdentity });
}
/** The owning task must already have joined capture/process resources. This
 * proves only exact native staging cleanup/fsync, not those lifecycle facts. */
export function retireSourceInspectionStaging(lock: HeldStateOwnerLock, staging: HeldSourceInspectionStaging): Promise<SourceInspectionStagingRetirement> {
  const binding = sourceStagingBinding(lock, staging);
  const pending = sourceRetirementTasks.get(staging);
  if (pending) return pending;
  const task = (async () => {
    let operationError: unknown;
    try {
      // Cleanup cannot be cancelled early: the owning scope must await every
      // exact native step and descriptor closure before it can retire.
      for (;;) {
        await setImmediate(); lock.assertHeld();
        if (binding.native.retireStep()) break;
      }
    } catch (error) { operationError = error; sourceStagingError(error); }
    finally {
      try { binding.native.close(); }
      catch (error) { throw new ResourceRetirementError('source staging cleanup descriptors did not retire',
        new AggregateError(operationError === undefined ? [error] : [operationError, error])); }
    }
    const receipt: SourceInspectionStagingRetirement = Object.freeze({ kind: 'physical_source_staging_retirement' });
    sourceRetirements.set(receipt, binding);
    return receipt;
  })();
  sourceRetirementTasks.set(staging, task);
  let active = sourceRetirementsByLock.get(lock);
  if (!active) { active = new Set(); sourceRetirementsByLock.set(lock, active); }
  active.add(task);
  void task.then(() => active.delete(task), () => active.delete(task));
  void task.catch(() => { if (sourceRetirementTasks.get(staging) === task) sourceRetirementTasks.delete(staging); });
  return task;
}
export function readSourceInspectionStagingRetirement(lock: HeldStateOwnerLock, receipt: SourceInspectionStagingRetirement):
  Readonly<{ inspectionId: string; stagingNonceDigest: string; stagingIdentity: SourceInspectionStagingIdentity;
    stagingObservation: 'exact_reserved_root_absent' | 'registered_reserved_root_absent'; directoryFsyncComplete: true }> {
  const binding = sourceRetirements.get(receipt);
  if (!binding || binding.lock !== lock) throw new KernelStorageError('ARTIFACT_MISMATCH', 'source staging retirement was not minted by this exact StateOwner');
  lock.assertHeld();
  // A later replacement at the same locator must not reuse a stale receipt.
  try { binding.native.assertRetired(); } catch (error) { sourceStagingError(error); }
  return Object.freeze({ inspectionId: binding.inspectionId, stagingNonceDigest: binding.stagingNonceDigest,
    stagingIdentity: binding.stagingIdentity, stagingObservation: registeredAbsentSourceStagings.has(binding)
      ? 'registered_reserved_root_absent' : 'exact_reserved_root_absent', directoryFsyncComplete: true });
}
/** Trusted composition-only staging handle. It is not a Linux/VM locator. */
export type HeldGenerationTree = Readonly<{
  identity: DescriptorIdentity;
  assertHeld(): void;
  close(): void;
}>;
export type BorrowedGenerationForExecution = Readonly<{
  fd: number;
  identity: DescriptorIdentity;
  assertHeld(): void;
  /** Actual filesystem total capacity, never free-space or a caller attestation.
   * Current Linux campaign requires a dedicated bounded StateRoot filesystem. */
  assertQuota(maxGenerationBytes: number): Readonly<{ totalBytes: number; filesystemType: string; identity: DescriptorIdentity }>;
  close(): void;
}>;
export type HeldGenerationFileReader = Readonly<{ readChunk(): Buffer | null; assertHeld(): void; close(): void }>;
export type HeldGenerationFileWriter = Readonly<{ writeChunk(bytes: Buffer): void; finish(): void; assertHeld(): void; close(): void }>;
export type GenerationSnapshotEntry = Readonly<{ path: string; kind: 'directory'; mode: number }> |
  Readonly<{ path: string; kind: 'symlink'; mode: number; target: string }> |
  Readonly<{ path: string; kind: 'file'; mode: number; byteCount: number; file: HeldGenerationFileReader }>;
export type HeldGenerationSnapshot = Readonly<{
  next(): GenerationSnapshotEntry | null;
  assertComplete(): void;
  close(): void;
}>;
type NativeGenerationTree = HeldGenerationTree & {
  mkdir(path: string): void;
  symlink(path: string, target: string): void;
  openSnapshot(): HeldGenerationSnapshot;
  openFileWriter(path: string, mode: number, byteCount: number): HeldGenerationFileWriter;
  borrow(): BorrowedGenerationForExecution;
  assertRetired(): number;
};
const nativeTrees = new WeakMap<HeldGenerationTree, NativeGenerationTree>();
const roots = new WeakMap<HeldStateOwnerLock, StateRootIdentityV1>();

export function stateRootIdentityForLock(lock: HeldStateOwnerLock): StateRootIdentityV1 {
  const root = roots.get(lock);
  if (!root) throw new TypeError('invalid StateOwner lock handle');
  lock.assertHeld();
  return root;
}

function wrapGenerationTree(native: NativeGenerationTree): HeldGenerationTree {
  const handle: HeldGenerationTree = Object.freeze({
    identity: Object.freeze({ ...native.identity }),
    assertHeld() { if (this !== handle) throw new TypeError('invalid private generation handle'); native.assertHeld(); },
    close() { if (this !== handle) throw new TypeError('invalid private generation handle'); native.close(); }
  });
  nativeTrees.set(handle, native);
  return handle;
}
function heldTree(tree: HeldGenerationTree): NativeGenerationTree {
  const native = nativeTrees.get(tree);
  if (!native) throw new TypeError('invalid private generation handle');
  native.assertHeld();
  return native;
}
/** Internal producer primitive, not a user/tool-selected filesystem operation. */
export function writeGenerationEntry(tree: HeldGenerationTree, entry:
  { path: string; kind: 'directory' } | { path: string; kind: 'symlink'; target: string }): void {
  const native = heldTree(tree);
  if (entry.kind === 'directory') native.mkdir(entry.path);
  else native.symlink(entry.path, entry.target);
}
/** Exhaustion, not opening a cursor, is the native rewalk/fsync observation. */
export function openGenerationSnapshot(tree: HeldGenerationTree): HeldGenerationSnapshot {
  return heldTree(tree).openSnapshot();
}
export function openGenerationFileWriter(tree: HeldGenerationTree, path: string, mode: 384 | 420 | 493,
  byteCount: number): HeldGenerationFileWriter {
  return heldTree(tree).openFileWriter(path, mode, byteCount);
}
/** Only a native-minted tree can transfer a duplicate to the closed launcher.
 * No public client accepts a number/path as an authority override. */
export function borrowGenerationForExecution(tree: HeldGenerationTree): BorrowedGenerationForExecution {
  return heldTree(tree).borrow();
}
/** Closed native owner, not a rescan, boolean or caller-supplied descriptor. */
export function assertRetiredGenerationTree(tree: HeldGenerationTree): number {
  const native = nativeTrees.get(tree);
  if (!native) throw new TypeError('invalid retired generation tree owner');
  try { return native.assertRetired(); }
  catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('generation resources did not retire under their original StateOwner', error);
    throw new KernelStorageError('RECOVERY_REQUIRED', 'generation native resource owners are not retired', { cause: error });
  }
}
/** Native-minted process/image observation, never a caller attestation. */
export type NativePeerObservation = Readonly<{
  pid: number;
  uid: number;
  gid: number;
  processStartToken: string;
  listener: DescriptorIdentity;
  acceptedSocket: DescriptorIdentity;
  imageFd: number;
  imageByteCount: number;
  close(): void;
}>;
export type HeldControlPeer = Readonly<{
  /** Transfer one duplicate to Node's Socket; the native original stays held. */
  takeSocketFd(): number;
  capture(): NativePeerObservation;
  assertObservation(observation: NativePeerObservation): void;
  close(): void;
}>;
export type HeldControlListener = Readonly<{ assertHeld(): void; close(): void }>;
/** Fixed installed auth transport, independent of StateOwner and SQLite.
 * The native original root/runtime/socket/selected image survive FD transfer. */
export type HeldInstalledControlClient = Readonly<{
  server: Readonly<{ pid: number; uid: number; gid: number; processStartToken: string }>;
  takeSocketFd(): number;
  assertHeld(): void;
  close(): void;
}>;
/** A physical move observation only: no containment death, tree or SQLite authority. */
export type GenerationQuarantineMove = Readonly<{
  quarantineCanonicalRootRelativePath: string;
  quarantineDeviceId: string;
  quarantineFileId: string;
  originalLocatorAbsent: true;
  renameNoReplace: true;
  directoryFsyncComplete: true;
}>;
export type HeldStateOwnerLock = Readonly<{
  root: DescriptorIdentity;
  runtime: DescriptorIdentity;
  lock: DescriptorIdentity;
  assertHeld(): void;
  assertPriorProcessDead(pid: number, processStartToken: string): void;
  /** Native time after observing the exact prior lifetime absent or replaced.
   * This grants no broker, descendant, claim or token-revocation proof. */
  observePriorProcessDeath(pid: number, processStartToken: string): number;
  openControlListener(onAccept: (peer: HeldControlPeer) => void, onError: (error: Error) => void): HeldControlListener;
  createGenerationTree(runId: string, generationId: string): HeldGenerationTree;
  /** A fixed recovery intent additionally permits its exact archived locator;
   * retained observation handles cannot write or transfer execution authority. */
  openGenerationTree(generation: WorkspaceGenerationIdentityV1, sourceRowVersion?: number): HeldGenerationTree;
  createSourceInspectionStaging(inspectionId: string, stagingNonceDigest: string): HeldSourceInspectionStaging;
  /** Only trusted recovery consumes the retained immutable reservation. An
   * absent root is physical absence, never an owner/task/process join proof. */
  openSourceInspectionStaging(inspectionId: string, stagingNonceDigest: string,
    identity: SourceInspectionStagingIdentity): HeldSourceInspectionStaging;
  createWorkerReservation(launchId: string, spawnNonceDigest: string): HeldWorkerReservation;
  openWorkerReservation(launchId: string, spawnNonceDigest: string, identity: DescriptorIdentity): HeldWorkerReservation;
  /** Trusted Supervisor primitive. The caller must first fence/retire writers;
   * this neither revokes open descriptors/mounts nor commits generation state. */
  quarantineGeneration(generation: WorkspaceGenerationIdentityV1, sourceRowVersion: number): GenerationQuarantineMove;
  close(): void;
}>;

export type NativeStateOwner = Readonly<{
  acquireLock(stateRoot: string, createLayout: boolean): HeldStateOwnerLock;
  processStartToken(): string;
  observeCurrentProcess(): Promise<Readonly<{
    pid: number; uid: number; processStartToken: string; executableImageDigest: string;
  }>>;
  openWorkspaceRoot(workspacePath: string): HeldWorkspaceRoot;
}>;

const workspaceRoots = new WeakMap<HeldWorkspaceRoot, string>();
/** Structural objects cannot impersonate the native producer. This proves
 * physical descriptor ownership only, never Trust or source-read permission. */
export function assertHeldWorkspaceRoot(root: HeldWorkspaceRoot): void {
  if (!workspaceRoots.has(root)) throw new TypeError('invalid native source workspace handle');
  root.assertHeld();
}

/** The canonical path is bound when the native handle is opened, not supplied
 * by a later caller beside a structurally matching descriptor identity. */
export function heldWorkspaceRootPath(root: HeldWorkspaceRoot): string {
  const workspacePath = workspaceRoots.get(root);
  if (workspacePath === undefined) throw new TypeError('invalid native source workspace handle');
  root.assertHeld();
  return workspacePath;
}

/** Read-only physical source authority. Trust and read-scope decisions precede
 * opening; this handle neither grants permission nor exposes an execution FD. */
export type HeldWorkspaceRoot = Readonly<{
  identity: DescriptorIdentity;
  /** Current raw permission bits from the original held root FD. Source
   * manifests normalize directory mode separately; identity stays unchanged. */
  readonly mode: number;
  /** Current actual link count from that same held root FD, never an identity
   * field or a substituted value for a missing destination parent. */
  readonly linkCount: number;
  repositoryDirectory?: DescriptorIdentity;
  assertHeld(): void;
  readGitConfigChunk(): Buffer | null;
  /** Metadata only. Entries must be explicitly selected before content is opened. */
  openSnapshot(): HeldWorkspaceCursor;
  /** Fixed instruction recipe: skip Git metadata, read only AGENTS.md bytes. */
  openInstructionSnapshot(): HeldWorkspaceCursor;
  /** Fixed declarative skill capture: skip Git metadata, never read symlink targets. */
  openSkillSnapshot(): HeldWorkspaceCursor;
  close(): void;
}>;

export type HeldWorkspaceFileReader = Readonly<{ readChunk(): Buffer | null; assertHeld(): void; close(): void }>;
export type HeldWorkspaceEntry = Readonly<{
  path: string;
  kind: 'directory' | 'file' | 'symlink' | 'unsupported';
  mode: number;
  byteCount: number;
  identity: DescriptorIdentity;
  linkCount: number;
  openFile(): HeldWorkspaceFileReader;
  openDirectory(): HeldWorkspaceCursor;
  readSymlink(): string;
  assertHeld(): void;
  /** Named path/leaf identity only; not directory-content snapshot evidence. */
  assertPathHeld(): void;
  close(): void;
}>;
export type HeldWorkspaceCursor = Readonly<{
  next(): HeldWorkspaceEntry | null;
  /** Exhaustion plus unchanged held directory metadata, not a global snapshot claim. */
  assertComplete(): void;
  close(): void;
}>;

type NativeLock = Omit<HeldStateOwnerLock, 'quarantineGeneration' | 'createGenerationTree' | 'openGenerationTree' |
  'createSourceInspectionStaging' | 'openSourceInspectionStaging' | 'createWorkerReservation' | 'openWorkerReservation'> & {
  moveGeneration(runId: string, generationId: string, quarantineId: string, deviceId: string, fileId: string): DescriptorIdentity;
  createGenerationTree(runId: string, generationId: string): NativeGenerationTree;
  openGenerationTree(runId: string, generationId: string, quarantineId?: string, deviceId?: string, fileId?: string): NativeGenerationTree;
  createSourceInspectionStaging(stagingId: string): NativeSourceInspectionStaging;
  openSourceInspectionStaging(stagingId: string, deviceId: string, fileId: string): NativeSourceInspectionStaging;
  createWorkerReservation(reservationId: string): NativeWorkerReservation;
  openWorkerReservation(reservationId: string, deviceId: string, fileId: string, ownerUid: number): NativeWorkerReservation;
  createAdminMcpInput(input: AdminMcpInputBinding): NativeAdminMcpInput;
  openRetainedAdminMcpInput(input: AdminMcpInputBinding): NativeAdminMcpInput;
  openAbsentAdminMcpInput(input: AdminMcpInputBinding): NativeAdminMcpInput;
  createAdminMcpStdioInput(...fields: readonly (string | number)[]): HeldAdminMcpStdioInput;
  openRetainedAdminMcpStdioInput(...fields: readonly (string | number)[]): HeldAdminMcpStdioInput;
  createRecoveryMcpStdioInput?(...fields: readonly (string | number)[]): HeldRecoveryMcpStdioInput;
  openRetainedRecoveryMcpStdioInput?(...fields: readonly (string | number)[]): HeldRecoveryMcpStdioInput;
  createRunMcpStdioInput(...fields: readonly (string | number)[]): HeldRunMcpStdioInput;
  openRetainedRunMcpStdioInput(...fields: readonly (string | number)[]): HeldRunMcpStdioInput;
  openPublicationGitIndex(root: HeldWorkspaceRoot, deviceId: string, fileId: string, ownerUid: number, maxBytes: number): HeldPublicationGitIndex;
  openPublicationOperation(root: HeldWorkspaceRoot, operation: NativePublicationOperationInput): NativePublicationOperation;
  openPublicationNamespaceObserver(root: HeldWorkspaceRoot, input: NativePublicationNamespaceInput): NativePublicationNamespaceObserver;
};
type NativePublicationExpected = Readonly<{ kind: 'file'; mode: number; byteCount: number; digest: string } |
  { kind: 'directory'; mode: number; identity: DescriptorIdentity } | { kind: 'symlink'; target: string; digest: string }>;
type NativePublicationDesired = Readonly<{ kind: 'file'; mode: 420 | 493; byteCount: number; digest: string } |
  { kind: 'directory'; mode: 493 } | { kind: 'symlink'; target: string; digest: string }>;
export type NativePublicationOperationInput = Readonly<{ arenaId: string; path: string; parents: readonly (DescriptorIdentity & { mode: number })[];
  /** Actual persisted PathProgress identities, not an adoption by name/hash.
   * The owning production reader additionally requires its genuine brand. */
  retained?: Readonly<{ arena: Pick<DescriptorIdentity, 'deviceId' | 'fileId'>;
    destination?: Pick<DescriptorIdentity, 'deviceId' | 'fileId'>; preimage?: Pick<DescriptorIdentity, 'deviceId' | 'fileId'> }>;
} & (
  { kind: 'create'; expected: { kind: 'absent' }; desired: Exclude<NativePublicationDesired, { kind: 'directory' }>; stagingName: string } |
  { kind: 'replace'; expected: NativePublicationExpected; desired: NativePublicationDesired; stagingName: string; quarantineName: string } |
  { kind: 'mkdir'; expected: { kind: 'absent' }; desired: { kind: 'directory'; mode: 493 } } |
  { kind: 'delete'; expected: NativePublicationExpected; desired: { kind: 'absent' }; quarantineName: string } |
  { kind: 'abort_rmdir'; expected: Extract<NativePublicationExpected, { kind: 'directory' }>;
      desired: { kind: 'absent' }; quarantineName: 'preimage' }
)>;
type PublicationPrivateIdentity = DescriptorIdentity & { mode: 448 };
export type NativePublicationNamespaceInput = Readonly<{ arenaId: string; path: string;
  parents: readonly (DescriptorIdentity & { mode: number })[]; arenaIdentity: PublicationPrivateIdentity; parentIdentity: PublicationPrivateIdentity;
  desired: NativePublicationDesired | { kind: 'absent' }; destinationIdentity?: DescriptorIdentity;
  stagingName?: string; quarantineName?: string; retainedPreimage?: Pick<DescriptorIdentity, 'deviceId' | 'fileId'>;
}>;
export type NativePublicationNamespaceObservation = Readonly<{ state: 'arena_absent' | 'original_arena_empty' | 'original_slots_present';
  parentIdentity: PublicationPrivateIdentity; destination: NativePublicationObservation;
  parent: Readonly<{ identity: DescriptorIdentity; mode: number; linkCount: number }> }>;
export type PublicationNamespaceRetirement = Readonly<{ kind: 'namespace_absence'; arenaId: string; parentIdentity: PublicationPrivateIdentity;
  arenaAbsent: true; arenaParentFsyncCompleted: true; workspaceParentFsyncCompleted: true }>;
/** Read-only physical role. There is no method for release or maintenance. */
export type HeldPublicationNamespaceObserver = Readonly<{ assertHeld(): void; observe(): NativePublicationNamespaceObservation;
  readDestinationChunk(): Buffer | null; close(): void }>;
type NativePublicationNamespaceObserver = HeldPublicationNamespaceObserver & { retireNamespace(): void; assertNamespaceRetired(): PublicationNamespaceRetirement;
  readRetirementDiagnostic(): unknown };
export type NativePublicationObservation = Readonly<{ kind: 'absent' } | {
  kind: 'file' | 'directory' | 'symlink' | 'unsupported'; identity: DescriptorIdentity;
  mode: number; byteCount: number; linkCount: number; digest?: string; target?: string; empty?: boolean;
}>;
/** Actual displaced data only. A complete read never validates the approved
 * preimage or permits cleanup, reconciliation success or another release. */
export type NativePublicationActualPreimage = Readonly<{
  location: Readonly<{ kind: 'publication_arena'; arenaId: string; component: string }>;
  kind: 'file' | 'directory' | 'symlink' | 'unsupported'; identity: DescriptorIdentity;
  mode: number; linkCount: number; byteCount: string; digest?: string; empty?: boolean;
}>;
/** Fixed physical mechanism, not approval or a Journal/native execution claim.
 * The trusted publication producer is its sole production consumer. */
export type HeldPublicationOperation = Readonly<{
  assertHeld(): void; stage(): void; writeChunk(bytes: Buffer): void; finishStage(): boolean;
  /** Physical release fence only. The sole producer calls this only after the
   * original permanent SQL claim; this method creates no permission itself. */
  arm(): void;
  readOriginalChunk(): Buffer | null; readPreimageChunk(): Buffer | null;
  /** Full expected-byte read while the original namespace is still unstarted,
   * including a partially/fully staged but irreversibly fenced operation. */
  readInspectionOriginalChunk(): Buffer | null;
  describeActualPreimage(): NativePublicationActualPreimage; readActualPreimageChunk(): Buffer | null;
  readDestinationChunk(): Buffer | null;
  /** One-way semantic fence. Original-claim maintenance may still observe,
   * preserve and remove its exact unpublished staging before actual close. */
  revoke(): void; discardStage(): void;
  /** Read-only original-inode namespace classification, not durable evidence. */
  inspectState(): 'unstarted' | 'effect_present' | 'cleaned';
  reconcile(): 'unstarted' | 'committed' | 'cleaned';
  restartRead(kind: 'original' | 'inspection_original' | 'preimage' | 'destination' | 'actual_preimage'): void;
  commit(): void; observe(): Readonly<{ parent: Readonly<{ identity: DescriptorIdentity; mode: number; linkCount: number }>;
    arena: Readonly<{ id: string; identity: DescriptorIdentity; mode: 448; linkCount: number;
      parentIdentity: DescriptorIdentity & { mode: 448 }; absent: boolean; retired: boolean; retirementObservation?: PublicationArenaRetirementObservation }>;
    destination: NativePublicationObservation; staging?: NativePublicationObservation; quarantine?: NativePublicationObservation }>;
  finishCleanup(): void; finishArenaRetirement(): void; assertArenaRetired(): void; close(): void;
}>;
const publicationLocks = new WeakMap<HeldStateOwnerLock, NativeLock>();
type NativePublicationOperation = HeldPublicationOperation & { readRetirementDiagnostic(): unknown };
type PublicationArenaPhysicalRetirement = Readonly<{ arenaId: string; arenaIdentity: DescriptorIdentity & { mode: 448 };
  parentIdentity: DescriptorIdentity & { mode: 448 }; retirementObservation: PublicationArenaRetirementObservation }>;
const publicationOperations = new WeakMap<HeldPublicationOperation, {
  lock: HeldStateOwnerLock; native: NativePublicationOperation; closed: boolean; postJoinObserved?: boolean; retirement?: PublicationArenaPhysicalRetirement;
  normalDiagnosticPublished?: boolean;
}>();
/** Actual held birth observation, not a retained artifact, grant or claim.
 * A structural value cannot enter the producer's native proof boundary. */
export function readHeldPublicationBirth(lock: HeldStateOwnerLock, operation: HeldPublicationOperation): Readonly<{
  arenaId: string; arenaIdentity: DescriptorIdentity & { mode: 448 }; parentIdentity: DescriptorIdentity & { mode: 448 };
}> {
  const binding = publicationOperations.get(operation);
  if (!binding || binding.lock !== lock) throw new TypeError('publication birth requires its exact original native owner');
  lock.assertHeld(); operation.assertHeld();
  const { arena } = operation.observe();
  if (arena.absent || arena.retired || arena.mode !== 448 || arena.parentIdentity.mode !== 448)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'publication native birth is not held in its actual private parent');
  return Object.freeze({ arenaId: arena.id, arenaIdentity: Object.freeze({ ...arena.identity, mode: arena.mode }),
    parentIdentity: Object.freeze({ ...arena.parentIdentity }) });
}
/** Joined actual original lifecycle only. Reopening the protected parent is a
 * readonly absence recheck, never an adoption or reconstruction of an arena. */
export function readRetiredPublicationArena(lock: HeldStateOwnerLock, operation: HeldPublicationOperation): PublicationArenaPhysicalRetirement {
  const binding = publicationOperations.get(operation);
  if (!binding || binding.lock !== lock) throw new TypeError('publication retirement requires its exact original native owner');
  lock.assertHeld();
  if (!binding.closed || !binding.retirement) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication arena retirement and descriptor join are incomplete');
  operation.assertArenaRetired(); binding.postJoinObserved = true; return binding.retirement;
}
export type HeldPublicationGitIndex = Readonly<{ present: boolean; byteCount: number; identity?: DescriptorIdentity;
  readChunk(): Buffer | null; assertHeld(): void; assertComplete(): void; close(): void }>;
const publicationGitIndexes = new WeakMap<HeldPublicationGitIndex, { lock: HeldStateOwnerLock; root: HeldWorkspaceRoot }>();
export function openHeldPublicationGitIndex(lock: HeldStateOwnerLock, root: HeldWorkspaceRoot,
  input: Readonly<{ repositoryDirectory: DescriptorIdentity; maxBytes: number }>): HeldPublicationGitIndex {
  const native = publicationLocks.get(lock);
  if (!native || !workspaceRoots.has(root)) throw new TypeError('publication Git index requires actual StateOwner and workspace handles');
  const closed = (value: unknown, names: readonly string[]) => {
    if (!value || typeof value !== 'object' || types.isProxy(value)) return false;
    const fields = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(fields);
    return keys.length === names.length && keys.every(key => typeof key === 'string' && names.includes(key) &&
      fields[key]!.enumerable && Object.hasOwn(fields[key]!, 'value') && fields[key]!.value !== undefined);
  };
  if (!closed(input, ['repositoryDirectory', 'maxBytes']) || !closed(input.repositoryDirectory, ['deviceId', 'fileId', 'ownerUid']) ||
      typeof input.repositoryDirectory.deviceId !== 'string' || !/^(0|[1-9]\d*)$/u.test(input.repositoryDirectory.deviceId) ||
      typeof input.repositoryDirectory.fileId !== 'string' || !/^[1-9]\d*$/u.test(input.repositoryDirectory.fileId) ||
      !Number.isSafeInteger(input.repositoryDirectory.ownerUid) || input.repositoryDirectory.ownerUid < 0 || input.repositoryDirectory.ownerUid > 0xffffffff ||
      !Number.isSafeInteger(input.maxBytes) || input.maxBytes < 1 || input.maxBytes > 268_435_456)
    throw new TypeError('publication Git index requires its original repository identity and fixed byte bound');
  const selected = immutableSnapshot(input);
  const fail = (error: unknown): never => {
    if (error instanceof ResourceRetirementError || error instanceof KernelStorageError) throw error;
    if ((error as NodeJS.ErrnoException | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('publication Git index descriptor did not retire', error);
    try { native.assertHeld(); } catch (retirement) {
      if ((retirement as NodeJS.ErrnoException | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
        throw new ResourceRetirementError('publication Git index descriptor did not retire', new AggregateError([error, retirement]));
    }
    throw new KernelStorageError('RECOVERY_REQUIRED', 'publication Git index has no complete unchanged physical observation', { cause: error });
  };
  let owned: HeldPublicationGitIndex;
  try {
    lock.assertHeld(); root.assertHeld();
    const expected = selected.repositoryDirectory;
    owned = native.openPublicationGitIndex(root, expected.deviceId, expected.fileId, expected.ownerUid, selected.maxBytes);
  } catch (error) { return fail(error); }
  const receiver = (value: unknown) => {
    const binding = publicationGitIndexes.get(value as HeldPublicationGitIndex);
    if (value !== handle || binding?.lock !== lock || binding.root !== root) throw new TypeError('invalid publication Git index handle');
  };
  const handle: HeldPublicationGitIndex = Object.freeze({ present: owned.present, byteCount: owned.byteCount,
    ...(owned.identity ? { identity: Object.freeze({ ...owned.identity }) } : {}),
    assertHeld() { receiver(this); try { owned.assertHeld(); } catch (error) { fail(error); } },
    assertComplete() { receiver(this); try { owned.assertComplete(); } catch (error) { fail(error); } },
    readChunk() { receiver(this); try { return owned.readChunk(); } catch (error) { return fail(error); } },
    close() { receiver(this); try { owned.close(); } catch (error) { fail(error); } }
  });
  publicationGitIndexes.set(handle, { lock, root }); return handle;
}
/** Composition-only bridge. Reject structural stand-ins before reading any
 * caller properties; C independently checks both actual native type brands. */
export function openHeldPublicationOperation(lock: HeldStateOwnerLock, root: HeldWorkspaceRoot,
  input: NativePublicationOperationInput): HeldPublicationOperation {
  const native = publicationLocks.get(lock);
  if (!native || !workspaceRoots.has(root)) throw new TypeError('publication requires actual StateOwner and workspace handles');
  lock.assertHeld(); root.assertHeld();
  const file = (value: { mode: number; byteCount: number; digest: string }, desired: boolean) =>
    Number.isSafeInteger(value.mode) && value.mode >= 0 && value.mode <= 0o7777 && (!desired || [0o644, 0o755].includes(value.mode)) &&
    Number.isSafeInteger(value.byteCount) && value.byteCount >= 0 && /^[0-9a-f]{64}$/u.test(value.digest);
  const symlink = (value: { target: string; digest: string }) => typeof value.target === 'string' && value.target.length > 0 &&
    value.target === value.target.normalize('NFC') && Buffer.from(value.target).toString() === value.target && !value.target.includes('\0') &&
    !value.target.includes('\\') && !value.target.startsWith('/') && Buffer.byteLength(value.target) <= 4096 &&
    !value.target.split('/').some(part => part.toLowerCase() === '.git') && sha256Bytes(Buffer.from(value.target)) === value.digest;
  const creates = input?.kind === 'create' || input?.kind === 'mkdir';
  const stages = input?.kind === 'create' || input?.kind === 'replace';
  const removes = input?.kind === 'delete' || input?.kind === 'abort_rmdir';
  const displaces = input?.kind === 'replace' || removes;
  const inode = (value: Pick<DescriptorIdentity, 'deviceId' | 'fileId'> | undefined) => value &&
    /^(0|[1-9]\d*)$/u.test(value.deviceId) && /^[1-9]\d*$/u.test(value.fileId);
  if (!input || !/^[A-Za-z0-9_-]{43}$/u.test(input.arenaId) || !['create', 'replace', 'mkdir', 'delete', 'abort_rmdir'].includes(input.kind) || typeof input.path !== 'string' ||
      normalizeBoundedPublicationPath(input.path) !== input.path || !Array.isArray(input.parents) || input.parents.length !== input.path.split('/').length ||
      input.parents.some(parent => !parent || !/^(0|[1-9]\d*)$/u.test(parent.deviceId) || !/^[1-9]\d*$/u.test(parent.fileId) ||
        !Number.isSafeInteger(parent.ownerUid) || parent.ownerUid < 0 || parent.ownerUid > 0xffffffff ||
        !Number.isSafeInteger(parent.mode) || parent.mode < 0 || parent.mode > 0o7777) ||
      !(creates ? input.expected?.kind === 'absent' : input.expected?.kind === 'file' ? file(input.expected, false) :
        input.expected?.kind === 'symlink' ? symlink(input.expected) :
        input.expected?.kind === 'directory' && Number.isSafeInteger(input.expected.mode) && input.expected.mode >= 0 && input.expected.mode <= 0o7777 &&
        input.expected.identity && /^(0|[1-9]\d*)$/u.test(input.expected.identity.deviceId) && /^[1-9]\d*$/u.test(input.expected.identity.fileId) &&
        Number.isSafeInteger(input.expected.identity.ownerUid) && input.expected.identity.ownerUid >= 0 && input.expected.identity.ownerUid <= 0xffffffff) ||
      !(removes ? input.desired?.kind === 'absent' : input.desired?.kind === 'directory' ? input.kind !== 'create' && input.desired.mode === 0o755 :
        input.desired?.kind === 'symlink' ? input.kind !== 'mkdir' && symlink(input.desired) : input.desired?.kind === 'file' && input.kind !== 'mkdir' && file(input.desired, true)) ||
      stages && (!('stagingName' in input) || typeof input.stagingName !== 'string' || normalizeBoundedPublicationPath(input.stagingName) !== input.stagingName || input.stagingName.includes('/')) ||
      displaces && (!('quarantineName' in input) || typeof input.quarantineName !== 'string' || normalizeBoundedPublicationPath(input.quarantineName) !== input.quarantineName || input.quarantineName.includes('/')) ||
      input.kind === 'abort_rmdir' && (input.expected.kind !== 'directory' || input.quarantineName !== 'preimage' || 'stagingName' in input) ||
      input.retained !== undefined && (!input.retained || !inode(input.retained.arena) || (!removes && !inode(input.retained.destination)) ||
        displaces && !inode(input.retained.preimage)))
    throw new TypeError('publication requires one exact canonical operation');
  const failed = (error: unknown): never => {
    if (error instanceof ResourceRetirementError || error instanceof KernelStorageError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('publication descriptors did not retire', error);
    // A directory probe can fail while retiring its temporary descriptor.
    // Its sticky native owner state takes precedence over the read error.
    try { native.assertHeld(); }
    catch (retirement) {
      if ((retirement as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
        throw new ResourceRetirementError('publication descriptors did not retire', new AggregateError([error, retirement]));
    }
    throw new KernelStorageError('RECOVERY_REQUIRED', 'fixed native publication did not prove its exact operation', { cause: error });
  };
  let owned: NativePublicationOperation;
  try { owned = native.openPublicationOperation(root, input); } catch (error) { failed(error); }
  const receiver = (value: unknown) => { if (value !== handle) throw new TypeError('invalid publication operation handle'); };
  const handle: HeldPublicationOperation = Object.freeze({
    assertHeld() { receiver(this); try { owned.assertHeld(); } catch (error) { failed(error); } },
    stage() { receiver(this); try { owned.stage(); } catch (error) { failed(error); } },
    arm() { receiver(this); try { owned.arm(); } catch (error) { failed(error); } },
    writeChunk(bytes: Buffer) { receiver(this); try { owned.writeChunk(bytes); } catch (error) { failed(error); } },
    finishStage() { receiver(this); try { return owned.finishStage(); } catch (error) { return failed(error); } },
    readOriginalChunk() { receiver(this); try { return owned.readOriginalChunk(); } catch (error) { return failed(error); } },
    readInspectionOriginalChunk() { receiver(this); try { return owned.readInspectionOriginalChunk(); } catch (error) { return failed(error); } },
    readPreimageChunk() { receiver(this); try { return owned.readPreimageChunk(); } catch (error) { return failed(error); } },
    describeActualPreimage() { receiver(this); try { return owned.describeActualPreimage(); } catch (error) { return failed(error); } },
    readActualPreimageChunk() { receiver(this); try { return owned.readActualPreimageChunk(); } catch (error) { return failed(error); } },
    readDestinationChunk() { receiver(this); try { return owned.readDestinationChunk(); } catch (error) { return failed(error); } },
    revoke() { receiver(this); try { owned.revoke(); } catch (error) { return failed(error); } },
    discardStage() { receiver(this); try { owned.discardStage(); } catch (error) { return failed(error); } },
    inspectState() { receiver(this); try { return owned.inspectState(); } catch (error) { return failed(error); } },
    reconcile() { receiver(this); try { return owned.reconcile(); } catch (error) { return failed(error); } },
    restartRead(kind) { receiver(this); try { owned.restartRead(kind); } catch (error) { return failed(error); } },
    commit() { receiver(this); try { owned.commit(); } catch (error) { failed(error); } },
    observe() { receiver(this); try { return owned.observe(); } catch (error) { return failed(error); } },
    finishCleanup() { receiver(this); try { owned.finishCleanup(); } catch (error) { failed(error); } },
    finishArenaRetirement() { receiver(this); try {
      owned.finishArenaRetirement(); const { arena } = owned.observe(), observation = arena.retirementObservation;
      if (!arena.retired || !arena.absent || !observation ||
          (process.platform === 'linux' ? observation.kind !== 'linux_unlinked' : process.platform !== 'darwin' || observation.kind !== 'darwin_unlinked'))
        throw new KernelStorageError('RECOVERY_REQUIRED', 'publication retirement lacks its actual platform unlink observation');
      publicationOperations.get(handle)!.retirement = Object.freeze({ arenaId: arena.id,
        arenaIdentity: Object.freeze({ ...arena.identity, mode: arena.mode }), parentIdentity: Object.freeze({ ...arena.parentIdentity }),
        retirementObservation: Object.freeze({ ...observation }) });
    } catch (error) { failed(error); } },
    assertArenaRetired() { receiver(this); try { owned.assertArenaRetired(); } catch (error) { failed(error); } },
    close() { receiver(this); try { owned.close(); publicationOperations.get(handle)!.closed = true; } catch (error) { failed(error); } }
  });
  publicationOperations.set(handle, { lock, native: owned!, closed: false });
  return handle;
}
type PublicationNamespaceBinding = { lock: HeldStateOwnerLock; native: NativePublicationNamespaceObserver;
  closed: boolean; retired: boolean; postJoinObserved?: boolean; fail(error: unknown): never };
const publicationNamespaceObservers = new WeakMap<HeldPublicationNamespaceObserver, PublicationNamespaceBinding>();
/** The original producer calls only after its receipt and completion are
 * fixed. This observer grants no result or authority and never invents a probe
 * nonce. No subscriber means no native read, identity access or output. */
export function noteNormalPublicationRetirement(lock: HeldStateOwnerLock, operation: HeldPublicationOperation,
  dispatch: PublicationRetirementDispatch): void {
  noteJoinedPublicationRetirement(() => {
    const held = publicationOperations.get(operation);
    if (!held || held.lock !== lock || held.normalDiagnosticPublished) throw 0;
    const slots = readJoinedPublicationRetirementSpans(lock, operation), key = publicationClaimRetirementDiagnosticKey(dispatch);
    // Set before the trusted subscriber runs, including callback re-entry.
    // This is diagnostic suppression only, never a cached physical result.
    held.normalDiagnosticPublished = true;
    return { version: 1, key, kind: 'original', joined: true, slots };
  });
}
/** Diagnostic friend only. A structural handle, foreign lock, incomplete close
 * or missing actual post-join observation cannot expose even inert intervals.
 * This read neither performs retirement nor supplies a proof of it. */
export function readJoinedPublicationRetirementSpans(lock: HeldStateOwnerLock,
  handle: HeldPublicationOperation | HeldPublicationNamespaceObserver): PublicationRetirementSpans {
  const held = publicationOperations.get(handle as HeldPublicationOperation) ?? publicationNamespaceObservers.get(handle as HeldPublicationNamespaceObserver);
  if (!held || held.lock !== lock) throw new TypeError('publication diagnostic requires its genuine same-lock native owner');
  if (!held.closed || !held.postJoinObserved) throw new TypeError('publication diagnostic requires its actual completed post-join observation');
  return decodePublicationRetirementSpans(held.native.readRetirementDiagnostic());
}
/** Descriptor-only physical role. The sole production consumer must first
 * validate the complete original claim/birth/progress/takeover graph. */
export function openHeldPublicationNamespaceObserver(lock: HeldStateOwnerLock, root: HeldWorkspaceRoot,
  input: NativePublicationNamespaceInput): HeldPublicationNamespaceObserver {
  const native = publicationLocks.get(lock);
  if (!native || !workspaceRoots.has(root)) throw new TypeError('publication namespace requires actual StateOwner and workspace handles');
  lock.assertHeld(); root.assertHeld();
  const closed = (value: unknown, required: readonly string[], optional: readonly string[] = []) => {
    if (!value || typeof value !== 'object') return false;
    const fields = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(fields);
    return required.every(key => Object.hasOwn(fields, key)) && keys.every(key => typeof key === 'string' &&
      [...required, ...optional].includes(key) && fields[key]!.enumerable && Object.hasOwn(fields[key]!, 'value') && fields[key]!.value !== undefined);
  };
  const inode = (value: unknown) => {
    if (!value || typeof value !== 'object') return false;
    const fields = Object.getOwnPropertyDescriptors(value), device = fields.deviceId?.value, file = fields.fileId?.value;
    return typeof device === 'string' && /^(0|[1-9]\d*)$/u.test(device) && typeof file === 'string' && /^[1-9]\d*$/u.test(file);
  };
  const identity = (value: DescriptorIdentity | undefined) => closed(value, ['deviceId', 'fileId', 'ownerUid']) && inode(value) &&
    Number.isSafeInteger(value!.ownerUid) && value!.ownerUid >= 0 && value!.ownerUid <= 0xffffffff;
  const parent = (value: DescriptorIdentity & { mode: number }) => closed(value, ['deviceId', 'fileId', 'ownerUid', 'mode']) && inode(value) &&
    Number.isSafeInteger(value.ownerUid) && value.ownerUid >= 0 && value.ownerUid <= 0xffffffff &&
    Number.isSafeInteger(value.mode) && value.mode >= 0 && value.mode <= 0o7777;
  const slot = (value: string | undefined) => value === undefined || typeof value === 'string' &&
    normalizeBoundedPublicationPath(value) === value && !value.includes('/');
  if (!closed(input, ['arenaId', 'path', 'parents', 'arenaIdentity', 'parentIdentity', 'desired'],
      ['destinationIdentity', 'stagingName', 'quarantineName', 'retainedPreimage']) ||
      typeof input.arenaId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(input.arenaId) || typeof input.path !== 'string' || normalizeBoundedPublicationPath(input.path) !== input.path ||
      !Array.isArray(input.parents) || input.parents.length !== input.path.split('/').length || input.parents.some(value => !parent(value)) ||
      !parent(input.arenaIdentity) || input.arenaIdentity.mode !== 0o700 || !parent(input.parentIdentity) || input.parentIdentity.mode !== 0o700 ||
      !slot(input.stagingName) || !slot(input.quarantineName) || !input.stagingName && !input.quarantineName ||
      input.stagingName !== undefined && input.stagingName === input.quarantineName ||
      input.retainedPreimage !== undefined && (!input.quarantineName || !closed(input.retainedPreimage, ['deviceId', 'fileId']) || !inode(input.retainedPreimage)))
    throw new TypeError('invalid fixed registered publication namespace');
  const desired = input.desired;
  if (!closed(desired, desired?.kind === 'file' ? ['kind', 'mode', 'byteCount', 'digest'] : desired?.kind === 'directory' ? ['kind', 'mode'] :
      desired?.kind === 'symlink' ? ['kind', 'target', 'digest'] : ['kind']) ||
      !(desired.kind === 'absent' ? input.destinationIdentity === undefined : identity(input.destinationIdentity)) ||
      !(desired.kind === 'absent' || desired.kind === 'directory' && desired.mode === 0o755 || desired.kind === 'file' &&
        [0o644, 0o755].includes(desired.mode) && Number.isSafeInteger(desired.byteCount) && desired.byteCount >= 0 && desired.byteCount <= 256 * 1024 * 1024 &&
        /^[0-9a-f]{64}$/u.test(desired.digest) || desired.kind === 'symlink' && typeof desired.target === 'string' && desired.target.length > 0 &&
        desired.target === desired.target.normalize('NFC') && Buffer.from(desired.target).toString() === desired.target && !desired.target.includes('\0') &&
        !desired.target.includes('\\') && !desired.target.startsWith('/') && Buffer.byteLength(desired.target) <= 4096 &&
        !desired.target.split('/').some(part => part.toLowerCase() === '.git') && sha256Bytes(Buffer.from(desired.target)) === desired.digest))
    throw new TypeError('invalid fixed publication namespace desired state');
  const fail = (error: unknown): never => {
    if ((error as NodeJS.ErrnoException)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('publication namespace descriptors did not retire', error);
    try { lock.assertHeld(); } catch (retirement) {
      if (retirement instanceof ResourceRetirementError) throw retirement;
      throw new KernelStorageError('RECOVERY_REQUIRED', 'publication namespace lost its actual StateOwner', { cause: retirement });
    }
    throw new KernelStorageError('RECOVERY_REQUIRED', 'publication registered namespace is not exactly observable', { cause: error });
  };
  const owned = (() => { try { return native.openPublicationNamespaceObserver(root, input); } catch (error) { return fail(error); } })();
  const receiver = (value: unknown) => { if (value !== handle) throw new TypeError('invalid publication namespace observer receiver'); };
  const handle: HeldPublicationNamespaceObserver = Object.freeze({
    assertHeld() { receiver(this); try { owned.assertHeld(); } catch (error) { fail(error); } },
    observe() { receiver(this); try { return owned.observe(); } catch (error) { return fail(error); } },
    readDestinationChunk() { receiver(this); try { return owned.readDestinationChunk(); } catch (error) { return fail(error); } },
    close() { receiver(this); try { owned.close(); publicationNamespaceObservers.get(handle)!.closed = true; } catch (error) { fail(error); } }
  });
  publicationNamespaceObservers.set(handle, { lock, native: owned, closed: false, retired: false, fail }); return handle;
}
function publicationNamespaceBinding(lock: HeldStateOwnerLock, handle: HeldPublicationNamespaceObserver) {
  const held = publicationNamespaceObservers.get(handle);
  if (!held || held.lock !== lock) throw new TypeError('publication namespace requires its genuine same-lock observer');
  return held;
}
/** Fixed original-claim maintenance only, never part of the read-only facade.
 * The producer repeats its genuine same-claim gate before calling this. */
export function retireHeldPublicationNamespace(lock: HeldStateOwnerLock, handle: HeldPublicationNamespaceObserver): void {
  const held = publicationNamespaceBinding(lock, handle);
  lock.assertHeld();
  if (held.closed) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication namespace maintenance cannot reopen closed handles');
  try { held.native.retireNamespace(); held.retired = true; } catch (error) { held.fail(error); }
}
/** Current namespace absence, not old-FD unlink or cleanup permission. */
export function readRetiredPublicationNamespace(lock: HeldStateOwnerLock, handle: HeldPublicationNamespaceObserver): PublicationNamespaceRetirement {
  const held = publicationNamespaceBinding(lock, handle); lock.assertHeld();
  if (!held.closed || !held.retired) throw new KernelStorageError('RECOVERY_REQUIRED', 'publication namespace lacks actual sync and joined handles');
  try { const actual = held.native.assertNamespaceRetired(); held.postJoinObserved = true; return actual; } catch (error) { return held.fail(error); }
}
function normalizeBoundedPublicationPath(value: string): string {
  if (value.normalize('NFC') !== value || Buffer.byteLength(value) > 4096 || value.includes('\0') || value.includes('\\') ||
      value.split('/').some(part => !part || part === '.' || part === '..' || part.toLowerCase() === '.git' || Buffer.byteLength(part) > 255))
    throw new TypeError('publication path is not canonical');
  return value;
}
type NativeCurrentProcess = Readonly<{
  pid: number; uid: number; processStartToken: string;
  imageFd: number; imageByteCount: number; imageIdentityKey: string;
  assertHeld(): void; close(): void;
}>;
type NativeInstalledKeeper = Readonly<{ assertHeld(): void; readyLocator(): Buffer; close(): void }>;
type NativeInstalledAnchor = Readonly<{ assertHeld(): void;
  withRoot(operation: (fd: number, rootPath: string) => void): void; close(): void }>;
/** A current checker observes an original keeper; no Anchor/root borrow exists. */
export type NativeInstalledUpgradeKeeperCheck = Readonly<{ purpose: 'current_checked_original_keeper'; assertCurrent(): void; close(): void }>;
type RawInstalledUpgradeKeeperCheck = Readonly<{ assertCurrent(): void; close(): void }>;
type NativeLocalModelExclusiveGate = Readonly<{ assertHeld(): void; close(): void }>;
type NativeCredentialScope = Readonly<{ generation: string; assertHeld(): void; close(): void;
  observeProducerLifetime(pid: number, ownerUid: number, processStartToken: string): 'present' | 'dead' }>;
type NativeKernelGlobalGate = Readonly<{ assertHeld(): void; close(): void }>;
type NativeMigrationCredentialGate = Readonly<{ assertHeld(): void; close(): void }>;
type NativeMigrationFilesystem = Readonly<{ assertHeld(): void; close(): void; createCandidate(): void;
  prepareLegacyLocksNext(): boolean; assertLegacyLocks(): void; releaseLegacyLocks(): Promise<void>;
  observeRoots(): Readonly<{ legacyRoot: HeldMigrationDirectoryObservation; backupRoot: HeldMigrationDirectoryObservation }>;
  publishInitialSpine(preparationRef: string, controlBytes: Buffer, previousLegacyMarkerBytes?: Buffer): void;
  advanceControl(controlBytes: Buffer): void; observeOriginalAuth(): HeldMigrationAuthObservation;
  publishAuthCutover(markerBytes: Buffer): void; publishKernelAuthority(markerBytes: Buffer): void;
  readControlBytes(): Buffer; readPreparationBytes(): Buffer; readRendezvousBytes(): Buffer;
  assertCredentialCutoverControl(controlBytes: Buffer): void;
  readBackupInventoryPage(after: string): Readonly<{ entries: readonly HeldMigrationBackupEntry[];
    firstOrdinal: number; totalEntries: number; complete: boolean }>;
  candidateBuildPath(): string; sealCandidateNext(): boolean;
  copyBackupNext(): false | HeldMigrationBackupEntry | null;
  verifyBackupSourceNext(): boolean;
  beginContextProjection(): void;
  nextContextSource(): HeldMigrationSourceFile | null;
  readContextSourceChunk(): Buffer | null; closeContextSource(): void }>;
type RawCurrentMigrationInspector = Readonly<{ assertHeld(): void; close(): void;
  prepareLegacyLocksNext(): boolean; assertLegacyLocks(): void; releaseLegacyLocks(): Promise<void>;
  beginExpectedEntry(packet: Buffer): void; verifyExpectedEntryNext(): boolean; finishExpectedEntries(): void;
  beginWholeTreeVerification(): void; verifyWholeTreesNext(): boolean; inspectRetainedLegacy(): unknown;
  selectOriginalKernelArchive(packet: Buffer): void; verifyArchiveManifestNext(): boolean; readArchiveManifestChunk(): Buffer | null;
  selectArchivePayload(packet: Buffer): void; verifyArchiveImageNext(): boolean; beginArchiveEntryPass(): void;
  beginArchiveCasEntry(packet: Buffer): void; verifyArchiveCasEntryNext(): boolean;
  verifyArchiveNamespaceNext(): boolean; inspectVerifiedArchive(): unknown }>;
export type PreparedImportImageObservation = Readonly<{
  file: Readonly<{ deviceId: string; fileId: string; ownerUid: number }>; sha256: string; byteCount: number; mode: number;
  stateRoot: DescriptorIdentity; migrationDirectory: DescriptorIdentity; collectionDirectory: DescriptorIdentity;
  packageDirectory: DescriptorIdentity; candidateDirectory: DescriptorIdentity;
  legacyRoot: DescriptorIdentity; migrationId: string;
}>;
export type NativePreparedImportCandidate = Readonly<{ assertHeld(): void; verifyNext(): boolean;
  beginRead(): void; endRead(): void; identity(): PreparedImportImageObservation; close(): void }>;
type NativeBinding = { acquireLock(stateRoot: string, createLayout: boolean): NativeLock; processStartToken(): string;
  tryLockClientDataDirectory?(directoryFd: number): HeldClientDataLock | null;
  duplicateClientStdout?(): number;
  duplicateClientStderr?(): number;
  decodeSourceGitLifecycle?(bytes: Buffer): SourceGitNativeLifecycleV2;
  decodeAdminMcpLifecycle?(bytes: Buffer): AdminMcpNativeLifecycle;
  decodeMcpStdioRecoveryLifecycle?(bytes: Buffer): McpStdioRecoveryNativeLifecycle;
  decodeMcpStdioRecoveryCleanup?(bytes: Buffer): McpStdioRecoveryNativeCleanup;
  decodeMcpStdioLifecycle?(bytes: Buffer): McpStdioNativeLifecycle;
  decodeMcpStdioCleanup?(bytes: Buffer): McpStdioNativeCleanup;
  decodeMcpAdminOriginalRetirement?(bytes: Buffer, originalLifecycle: Buffer): McpAdminOriginalRetirement;
  captureCurrentProcess(): NativeCurrentProcess;
  openWorkspaceRoot(workspacePath: string): HeldWorkspaceRoot;
  inspectKernelGlobalGate?(): NativeKernelGlobalGate | null;
  acquireKernelGlobalShared?(): NativeKernelGlobalGate;
  acquireKernelGlobalExclusive?(): NativeKernelGlobalGate;
  inspectLegacyEntry?(shared: NativeKernelGlobalGate, legacyRoot: string): LegacyEntryObservation;
  verifyLegacyMigratedAuth?(shared: NativeKernelGlobalGate, legacyRoot: string, contentDigest: string, byteCount: number):
    Readonly<{ kind: 'matched_auth_bytes'; contentDigest: string; byteCount: number; rootIdentity: DescriptorIdentity }>;
  inspectKernelMigrationEntry?(owner: NativeLock): KernelMigrationEntryObservation;
  inspectKernelMigrationBeforeOwner?(shared: NativeKernelGlobalGate, rootFd: number, root: readonly bigint[]): KernelMigrationEntryObservation;
  bindMigrationCredentialGate?(owner: NativeLock, exclusive: NativeKernelGlobalGate): NativeMigrationCredentialGate;
  acquireMigrationFilesystem?(bound: NativeMigrationCredentialGate, migrationId: string, legacyRoot: string): NativeMigrationFilesystem;
  openCurrentMigrationInspector?(bound: NativeMigrationCredentialGate, migrationId: string, archiveId: string,
    legacyRoot: string, roots: readonly bigint[], control: Buffer, authority: Buffer, rendezvous: Buffer, authMarker: Buffer): RawCurrentMigrationInspector;
  openPreparedImportCandidate?(scope: NativeMigrationFilesystem): NativePreparedImportCandidate;
  createKernelArchive?(bound: NativeMigrationCredentialGate, migrationId: string, archiveId: string, controlBytes: Buffer): RawKernelArchive;
  deriveLocalModelStoreGate?(original: NativeMigrationCredentialGate): NativeLocalModelExclusiveGate;
  acquireLocalModelStore?(rootFd: number, stateRoot: string, root: readonly bigint[],
    exclusive?: NativeLocalModelExclusiveGate): NativeLocalModelStore | null;
  acquireCredentialScope?(rootFd: number, stateRoot: string, root: readonly bigint[],
    migration?: NativeMigrationCredentialGate): NativeCredentialScope;
  connectInstalledControl?(rootFd: number, stateRoot: string, root: readonly bigint[],
    imageFd: number, image: readonly bigint[]): HeldInstalledControlClient;
  initializeInstalledKeeper?(stateRoot: string, bundleDigest: string, relativePath: string,
    image: readonly bigint[], root: readonly bigint[]): NativeInstalledKeeper;
  acquireInstalledAnchor?(stateRoot: string, bundleDigest: string, relativePath: string,
    image: readonly bigint[], root: readonly bigint[], locator: Buffer): NativeInstalledAnchor;
  checkInstalledUpgradeKeeper?(stateRoot: string, bundleDigest: string, relativePath: string,
    image: readonly bigint[], root: readonly bigint[], locator: Buffer, packageRoot: string,
    controllerRelativePath: string, controllerImage: readonly bigint[], packageIdentity: readonly bigint[]): RawInstalledUpgradeKeeperCheck;
  executeInstalledImage?(fd: number, image: readonly bigint[], bootstrap: readonly bigint[], root: readonly bigint[],
    stateRoot: string, bundleDigest: string, relativePath: string, role: 'keeper' | 'supervisor' | 'endpoint' | 'credential', command?: string): never };
const nativeBindings = new WeakMap<NativeStateOwner, NativeBinding>();

export type KernelArchiveBirthObservation = Readonly<{
  stateRoot: DescriptorIdentity; migrationDirectory: DescriptorIdentity; archiveCollection: DescriptorIdentity;
  archiveDirectory: DescriptorIdentity; controlFile: DescriptorIdentity; file: DescriptorIdentity;
  migrationId: string; archiveId: string; controlContentDigest: string; localModelStore: 'absent'; mode: number; linkCount: number;
}>;
export type KernelArchiveImageObservation = KernelArchiveBirthObservation & Readonly<{ sha256: string; byteCount: number }>;
export type KernelArchiveBackupJoin = Readonly<{ outcome: 'commit_phase_two_observed' | 'cancelled' | 'failed' | 'not_selected' | 'no_commit_phase_two';
  mainOpens: number; mainCloses: number; journalOpens: number; journalCloses: number; journalBirths: number; journalDeletions: number }>;
type RawKernelArchive = Readonly<{ assertHeld(): void; describeBirth(): KernelArchiveBirthObservation;
  beginBackup(): string; requestCancel(): void; joinBackup(): KernelArchiveBackupJoin; sealNext(): boolean;
  identity(): KernelArchiveImageObservation; beginRead(): string; endRead(): void;
  beginCasCapture(): void; captureCasNext(): boolean; casCaptureIdentity(): KernelArchiveCasIdentity;
  readCasCaptureEntries(start: number): readonly KernelArchiveCasEntry[];
  beginManifest(bytes: Buffer): void; sealManifestNext(): boolean;
  manifestIdentity(): KernelArchiveManifestObservation; close(): void }>;
export type KernelArchiveManifestObservation = Readonly<{ file: DescriptorIdentity; sha256: string; byteCount: number }>;
export type HeldKernelArchive = Readonly<{ assertHeld(): void; close(): void }>;
const kernelArchives = new WeakMap<HeldKernelArchive, Readonly<{ native: NativeStateOwner; original: RawKernelArchive;
  gate: HeldMigrationCredentialGate; image: FileHandle; control: KernelRollbackDrainingControlV1; birth: KernelArchiveBirthObservation }>>();
const unretiredKernelArchives = new Set<HeldKernelArchive>();
const kernelArchiveCaptureReads = new WeakMap<HeldKernelArchive, { complete: boolean }>();
function archiveObservation(value: unknown, control: KernelRollbackDrainingControlV1, sealed: boolean): KernelArchiveBirthObservation | KernelArchiveImageObservation {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['stateRoot', 'migrationDirectory', 'archiveCollection', 'archiveDirectory', 'controlFile', 'file',
    'migrationId', 'archiveId', 'controlContentDigest', 'localModelStore', 'mode', 'linkCount', ...(sealed ? ['sha256', 'byteCount'] : [])]);
  for (const key of ['stateRoot', 'migrationDirectory', 'archiveCollection', 'archiveDirectory', 'controlFile', 'file'])
    migrationObservedRootIdentity(data[key]);
  if (data.migrationId !== control.migrationId || data.archiveId !== control.archiveId ||
      data.controlContentDigest !== canonicalSha256(control) || data.localModelStore !== 'absent' || data.mode !== (sealed ? 0o400 : 0o600) || data.linkCount !== 1)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'original archive observation differs from its draining intent');
  if (sealed) { controlWireRef(data.sha256); controlWireInteger(data.byteCount, 1, 53_687_091_200); }
  return immutableSnapshot(data) as KernelArchiveBirthObservation | KernelArchiveImageObservation;
}
/** Called only by the fixed installed producer while its original selected
 * image/EX/Owner are held. It cannot adopt an archive or accept a destination. */
export async function createHeldKernelArchive(native: NativeStateOwner, gate: HeldMigrationCredentialGate,
  image: FileHandle, value: KernelRollbackDrainingControlV1): Promise<HeldKernelArchive> {
  const binding = nativeBindings.get(native), original = migrationCredentialGates.get(gate);
  if (!binding || typeof binding.createKernelArchive !== 'function' || !original || original.native !== native ||
      process.platform !== 'linux' || process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'archive requires the fixed installed Linux Node24 original EX/Owner');
  const control = decodeKernelRollbackDrainingControl(value), root = roots.get(original.owner);
  if (!root || control.stateRootIdentityRef !== canonicalSha256(root) || control.stateRootIdentityDigest !== root.identityDigest ||
      control.stateRootCanonicalAbsolutePath !== root.canonicalAbsolutePath)
    throw new TypeError('archive draining intent belongs to another actual original root');
  gate.assertHeld(); original.owner.assertHeld(); await assertHeldCredentialNativeImage(native, image); gate.assertHeld();
  let actual: RawKernelArchive;
  try { actual = binding.createKernelArchive(original.original, control.migrationId, control.archiveId, canonicalJsonBytes(control)); }
  catch (error) { return kernelGlobalFailure(error); }
  const held: HeldKernelArchive = Object.freeze({
    assertHeld(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('archive requires its original receiver');
      try { actual.assertHeld(); } catch (error) { return kernelGlobalFailure(error); }
    },
    close(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('archive requires its original receiver');
      try { actual.close(); } catch (error) { unretiredKernelArchives.add(held);
        throw new ResourceRetirementError('original archive scope did not actually retire', error); }
    }
  });
  try {
    const birth = archiveObservation(actual.describeBirth(), control, false) as KernelArchiveBirthObservation;
    if (canonicalSha256(birth.stateRoot) !== canonicalSha256({ deviceId: root.deviceId, fileId: root.directoryFileId, ownerUid: root.ownerUid }))
      throw new TypeError('archive birth belongs to another actual original root');
    kernelArchives.set(held, { native, original: actual, gate, image, control, birth }); return held;
  } catch (error) {
    try { actual.close(); } catch (retirement) { unretiredKernelArchives.add(held);
      throw new ResourceRetirementError('archive birth validation and retirement did not complete', new AggregateError([error, retirement])); }
    throw error;
  }
}
function heldKernelArchive(scope: HeldKernelArchive) {
  const held = kernelArchives.get(scope);
  if (!held) throw new TypeError('archive requires its genuine original native producer');
  scope.assertHeld(); return held;
}
export function assertHeldKernelArchive(scope: HeldKernelArchive): void { heldKernelArchive(scope); }
/** Original-driver registry friend: this archive may copy only the actual
 * owner's fixed kernel.sqlite3, never a credential or arbitrary SQLite path. */
export function assertHeldKernelArchiveSource(scope: HeldKernelArchive, sourcePath: string): void {
  const held = heldKernelArchive(scope);
  if (sourcePath !== path.join(held.control.stateRootCanonicalAbsolutePath, 'kernel.sqlite3'))
    throw new TypeError('archive source is not its original StateOwner fixed Kernel database');
}
export function assertHeldMigrationGateRoot(native: NativeStateOwner, gate: HeldMigrationCredentialGate, expected: StateRootIdentityV1): void {
  const actual = migrationCredentialGates.get(gate), root = actual && roots.get(actual.owner);
  if (!actual || actual.native !== native || !root || canonicalSha256(root) !== canonicalSha256(expected))
    throw new TypeError('migration EX belongs to another genuine selected root');
  actual.owner.assertHeld(); gate.assertHeld();
}

/** Same selected native image and exact original Owner, not root equality or
 * a structural assertHeld callback. Read-only EX history and current inspector
 * composition use this before reading any protected original source cut. */
export function assertHeldMigrationGateOwner(native: NativeStateOwner, gate: HeldMigrationCredentialGate, owner: HeldStateOwnerLock): void {
  const actual = migrationCredentialGates.get(gate);
  if (!actual || actual.native !== native || actual.owner !== owner)
    throw new TypeError('migration EX requires its exact original StateOwner holder');
  actual.owner.assertHeld(); gate.assertHeld();
}

export function describeHeldKernelArchiveBirth(scope: HeldKernelArchive): KernelArchiveBirthObservation {
  const held = heldKernelArchive(scope); const actual = archiveObservation(held.original.describeBirth(), held.control, false);
  if (canonicalSha256(actual) !== canonicalSha256(held.birth)) throw new KernelStorageError('RECOVERY_REQUIRED', 'archive original birth changed');
  return held.birth;
}
/** Private SQLite-source friend. URI remains inside the original-driver
 * module, never a control response or caller-selected destination. */
export async function beginHeldKernelArchiveBackup(scope: HeldKernelArchive): Promise<Readonly<{
  uri: string; requestCancel(): void; join(): KernelArchiveBackupJoin;
}>> {
  const held = heldKernelArchive(scope); await assertHeldCredentialNativeImage(held.native, held.image);
  let uri: string;
  try { uri = held.original.beginBackup(); } catch (error) { return kernelGlobalFailure(error); }
  try {
    if (!/^file:\/cliq-owned-archive\?mode=rw&vfs=cliq-owned-archive-target-v1&cliq_archive_lease=[0-9a-f]{64}$/u.test(uri))
      throw new TypeError('original archive returned an invalid fixed private URI');
    const bootstrap = new DatabaseSync(':memory:', { allowExtension: true });
    try {
      await assertHeldCredentialNativeImage(held.native, held.image);
      (bootstrap.loadExtension as (image: string, entry: string) => void).call(bootstrap,
        `/proc/self/fd/${held.image.fd}`, 'sqlite3_cliqownedarchive_init');
      bootstrap.enableLoadExtension(false);
    } finally { try { bootstrap.close(); } catch (error) { unretiredPreparedArchiveBootstraps.add(bootstrap);
      throw new ResourceRetirementError('archive SQLite bootstrap did not actually retire', error); } }
    scope.assertHeld();
  } catch (error) {
    try { held.original.requestCancel(); held.original.joinBackup(); }
    catch (retirement) { unretiredKernelArchives.add(scope);
      throw new ResourceRetirementError('archive preparation did not join its actual native lease', new AggregateError([error, retirement])); }
    throw error;
  }
  return Object.freeze({ uri,
    requestCancel() { held.original.requestCancel(); },
    join() { return decodeKernelArchiveJoin(held.original.joinBackup()); }
  });
}
const unretiredPreparedArchiveBootstraps = new Set<DatabaseSync>();
function decodeKernelArchiveJoin(value: unknown): KernelArchiveBackupJoin {
  assertControlWireJson(value); const data = controlWireRecord(value,
    ['outcome', 'mainOpens', 'mainCloses', 'journalOpens', 'journalCloses', 'journalBirths', 'journalDeletions']);
  if (!['commit_phase_two_observed', 'cancelled', 'failed', 'not_selected', 'no_commit_phase_two'].includes(String(data.outcome)))
    throw new TypeError('archive backup join outcome is not closed');
  for (const key of ['mainOpens', 'mainCloses', 'journalOpens', 'journalCloses', 'journalBirths', 'journalDeletions']) controlWireInteger(data[key], 0);
  if (data.mainOpens !== data.mainCloses || data.journalOpens !== data.journalCloses || data.journalBirths !== data.journalDeletions)
    throw new ResourceRetirementError('archive actual SQLite callbacks or journal did not join', undefined);
  return immutableSnapshot(data) as KernelArchiveBackupJoin;
}
export async function sealHeldKernelArchive(scope: HeldKernelArchive, signal?: AbortSignal): Promise<KernelArchiveImageObservation> {
  const held = heldKernelArchive(scope);
  for (;;) { signal?.throwIfAborted(); scope.assertHeld();
    if (held.original.sealNext()) break; await setImmediate(); }
  const value = archiveObservation(held.original.identity(), held.control, true) as KernelArchiveImageObservation;
  for (const field of ['stateRoot', 'migrationDirectory', 'archiveCollection', 'archiveDirectory', 'controlFile', 'file'] as const)
    if (canonicalSha256(value[field]) !== canonicalSha256(held.birth[field]))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'sealed archive changed its original birth identity');
  return value;
}
export function beginHeldKernelArchiveRead(scope: HeldKernelArchive): string {
  const held = heldKernelArchive(scope); const uri = held.original.beginRead();
  if (!/^file:\/cliq-owned-archive\?mode=ro&vfs=cliq-owned-archive-target-v1&cliq_archive_lease=[0-9a-f]{64}$/u.test(uri))
    throw new ResourceRetirementError('archive readonly lease returned an invalid fixed URI', undefined);
  return uri;
}
export function endHeldKernelArchiveRead(scope: HeldKernelArchive): void {
  const held = kernelArchives.get(scope); if (!held) throw new TypeError('archive read join requires its original producer');
  try { held.original.endRead(); } catch (error) { unretiredKernelArchives.add(scope);
    throw new ResourceRetirementError('archive actual readonly SQLite lease did not join', error); }
}

/** Fixed complete native namespace capture under the original archive. All
 * metadata is independently checked, but never supplies native authority. */
export async function captureHeldKernelArchiveCas(scope: HeldKernelArchive, sqliteByteCount: number, signal?: AbortSignal):
  Promise<Readonly<{ identity: KernelArchiveCasIdentity; entries: AsyncIterableIterator<readonly KernelArchiveCasEntry[]> }>> {
  const held = heldKernelArchive(scope);
  if (typeof held.original.beginCasCapture !== 'function' || typeof held.original.captureCasNext !== 'function' ||
      typeof held.original.casCaptureIdentity !== 'function' || typeof held.original.readCasCaptureEntries !== 'function')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'selected archive has no complete native namespace capture');
  signal?.throwIfAborted(); held.original.beginCasCapture();
  for (;;) {
    signal?.throwIfAborted(); scope.assertHeld();
    if (held.original.captureCasNext()) break;
    await setImmediate();
  }
  const identity = decodeKernelArchiveCasIdentity(held.original.casCaptureIdentity());
  if (identity.sourceDirectory.ownerUid !== held.birth.stateRoot.ownerUid ||
      identity.sourceDirectory.deviceId !== held.birth.stateRoot.deviceId ||
      identity.archiveDirectory.ownerUid !== held.birth.archiveDirectory.ownerUid ||
      identity.archiveDirectory.deviceId !== held.birth.archiveDirectory.deviceId)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'archive CAS identities differ from the original held roots');
  controlWireInteger(sqliteByteCount, 1, KERNEL_ARCHIVE_MAX_BYTES);
  const read = { complete: false }; kernelArchiveCaptureReads.set(scope, read);
  const entries = (async function* (): AsyncIterableIterator<readonly KernelArchiveCasEntry[]> {
    const digest = createHash('sha256'); let previous = '', total = 0, count = 0;
    while (count < identity.entryCount) {
      signal?.throwIfAborted(); scope.assertHeld();
      const rawPage = held.original.readCasCaptureEntries(count);
      if (!Array.isArray(rawPage) || rawPage.length !== Math.min(64, identity.entryCount - count))
        throw new KernelStorageError('RECOVERY_REQUIRED', 'archive CAS metadata is not its exact complete fixed page');
      const page: KernelArchiveCasEntry[] = [];
      for (const raw of rawPage) {
        const entry = decodeKernelArchiveCasEntry(raw);
        if (entry.name <= previous || entry.byteCount > KERNEL_ARCHIVE_MAX_BYTES - total)
          throw new KernelStorageError('RECOVERY_REQUIRED', 'archive CAS page order or complete size changed');
        previous = entry.name; total += entry.byteCount; page.push(entry); count++;
        digest.update(entry.name).update('\0').update(entry.kind).update('\0').update(entry.sha256).update('\0').update(String(entry.byteCount)).update('\n');
      }
      yield Object.freeze(page); await setImmediate();
    }
    signal?.throwIfAborted(); scope.assertHeld();
    if (total !== identity.totalBytes || identity.combinedPayloadBytes !== total + sqliteByteCount || digest.digest('hex') !== identity.entriesDigest ||
        canonicalSha256(decodeKernelArchiveCasIdentity(held.original.casCaptureIdentity())) !== canonicalSha256(identity))
      throw new KernelStorageError('RECOVERY_REQUIRED', 'archive CAS complete entry digest, identity or payload sum changed');
    read.complete = true;
  })();
  return Object.freeze({ identity, entries });
}

/** Only the same holder's fixed private manifest destination can be written.
 * Every issued native step and final complete readonly hash remains real. */
export async function sealHeldKernelArchiveManifest(scope: HeldKernelArchive, bytes: Buffer, signal?: AbortSignal): Promise<KernelArchiveManifestObservation> {
  const held = heldKernelArchive(scope);
  if (!kernelArchiveCaptureReads.get(scope)?.complete)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'archive manifest requires actual EOF of its complete original metadata pages');
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > KERNEL_ARCHIVE_MAX_MANIFEST_BYTES)
    throw new TypeError('archive manifest bytes exceed the fixed complete metadata profile');
  if (typeof held.original.beginManifest !== 'function' || typeof held.original.sealManifestNext !== 'function' ||
      typeof held.original.manifestIdentity !== 'function')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'selected archive has no complete native manifest seal');
  const hash = createHash('sha256');
  for (let offset = 0; offset < bytes.length; offset += 65_536) {
    signal?.throwIfAborted(); scope.assertHeld(); hash.update(bytes.subarray(offset, offset + 65_536)); await setImmediate();
  }
  signal?.throwIfAborted(); const digest = hash.digest('hex'); held.original.beginManifest(bytes);
  for (;;) {
    signal?.throwIfAborted(); scope.assertHeld();
    if (held.original.sealManifestNext()) break;
    await setImmediate();
  }
  const data = controlWireRecord(held.original.manifestIdentity(), ['file', 'sha256', 'byteCount']);
  const file = decodeKernelArchiveDirectoryIdentity(data.file), byteCount = controlWireInteger(data.byteCount, 1, KERNEL_ARCHIVE_MAX_BYTES);
  if (byteCount !== bytes.length || controlWireRef(data.sha256) !== digest || file.ownerUid !== held.birth.stateRoot.ownerUid ||
      file.deviceId !== held.birth.archiveDirectory.deviceId)
    throw new KernelStorageError('RECOVERY_REQUIRED', 'archive manifest differs from its actual complete original bytes');
  scope.assertHeld(); return Object.freeze({ file, sha256: digest, byteCount });
}

/** Account-wide cooperation fence only. It grants no credential, StateOwner,
 * Trust, Run or filesystem authority. Native fixes the actual NSS home; no
 * caller can choose its location through StateRoot, HOME or CLIQ_HOME. */
export type HeldKernelGlobalGate = Readonly<{ assertHeld(): void; close(): void }>;
export type LegacyEntryObservation = Readonly<{ kind: 'legacy_root_absent' | 'rendezvous_absent' }> |
  Readonly<{ kind: 'rendezvous_present'; bytes: Buffer; contentDigest: string; rootIdentity: DescriptorIdentity }>;
export type KernelMigrationEntryObservation = Readonly<{ kind: 'unmigrated' }> |
  Readonly<{ kind: 'controlled'; controlBytes: Buffer; authorityBytes?: Buffer }>;
/** Same original owner/root only; cannot be supplied as an unbound EX gate. */
export type HeldMigrationCredentialGate = Readonly<{ assertHeld(): void; close(): void }>;
const kernelGlobalGates = new WeakMap<HeldKernelGlobalGate, Readonly<{
  native: NativeStateOwner; original: NativeKernelGlobalGate; exclusive: boolean;
}>>();
const migrationCredentialGates = new WeakMap<HeldMigrationCredentialGate, Readonly<{
  native: NativeStateOwner; original: NativeMigrationCredentialGate; owner: HeldStateOwnerLock;
}>>();
export type HeldMigrationFilesystem = Readonly<{ assertHeld(): void; close(): void }>;
export type HeldMigrationDirectoryObservation = Readonly<{ canonicalAbsolutePath: string; ownerUid: number;
  deviceId: string; directoryFileId: string; mode: number; openedNoFollow: true }>;
export type HeldMigrationRootsObservation = Readonly<{ migrationId: string; stateRoot: StateRootIdentityV1;
  legacyRoot: HeldMigrationDirectoryObservation; backupRoot: HeldMigrationDirectoryObservation }>;
export type HeldMigrationAuthObservation = Readonly<{ presence: 'absent'; noFollowLookupResult: 'ENOENT' }> |
  Readonly<{ presence: 'present'; file: DescriptorIdentity; byteCount: number; contentDigest: string; mode: 384; linkCount: 1 }>;
type MigrationBackupBase = Readonly<{ canonicalRootRelativePath: string; sourceIdentity: DescriptorIdentity;
  backupIdentity: DescriptorIdentity; mode: number; purpose: 'backup_only' | 'portable_context' | 'validation_only' }>;
export type HeldMigrationBackupFile = MigrationBackupBase & Readonly<{
  kind: 'regular_file'; contentDigest: string; byteCount: number; linkCount: 1;
}>;
export type HeldMigrationBackupEntry = HeldMigrationBackupFile |
  (MigrationBackupBase & Readonly<{ kind: 'directory' }>) |
  (MigrationBackupBase & Readonly<{ kind: 'unfollowed_link_metadata'; linkTextDigest: string }>);
export type HeldMigrationSourceFile = HeldMigrationBackupFile & Readonly<{ purpose: 'portable_context' | 'validation_only' }>;
export type HeldMigrationContextSourceEvent =
  | Readonly<{ kind: 'source_begin'; source: HeldMigrationSourceFile }>
  | Readonly<{ kind: 'source_chunk'; bytes: Uint8Array }>
  | Readonly<{ kind: 'source_complete'; source: HeldMigrationSourceFile }>;
const migrationFilesystems = new WeakMap<HeldMigrationFilesystem, Readonly<{
  native: NativeStateOwner; original: NativeMigrationFilesystem; bound: HeldMigrationCredentialGate;
  migrationId: string; legacyRoot: string;
}>>();
// A failed real writer close retains this actual native scope as well as the
// original Node connection. GC/ordinary close cannot undercut that producer.
const activeMigrationCandidateBuilders = new Map<HeldMigrationFilesystem, SqliteDriver | undefined>();
const unretiredMigrationContextScopes = new Set<HeldMigrationFilesystem>();
function kernelGlobalFailure(error: unknown): never {
  if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
    throw new ResourceRetirementError('account gate or original migration binding did not retire', error);
  // This is native acquisition contention, not authority or an instruction to
  // retry. Migration/rollback must refuse before publishing its protected cut.
  if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_KERNEL_GLOBAL_BUSY') throw error;
  throw new KernelStorageError('RECOVERY_REQUIRED', 'original account gate or migration binding is unavailable', { cause: error });
}
function heldKernelGlobalGate(native: NativeStateOwner, mode: 'inspect' | 'shared' | 'exclusive'): HeldKernelGlobalGate | null {
  const binding = nativeBindings.get(native);
  const acquire = mode === 'inspect' ? binding?.inspectKernelGlobalGate :
    mode === 'shared' ? binding?.acquireKernelGlobalShared : binding?.acquireKernelGlobalExclusive;
  if (!binding || typeof acquire !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'account gate requires the original supporting native image');
  let original: NativeKernelGlobalGate | null;
  try { original = Reflect.apply(acquire, binding, []); } catch (error) { return kernelGlobalFailure(error); }
  if (original === null) {
    if (mode !== 'inspect') throw new KernelStorageError('ARTIFACT_MISMATCH', 'owning account gate returned absence');
    return null;
  }
  const actual = original;
  const held: HeldKernelGlobalGate = Object.freeze({
    assertHeld(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('account gate requires its original receiver and no arguments');
      try { actual.assertHeld(); } catch (error) { kernelGlobalFailure(error); }
    },
    close(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('account gate requires its original receiver and no arguments');
      try { actual.close(); } catch (error) { kernelGlobalFailure(error); }
    }
  });
  kernelGlobalGates.set(held, { native, original: actual, exclusive: mode === 'exclusive' });
  return held;
}
/** Exact absent is not completed quiescence; this path never creates or syncs. */
export function inspectHeldKernelGlobalGate(native: NativeStateOwner): HeldKernelGlobalGate | null {
  return heldKernelGlobalGate(native, 'inspect');
}
export function acquireHeldKernelGlobalShared(native: NativeStateOwner): HeldKernelGlobalGate {
  return heldKernelGlobalGate(native, 'shared')!;
}
export function acquireHeldKernelGlobalExclusive(native: NativeStateOwner): HeldKernelGlobalGate {
  return heldKernelGlobalGate(native, 'exclusive')!;
}
/** Fixed no-write, no-StateOwner rendezvous observation under the original
 * account SH. Complete original FD/hash/EOF/close is native; the result grants
 * no Kernel authority and cannot be used after releasing SH to start Legacy. */
export function inspectHeldLegacyEntry(native: NativeStateOwner, shared: HeldKernelGlobalGate,
  legacyRoot: string): LegacyEntryObservation {
  const binding = nativeBindings.get(native), gate = kernelGlobalGates.get(shared);
  if (!binding || !gate || gate.native !== native || gate.exclusive || typeof binding.inspectLegacyEntry !== 'function' ||
      normalizeAbsolutePath(legacyRoot) !== legacyRoot)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'Legacy entry requires its original supporting native image, root locator and shared gate');
  shared.assertHeld(); let value: LegacyEntryObservation;
  try { value = binding.inspectLegacyEntry(gate.original, legacyRoot); } catch (error) { return kernelGlobalFailure(error); }
  shared.assertHeld();
  if (!value || typeof value !== 'object' || types.isProxy(value)) throw new TypeError('Legacy entry observation is invalid');
  if (value.kind === 'legacy_root_absent' || value.kind === 'rendezvous_absent') {
    if (Reflect.ownKeys(value).length !== 1) throw new TypeError('Legacy entry absence is not closed');
    return Object.freeze({ kind: value.kind });
  }
  if (value.kind !== 'rendezvous_present' || Reflect.ownKeys(value).length !== 4 || !Buffer.isBuffer(value.bytes) ||
      value.bytes.length < 1 || value.bytes.length > 1_048_576 || !/^[0-9a-f]{64}$/u.test(value.contentDigest) ||
      createHash('sha256').update(value.bytes).digest('hex') !== value.contentDigest)
    throw new TypeError('Legacy rendezvous differs from its complete native bytes');
  const rootIdentity = migrationObservedRootIdentity(value.rootIdentity);
  return Object.freeze({ kind: value.kind, bytes: Buffer.from(value.bytes), contentDigest: value.contentDigest, rootIdentity });
}
function migrationObservedRootIdentity(value: unknown): DescriptorIdentity {
  assertControlWireJson(value); const data = controlWireRecord(value, ['deviceId', 'fileId', 'ownerUid']);
  for (const field of ['deviceId', 'fileId']) if (!/^(0|[1-9][0-9]{0,19})$/u.test(controlWireText(data[field], 20)))
    throw new TypeError('migration observed directory identity is invalid');
  controlWireInteger(data.ownerUid, 0, 0xffff_ffff); return immutableSnapshot(data) as DescriptorIdentity;
}
/** Native reads only literal auth.json and exports no bytes. Expected bytes
 * come from the same closed secret-free marker used by the real publisher. */
export function verifyHeldLegacyMigratedAuth(native: NativeStateOwner, shared: HeldKernelGlobalGate,
  legacyRoot: string, value: LegacyAuthMigratedMarkerV1): DescriptorIdentity {
  const binding = nativeBindings.get(native), gate = kernelGlobalGates.get(shared);
  if (!binding || !gate || gate.native !== native || gate.exclusive || typeof binding.verifyLegacyMigratedAuth !== 'function' ||
      normalizeAbsolutePath(legacyRoot) !== legacyRoot)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'auth startup verification requires its original supporting image and shared gate');
  const marker = decodeLegacyAuthMigratedMarker(value), bytes = canonicalJsonBytes(marker), ref = sha256Bytes(bytes);
  shared.assertHeld(); let observed: Readonly<{ kind: 'matched_auth_bytes'; contentDigest: string; byteCount: number; rootIdentity: DescriptorIdentity }>;
  try { observed = binding.verifyLegacyMigratedAuth(gate.original, legacyRoot, ref, bytes.length); }
  catch (error) { return kernelGlobalFailure(error); }
  shared.assertHeld();
  if (!observed || types.isProxy(observed) || Reflect.ownKeys(observed).length !== 4 ||
      observed.kind !== 'matched_auth_bytes' || observed.contentDigest !== ref || observed.byteCount !== bytes.length)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'auth startup verification differs from its complete original marker bytes');
  return migrationObservedRootIdentity(observed.rootIdentity);
}
/** Installed-borrow friend only: readonly current fixed documents before any
 * Owner/SQL action. The selected runtime retains and revalidates the real FD;
 * neither a caller-selected pathname nor a temporary StateOwner is opened. */
export function inspectHeldKernelMigrationBeforeOwner(native: NativeStateOwner, shared: HeldKernelGlobalGate,
  root: FileHandle, identity: BigIntStats): KernelMigrationEntryObservation {
  const binding = nativeBindings.get(native), gate = kernelGlobalGates.get(shared);
  if (!binding || !gate || gate.native !== native || gate.exclusive || typeof binding.inspectKernelMigrationBeforeOwner !== 'function')
    throw new TypeError('pre-Owner migration entry requires its genuine selected image and account SH');
  shared.assertHeld(); let value: KernelMigrationEntryObservation;
  try { value = binding.inspectKernelMigrationBeforeOwner(gate.original, root.fd,
    [identity.dev, identity.ino, identity.uid, identity.gid, identity.mode]); }
  catch (error) { return kernelGlobalFailure(error); }
  shared.assertHeld(); return migrationEntryObservation(value);
}
function migrationEntryObservation(value: KernelMigrationEntryObservation): KernelMigrationEntryObservation {
  if (!value || typeof value !== 'object' || types.isProxy(value)) throw new TypeError('migration startup observation is invalid');
  if (value.kind === 'unmigrated' && Reflect.ownKeys(value).length === 1) return Object.freeze({ kind: 'unmigrated' });
  if (value.kind !== 'controlled' || Reflect.ownKeys(value).length !== (value.authorityBytes === undefined ? 2 : 3) ||
      !Buffer.isBuffer(value.controlBytes) || !value.controlBytes.length || value.controlBytes.length > 1_048_576 ||
      value.authorityBytes !== undefined && (!Buffer.isBuffer(value.authorityBytes) || !value.authorityBytes.length || value.authorityBytes.length > 1_048_576))
    throw new TypeError('migration startup documents are not complete bounded bytes');
  return Object.freeze({ kind: 'controlled', controlBytes: Buffer.from(value.controlBytes),
    ...(value.authorityBytes === undefined ? {} : { authorityBytes: Buffer.from(value.authorityBytes) }) });
}
/** Current fixed startup documents under the original root; no old package or
 * creator is adopted. The owning Store independently keeps real account SH. */
export function inspectHeldKernelMigrationEntry(native: NativeStateOwner,
  owner: HeldStateOwnerLock): KernelMigrationEntryObservation {
  const binding = nativeBindings.get(native), original = publicationLocks.get(owner);
  if (!binding || !original || typeof binding.inspectKernelMigrationEntry !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'migration startup requires its supporting original root holder');
  owner.assertHeld(); let value: KernelMigrationEntryObservation;
  try { value = binding.inspectKernelMigrationEntry(original); } catch (error) { return kernelGlobalFailure(error); }
  owner.assertHeld();
  if (!value || typeof value !== 'object' || types.isProxy(value)) throw new TypeError('migration startup observation is invalid');
  if (value.kind === 'unmigrated' && Reflect.ownKeys(value).length === 1) return Object.freeze({ kind: 'unmigrated' });
  if (value.kind !== 'controlled' || Reflect.ownKeys(value).length !== (value.authorityBytes === undefined ? 2 : 3) ||
      !Buffer.isBuffer(value.controlBytes) || !value.controlBytes.length || value.controlBytes.length > 1_048_576 ||
      value.authorityBytes !== undefined && (!Buffer.isBuffer(value.authorityBytes) || !value.authorityBytes.length || value.authorityBytes.length > 1_048_576))
    throw new TypeError('migration startup documents are not complete bounded bytes');
  return Object.freeze({ kind: 'controlled', controlBytes: Buffer.from(value.controlBytes),
    ...(value.authorityBytes === undefined ? {} : { authorityBytes: Buffer.from(value.authorityBytes) }) });
}
/** Composition-only native friend: root identity comes from the original
 * StateOwner tag, never a structural proof or caller-supplied directory FD. */
export function bindHeldMigrationCredentialGate(native: NativeStateOwner, owner: HeldStateOwnerLock,
  exclusive: HeldKernelGlobalGate): HeldMigrationCredentialGate {
  const binding = nativeBindings.get(native), gate = kernelGlobalGates.get(exclusive), lock = publicationLocks.get(owner);
  if (!binding || typeof binding.bindMigrationCredentialGate !== 'function' || !lock || !gate ||
      gate.native !== native || !gate.exclusive)
    throw new TypeError('migration credentials require the original StateOwner and same-image exclusive account gate');
  owner.assertHeld(); exclusive.assertHeld();
  let original: NativeMigrationCredentialGate;
  try { original = binding.bindMigrationCredentialGate(lock, gate.original); }
  catch (error) { return kernelGlobalFailure(error); }
  const held: HeldMigrationCredentialGate = Object.freeze({
    assertHeld(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('migration binding requires its original receiver and no arguments');
      try { original.assertHeld(); } catch (error) { kernelGlobalFailure(error); }
    },
    close(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('migration binding requires its original receiver and no arguments');
      try { original.close(); } catch (error) { kernelGlobalFailure(error); }
    }
  });
  migrationCredentialGates.set(held, { native, original, owner });
  return held;
}

/** Fixed new-package birth only. Existing paths are never adopted as this
 * creator; recovery needs its separate original provenance/death contract. */
export function acquireHeldMigrationFilesystem(native: NativeStateOwner, bound: HeldMigrationCredentialGate,
  migrationId: string, legacyRoot: string): HeldMigrationFilesystem {
  const binding = nativeBindings.get(native), original = migrationCredentialGates.get(bound);
  if (!binding || typeof binding.acquireMigrationFilesystem !== 'function' || !original || original.native !== native)
    throw new TypeError('migration filesystem requires its original same-image bound owner');
  if (!/^[A-Za-z0-9_-]{43}$/u.test(migrationId) || normalizeAbsolutePath(legacyRoot) !== legacyRoot)
    throw new TypeError('migration filesystem requires its fixed migration identity and canonical Legacy root');
  bound.assertHeld();
  let actual: NativeMigrationFilesystem;
  try { actual = binding.acquireMigrationFilesystem(original.original, migrationId, legacyRoot); }
  catch (error) { return kernelGlobalFailure(error); }
  const held: HeldMigrationFilesystem = Object.freeze({
    assertHeld(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('migration filesystem requires its original receiver and no arguments');
      try { actual.assertHeld(); } catch (error) { kernelGlobalFailure(error); }
    },
    close(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('migration filesystem requires its original receiver and no arguments');
      if (activeMigrationCandidateBuilders.has(held) || unretiredMigrationContextScopes.has(held))
        throw new ResourceRetirementError('migration candidate/context producer has not actually joined', undefined);
      try { actual.close(); } catch (error) { kernelGlobalFailure(error); }
    }
  });
  migrationFilesystems.set(held, { native, original: actual, bound, migrationId, legacyRoot });
  return held;
}
const migrationLegacyRetirements = new WeakMap<HeldMigrationFilesystem, Promise<void>>();
export type HeldCurrentMigrationInspector = Readonly<{ assertHeld(): void; close(): void }>;
const currentMigrationInspectors = new WeakMap<HeldCurrentMigrationInspector, Readonly<{
  native: NativeStateOwner; gate: HeldMigrationCredentialGate; owner: HeldStateOwnerLock; raw: RawCurrentMigrationInspector;
}>>();
const unretiredCurrentMigrationInspectors = new Set<HeldCurrentMigrationInspector>();
const currentMigrationRetirements = new WeakMap<HeldCurrentMigrationInspector, Promise<void>>();
/** Private readonly friend. Its data witnesses do not establish a completed
 * import or grant restoration: the conductor independently closes real SQL/CAS
 * history and owns this exact EX/Owner throughout every current observation. */
export function openHeldCurrentMigrationInspector(native: NativeStateOwner, gate: HeldMigrationCredentialGate,
  owner: HeldStateOwnerLock, input: Readonly<{ migrationId: string; archiveId: string; legacyRoot: HeldMigrationDirectoryObservation;
    backupRoot: HeldMigrationDirectoryObservation; entryCount: number; controlBytes: Buffer; authorityBytes: Buffer;
    rendezvousBytes: Buffer; authMarkerBytes: Buffer }>): HeldCurrentMigrationInspector {
  assertHeldMigrationGateOwner(native, gate, owner);
  const binding = nativeBindings.get(native), actual = migrationCredentialGates.get(gate)!, root = stateRootIdentityForLock(owner);
  if (!binding?.openCurrentMigrationInspector) throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'selected native image lacks its fixed current migration inspector');
  const legacy = migrationDirectoryObservation(input.legacyRoot), backup = migrationDirectoryObservation(input.backupRoot);
  if (![input.migrationId, input.archiveId].every(id => /^[A-Za-z0-9_-]{43}$/u.test(id)) ||
      legacy.ownerUid !== root.ownerUid || backup.ownerUid !== root.ownerUid || backup.mode !== 0o700 ||
      backup.canonicalAbsolutePath !== path.join(root.canonicalAbsolutePath, 'migration', 'owned-import', input.migrationId, 'backup'))
    throw new TypeError('current inspector requires the exact original migration roots');
  controlWireInteger(input.entryCount);
  const documents = [input.controlBytes, input.authorityBytes, input.rendezvousBytes, input.authMarkerBytes].map(bytes => {
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 1_048_576) throw new TypeError('current inspector requires complete bounded fixed documents');
    return Buffer.from(bytes);
  });
  let raw: RawCurrentMigrationInspector;
  try { raw = binding.openCurrentMigrationInspector(actual.original, input.migrationId, input.archiveId, legacy.canonicalAbsolutePath,
    [BigInt(legacy.deviceId), BigInt(legacy.directoryFileId), BigInt(legacy.mode), BigInt(backup.deviceId),
      BigInt(backup.directoryFileId), BigInt(backup.mode), BigInt(root.ownerUid), BigInt(input.entryCount)],
    documents[0]!, documents[1]!, documents[2]!, documents[3]!); }
  catch (error) { return kernelGlobalFailure(error); }
  const held: HeldCurrentMigrationInspector = Object.freeze({
    assertHeld(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('current inspector requires its genuine receiver');
      assertHeldMigrationGateOwner(native, gate, owner); try { raw.assertHeld(); } catch (error) { return kernelGlobalFailure(error); }
    },
    close(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('current inspector requires its genuine receiver');
      try { raw.close(); unretiredCurrentMigrationInspectors.delete(held); }
      catch (error) { unretiredCurrentMigrationInspectors.add(held); throw new ResourceRetirementError('current inspector original resources did not actually close', error); }
    }
  });
  currentMigrationInspectors.set(held, { native, gate, owner, raw }); return held;
}
function currentMigrationInspector(scope: HeldCurrentMigrationInspector): RawCurrentMigrationInspector {
  const held = currentMigrationInspectors.get(scope);
  if (!held) throw new TypeError('current observation requires its genuine native inspector');
  assertHeldMigrationGateOwner(held.native, held.gate, held.owner); return held.raw;
}
async function currentInspectionSteps(scope: HeldCurrentMigrationInspector, step: () => boolean, signal?: AbortSignal): Promise<void> {
  for (;;) {
    signal?.throwIfAborted(); scope.assertHeld(); const complete = step();
    if (typeof complete !== 'boolean') throw new TypeError('current native observation returned a non-closed completion');
    if (complete) { scope.assertHeld(); return; } await setImmediate();
  }
}
export async function verifyHeldCurrentMigrationLegacy(scope: HeldCurrentMigrationInspector,
  entries: AsyncIterable<HeldMigrationBackupEntry>, signal?: AbortSignal): Promise<Readonly<{
    kind: 'retained_original_objects_unchanged'; sourceAuth: 'matched_original_marker' | 'absent';
    legacyRoot: HeldMigrationDirectoryObservation; entryCount: number; byteCount: number; inspectionEpoch: string }>> {
  const raw = currentMigrationInspector(scope);
  await currentInspectionSteps(scope, () => raw.prepareLegacyLocksNext(), signal); raw.assertLegacyLocks();
  for await (const entry of entries) {
    signal?.throwIfAborted(); scope.assertHeld(); raw.beginExpectedEntry(encodeCurrentMigrationExpectedEntry(entry));
    await currentInspectionSteps(scope, () => raw.verifyExpectedEntryNext(), signal);
  }
  raw.finishExpectedEntries(); raw.beginWholeTreeVerification();
  await currentInspectionSteps(scope, () => raw.verifyWholeTreesNext(), signal);
  const data = controlWireRecord(raw.inspectRetainedLegacy(), ['kind', 'sourceAuth', 'legacyRoot', 'entryCount', 'byteCount', 'inspectionEpoch']);
  if (data.kind !== 'retained_original_objects_unchanged' || !['matched_original_marker', 'absent'].includes(data.sourceAuth as string) ||
      !/^[1-9][0-9]*$/u.test(controlWireText(data.inspectionEpoch, 20))) throw new TypeError('current native source observation is not complete');
  migrationDirectoryObservation(data.legacyRoot); controlWireInteger(data.entryCount); controlWireInteger(data.byteCount, 0, KERNEL_ARCHIVE_MAX_BYTES);
  scope.assertHeld(); return immutableSnapshot(data) as Awaited<ReturnType<typeof verifyHeldCurrentMigrationLegacy>>;
}
/** Header first, then independently rehashed entry stream. No entry vector or
 * caller-selected file path survives; null means that exact reader reached EOF,
 * rehashed, fsynced and really closed before either strict decoder is finished. */
export async function verifyHeldCurrentKernelArchive(scope: HeldCurrentMigrationInspector, selection: CurrentArchiveManifestSelection,
  expectedControl: KernelRollbackDrainingControlV1, signal?: AbortSignal): Promise<Readonly<{
    header: CompleteKernelArchiveHeader; observation: Readonly<{ kind: 'current_checked_original_archive'; entryCount: number;
      totalBytes: number; manifestSha256: string; archiveDirectory: DescriptorIdentity; manifestFile: DescriptorIdentity;
      databaseFile: DescriptorIdentity; casDirectory: DescriptorIdentity }> }>> {
  const raw = currentMigrationInspector(scope), control = decodeKernelRollbackDrainingControl(expectedControl);
  raw.selectOriginalKernelArchive(encodeCurrentArchiveManifestSelection(selection));
  await currentInspectionSteps(scope, () => raw.verifyArchiveManifestNext(), signal);
  const headerReader = new CompleteKernelArchiveManifestStream({ byteCount: selection.manifest.byteCount, sha256: selection.manifest.sha256 });
  for (;;) { signal?.throwIfAborted(); scope.assertHeld(); const chunk = raw.readArchiveManifestChunk();
    if (chunk === null) break; headerReader.feed(chunk); await setImmediate(); }
  const header = headerReader.finish();
  if (canonicalSha256(header.control) !== canonicalSha256(control) ||
      canonicalSha256(header.archiveDirectory) !== canonicalSha256(selection.archiveDirectory))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'archive header belongs to another original draining intent or birth');
  raw.selectArchivePayload(encodeCurrentArchivePayload(header));
  await currentInspectionSteps(scope, () => raw.verifyArchiveImageNext(), signal); raw.beginArchiveEntryPass();
  const entryReader = new CompleteKernelArchiveManifestStream({ byteCount: selection.manifest.byteCount, sha256: selection.manifest.sha256 });
  for (;;) {
    signal?.throwIfAborted(); scope.assertHeld(); const chunk = raw.readArchiveManifestChunk(); if (chunk === null) break;
    for (const entry of entryReader.feed(chunk)) {
      raw.beginArchiveCasEntry(encodeCurrentArchiveCasEntry(entry));
      await currentInspectionSteps(scope, () => raw.verifyArchiveCasEntryNext(), signal);
    }
    await setImmediate();
  }
  if (canonicalSha256(entryReader.finish()) !== canonicalSha256(header))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'archive header changed during its original entry pass');
  await currentInspectionSteps(scope, () => raw.verifyArchiveNamespaceNext(), signal);
  const data = controlWireRecord(raw.inspectVerifiedArchive(), ['kind', 'entryCount', 'totalBytes', 'manifestSha256',
    'archiveDirectory', 'manifestFile', 'databaseFile', 'casDirectory']);
  if (data.kind !== 'current_checked_original_archive' || data.entryCount !== header.cas.entryCount ||
      data.totalBytes !== header.cas.combinedPayloadBytes + selection.manifest.byteCount || data.manifestSha256 !== selection.manifest.sha256 ||
      canonicalSha256(data.archiveDirectory) !== canonicalSha256(header.archiveDirectory) ||
      canonicalSha256(data.manifestFile) !== canonicalSha256(selection.manifest.file) ||
      canonicalSha256(data.databaseFile) !== canonicalSha256(header.database.file) ||
      canonicalSha256(data.casDirectory) !== canonicalSha256(header.cas.archiveDirectory))
    throw new KernelStorageError('RECOVERY_REQUIRED', 'current archive observation differs from its full original manifest');
  for (const key of ['archiveDirectory', 'manifestFile', 'databaseFile', 'casDirectory']) migrationObservedRootIdentity(data[key]);
  scope.assertHeld(); return Object.freeze({ header, observation: immutableSnapshot(data) as Awaited<ReturnType<typeof verifyHeldCurrentKernelArchive>>['observation'] });
}
export function releaseHeldCurrentMigrationLegacyLocks(scope: HeldCurrentMigrationInspector): Promise<void> {
  const existing = currentMigrationRetirements.get(scope); if (existing) return existing;
  const raw = currentMigrationInspector(scope); let original: Promise<void>;
  try { original = raw.releaseLegacyLocks(); }
  catch (error) { unretiredCurrentMigrationInspectors.add(scope); throw new ResourceRetirementError('current inspector Legacy resources did not join', error); }
  const joined = Promise.resolve(original).catch(error => {
    unretiredCurrentMigrationInspectors.add(scope); throw new ResourceRetirementError('current inspector Legacy resources did not join', error);
  });
  currentMigrationRetirements.set(scope, joined); return joined;
}
/** Prepare the fixed canonical Legacy lock cohort only after its actual
 * initial spine. Yield between native discovery/birth steps; the independent
 * native heartbeat retains the original 5-second lease during SQL work. */
export async function prepareHeldMigrationLegacyLocks(scope: HeldMigrationFilesystem, signal?: AbortSignal): Promise<void> {
  const held = migrationFilesystems.get(scope);
  if (!held || typeof held.original.prepareLegacyLocksNext !== 'function' ||
      typeof held.original.assertLegacyLocks !== 'function' || typeof held.original.releaseLegacyLocks !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed migration lacks its fixed canonical Legacy lock lifecycle');
  if (migrationLegacyRetirements.has(scope)) throw new TypeError('a retired Legacy cohort cannot be prepared again');
  try {
    for (;;) {
      signal?.throwIfAborted(); scope.assertHeld();
      const complete = held.original.prepareLegacyLocksNext();
      if (typeof complete !== 'boolean') throw new TypeError('Legacy lock discovery returned non-closed data');
      if (complete) { held.original.assertLegacyLocks(); scope.assertHeld(); return; }
      await setImmediate();
    }
  } catch (error) {
    if (error instanceof KernelStorageError || error instanceof TypeError || signal?.aborted) throw error;
    return kernelGlobalFailure(error);
  }
}
/** Fresh full physical lock-set/nonce/lease check at the actual final boundary,
 * never a cached prepare result or a substitute for source complete hashes. */
export function assertHeldMigrationLegacyLocks(scope: HeldMigrationFilesystem): void {
  const held = migrationFilesystems.get(scope);
  if (!held || typeof held.original.assertLegacyLocks !== 'function' || migrationLegacyRetirements.has(scope))
    throw new TypeError('final migration boundary requires its genuine unretired Legacy lock cohort');
  try { held.original.assertLegacyLocks(); } catch (error) { return kernelGlobalFailure(error); }
}
/** Real native stop/join/owned-directory cleanup, including partial birth.
 * Failure remains strongly retained by the original Store/scope. Repeated
 * callers observe one original task; no consumed FD or unlink is retried. */
export function releaseHeldMigrationLegacyLocks(scope: HeldMigrationFilesystem): Promise<void> {
  const existing = migrationLegacyRetirements.get(scope); if (existing) return existing;
  const held = migrationFilesystems.get(scope);
  if (!held || typeof held.original.releaseLegacyLocks !== 'function')
    throw new TypeError('Legacy retirement requires its original native migration filesystem');
  let operation: Promise<void>;
  try { operation = held.original.releaseLegacyLocks(); }
  catch (error) { throw new ResourceRetirementError('original Legacy lock resources did not join', error); }
  const joined = Promise.resolve(operation).catch(error => {
    throw new ResourceRetirementError('original Legacy lock resources did not join', error);
  });
  migrationLegacyRetirements.set(scope, joined); return joined;
}
/** Original construction arguments are retained beside the genuine native
 * holder; a later caller may not relabel another source root or migration id. */
export function assertHeldMigrationSourceRoot(scope: HeldMigrationFilesystem, migrationId: string, legacyRoot: string): void {
  const held = migrationFilesystems.get(scope);
  if (!held || held.migrationId !== migrationId || held.legacyRoot !== legacyRoot)
    throw new TypeError('migration source consumer requires its original root and migration identity');
  scope.assertHeld();
}
/** Selected-runtime friend: equality of two actual held producers, never an
 * authority constructor. A genuine scope from another root is still foreign. */
export function assertHeldMigrationFilesystemRoot(native: NativeStateOwner, scope: HeldMigrationFilesystem,
  selectedRoot: StateRootIdentityV1): void {
  const held = migrationFilesystems.get(scope), bound = held && migrationCredentialGates.get(held.bound);
  const actual = bound && roots.get(bound.owner);
  if (!held || held.native !== native || !bound || !actual || canonicalSha256(actual) !== canonicalSha256(selectedRoot))
    throw new TypeError('migration filesystem is not the original selected StateOwner root');
  scope.assertHeld(); bound.owner.assertHeld();
}
/** Exact original native tag, not equality of a root path or data identity. */
export function assertHeldMigrationFilesystemOwner(scope: HeldMigrationFilesystem, owner: HeldStateOwnerLock): void {
  const held = migrationFilesystems.get(scope), bound = held && migrationCredentialGates.get(held.bound);
  if (!held || !bound || bound.owner !== owner) throw new TypeError('migration filesystem belongs to another original StateOwner holder');
  owner.assertHeld(); held.bound.assertHeld(); scope.assertHeld();
}

/** Fixed friend of the original credential producer. Equality of retained root
 * data is insufficient: both real scopes must borrow this very EX/Owner. */
export function assertHeldMigrationCredentialFilesystem(gate: HeldMigrationCredentialGate,
  scope: HeldMigrationFilesystem, owner: HeldStateOwnerLock): void {
  const filesystem = migrationFilesystems.get(scope), held = migrationCredentialGates.get(gate);
  if (!filesystem || !held || filesystem.bound !== gate || held.owner !== owner || filesystem.native !== held.native)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential import requires its original migration EX and filesystem holder');
  assertHeldMigrationFilesystemOwner(scope, owner); gate.assertHeld();
}
const unretiredMigrationWorkspaceRoots = new Set<HeldWorkspaceRoot>();
/** Fixed physical identity observation inside the original candidate stage.
 * It borrows this scope's already verified native image, without recursively
 * entering the installed selection queue held by that very stage. No root FD,
 * configuration, Trust, tool permission or executable owner is returned. */
export function observeHeldMigrationWorkspaceIdentity(scope: HeldMigrationFilesystem,
  workspacePath: string, ownerPrincipalId: string): Extract<WorkspaceIdentityV1, { kind: 'live' }> {
  const held = migrationFilesystems.get(scope);
  if (!held) throw new TypeError('workspace observation requires its genuine migration filesystem');
  scope.assertHeld();
  const canonicalPath = normalizeAbsolutePath(workspacePath); controlWireText(ownerPrincipalId);
  let opened: HeldWorkspaceRoot;
  try { opened = held.native.openWorkspaceRoot(canonicalPath); }
  catch (error) {
    if (error instanceof KernelStorageError || error instanceof ResourceRetirementError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('migration workspace observation did not retire', error);
    throw new KernelStorageError('INVALID_REQUEST', 'migration workspace requires an actual same-user no-follow root', { cause: error });
  }
  try {
    opened.assertHeld(); scope.assertHeld();
    let repository: RepositoryIdentityV2 | undefined;
    if (opened.repositoryDirectory !== undefined) {
      repository = { schemaVersion: 2, format: 'cliq-repository-identity-v2', platform: 'linux',
        gitDirectoryRelativePath: '.git', gitDirectoryIdentity: opened.repositoryDirectory, repositoryIdentityDigest: '' };
      repository.repositoryIdentityDigest = digestOmitting(repository, 'repositoryIdentityDigest');
    }
    const identity: Extract<WorkspaceIdentityV1, { kind: 'live' }> = { schemaVersion: 1, format: 'cliq-workspace-identity-v1',
      ownerPrincipalId, platform: 'linux', kind: 'live', canonicalRootPath: canonicalPath, rootIdentity: opened.identity,
      ...(repository ? { repositoryIdentityDigest: repository.repositoryIdentityDigest } : {}), identityDigest: '' };
    identity.identityDigest = digestOmitting(identity, 'identityDigest'); return immutableSnapshot(identity);
  } finally {
    try { opened.close(); }
    catch (error) {
      unretiredMigrationWorkspaceRoots.add(opened);
      throw new ResourceRetirementError('original migration workspace descriptor did not actually retire', error);
    }
  }
}
function migrationPublicationScope(scope: HeldMigrationFilesystem) {
  const held = migrationFilesystems.get(scope), bound = held && migrationCredentialGates.get(held.bound);
  const stateRoot = bound && roots.get(bound.owner);
  if (!held || !bound || !stateRoot) throw new TypeError('migration publication requires its genuine original owner/root scope');
  bound.owner.assertHeld(); held.bound.assertHeld(); scope.assertHeld();
  return { ...held, stateRoot };
}
function migrationDirectoryObservation(value: unknown): HeldMigrationDirectoryObservation {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['canonicalAbsolutePath', 'ownerUid', 'deviceId', 'directoryFileId', 'mode', 'openedNoFollow']);
  const path = controlWireText(data.canonicalAbsolutePath, 4096);
  if (normalizeAbsolutePath(path) !== path || data.openedNoFollow !== true) throw new TypeError('migration root observation is not no-follow canonical data');
  controlWireInteger(data.ownerUid, 0, 0xffff_ffff); controlWireInteger(data.mode, 0, 0o7777);
  for (const field of ['deviceId', 'directoryFileId']) if (!/^(0|[1-9][0-9]{0,19})$/u.test(controlWireText(data[field], 20)))
    throw new TypeError('migration root id is not an exact unsigned decimal');
  return immutableSnapshot(data) as HeldMigrationDirectoryObservation;
}
export function observeHeldMigrationRoots(scope: HeldMigrationFilesystem): HeldMigrationRootsObservation {
  const held = migrationPublicationScope(scope);
  if (typeof held.original.observeRoots !== 'function') throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks fixed migration root observation');
  let observed: unknown;
  try { observed = held.original.observeRoots(); } catch (error) { return kernelGlobalFailure(error); }
  assertControlWireJson(observed); const data = controlWireRecord(observed, ['legacyRoot', 'backupRoot']);
  const legacyRoot = migrationDirectoryObservation(data.legacyRoot), backupRoot = migrationDirectoryObservation(data.backupRoot);
  if (legacyRoot.canonicalAbsolutePath !== held.legacyRoot || legacyRoot.ownerUid !== held.stateRoot.ownerUid ||
      (legacyRoot.mode & 0o7022) !== 0 || backupRoot.mode !== 0o700 || backupRoot.ownerUid !== held.stateRoot.ownerUid ||
      backupRoot.canonicalAbsolutePath !== `${held.stateRoot.canonicalAbsolutePath}/migration/owned-import/${held.migrationId}/backup`)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'migration root observations differ from their actual original scope');
  scope.assertHeld(); return immutableSnapshot({ migrationId: held.migrationId, stateRoot: held.stateRoot, legacyRoot, backupRoot });
}
function decodeMigrationDocument(bytes: Buffer): unknown {
  try {
    if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > 1_048_576) throw new TypeError('size');
    const value: unknown = parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!canonicalJsonBytes(value).equals(bytes)) throw new TypeError('canonical bytes'); return value;
  } catch { throw new KernelStorageError('ARTIFACT_MISMATCH', 'migration document is not complete bounded canonical data'); }
}
function assertMigrationControlRoot(scope: HeldMigrationFilesystem, control: OwnedLegacyImportControl): void {
  const held = migrationPublicationScope(scope);
  if (control.migrationId !== held.migrationId || control.stateRootIdentityRef !== canonicalSha256(held.stateRoot) ||
      control.stateRootIdentityDigest !== held.stateRoot.identityDigest || control.stateRootCanonicalAbsolutePath !== held.stateRoot.canonicalAbsolutePath)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'migration control belongs to another original owner root');
}
export function readHeldMigrationControl(scope: HeldMigrationFilesystem): Readonly<OwnedLegacyImportControl> {
  const held = migrationPublicationScope(scope);
  if (typeof held.original.readControlBytes !== 'function') throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks original control reading');
  let bytes: Buffer;
  try { bytes = held.original.readControlBytes(); } catch (error) { return kernelGlobalFailure(error); }
  const control = decodeOwnedLegacyImportControl(decodeMigrationDocument(bytes)); assertMigrationControlRoot(scope, control); return control;
}
export function readHeldMigrationPreparationBytes(scope: HeldMigrationFilesystem): Buffer {
  const held = migrationPublicationScope(scope);
  if (typeof held.original.readPreparationBytes !== 'function') throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks original preparation reading');
  let bytes: Buffer;
  try { bytes = held.original.readPreparationBytes(); } catch (error) { return kernelGlobalFailure(error); }
  decodeMigrationDocument(bytes); scope.assertHeld(); return Buffer.from(bytes);
}
export function readHeldMigrationRendezvous(scope: HeldMigrationFilesystem): Readonly<LegacyMigrationRendezvous> {
  const held = migrationPublicationScope(scope);
  if (typeof held.original.readRendezvousBytes !== 'function') throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks original rendezvous reading');
  let bytes: Buffer;
  try { bytes = held.original.readRendezvousBytes(); } catch (error) { return kernelGlobalFailure(error); }
  const data = decodeLegacyMigrationRendezvous(decodeMigrationDocument(bytes));
  if (data.migrationId !== held.migrationId || data.stateRootIdentityRef !== canonicalSha256(held.stateRoot) ||
      data.stateRootIdentityDigest !== held.stateRoot.identityDigest || data.stateRootCanonicalAbsolutePath !== held.stateRoot.canonicalAbsolutePath)
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'migration rendezvous belongs to another original root');
  scope.assertHeld(); return data;
}
/** Private physical publication only. A previous Legacy marker is an exact
 * captured authorized preimage, never this new scope's old creation proof.
 * Production must leave that option unused until its full prior-generation/
 * receipt reader has independently validated the current Legacy authority. */
export function publishHeldMigrationInitialSpine(scope: HeldMigrationFilesystem, expectedPreparation: OwnedLegacyImportPreparationV1,
  initial: OwnedLegacyImportControl, previousLegacyAuthority?: MigrationAuthorityMarker): void {
  const held = migrationPublicationScope(scope), control = decodeOwnedLegacyImportControl(initial);
  const preparation = decodeOwnedLegacyImportPreparation(expectedPreparation), preparationRef = canonicalSha256(preparation);
  assertMigrationControlRoot(scope, control);
  if (control.phase !== 'cutover_preflight' || control.preparationRef !== preparationRef ||
      control.preparationDigest !== preparation.preparationDigest || preparation.migrationId !== held.migrationId ||
      preparation.stateRootIdentityRef !== control.stateRootIdentityRef || preparation.stateRootIdentityDigest !== control.stateRootIdentityDigest ||
      typeof held.original.publishInitialSpine !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'initial migration spine lacks its original preparation and fixed phase');
  const previous = previousLegacyAuthority === undefined ? undefined : decodeMigrationAuthorityMarker(previousLegacyAuthority);
  if (previous && previous.authority !== 'legacy') throw new KernelStorageError('RECOVERY_REQUIRED', 'only a fully verified previous Legacy authority is an eligible new preimage');
  try {
    if (previous === undefined) held.original.publishInitialSpine(preparationRef, canonicalJsonBytes(control));
    else held.original.publishInitialSpine(preparationRef, canonicalJsonBytes(control), canonicalJsonBytes(previous));
  }
  catch (error) { return kernelGlobalFailure(error); }
  const preparationBytes = readHeldMigrationPreparationBytes(scope);
  if (!preparationBytes.equals(canonicalJsonBytes(preparation)) || sha256Bytes(preparationBytes) !== preparationRef ||
      canonicalSha256(readHeldMigrationControl(scope)) !== canonicalSha256(control) ||
      canonicalSha256(readHeldMigrationRendezvous(scope)) !== canonicalSha256(control))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'initial migration publication did not retain its exact original preparation/control/stop copy');
}
export function advanceHeldMigrationControl(scope: HeldMigrationFilesystem, successor: OwnedLegacyImportControl): void {
  const held = migrationPublicationScope(scope), previous = readHeldMigrationControl(scope), next = decodeOwnedLegacyImportControl(successor);
  assertMigrationControlRoot(scope, next); assertOwnedImportControlSuccessor(previous, next);
  if (typeof held.original.advanceControl !== 'function') throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks fixed control progression');
  try { held.original.advanceControl(canonicalJsonBytes(next)); } catch (error) { return kernelGlobalFailure(error); }
  if (canonicalSha256(readHeldMigrationControl(scope)) !== canonicalSha256(next)) throw new KernelStorageError('ARTIFACT_MISMATCH', 'control progression retained different bytes');
}
/** Synchronous final-transaction friend. No read callback, clock, platform
 * operation or supplied projection enters. Actual current FD metadata and its
 * complete previously read bytes must match this one phase-3 control. */
export function assertHeldCredentialCutoverControl(scope: HeldMigrationFilesystem,
  expected: Extract<OwnedLegacyImportControl, { phase: 'credential_cutover' }>): void {
  const held = migrationPublicationScope(scope), control = decodeOwnedLegacyImportControl(expected);
  assertMigrationControlRoot(scope, control);
  if (control.phase !== 'credential_cutover' || typeof held.original.assertCredentialCutoverControl !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'final import requires its original fixed credential-cutover control');
  try { held.original.assertCredentialCutoverControl(canonicalJsonBytes(control)); } catch (error) { return kernelGlobalFailure(error); }
}
export function observeHeldMigrationOriginalAuth(scope: HeldMigrationFilesystem): HeldMigrationAuthObservation {
  const held = migrationPublicationScope(scope);
  if (typeof held.original.observeOriginalAuth !== 'function') throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks private original auth observation');
  let value: unknown;
  try { value = held.original.observeOriginalAuth(); } catch (error) { return kernelGlobalFailure(error); }
  assertControlWireJson(value);
  if (value && typeof value === 'object' && !Array.isArray(value) && (value as Record<string, unknown>).presence === 'absent') {
    const data = controlWireRecord(value, ['presence', 'noFollowLookupResult']);
    if (data.noFollowLookupResult !== 'ENOENT') throw new TypeError('original auth absence is not exact ENOENT');
    scope.assertHeld(); return Object.freeze({ presence: 'absent', noFollowLookupResult: 'ENOENT' });
  }
  const data = controlWireRecord(value, ['presence', 'file', 'byteCount', 'contentDigest', 'mode', 'linkCount']);
  const file = controlWireRecord(data.file, ['deviceId', 'fileId', 'ownerUid']);
  for (const field of ['deviceId', 'fileId']) if (!/^(0|[1-9][0-9]{0,19})$/u.test(controlWireText(file[field], 20))) throw new TypeError('auth descriptor id is invalid');
  controlWireInteger(file.ownerUid, 0, 0xffff_ffff); controlWireInteger(data.byteCount, 1, 1_048_576); controlWireRef(data.contentDigest);
  if (data.presence !== 'present' || data.mode !== 0o600 || data.linkCount !== 1 || file.ownerUid !== held.stateRoot.ownerUid)
    throw new TypeError('original auth observation differs from its private descriptor');
  scope.assertHeld(); return immutableSnapshot(data) as HeldMigrationAuthObservation;
}
export { observeHeldMigrationOriginalAuth as observeHeldMigrationLegacyAuth };
export function publishHeldMigrationAuthCutover(scope: HeldMigrationFilesystem, input: LegacyAuthMigratedMarkerV1): void {
  const held = migrationPublicationScope(scope), marker = decodeLegacyAuthMigratedMarker(input), control = readHeldMigrationControl(scope);
  if (control.phase !== 'cutover_import_committed' || marker.migrationId !== held.migrationId ||
      marker.credentialReadyRef !== control.credentialReadyRef || marker.credentialReadyDigest !== control.credentialReadyDigest ||
      marker.markerDigest !== control.legacyAuthMarkerDigest || typeof held.original.publishAuthCutover !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'auth marker differs from its original committed-import control');
  try { held.original.publishAuthCutover(canonicalJsonBytes(marker)); } catch (error) { return kernelGlobalFailure(error); }
  scope.assertHeld();
}
export function publishHeldMigrationKernelAuthority(scope: HeldMigrationFilesystem, input: MigrationAuthorityMarker): void {
  const held = migrationPublicationScope(scope), marker = decodeMigrationAuthorityMarker(input), control = readHeldMigrationControl(scope);
  const bytes = readHeldMigrationPreparationBytes(scope), preparation = decodeOwnedLegacyImportPreparation(decodeMigrationDocument(bytes));
  if (control.phase !== 'cutover_import_committed' || marker.authority !== 'kernel' || marker.migrationId !== held.migrationId ||
      marker.stateRootIdentityRef !== control.stateRootIdentityRef || marker.stateRootIdentityDigest !== control.stateRootIdentityDigest ||
      marker.stateRootCanonicalAbsolutePath !== control.stateRootCanonicalAbsolutePath || marker.generationId !== control.targetGenerationId ||
      marker.candidateRef !== control.candidateRef || marker.candidateDigest !== control.candidateDigest ||
      marker.receiptRef !== control.committedReceiptRef || marker.receiptDigest !== control.committedReceiptDigest ||
      sha256Bytes(bytes) !== control.preparationRef || preparation.preparationDigest !== control.preparationDigest ||
      marker.kernelGenerationIdentityRef !== preparation.kernelGenerationIdentityRef ||
      marker.kernelGenerationIdentityDigest !== preparation.kernelGenerationIdentityDigest || marker.publishedAt < control.updatedAt ||
      typeof held.original.publishKernelAuthority !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'Kernel marker differs from its original committed import/preparation closure');
  try { held.original.publishKernelAuthority(canonicalJsonBytes(marker)); } catch (error) { return kernelGlobalFailure(error); }
  if (canonicalSha256(readHeldMigrationRendezvous(scope)) !== canonicalSha256(marker))
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'Kernel authority rendezvous retained different bytes');
  scope.assertHeld();
}
/** Re-observes every entry of this holder's actual completed backup. Pages
 * reuse the retained manifest's closed entry decoder, rather than inferring
 * fields from names or trusting a caller-supplied inventory. Early return or
 * cancellation is partial; only the real native EOF completes this walk. */
export async function* readHeldMigrationBackupInventory(scope: HeldMigrationFilesystem,
  signal?: AbortSignal): AsyncIterableIterator<HeldMigrationBackupEntry> {
  const held = migrationPublicationScope(scope);
  if (typeof held.original.readBackupInventoryPage !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks original backup inventory observation');
  let after = '', ordinal = 0, capturedTotal: number | undefined;
  for (;;) {
    signal?.throwIfAborted(); scope.assertHeld();
    let value: unknown;
    try { value = held.original.readBackupInventoryPage(after); } catch (error) { return kernelGlobalFailure(error); }
    assertControlWireJson(value);
    const page = controlWireRecord(value, ['entries', 'firstOrdinal', 'totalEntries', 'complete']);
    const first = controlWireInteger(page.firstOrdinal), total = controlWireInteger(page.totalEntries);
    if (first !== ordinal || (capturedTotal !== undefined && total !== capturedTotal) || !Array.isArray(page.entries) ||
        page.entries.length > 32 || typeof page.complete !== 'boolean' || page.entries.length > total - ordinal ||
        page.complete !== (ordinal + page.entries.length === total) || (!page.complete && page.entries.length === 0))
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'original backup inventory page is discontinuous or incomplete');
    capturedTotal = total;
    if (page.entries.length) {
      // Native page width leaves room for all 4096-byte relative paths and
      // metadata under the unchanged 256KiB manifest leaf budget.
      const firstEntry = controlWireRecord(page.entries[0], ['canonicalRootRelativePath', 'sourceIdentity', 'backupIdentity', 'mode', 'purpose', 'kind'],
        ['contentDigest', 'byteCount', 'linkCount', 'linkTextDigest']);
      const lastEntry = controlWireRecord(page.entries[page.entries.length - 1], ['canonicalRootRelativePath', 'sourceIdentity', 'backupIdentity', 'mode', 'purpose', 'kind'],
        ['contentDigest', 'byteCount', 'linkCount', 'linkTextDigest']);
      const decoded = decodeOwnedImportInventoryPage({ schemaVersion: 1, format: 'cliq-owned-import-inventory-page-v1', kind: 'leaf', height: 0,
        firstPath: firstEntry.canonicalRootRelativePath, lastPath: lastEntry.canonicalRootRelativePath,
        entryCount: page.entries.length, entries: page.entries });
      if (decoded.kind !== 'leaf') throw new KernelStorageError('ARTIFACT_MISMATCH', 'original backup page is not a closed leaf');
      for (const entry of decoded.entries) {
        if (entry.sourceIdentity.ownerUid !== held.stateRoot.ownerUid || entry.backupIdentity.ownerUid !== held.stateRoot.ownerUid ||
            Buffer.compare(Buffer.from(after, 'utf8'), Buffer.from(entry.canonicalRootRelativePath, 'utf8')) >= 0)
          throw new KernelStorageError('ARTIFACT_MISMATCH', 'original backup inventory changed identity or byte order');
        signal?.throwIfAborted(); scope.assertHeld();
        after = entry.canonicalRootRelativePath; ordinal++;
        yield entry;
      }
    }
    signal?.throwIfAborted(); scope.assertHeld();
    if (page.complete) return;
    await setImmediate();
  }
}
/** All entries finish actual copy/full reread before they are yielded. Only
 * native null ends the complete enumeration/fsync; an early return is partial. */
export async function* copyHeldMigrationBackup(scope: HeldMigrationFilesystem,
  signal?: AbortSignal): AsyncIterableIterator<HeldMigrationBackupEntry> {
  const held = migrationFilesystems.get(scope);
  if (!held) throw new TypeError('backup requires its genuine migration filesystem');
  for (;;) {
    signal?.throwIfAborted(); scope.assertHeld();
    let next: false | HeldMigrationBackupEntry | null;
    try { next = held.original.copyBackupNext(); } catch (error) { return kernelGlobalFailure(error); }
    scope.assertHeld();
    if (next === null) return;
    if (next !== false) yield immutableSnapshot(next);
    await setImmediate();
  }
}
/** Exact second data pass, only after every first-pass native EOF/hash/close.
 * This is not a semantic preflight/authority proof: the original owner still
 * checks the closed inventory. Native fixes one transition, original captured
 * roots, metadata budget and cumulative two-pass read accounting. */
export function beginHeldMigrationContextProjection(scope: HeldMigrationFilesystem): void {
  const held = migrationFilesystems.get(scope);
  if (!held) throw new TypeError('context projection requires its genuine original migration filesystem');
  scope.assertHeld();
  if (typeof held.original.beginContextProjection !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks the fixed original-source projection pass');
  try { held.original.beginContextProjection(); } catch (error) { return kernelGlobalFailure(error); }
  scope.assertHeld();
}
/** Rechecks all original source-entry metadata, with a real close per bounded
 * observation. Native infers the sole pre-candidate/final boundary; callers
 * cannot select arbitrary paths, reset budgets or turn this into old creator
 * evidence. It does not substitute for the genuine global/legacy stop locks. */
export async function verifyHeldMigrationSourceSnapshot(scope: HeldMigrationFilesystem, signal?: AbortSignal): Promise<void> {
  const held = migrationFilesystems.get(scope);
  if (!held) throw new TypeError('source verification requires its genuine original migration filesystem');
  if (typeof held.original.verifyBackupSourceNext !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected native image lacks complete original-source verification');
  for (;;) {
    signal?.throwIfAborted(); scope.assertHeld(); let complete: boolean;
    try { complete = held.original.verifyBackupSourceNext(); } catch (error) { return kernelGlobalFailure(error); }
    scope.assertHeld(); if (complete) return;
    await setImmediate();
  }
}
/** Fixed backup context inputs only. Partial chunks are not complete data:
 * EOF authenticates the whole original hash and actual join precedes the
 * source_complete event. Cancellation/break joins without certifying bytes. */
export async function* readHeldMigrationContextSources(scope: HeldMigrationFilesystem,
  signal?: AbortSignal): AsyncIterableIterator<HeldMigrationContextSourceEvent> {
  const held = migrationFilesystems.get(scope);
  if (!held) throw new TypeError('context sources require their genuine migration filesystem');
  let reading = false;
  const joinOriginal = () => {
    // Consume this logical close attempt before calling native. An error is
    // uncertainty, never permission to repeat a possibly consumed operation.
    reading = false;
    try { held.original.closeContextSource(); }
    catch (error) { unretiredMigrationContextScopes.add(scope);
      throw new ResourceRetirementError('original migration context source did not join', error); }
  };
  try {
    for (;;) {
      signal?.throwIfAborted(); scope.assertHeld();
      let source: HeldMigrationSourceFile | null;
      try { source = held.original.nextContextSource(); } catch (error) { return kernelGlobalFailure(error); }
      if (source === null) return;
      reading = true;
      const original = immutableSnapshot(source);
      yield Object.freeze({ kind: 'source_begin', source: original });
      for (;;) {
        signal?.throwIfAborted(); scope.assertHeld();
        let bytes: Buffer | null;
        try { bytes = held.original.readContextSourceChunk(); } catch (error) { return kernelGlobalFailure(error); }
        scope.assertHeld();
        if (bytes === null) break;
        yield Object.freeze({ kind: 'source_chunk', bytes });
        await setImmediate();
      }
      joinOriginal();
      scope.assertHeld(); yield Object.freeze({ kind: 'source_complete', source: original });
    }
  } finally {
    if (reading) joinOriginal();
  }
}
export type PreparedImportWriterSummary = Readonly<{
  sessions: number; items: number; artifactUses: number; newArtifacts: number; inputRowsDigest: string;
}>;
export type HeldPreparedImportWriter = Readonly<{
  append(batch: PreparedLegacyImportRows): void;
  sessionItems(sessionId: string): AsyncIterableIterator<PreparedLegacyItemRow>;
  sessions(): AsyncIterableIterator<PreparedLegacySessionRow>;
  session(sessionId: string): PreparedLegacySessionRow | undefined;
  sessionItemTail(sessionId: string): bigint;
  finalizeSession(original: PreparedLegacySessionRow, input: Readonly<{ contextProjectionRef: string; throughItemSeq: bigint }>): void;
  finish(): Promise<PreparedImportWriterSummary>;
  close(): Promise<void>;
}>;
export type PreparedImportStageSink = Pick<HeldPreparedImportWriter, 'append' | 'sessionItems' | 'sessions' |
  'session' | 'sessionItemTail' | 'finalizeSession'>;
/** Fixed streaming producer. Only bounded typed data batches cross this
 * interface; the original driver/path and full history never escape. */
export function beginHeldPreparedImportWriter(scope: HeldMigrationFilesystem, input: Readonly<{
  schema: SignedKernelSchemaV1; baseline: PreparedImportBaseline; signal?: AbortSignal;
}>): HeldPreparedImportWriter {
  const held = migrationFilesystems.get(scope);
  if (!held) throw new TypeError('candidate build requires its original migration filesystem');
  if (process.platform !== 'linux' || process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'candidate preview producer requires its fixed installed Node 24.21.0 role');
  if (activeMigrationCandidateBuilders.has(scope)) throw new TypeError('original candidate builder is already active');
  input.signal?.throwIfAborted(); scope.assertHeld(); activeMigrationCandidateBuilders.set(scope, undefined);
  let database: SqliteDriver | undefined, terminal = false, retained = false, appendFailure: unknown, appendFailed = false;
  let retirementFailure: ResourceRetirementError | undefined;
  let finishing: Promise<PreparedImportWriterSummary> | undefined;
  const shutdown = new AbortController();
  const counts = { sessions: 0, items: 0, artifactUses: 0, newArtifacts: 0 };
  const hashes = { artifacts: createHash('sha256'), sessions: createHash('sha256'), items: createHash('sha256') };
  const retireWriter = (primary?: unknown) => {
    if (!database) return;
    const original = database; database = undefined;
    try { original.close(); activeMigrationCandidateBuilders.set(scope, undefined); }
    catch (error) { retained = true; activeMigrationCandidateBuilders.set(scope, original);
      retirementFailure = new ResourceRetirementError('candidate original SQLite writer did not retire',
        new AggregateError(primary === undefined ? [error] : [primary, error])); throw retirementFailure; }
  };
  const current = () => {
    if (terminal || finishing || appendFailed) throw appendFailure ?? new TypeError('original candidate writer is closed, failed or finishing');
    input.signal?.throwIfAborted(); shutdown.signal.throwIfAborted(); scope.assertHeld();
  };
  try {
    held.original.createCandidate();
    database = openSqliteDriver(held.original.candidateBuildPath());
    activeMigrationCandidateBuilders.set(scope, database);
    initializePreparedImportPreview(database, input.schema, input.baseline);
  } catch (error) {
    retireWriter(error); if (!retained) activeMigrationCandidateBuilders.delete(scope);
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
      activeMigrationCandidateBuilders.set(scope, undefined); return kernelGlobalFailure(error);
    }
    throw error;
  }
  const writer: HeldPreparedImportWriter = Object.freeze({
    async *sessions() {
      if (this !== writer) throw new TypeError('invalid original candidate writer receiver');
      let after = '';
      for (;;) {
        current(); const page = readPreparedImportSessionsPage(database!, after);
        scope.assertHeld(); if (!page.length) return;
        for (const row of page) { current(); yield row; }
        after = page.at(-1)!.id; await setImmediate();
      }
    },
    session(sessionId) {
      if (this !== writer) throw new TypeError('invalid original candidate writer receiver');
      current(); const row = readPreparedImportSessionHeader(database!, sessionId); scope.assertHeld(); return row;
    },
    sessionItemTail(sessionId) {
      if (this !== writer) throw new TypeError('invalid original candidate writer receiver');
      current(); const tail = readPreparedImportSessionItemTail(database!, sessionId); scope.assertHeld(); return tail;
    },
    finalizeSession(original, input) {
      if (this !== writer) throw new TypeError('invalid original candidate writer receiver');
      current();
      try {
        finalizePreparedImportSession(database!, original, input);
        // The original append digest still binds the exact initial header.
        // Bind its sole fixed preview transition as well; the sealed complete
        // projection digest separately names the actual final row set.
        hashes.sessions.update(canonicalJsonBytes({ format: 'cliq-owned-import-session-context-final-v1',
          sessionId: original.id, initialContextRef: original.context_projection_ref,
          contextProjectionRef: input.contextProjectionRef, throughItemSeq: input.throughItemSeq.toString() })).update('\n');
        scope.assertHeld();
      } catch (error) { appendFailed = true; appendFailure = error; throw error; }
    },
    async *sessionItems(sessionId) {
      if (this !== writer) throw new TypeError('invalid original candidate writer receiver');
      let after = 0n;
      for (;;) {
        current();
        const page = readPreparedImportSessionItemsPage(database!, sessionId, after);
        scope.assertHeld(); if (page.length === 0) return;
        // No SQLite iterator or transaction is held over these yields.
        for (const row of page) { current(); yield row; }
        after = page[page.length - 1]!.item_seq;
        await setImmediate();
      }
    },
    append(batch) {
      if (this !== writer) throw new TypeError('invalid original candidate writer receiver');
      current();
      try {
        const appended = appendPreparedImportRows(database!, batch);
        updatePreparedImportInputDigests(hashes, batch);
        counts.sessions += appended.sessions; counts.items += appended.items;
        counts.newArtifacts += appended.newArtifacts; counts.artifactUses += batch.artifacts.length;
        if (Object.values(counts).some(count => !Number.isSafeInteger(count))) throw new TypeError('candidate stage count exceeds the exact counter range');
        scope.assertHeld();
      } catch (error) { appendFailed = true; appendFailure = error; throw error; }
    },
    finish() {
      if (this !== writer) return Promise.reject(new TypeError('invalid original candidate writer receiver'));
      if (finishing) return finishing;
      if (terminal) return Promise.reject(new TypeError('candidate writer already retired'));
      finishing = (async () => {
        try {
          if (appendFailed) throw appendFailure;
          input.signal?.throwIfAborted(); shutdown.signal.throwIfAborted(); scope.assertHeld();
          finishPreparedImportPreview(database!); retireWriter();
          for (;;) {
            input.signal?.throwIfAborted(); shutdown.signal.throwIfAborted();
            if (held.original.sealCandidateNext()) break;
            await setImmediate();
          }
          scope.assertHeld();
          const inputRowsDigest = canonicalSha256({ format: 'cliq-owned-import-staged-rows-v1', ...counts,
            artifactUsesDigest: hashes.artifacts.copy().digest('hex'), sessionsDigest: hashes.sessions.copy().digest('hex'), itemsDigest: hashes.items.copy().digest('hex') });
          return Object.freeze({ ...counts, inputRowsDigest });
        } catch (error) {
          retireWriter(error);
          if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
            retained = true; retirementFailure = new ResourceRetirementError('candidate native seal has uncertain retirement', error); throw retirementFailure;
          }
          throw error;
        } finally { terminal = true; if (!retained) activeMigrationCandidateBuilders.delete(scope); }
      })();
      return finishing;
    },
    async close() {
      if (this !== writer) throw new TypeError('invalid original candidate writer receiver');
      if (retirementFailure) throw retirementFailure;
      shutdown.abort();
      if (finishing) { try { await finishing; } catch (error) { if (error instanceof ResourceRetirementError) throw error; } return; }
      if (terminal) return;
      try { retireWriter(); } finally { terminal = true; if (!retained) activeMigrationCandidateBuilders.delete(scope); }
    }
  });
  return writer;
}
/** Small-data convenience over the same streaming lifecycle, never a second
 * writer/ledger or a requirement to retain complete production source arrays. */
export async function buildHeldPreparedImportCandidate(scope: HeldMigrationFilesystem, input: Readonly<{
  schema: SignedKernelSchemaV1; baseline: PreparedImportBaseline; imported: PreparedLegacyImportRows; signal?: AbortSignal;
}>): Promise<PreparedImportWriterSummary> {
  const writer = beginHeldPreparedImportWriter(scope, input);
  try {
    for (let offset = 0, length = Math.max(input.imported.sessions.length, input.imported.items.length, input.imported.artifacts.length); offset < length; offset += 64) {
      writer.append({ sessions: input.imported.sessions.slice(offset, offset + 64), items: input.imported.items.slice(offset, offset + 64),
        artifacts: input.imported.artifacts.slice(offset, offset + 64) });
      await setImmediate();
    }
    return await writer.finish();
  } finally { await writer.close(); }
}
/** No descriptor/path escapes. The fixed reader's original same-image scope
 * can only be opened from the genuine parent whose candidate really sealed. */
export function openHeldPreparedImportCandidate(native: NativeStateOwner, scope: HeldMigrationFilesystem): NativePreparedImportCandidate {
  const binding = nativeBindings.get(native), held = migrationFilesystems.get(scope);
  if (!binding || typeof binding.openPreparedImportCandidate !== 'function' || !held || held.native !== native)
    throw new TypeError('prepared candidate requires its genuine same-image migration filesystem');
  scope.assertHeld();
  try { return Object.freeze(binding.openPreparedImportCandidate(held.original)); }
  catch (error) { return kernelGlobalFailure(error); }
}

/** A private client-file serialization owner only. It grants no StateOwner,
 * credential, database, Run, process-death or execution authority. */
export type HeldClientDataLock = Readonly<{ assertHeld(): void; close(): void }>;
export function tryLockClientDataDirectory(native: NativeStateOwner, directoryFd: number): HeldClientDataLock | null {
  const binding = nativeBindings.get(native);
  if (!binding) throw new KernelStorageError('ARTIFACT_MISMATCH', 'client-data locking requires the original loaded native image');
  if (typeof binding.tryLockClientDataDirectory !== 'function')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed helper lacks private client-data serialization');
  if (!Number.isSafeInteger(directoryFd) || directoryFd < 0 || directoryFd > 0x7fffffff)
    throw new TypeError('client-data locking requires one held directory descriptor');
  const convert = (error: unknown): never => {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('private client-data lock did not retire', error);
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'private client-data lock is unavailable or changed', { cause: error });
  };
  let original: HeldClientDataLock | null;
  try { original = binding.tryLockClientDataDirectory(directoryFd); } catch (error) { return convert(error); }
  if (original === null) return null;
  const held: HeldClientDataLock = Object.freeze({
    assertHeld(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('client-data lock requires its original receiver and no arguments');
      try { original.assertHeld(); } catch (error) { convert(error); }
    },
    close(...args: unknown[]) {
      if (this !== held || args.length) throw new TypeError('client-data lock requires its original receiver and no arguments');
      try { original.close(); } catch (error) { convert(error); }
    }
  });
  return held;
}

/** Fixed stdio-only bridge, available solely on the original loaded image.
 * The caller immediately transfers the duplicate to its own Socket owner. */
export function duplicateClientStdio(native: NativeStateOwner, role: 'stdout' | 'stderr'): number {
  if (role !== 'stdout' && role !== 'stderr') throw new TypeError('invalid client stdio role');
  const binding = nativeBindings.get(native), duplicate = role === 'stdout' ? binding?.duplicateClientStdout : binding?.duplicateClientStderr;
  if (!binding || typeof duplicate !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed helper lacks owned client stdio');
  return Reflect.apply(duplicate, binding, []);
}
// Byte-identical copies may dlopen as different images with different static
// VFS state. Credential bootstrap must use the actual first loaded image.
const loadedImageIdentities = new WeakMap<NativeStateOwner, BigIntStats>();

/** Composition-only bridge: the verified installed selection supplies its
 * original FileHandles, never a caller socket, PID or executable locator. */
export function openHeldInstalledControlClient(native: NativeStateOwner, input: Readonly<{
  root: FileHandle; rootIdentity: BigIntStats; stateRoot: string;
  image: FileHandle; imageIdentity: BigIntStats;
}>): HeldInstalledControlClient {
  const binding = nativeBindings.get(native);
  if (!binding || typeof binding.connectInstalledControl !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed helper lacks fixed control client');
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed control client requires Linux');
  const convert = (error: unknown): never => {
    if (error instanceof KernelStorageError || error instanceof ResourceRetirementError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('installed control client descriptors did not retire', error);
    throw new KernelStorageError('RECOVERY_REQUIRED', 'fixed installed Supervisor connection or identity is unavailable', { cause: error });
  };
  let owned: HeldInstalledControlClient | undefined;
  try {
    const root = input.rootIdentity, image = input.imageIdentity;
    owned = binding.connectInstalledControl(input.root.fd, input.stateRoot,
      [root.dev, root.ino, root.uid, root.gid, root.mode], input.image.fd,
      [image.dev, image.ino, image.uid, image.gid, image.mode, image.size, image.nlink, image.mtimeNs, image.ctimeNs]);
    owned.assertHeld();
  } catch (error) {
    if (owned) {
      try { owned.close(); }
      catch (retirement) { throw new ResourceRetirementError('installed control acquisition did not retire', new AggregateError([error, retirement])); }
    }
    return convert(error);
  }
  const held = owned;
  const client: HeldInstalledControlClient = Object.freeze({ server: Object.freeze({ ...held.server }),
    takeSocketFd() {
      if (this !== client) throw new TypeError('invalid installed control client');
      try { return held.takeSocketFd(); } catch (error) { return convert(error); }
    },
    assertHeld() {
      if (this !== client) throw new TypeError('invalid installed control client');
      try { held.assertHeld(); } catch (error) { return convert(error); }
    },
    close() {
      if (this !== client) throw new TypeError('invalid installed control client');
      try { held.close(); } catch (error) { return convert(error); }
    }
  });
  return client;
}

/** Private credential bridge, not a descriptor getter or loader selector.
 * The installed producer still owns and revalidates this signed FileHandle. */
export async function assertHeldCredentialNativeImage(native: NativeStateOwner, image: FileHandle): Promise<void> {
  const expected = loadedImageIdentities.get(native);
  if (!expected) throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential native image has no actual load provenance');
  let actual: BigIntStats;
  try { actual = await image.stat({ bigint: true }); }
  catch { throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential native image is no longer held'); }
  if (!['dev', 'ino', 'size', 'uid', 'gid', 'mode', 'nlink', 'mtimeNs', 'ctimeNs'].every(key =>
    actual[key as keyof BigIntStats] === expected[key as keyof BigIntStats])) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'credential helper is not the physically loaded image; a fresh process is required');
  }
}

/** Fixed same-image/same-engine bridge. The producer retains both originals;
 * callers cannot select a data FD, VFS, extension entry, URI or SQLite engine. */
export async function withHeldCredentialNativeScope<T>(native: NativeStateOwner, input: Readonly<{
  image: FileHandle; root: FileHandle; rootIdentity: BigIntStats; stateRoot: string;
  migrationGate?: HeldMigrationCredentialGate;
}>, operation: (scope: NativeCredentialScope) => Promise<T>): Promise<T> {
  const binding = nativeBindings.get(native);
  if (!binding || typeof binding.acquireCredentialScope !== 'function' ||
      typeof binding.inspectKernelGlobalGate !== 'function' || typeof binding.acquireKernelGlobalShared !== 'function' ||
      typeof binding.acquireKernelGlobalExclusive !== 'function' || typeof binding.bindMigrationCredentialGate !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed helper lacks the original account-domain credential gate contract');
  if (process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'credential authority requires the fixed installed Node 24.21.0 backend');
  await assertHeldCredentialNativeImage(native, input.image);
  let owned: NativeCredentialScope;
  const convert = (error: unknown): never => {
    if (error instanceof KernelStorageError || error instanceof TypeError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('credential scope descriptors did not retire', error);
    // Verified native reports this only after complete healthy acquisition
    // cleanup. Contention is not corruption or a request to recover state.
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_CREDENTIAL_BUSY') throw error;
    throw new KernelStorageError('RECOVERY_REQUIRED', 'credential scope could not hold its original physical bindings', { cause: error });
  };
  try {
    const root = input.rootIdentity;
    const tuple = [root.dev, root.ino, root.uid, root.gid, root.mode];
    if (input.migrationGate !== undefined) {
      const held = migrationCredentialGates.get(input.migrationGate);
      if (!held || held.native !== native) throw new TypeError('credential scope requires its genuine same-image migration binding');
      held.owner.assertHeld(); input.migrationGate.assertHeld();
      // Native compares this actual selected-root FD with the original owner.
      // It borrows EX instead of reacquiring SH and self-deadlocking.
      owned = binding.acquireCredentialScope(input.root.fd, input.stateRoot, tuple, held.original);
    } else {
      // Native owns its actual account SH through the complete pager/data-FD
      // retirement. No caller-provided boolean can select the borrow branch.
      owned = binding.acquireCredentialScope(input.root.fd, input.stateRoot, tuple);
    }
  } catch (error) { return convert(error); }
  let result: T;
  let failed = false;
  let failure: unknown;
  try {
    owned.assertHeld();
    const bootstrap = new DatabaseSync(':memory:', { allowExtension: true });
    try {
      await assertHeldCredentialNativeImage(native, input.image);
      // This optional entrypoint is provided by the fixed 24.21.0 backend;
      // the repository's client-minimum Node typings predate that overload.
      (bootstrap.loadExtension as (image: string, entry: string) => void).call(bootstrap,
        `${process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd'}/${input.image.fd}`, 'sqlite3_cliqcredentialvfs_init');
      bootstrap.enableLoadExtension(false);
      owned.assertHeld();
    } finally {
      try { bootstrap.close(); }
      catch (error) { throw new ResourceRetirementError('credential SQLite bootstrap did not retire', error); }
    }
    result = await operation(owned);
  } catch (error) { failed = true; failure = error; }
  // A failed database retirement is not permission to close guards beneath a
  // potentially live pager. Native holds the context until a fresh process.
  if (failure instanceof ResourceRetirementError) throw failure;
  try { owned.close(); }
  catch (error) { throw new ResourceRetirementError('credential native scope did not retire',
    new AggregateError(failed ? [failure, error] : [error])); }
  if (failed) throw failure;
  return result!;
}

/** Same selected StateOwner image, distinct fixed model-store purpose. This
 * bridge supplies only the already-held original root; no callback can select
 * another FD, pathname, SQLite engine, VFS or credential scope. */
export function withHeldLocalModelStoreScope<T>(native: NativeStateOwner, input: Readonly<{
  image: FileHandle; root: FileHandle; rootIdentity: BigIntStats; stateRoot: string;
}>, operation: (scope: NativeLocalModelStore) => Promise<T>): Promise<T> {
  return withHeldModelStoreScope(native, input, async scope => {
    if (!scope) throw new KernelStorageError('RECOVERY_REQUIRED', 'ordinary model store unexpectedly reported absence');
    return operation(scope);
  });
}
/** Existing-source archive borrow only. A genuine original migration binding
 * proves the same Root/Owner/global EX; native derives a separate model tag.
 * Absence is actual no-follow ENOENT. No SH, second pager or source mutation
 * is acquired, and a partial existing layout is never repaired for backup. */
export function withHeldMigrationLocalModelStoreScope<T>(native: NativeStateOwner, input: Readonly<{
  image: FileHandle; root: FileHandle; rootIdentity: BigIntStats; stateRoot: string;
  migrationGate: HeldMigrationCredentialGate;
}>, operation: (scope: NativeLocalModelStore | null) => Promise<T>): Promise<T> {
  return withHeldModelStoreScope(native, input, operation);
}
async function withHeldModelStoreScope<T>(native: NativeStateOwner, input: Readonly<{
  image: FileHandle; root: FileHandle; rootIdentity: BigIntStats; stateRoot: string;
  migrationGate?: HeldMigrationCredentialGate;
}>, operation: (scope: NativeLocalModelStore | null) => Promise<T>): Promise<T> {
  const binding = nativeBindings.get(native);
  if (!binding || typeof binding.acquireLocalModelStore !== 'function' || typeof binding.deriveLocalModelStoreGate !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'selected helper lacks the fixed original model-store owner');
  if (process.versions.node !== '24.21.0')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'model store requires the fixed installed Node 24.21.0 backend');
  // This compares the original signed loaded image only; it neither opens nor
  // borrows a credential authority. Family purposes remain distinct.
  await assertHeldCredentialNativeImage(native, input.image);
  const convert = (error: unknown): never => {
    if (error instanceof KernelStorageError || error instanceof ResourceRetirementError || error instanceof TypeError) throw error;
    const code = (error as { code?: unknown } | null)?.code;
    if (code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('original model-store descriptors did not retire', error);
    if (code === 'ERR_CLIQ_LOCAL_MODEL_BUSY') throw error;
    if (code === 'ERR_CLIQ_LOCAL_MODEL_PACKAGE') throw new TypeError('original model package failed its closed integrity contract', { cause: error });
    throw new KernelStorageError('RECOVERY_REQUIRED', 'original model-store physical custody is unavailable', { cause: error });
  };
  let scope: NativeLocalModelStore | null | undefined, exclusive: NativeLocalModelExclusiveGate | undefined;
  let result: T | undefined, failed = false, failure: unknown;
  try {
    if (input.migrationGate !== undefined) {
      const original = migrationCredentialGates.get(input.migrationGate);
      if (!original || original.native !== native) throw new TypeError('model-store EX borrow requires its original same-image migration source');
      original.owner.assertHeld(); input.migrationGate.assertHeld();
      exclusive = binding.deriveLocalModelStoreGate(original.original); exclusive.assertHeld();
    }
    const root = input.rootIdentity;
    const tuple = [root.dev, root.ino, root.uid, root.gid, root.mode];
    scope = exclusive ? binding.acquireLocalModelStore(input.root.fd, input.stateRoot, tuple, exclusive) :
      binding.acquireLocalModelStore(input.root.fd, input.stateRoot, tuple);
    if (scope) {
      scope.assertHeld();
      const bootstrap = new DatabaseSync(':memory:', { allowExtension: true });
      try {
        await assertHeldCredentialNativeImage(native, input.image);
        (bootstrap.loadExtension as (image: string, entry: string) => void).call(bootstrap,
          `${process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd'}/${input.image.fd}`, 'sqlite3_cliqlocalmodelvfs_init');
        bootstrap.enableLoadExtension(false); scope.assertHeld();
      } finally {
        try { bootstrap.close(); }
        catch (error) { throw new ResourceRetirementError('model-store SQLite bootstrap did not retire', error); }
      }
    }
    result = await operation(scope);
    scope?.assertHeld(); exclusive?.assertHeld();
  } catch (error) { failed = true; failure = error; }
  // Uncertain pagers/FDs retain their exact derived source, never unlock EX
  // beneath a borrower or infer a join from an exception/JS timeout.
  if (failure instanceof ResourceRetirementError) throw failure;
  if ((failure as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') return convert(failure);
  try { scope?.close(); exclusive?.close(); }
  catch (error) { throw new ResourceRetirementError('original model-store scope or EX source did not retire',
    new AggregateError(failed ? [failure, error] : [error])); }
  if (failed) return convert(failure);
  return result!;
}

/** Private verified-installation bridge. The keeper owns only containment and
 * its independent image observation, never StateOwner or a caller-supplied FD. */
export function initializeHeldInstalledKeeper(native: NativeStateOwner, input: Readonly<{
  stateRoot: string; root: BigIntStats; image: BigIntStats; bundleDigest: string; relativePath: string;
}>): NativeInstalledKeeper {
  const binding = nativeBindings.get(native);
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed keeper requires Linux');
  if (!binding || typeof binding.initializeInstalledKeeper !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native helper lacks keeper initialization');
  const failed = (error: unknown): never => {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('installed keeper descriptors did not retire', error);
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      (error as { message?: string } | null)?.message ?? 'installed native keeper refused its physical identity', { cause: error });
  };
  let owned: NativeInstalledKeeper;
  try {
    const image = input.image;
    owned = binding.initializeInstalledKeeper(input.stateRoot, input.bundleDigest, input.relativePath,
      [image.dev, image.ino, image.size, image.uid, image.gid, image.mode, image.nlink, image.mtimeNs, image.ctimeNs],
      [input.root.dev, input.root.ino, input.root.uid, input.root.gid, input.root.mode]);
  } catch (error) { failed(error); }
  const handle: NativeInstalledKeeper = Object.freeze({
    assertHeld() {
      if (this !== handle) throw new TypeError('invalid installed keeper handle');
      try { owned.assertHeld(); } catch (error) { failed(error); }
    },
    readyLocator() {
      if (this !== handle) throw new TypeError('invalid installed keeper handle');
      try { return owned.readyLocator(); } catch (error) { return failed(error); }
    },
    close() {
      if (this !== handle) throw new TypeError('invalid installed keeper handle');
      try { owned.close(); } catch (error) { failed(error); }
    },
  });
  return handle;
}

/** Private consumer bridge. The locator is untrusted; native acquisition binds
 * the live signed keeper and obtains its original pin through held procfs. */
export function checkHeldInstalledUpgradeKeeper(native: NativeStateOwner, input: Readonly<{
  stateRoot: string; root: BigIntStats; image: BigIntStats; bundleDigest: string; relativePath: string; locator: Buffer;
  packageRoot: string; packageIdentity: BigIntStats; controllerRelativePath: string; controllerImage: BigIntStats;
}>): NativeInstalledUpgradeKeeperCheck {
  const binding = nativeBindings.get(native);
  if (!binding) throw new KernelStorageError('ARTIFACT_MISMATCH', 'current keeper check requires the genuine loaded image');
  if (process.platform !== 'linux' || typeof binding.checkInstalledUpgradeKeeper !== 'function')
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'current keeper check requires its fixed Linux helper');
  const failed = (error: unknown): never => {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('current keeper check descriptors did not retire', error);
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'current keeper check refused its controller or original source', { cause: error });
  };
  const image = (v: BigIntStats) => [v.dev, v.ino, v.size, v.uid, v.gid, v.mode, v.nlink, v.mtimeNs, v.ctimeNs];
  const root = (v: BigIntStats) => [v.dev, v.ino, v.uid, v.gid, v.mode];
  let owned: RawInstalledUpgradeKeeperCheck;
  try { owned = binding.checkInstalledUpgradeKeeper(input.stateRoot, input.bundleDigest, input.relativePath,
    image(input.image), root(input.root), input.locator, input.packageRoot, input.controllerRelativePath,
    image(input.controllerImage), root(input.packageIdentity)); }
  catch (error) { failed(error); }
  const check: NativeInstalledUpgradeKeeperCheck = Object.freeze({ purpose: 'current_checked_original_keeper',
    assertCurrent() {
      if (this !== check) throw new TypeError('invalid current keeper check receiver');
      try { owned.assertCurrent(); } catch (error) { failed(error); }
    },
    close() {
      if (this !== check) throw new TypeError('invalid current keeper check receiver');
      try { owned.close(); } catch (error) { failed(error); }
    },
  });
  return check;
}

export function acquireHeldInstalledAnchor(native: NativeStateOwner, input: Readonly<{
  stateRoot: string; root: BigIntStats; image: BigIntStats; bundleDigest: string; relativePath: string; locator: Buffer;
}>): NativeInstalledAnchor {
  const binding = nativeBindings.get(native);
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed anchor requires Linux');
  if (!binding || typeof binding.acquireInstalledAnchor !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native helper lacks anchor acquisition');
  const failed = (error: unknown): never => {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('installed anchor descriptors did not retire', error);
    throw new KernelStorageError('ARTIFACT_MISMATCH',
      (error as { message?: string } | null)?.message ?? 'installed native anchor refused its physical identity', { cause: error });
  };
  let owned: NativeInstalledAnchor;
  try {
    const image = input.image;
    owned = binding.acquireInstalledAnchor(input.stateRoot, input.bundleDigest, input.relativePath,
      [image.dev, image.ino, image.size, image.uid, image.gid, image.mode, image.nlink, image.mtimeNs, image.ctimeNs],
      [input.root.dev, input.root.ino, input.root.uid, input.root.gid, input.root.mode], input.locator);
  } catch (error) { failed(error); }
  const handle: NativeInstalledAnchor = Object.freeze({
    assertHeld() {
      if (this !== handle) throw new TypeError('invalid installed anchor handle');
      try { owned.assertHeld(); } catch (error) { failed(error); }
    },
    withRoot(operation) {
      if (this !== handle) throw new TypeError('invalid installed anchor handle');
      let callbackFailure: { error: unknown } | undefined;
      try { owned.withRoot((fd, rootPath) => {
        try { return operation(fd, rootPath); }
        catch (error) { callbackFailure = { error }; throw error; }
      }); } catch (error) {
        if (callbackFailure && error === callbackFailure.error) throw error;
        failed(error);
      }
    },
    close() {
      if (this !== handle) throw new TypeError('invalid installed anchor handle');
      try { owned.close(); } catch (error) { failed(error); }
    },
  });
  return handle;
}

/** Private installed-producer bridge, not a NativeStateOwner public operation.
 * Only the producer supplies these checked identities; C borrows the original
 * FileHandle and independently binds both filesystem images before exec. */
export function executeHeldInstalledImage(native: NativeStateOwner, file: FileHandle, input: Readonly<{
  stateRoot: string; root: BigIntStats; bootstrap: BigIntStats; image: BigIntStats;
  bundleDigest: string; relativePath: string; role: 'keeper' | 'supervisor' | 'endpoint' | 'credential'; command?: string;
}>): never {
  const binding = nativeBindings.get(native);
  if (process.platform !== 'linux') throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'installed execution requires Linux');
  if (!binding || typeof binding.executeInstalledImage !== 'function')
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native helper lacks fixed-role execution');
  const imageTuple = (info: BigIntStats) => [info.dev, info.ino, info.size, info.uid, info.gid, info.mode, info.nlink, info.mtimeNs, info.ctimeNs];
  try {
    binding.executeInstalledImage(file.fd, imageTuple(input.image), imageTuple(input.bootstrap),
      [input.root.dev, input.root.ino, input.root.uid, input.root.gid, input.root.mode],
      input.stateRoot, input.bundleDigest, input.relativePath, input.role,
      ...(input.role === 'credential' ? [input.command] : []));
  } catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('installed native execution descriptors did not retire', error);
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native execution refused its bootstrap or selected image', { cause: error });
  }
  throw new KernelStorageError('ARTIFACT_MISMATCH', 'installed native execution unexpectedly returned');
}

/** One canonical projection for bootstrap and native filesystem consumers.
 * This derives bytes only; the caller must hold and validate the native lock. */
export function stateRootIdentityFromDescriptor(stateRoot: string, descriptor: DescriptorIdentity): StateRootIdentityV1 {
  const root: StateRootIdentityV1 = {
    schemaVersion: 1, format: 'cliq-state-root-identity-v1', platform: process.platform === 'linux' ? 'linux' : 'macos',
    canonicalAbsolutePath: stateRoot, ownerUid: descriptor.ownerUid, deviceId: descriptor.deviceId,
    directoryFileId: descriptor.fileId, mode: 448, openedNoFollow: true, layoutVersion: 1, identityDigest: ''
  };
  root.identityDigest = digestOmitting(root, 'identityDigest');
  return Object.freeze(root);
}

/** Hide the native locator arguments; callers supply only the frozen identity
 * and the durable source version. No caller-selected destination or fallback. */
function wrapLock(held: NativeLock, stateRoot: string): HeldStateOwnerLock {
  const root = stateRootIdentityFromDescriptor(stateRoot, held.root);
  const rootRef = canonicalSha256(root);
  const receiver = (value: unknown) => {
    if (value !== handle) throw new TypeError('invalid StateOwner lock handle');
  };
  const handle: HeldStateOwnerLock = {
    root: held.root, runtime: held.runtime, lock: held.lock,
    assertHeld() { receiver(this); held.assertHeld(); },
    assertPriorProcessDead(pid, token) { receiver(this); held.assertPriorProcessDead(pid, token); },
    observePriorProcessDeath(pid, token) {
      receiver(this);
      try { return held.observePriorProcessDeath(pid, token); }
      catch (error) {
        if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
          throw new ResourceRetirementError('prior process observation descriptors did not retire', error);
        throw error;
      }
    },
    openControlListener(onAccept, onError) {
      receiver(this);
      held.assertHeld();
      if (typeof onAccept !== 'function' || typeof onError !== 'function') throw new TypeError('control listener requires callbacks');
      return held.openControlListener(onAccept, onError);
    },
    createWorkerReservation(launchId, spawnNonceDigest) {
      receiver(this); held.assertHeld();
      const name = checkedWorkerReservation(launchId, spawnNonceDigest);
      try { return wrapWorkerReservation(handle, held.createWorkerReservation(name), launchId, spawnNonceDigest); }
      catch (error) { workerReservationError(error); }
    },
    openWorkerReservation(launchId, spawnNonceDigest, identity) {
      receiver(this); held.assertHeld();
      const name = checkedWorkerReservation(launchId, spawnNonceDigest);
      if (!identity || Object.keys(identity).length !== 3 || !/^(0|[1-9][0-9]*)$/u.test(identity.deviceId) ||
          !/^[1-9][0-9]*$/u.test(identity.fileId) || identity.ownerUid !== held.root.ownerUid ||
          identity.deviceId !== held.root.deviceId) throw new KernelStorageError('ARTIFACT_MISMATCH', 'worker witness has a foreign StateRoot identity');
      try { return wrapWorkerReservation(handle,
        held.openWorkerReservation(name, identity.deviceId, identity.fileId, identity.ownerUid), launchId, spawnNonceDigest); }
      catch (error) { workerReservationError(error); }
    },
    createGenerationTree(runId, generationId) {
      receiver(this); held.assertHeld();
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(runId) || !/^[A-Za-z0-9_-]{43}$/.test(generationId)) {
        throw new KernelStorageError('INVALID_REQUEST', 'private generation requires canonical Run/generation ids');
      }
      return wrapGenerationTree(held.createGenerationTree(runId, generationId));
    },
    openGenerationTree(value, sourceRowVersion) {
      receiver(this); held.assertHeld();
      const generation = decodeWorkspaceGenerationIdentity(value);
      const locator = generation.locator;
      if (process.platform !== 'linux' || locator.kind !== 'linux_directory' ||
          locator.stateRootIdentityRef !== rootRef || locator.stateRootIdentityDigest !== root.identityDigest ||
          locator.ownerUid !== root.ownerUid ||
          locator.canonicalRootRelativePath !== `runs/${generation.runId}/generations/${generation.generationId}`) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'private generation open requires the exact Linux StateRoot locator');
      }
      if (sourceRowVersion !== undefined && (!Number.isSafeInteger(sourceRowVersion) || sourceRowVersion < 1)) {
        throw new KernelStorageError('INVALID_REQUEST', 'retained generation open requires the exact positive source version');
      }
      const tree = sourceRowVersion === undefined ? held.openGenerationTree(generation.runId, generation.generationId) :
        held.openGenerationTree(generation.runId, generation.generationId,
          identityHash(generation.generationId, String(sourceRowVersion)), locator.deviceId, locator.directoryFileId);
      if (tree.identity.deviceId !== locator.deviceId || tree.identity.fileId !== locator.directoryFileId ||
          tree.identity.ownerUid !== locator.ownerUid) {
        tree.close();
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'private generation descriptor differs from its frozen identity');
      }
      return wrapGenerationTree(tree);
    },
    createSourceInspectionStaging(inspectionId, stagingNonceDigest) {
      receiver(this); held.assertHeld();
      const stagingId = checkedSourceInspection(inspectionId, stagingNonceDigest);
      try { return wrapSourceInspectionStaging(handle, held.createSourceInspectionStaging(stagingId), inspectionId, stagingNonceDigest, true); }
      catch (error) { sourceStagingError(error); }
    },
    openSourceInspectionStaging(inspectionId, stagingNonceDigest, identity) {
      receiver(this); held.assertHeld();
      const stagingId = checkedSourceInspection(inspectionId, stagingNonceDigest);
      if (!identity || Object.keys(identity).length !== 4 || typeof identity.deviceId !== 'string' || typeof identity.fileId !== 'string' ||
          !/^(0|[1-9][0-9]*)$/.test(identity.deviceId) ||
          !/^(0|[1-9][0-9]*)$/.test(identity.fileId) || identity.deviceId !== held.root.deviceId ||
          identity.ownerUid !== held.root.ownerUid || identity.mode !== 448 ||
          BigInt(identity.deviceId) > 0xffffffffffffffffn || BigInt(identity.fileId) > 0xffffffffffffffffn)
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'retained source staging requires its exact same-device private identity');
      try { return wrapSourceInspectionStaging(handle, held.openSourceInspectionStaging(stagingId, identity.deviceId, identity.fileId),
        inspectionId, stagingNonceDigest, false); }
      catch (error) { sourceStagingError(error); }
    },
    close() {
      receiver(this);
      if (sourceRetirementsByLock.get(handle)?.size)
        throw new ResourceRetirementError('StateOwner cannot release during active source staging cleanup', new Error('source cleanup is not joined'));
      try { held.close(); }
      catch (error) {
        if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
          throw new ResourceRetirementError('native resource retirement prevents StateOwner release', error);
        throw error;
      }
    },
    quarantineGeneration(value, sourceRowVersion) {
      receiver(this);
      held.assertHeld();
      const generation = decodeWorkspaceGenerationIdentity(value);
      const locator = generation.locator;
      const linux = locator.kind === 'linux_directory';
      const source = `runs/${generation.runId}/generations/${generation.generationId}${linux ? '' : '.img'}`;
      if (!Number.isSafeInteger(sourceRowVersion) || sourceRowVersion < 1 ||
          generation.generationId !== identityHash(generation.runId, generation.sourceCheckpointId,
            generation.sourceWorkspaceStateRef, generation.creationNonceDigest) ||
          linux !== (process.platform === 'linux') || locator.stateRootIdentityRef !== rootRef ||
          locator.stateRootIdentityDigest !== root.identityDigest ||
          (linux ? locator.canonicalRootRelativePath : locator.backingStoreCanonicalRootRelativePath) !== source ||
          (linux ? locator.ownerUid : locator.backingStoreOwnerUid) !== root.ownerUid) {
        throw new KernelStorageError('ARTIFACT_MISMATCH', 'generation quarantine requires the exact host, StateRoot, generation locator and source version');
      }
      const quarantineId = identityHash(generation.generationId, String(sourceRowVersion));
      const moved = held.moveGeneration(generation.runId, generation.generationId, quarantineId,
        linux ? locator.deviceId : locator.backingStoreDeviceId, linux ? locator.directoryFileId : locator.backingStoreFileId);
      return Object.freeze({
        quarantineCanonicalRootRelativePath: `quarantine/workspace-generations/${quarantineId}`,
        quarantineDeviceId: moved.deviceId, quarantineFileId: moved.fileId,
        originalLocatorAbsent: true, renameNoReplace: true, directoryFsyncComplete: true
      });
    }
  };
  roots.set(handle, root);
  publicationLocks.set(handle, held);
  return handle;
}

let loaded: { digest: string; implementation: NativeStateOwner } | undefined;
// Cache bytes, never authority. Every use still captures and revalidates the
// actual mapped image; the private key includes the complete native stat tuple.
let currentImageHash: { key: string; digest: string } | undefined;

async function observeCurrentProcess(binding: NativeBinding) {
  let observation: NativeCurrentProcess | undefined;
  let operationError: unknown;
  try {
    observation = binding.captureCurrentProcess();
    observation.assertHeld();
    const executableImageDigest = currentImageHash?.key === observation.imageIdentityKey
      ? currentImageHash.digest
      : await hashHeldProcessImage(observation.imageFd, observation.imageByteCount, () => observation!.assertHeld());
    observation.assertHeld();
    currentImageHash = { key: observation.imageIdentityKey, digest: executableImageDigest };
    return Object.freeze({ pid: observation.pid, uid: observation.uid,
      processStartToken: observation.processStartToken, executableImageDigest });
  } catch (error) {
    operationError = error;
    if (error instanceof KernelStorageError || error instanceof ResourceRetirementError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT') {
      throw new ResourceRetirementError('Supervisor process image descriptors did not retire', error);
    }
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'actual Supervisor process image is unavailable or changed', { cause: error });
  } finally {
    try { observation?.close(); }
    catch (error) { throw new ResourceRetirementError('Supervisor process image descriptor did not retire',
      operationError === undefined ? error : new AggregateError([operationError, error])); }
  }
}

/** Load only the fixed host helper, through its verified held descriptor.
 * Bundle signature verification belongs to the trusted StateStore bootstrap. */
export async function loadNativeStateOwner(bundle?: RuntimeBundleManifest): Promise<NativeStateOwner> {
  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', `StateOwner is unsupported on ${process.platform}`);
  }
  const file = await open(STATE_OWNER_NATIVE_PATH, constants.O_RDONLY | constants.O_NOFOLLOW);
  let operationError: unknown;
  try {
    return await loadHeldStateOwnerImage(file, bundle);
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    try { await file.close(); }
    catch (error) { throw new ResourceRetirementError('installed StateOwner image descriptor did not retire',
      operationError === undefined ? error : new AggregateError([operationError, error])); }
  }
}

/** Internal fixed-image bridge for the installed producer. The file is already
 * held by its owning scope; this routine neither closes it nor exposes a
 * descriptor/path selector through the installed public handle. */
export async function loadHeldStateOwnerImage(file: FileHandle, bundle?: RuntimeBundleManifest): Promise<NativeStateOwner> {
  const before = await file.stat({ bigint: true });
  if (!before.isFile() || before.uid !== BigInt(process.geteuid!()) || before.nlink !== 1n ||
      (before.mode & 0o7777n) !== 0o500n || before.size <= 0n || before.size > 16n * 1024n * 1024n) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper must be an owner-only 0500 regular file of at most 16 MiB');
  }
  const fd = file.fd;
  // Installed files survive several borrows. Positional reads never consume
  // their shared file offset, and a closed FileHandle cannot lend a reused fd.
  const digest = await hashHeldProcessImage(fd, Number(before.size), () => {
    if (file.fd !== fd) throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native image handle is closed');
  });
  const after = await file.stat({ bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
      before.uid !== after.uid || before.mode !== after.mode || before.nlink !== after.nlink ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper changed while being read');
  }
  if (bundle) {
    const entry = bundle.entries.find((candidate) => candidate.entryId === STATE_OWNER_NATIVE_ENTRY_ID);
    if (!entry || entry.role !== 'platform_helper' || !entry.executable || entry.version !== '1' ||
        entry.relativePath !== STATE_OWNER_NATIVE_RELATIVE_PATH || entry.digest !== digest || entry.byteCount !== Number(after.size)) {
      throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper does not match the signed RuntimeBundle');
    }
  }
  if (loaded) {
    if (loaded.digest !== digest) throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper changed within this process');
    return loaded.implementation;
  }
  const nativeModule = new Module(STATE_OWNER_NATIVE_PATH);
  process.dlopen(nativeModule, `${process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd'}/${file.fd}`);
  const binding: NativeBinding = nativeModule.exports;
  if (typeof binding.acquireLock !== 'function' || typeof binding.processStartToken !== 'function' ||
      typeof binding.captureCurrentProcess !== 'function' || typeof binding.openWorkspaceRoot !== 'function') {
    throw new KernelStorageError('ARTIFACT_MISMATCH', 'StateOwner native helper has an unsupported interface');
  }
  const implementation: NativeStateOwner = {
    acquireLock(stateRoot, createLayout) {
      if (normalizeAbsolutePath(stateRoot) !== stateRoot) throw new TypeError('StateOwner root must be canonical');
      const held = binding.acquireLock(stateRoot, createLayout);
      try { return wrapLock(held, stateRoot); } catch (error) { held.close(); throw error; }
    },
    processStartToken: () => binding.processStartToken(),
    observeCurrentProcess: () => observeCurrentProcess(binding),
    openWorkspaceRoot(workspacePath) {
      if (normalizeAbsolutePath(workspacePath) !== workspacePath) throw new TypeError('source workspace root must be canonical');
      const root = Object.freeze(binding.openWorkspaceRoot(workspacePath));
      workspaceRoots.set(root, workspacePath);
      return root;
    }
  };
  loaded = { digest, implementation: Object.freeze(implementation) };
  nativeBindings.set(loaded.implementation, binding);
  loadedImageIdentities.set(loaded.implementation, before);
  return loaded.implementation;
}

export function assertStateOwnerLock(lock: HeldStateOwnerLock): void {
  try {
    lock.assertHeld();
  } catch (error) {
    if (error instanceof ResourceRetirementError) throw error;
    if ((error as { code?: unknown } | null)?.code === 'ERR_CLIQ_RESOURCE_RETIREMENT')
      throw new ResourceRetirementError('StateOwner retains unresolved resource retirement', error);
    throw new KernelStorageError('RECOVERY_REQUIRED', 'StateOwner root/runtime/lock descriptor identity changed or closed');
  }
}
