// Closed evidence data only. Passing this decoder never grants Store/native
// authority or proves that an installed/Linux action actually occurred.
import assert from 'node:assert/strict';
import { types } from 'node:util';
import { LEGACY_UPGRADE_SOURCE } from './legacy-upgrade-source-data.js';
import { copyCredentialSecretScanFailureDiagnostic } from './credential-secret-scan.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { readInstalledRuntimeUpgradeFailureMarker } from '../../../src/state/installed-upgrade-diagnostics.js';

export const INSTALLED_UPGRADE_CREDENTIAL_ACTIONS = ['install_services', 'enroll', 'read', 'revoke'] as const;
const credentialFailureCodes = ['ADMISSION_KEY_CONFLICT', 'REQUEST_ID_CONFLICT', 'ARTIFACT_MISMATCH', 'AGENT_HANDOFF_PENDING',
  'MODEL_RETRY_PENDING', 'BUDGET_EXHAUSTED', 'EVENT_CURSOR_EXPIRED', 'INVALID_REQUEST', 'LEASE_FENCED', 'NOT_FOUND',
  'RECOVERY_REQUIRED', 'REVISION_CONFLICT', 'STATE_TRANSITION_INVALID', 'UNSUPPORTED_PLATFORM'] as const;

// Only exact existing internal literals classify the already-scanned failure.
// These fixed hints do not retain error text or change the original refusal.
const credentialFailureReasons = {
  'credential authority history is not contiguous': 'credential_history',
  'credential result kind, generation or expiry differs': 'credential_history',
  'credential committed operation has no authority result': 'credential_history',
  'credential fact index differs': 'credential_history',
  'credential attempts are not contiguous frozen-core attempts': 'credential_history',
  'credential phase continuity differs': 'credential_history',
  'credential transition rewrites its original preparation': 'credential_history',
  'credential revision has no unique creating operation': 'credential_history',
  'credential revision differs from its committed operation': 'credential_history',
  'credential revoke has no active predecessor': 'credential_revoke_history',
  'credential revoke rewrites its active predecessor': 'credential_revoke_history',
  'credential revoke has no original receipt': 'credential_revoke_history',
  'credential revoke row identity differs': 'credential_revoke_history',
  'credential cleanup evidence precedes its phase': 'credential_revoke_history',
  'credential cleanup receipt differs from its observation': 'credential_revoke_history',
  'credential revoke receipt differs from its terminal result': 'credential_revoke_history',
  'credential preparation provenance differs': 'credential_original_source',
  'credential original authority row is missing': 'credential_original_source',
  'credential original authority row index differs': 'credential_original_source',
  'credential original endpoint differs': 'credential_original_source',
  'retained credential producer differs from its original signed source': 'credential_producer_source',
  'retained current producer data is not bounded original data': 'credential_current_source',
  'retained current producer differs from its exact original signed bundle': 'credential_current_source',
  'endpoint retained object is missing or does not rehash': 'credential_retained_object',
  'credential authority database did not retire': 'credential_retirement',
  'ordinary credential entry cannot be called while a scope is acquiring, active or draining': 'credential_scope_busy',
} as const;
type CredentialFailureReason = typeof credentialFailureReasons[keyof typeof credentialFailureReasons];

/** Read only the fixed startup failure code from already-scanned child stderr.
 * No error message, stack, path, credential or arbitrary native code survives. */
export function readInstalledUpgradeCredentialFailure(bytes: Buffer,
  action: typeof INSTALLED_UPGRADE_CREDENTIAL_ACTIONS[number], status: number) {
  assert(INSTALLED_UPGRADE_CREDENTIAL_ACTIONS.includes(action)); assert(Number.isSafeInteger(status) && status > 0 && status <= 255);
  let code: typeof credentialFailureCodes[number] | null = null, reason: CredentialFailureReason | undefined;
  try {
    assert(Buffer.isBuffer(bytes) && !types.isProxy(bytes) && bytes.length <= 65536);
    const lines = new TextDecoder('utf-8', { fatal: true }).decode(bytes).split('\n'); assert(lines.length <= 128);
    let seen = false;
    for (const line of lines) {
      if (!line.startsWith('{')) continue;
      const row = parseJsonStrict(line) as Record<string, unknown>;
      if (!row || typeof row !== 'object' || Array.isArray(row) || row.diagnosticOnly !== true || row.scope !== 'installed-read-startup') continue;
      assert(!seen && Object.keys(row).every(key => ['diagnosticOnly', 'scope', 'code', 'message', 'path'].includes(key))); seen = true;
      code = credentialFailureCodes.find(value => value === row.code) ?? null;
      if (typeof row.message === 'string' && Object.hasOwn(credentialFailureReasons, row.message))
        reason = credentialFailureReasons[row.message as keyof typeof credentialFailureReasons];
    }
  } catch { code = null; reason = undefined; }
  return Object.freeze({ diagnosticOnly: true as const, kind: 'credential_command_failed' as const, action, status, code,
    ...(reason === undefined ? {} : { reason }) });
}

export const INSTALLED_UPGRADE_PROFILE = 'actual_2513_schema7_to_signed8_edit_run_v1';
export const INSTALLED_UPGRADE_PHASES = ['source_and_packages', 'actual_schema7_installation', 'schema7_public_authorization_and_run',
  'formal_signed_upgrade_and_real_ready', 'explicit_schema8_new_authorization_and_run', 'same_receipt_recovery_and_old_first_response',
  'upgrade_assertions_complete', 'secret_corpus', 'complete', 'secret_scan_or_report_failure'] as const;
function object(value: unknown, required: string[], optional: string[] = []): Record<string, any> {
  assert(value && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value));
  assert([null, Object.prototype].includes(Object.getPrototypeOf(value)));
  const descriptors = Object.getOwnPropertyDescriptors(value);
  assert(required.every(key => descriptors[key] && 'value' in descriptors[key] && descriptors[key].enumerable));
  assert(Reflect.ownKeys(descriptors).every(key => typeof key === 'string' && [...required, ...optional].includes(key) &&
    'value' in descriptors[key]! && descriptors[key]!.enumerable));
  return Object.assign(Object.create(null), Object.fromEntries(Object.entries(descriptors).map(([key, field]) => [key, field.value]))) as Record<string, any>;
}
function natural(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  assert(typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum); return value;
}
function array(value: unknown, maximum: number): unknown[] {
  assert(Array.isArray(value) && !types.isProxy(value) && value.length <= maximum);
  assert.equal(Object.getPrototypeOf(value), Array.prototype);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  assert(Reflect.ownKeys(descriptors).length === value.length + 1);
  for (let index = 0; index < value.length; index++) assert(descriptors[String(index)] && 'value' in descriptors[String(index)]!);
  return value;
}
function ref(value: unknown): void { assert(typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)); }
function allTrue(value: unknown, keys: string[]) { const row = object(value, keys); for (const key of keys) assert.equal(row[key], true); }

export function decodeInstalledUpgradeReport(value: unknown): Readonly<Record<string, any>> {
  const row = object(value, ['diagnosticOnly', 'qualified', 'schemaVersion', 'format', 'fixtureProfile', 'phase', 'secretOutputScan'],
    ['scope', 'cases', 'officialReleaseQualified', 'wholeI4Qualified', 'legacy43ErrorReceipt', 'originalSource', 'packages',
      'oldCredentialNewRuntimeRefusal', 'upgrade', 'servicesStoppedAndJoined', 'secretServiceJoined', 'httpsJoined', 'transport', 'secretCorpus', 'error',
      'secretScanFailure', 'secretCorpusScanProgress', 'credentialCommandFailure', 'upgradeCommandFailure']);
  assert.equal(row.diagnosticOnly, true); assert.equal(row.schemaVersion, 1); assert.equal(typeof row.qualified, 'boolean');
  assert.equal(row.format, 'cliq-installed-runtime-upgrade-qualification-v1'); assert.equal(row.fixtureProfile, INSTALLED_UPGRADE_PROFILE);
  assert(INSTALLED_UPGRADE_PHASES.includes(row.phase));
  if (row.scope !== undefined) assert.equal(row.scope, 'signed_schema7_to8_two_unverified_edit_runs');
  if (row.officialReleaseQualified !== undefined) assert.equal(row.officialReleaseQualified, false);
  if (row.wholeI4Qualified !== undefined) assert.equal(row.wholeI4Qualified, false);
  if (row.legacy43ErrorReceipt !== undefined) assert.equal(object(row.legacy43ErrorReceipt, ['kind']).kind, 'not_exercised');
  if (row.credentialCommandFailure !== undefined) {
    const failure = object(row.credentialCommandFailure, ['diagnosticOnly', 'kind', 'action', 'status', 'code'], ['reason']);
    assert.equal(failure.diagnosticOnly, true); assert.equal(failure.kind, 'credential_command_failed');
    assert(INSTALLED_UPGRADE_CREDENTIAL_ACTIONS.includes(failure.action));
    assert(natural(failure.status, 255) > 0); assert(failure.code === null || credentialFailureCodes.includes(failure.code));
    if (failure.reason !== undefined) assert(Object.values(credentialFailureReasons).includes(failure.reason));
    assert.equal(row.qualified, false);
  }
  if (row.upgradeCommandFailure !== undefined) {
    const failure = object(row.upgradeCommandFailure, ['exitStatus', 'marker']);
    assert(failure.exitStatus === null || Number.isSafeInteger(failure.exitStatus) && failure.exitStatus > 0 && failure.exitStatus <= 255,
      'upgrade command failure has an invalid exit status');
    if (failure.marker !== null) {
      assert(typeof failure.marker === 'string' && Buffer.byteLength(failure.marker) <= 129, 'upgrade command marker is not bounded text');
      const bytes = Buffer.from(failure.marker), decoded = readInstalledRuntimeUpgradeFailureMarker(bytes);
      assert(decoded?.equals(bytes), 'upgrade command marker is not its exact fixed source line');
    }
    assert.equal(row.qualified, false, 'a failed upgrade command cannot qualify');
  }
  if (row.originalSource !== undefined) {
    const source = object(row.originalSource, Object.keys(LEGACY_UPGRADE_SOURCE));
    for (const [key, expected] of Object.entries(LEGACY_UPGRADE_SOURCE)) assert.equal(source[key], expected);
  }
  if (row.packages !== undefined) {
    const packages = object(row.packages, ['sourceBundleRef', 'targetBundleRef', 'sourceManifestDigest', 'targetManifestDigest', 'sameActualPublisher', 'schemaConversionDigest']);
    for (const key of ['sourceBundleRef', 'targetBundleRef', 'sourceManifestDigest', 'targetManifestDigest', 'schemaConversionDigest']) ref(packages[key]);
    assert.notEqual(packages.sourceBundleRef, packages.targetBundleRef); assert.notEqual(packages.sourceManifestDigest, packages.targetManifestDigest);
    assert.equal(packages.sameActualPublisher, true);
  }
  const cases = row.cases === undefined ? [] : array(row.cases, 2), runIds = new Set(), resultRefs = new Set(), retirementRefs = new Set(), firstResponses = new Set();
  for (const [index, value] of cases.entries()) {
    const result = object(value, ['schemaVersion', 'runId', 'status', 'resultRef', 'firstResponseSha256', 'modelPosts', 'toolCalls',
      'launchCount', 'retirementRefs', 'hostSourceUnchanged', 'publicRecoveryRead', 'actualWorkerLifetimesAbsent']);
    assert.equal(result.schemaVersion, index ? 8 : 7); assert.equal(result.status, 'completed_unverified');
    assert(typeof result.runId === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(result.runId) && !runIds.has(result.runId)); runIds.add(result.runId);
    ref(result.resultRef); ref(result.firstResponseSha256); assert(!resultRefs.has(result.resultRef)); resultRefs.add(result.resultRef);
    assert(!firstResponses.has(result.firstResponseSha256)); firstResponses.add(result.firstResponseSha256);
    assert.equal(result.modelPosts, 2); assert.equal(result.toolCalls, 1); natural(result.launchCount, 16); assert(result.launchCount > 0);
    const refs = array(result.retirementRefs, 16); assert.equal(refs.length, result.launchCount);
    for (const item of refs) { ref(item); assert(!retirementRefs.has(item)); retirementRefs.add(item); }
    for (const key of ['hostSourceUnchanged', 'publicRecoveryRead', 'actualWorkerLifetimesAbsent']) assert.equal(result[key], true);
  }
  if (row.oldCredentialNewRuntimeRefusal !== undefined) {
    const rejected = object(row.oldCredentialNewRuntimeRefusal, ['code', 'noNewRun', 'noModelDispatch']);
    assert(['AUTHORIZATION_REQUIRED', 'ARTIFACT_MISMATCH', 'UNSUPPORTED_EXECUTION_IDENTITY', 'INVALID_REQUEST'].includes(rejected.code));
    assert.equal(rejected.noNewRun, true); assert.equal(rejected.noModelDispatch, true);
  }
  if (row.upgrade !== undefined) {
    const upgraded = object(row.upgrade, ['receiptRef', 'originalSupervisorAndKeeperLifetimesAbsent', 'realTargetHello',
      'oldFirstResponseUnchanged', 'originalCasBytesAndInodesUnchanged', 'oldEndpointAndCredentialReadable', 'oldCredentialRevocable',
      'explicitNewRuntimeEndpointAndCredential', 'sameReceiptRecovery', 'pagedRetirementGraphFullyRead', 'retirementResourceRowCount']); ref(upgraded.receiptRef);
    assert(natural(upgraded.retirementResourceRowCount, 400000) >= 3);
    for (const [key, value] of Object.entries(upgraded)) if (!['receiptRef', 'retirementResourceRowCount'].includes(key)) assert.equal(value, true);
  }
  for (const key of ['servicesStoppedAndJoined', 'secretServiceJoined', 'httpsJoined']) if (row[key] !== undefined) assert.equal(typeof row[key], 'boolean');
  if (row.transport !== undefined) {
    const transport = object(row.transport, ['postCount', 'acceptedTcp', 'acceptedTls', 'providerHealthy']);
    for (const key of ['postCount', 'acceptedTcp', 'acceptedTls']) natural(transport[key], 4);
    assert(transport.postCount <= transport.acceptedTls && transport.acceptedTls <= transport.acceptedTcp); assert.equal(typeof transport.providerHealthy, 'boolean');
  }
  if (row.secretCorpus !== undefined) {
    const corpus = object(row.secretCorpus, ['diagnosticOnly', 'qualified', 'filesScanned', 'fileBytesScanned', 'sqliteDatabasesScanned',
      'logicalRowsScanned', 'logicalValuesScanned', 'logicalBytesScanned', 'evidenceDirectoriesScanned']);
    assert.equal(corpus.diagnosticOnly, true); assert.equal(corpus.qualified, true);
    for (const key of ['filesScanned', 'fileBytesScanned', 'sqliteDatabasesScanned', 'logicalRowsScanned', 'logicalValuesScanned', 'logicalBytesScanned', 'evidenceDirectoriesScanned']) natural(corpus[key]);
    assert(corpus.filesScanned <= 2048); assert.equal(corpus.sqliteDatabasesScanned, 2); assert.equal(corpus.evidenceDirectoriesScanned, 0);
  }
  if (row.error !== undefined) {
    const error = object(row.error, ['diagnosticOnly', 'kind', 'sourceFrames']); assert.equal(error.diagnosticOnly, true);
    assert.equal(error.kind, 'installed_runtime_upgrade_failed');
    for (const value of array(error.sourceFrames, 8)) {
      const frame = object(value, ['file', 'line', 'column']);
      assert(['installed-upgrade-journey.ts', 'installed-upgrade-build.ts', 'legacy-upgrade-source.ts', 'qualification-source.ts',
        'installed-supervisor-package.ts', 'installed-client-consumer.ts'].includes(frame.file));
      assert(natural(frame.line, 9999999) > 0 && natural(frame.column, 9999999) > 0);
    }
    assert.equal(row.qualified, false);
  }
  if (row.secretScanFailure !== undefined) { copyCredentialSecretScanFailureDiagnostic(row.secretScanFailure); assert.equal(row.qualified, false); }
  if (row.secretCorpusScanProgress !== undefined) {
    const progress = object(row.secretCorpusScanProgress, ['diagnosticOnly', 'source'], ['corpusCounters']); assert.equal(progress.diagnosticOnly, true);
    const source = object(progress.source, ['kind', 'part'], ['database', 'tableBucket', 'logicalRowsObserved', 'logicalValuesAttempted', 'logicalBytesObserved']);
    if (source.kind === 'database_logical') {
      object(source, ['kind', 'database', 'tableBucket', 'part', 'logicalRowsObserved', 'logicalValuesAttempted', 'logicalBytesObserved']);
      assert(['kernel', 'authority'].includes(source.database)); assert(['table_name', 'table_sql', 'cell'].includes(source.part));
      assert(['artifacts', 'control', 'events', 'items', 'checkpoints', 'journal', 'other', 'canonical_time_fence', 'state_owners', 'sessions', 'runs',
        'worker_launches', 'workspace_generations', 'local_inference_activation_cycles', 'local_inference_launches', 'list_read_cuts', 'list_read_cut_entries',
        'child_allocations', 'authorization_grants', 'source_inspection_attempts', 'mcp_registrations', 'admin_operations'].includes(source.tableBucket));
      for (const key of ['logicalRowsObserved', 'logicalValuesAttempted', 'logicalBytesObserved']) natural(source[key]);
    } else if (source.kind === 'database_file') {
      object(source, ['kind', 'database', 'part']); assert(['kernel', 'authority'].includes(source.database)); assert(['main', 'wal', 'journal', 'shm'].includes(source.part));
    } else {
      object(source, ['kind', 'part']); assert(source.kind === 'cas' && ['entry_name', 'file_bytes'].includes(source.part) || source.kind === 'evidence' && source.part === 'file_bytes');
    }
    if (progress.corpusCounters !== undefined) {
      const counters = object(progress.corpusCounters, ['filesScanned', 'fileBytesScanned', 'sqliteDatabasesScanned', 'logicalRowsScanned',
        'logicalValuesScanned', 'logicalBytesScanned', 'evidenceDirectoriesScanned', 'inventoryEntriesObserved']);
      for (const value of Object.values(counters)) natural(value);
    }
    assert.equal(row.qualified, false);
  }
  const scan = object(row.secretOutputScan, ['bytesScanned', 'chunksScanned', 'streamsOpened', 'streamsClosed', 'needleCount', 'retainedNeedleBytes',
    'retainedTailBytes', 'matched', 'limitExceeded', 'closed']);
  for (const key of ['bytesScanned', 'chunksScanned', 'streamsOpened', 'streamsClosed', 'needleCount', 'retainedNeedleBytes', 'retainedTailBytes']) natural(scan[key]);
  assert.equal(typeof scan.matched, 'boolean'); assert.equal(typeof scan.limitExceeded, 'boolean'); assert.equal(scan.closed, true);
  assert(scan.streamsClosed <= scan.streamsOpened);
  if (row.qualified) {
    assert.equal(row.phase, 'complete'); assert.equal(row.scope, 'signed_schema7_to8_two_unverified_edit_runs');
    assert.equal(row.officialReleaseQualified, false); assert.equal(row.wholeI4Qualified, false);
    assert(row.legacy43ErrorReceipt && row.originalSource && row.packages && row.upgrade && row.oldCredentialNewRuntimeRefusal && row.secretCorpus);
    assert.equal(cases.length, 2); allTrue({ servicesStoppedAndJoined: row.servicesStoppedAndJoined, secretServiceJoined: row.secretServiceJoined,
      httpsJoined: row.httpsJoined }, ['servicesStoppedAndJoined', 'secretServiceJoined', 'httpsJoined']);
    assert(row.transport && row.transport.postCount === 4 && row.transport.acceptedTcp === 4 && row.transport.acceptedTls === 4 && row.transport.providerHealthy);
    assert(scan.bytesScanned <= 512 * 1024 * 1024 && scan.streamsOpened <= 4096 && scan.streamsOpened === scan.streamsClosed &&
      scan.needleCount > 0 && scan.retainedNeedleBytes === 0 && scan.retainedTailBytes === 0 && !scan.matched && !scan.limitExceeded);
  }
  return row;
}
