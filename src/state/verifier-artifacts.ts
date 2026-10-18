import { digestOmitting, normalizeAbsolutePath, normalizeBoundedText, assertArtifactRef, parseCanonicalTime } from '../kernel/identity.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import type { RepairDiagnosticItem, VerificationReceipt, VerifierCommandV1, VerifierEnvironmentV1, VerifierExecutableIdentityV1,
  VerifierRepairDiagnosticV1, VerifierRepairModelContentV1, VerifierResultItem, VerifierStopEvidence, VerifierStopItem } from '../kernel/verifier.js';
import type { VerifierSpec } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';

function mismatch(): never { throw new KernelStorageError('ARTIFACT_MISMATCH', 'verifier artifact is not canonical closed retained data'); }
function closed(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      required.some(key => !Object.hasOwn(value, key)) || Reflect.ownKeys(value).some(key =>
        typeof key !== 'string' || !required.includes(key) && !optional.includes(key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(property => !Object.hasOwn(property, 'value') || !property.enumerable)) mismatch();
  return value as Record<string, unknown>;
}
function text(value: unknown, maximum = 128, minimum = 1): string {
  try {
    if (typeof value !== 'string' || normalizeBoundedText(value, minimum, maximum) !== value) mismatch();
    return value;
  } catch { return mismatch(); }
}
function ref(value: unknown): string {
  const result = text(value, 64);
  try { assertArtifactRef(result); } catch { mismatch(); }
  return result;
}
function array(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum || Reflect.ownKeys(value).some(key =>
      key !== 'length' && (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= value.length))) mismatch();
  for (let index = 0; index < value.length; index++) {
    const entry = Object.getOwnPropertyDescriptor(value, String(index));
    if (!entry || !Object.hasOwn(entry, 'value')) mismatch();
  }
  return value;
}
function path(value: unknown, root = false): string {
  const result = text(value, 4096);
  if (root && result === '.') return result;
  if (result.includes('\\') || result.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255)) mismatch();
  return result;
}
function literal(value: unknown): void {
  const data = closed(value, ['kind', 'value']);
  if (data.kind !== 'non_secret_literal') mismatch();
  text(data.value, 8192, 0);
}
function digest(value: Record<string, unknown>, key: string): void {
  if (ref(value[key]) !== digestOmitting(value, key)) mismatch();
}
function integer(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) mismatch();
  return value;
}
function time(value: unknown): number {
  try { return parseCanonicalTime(text(value)); } catch { return mismatch(); }
}

/** Data decoding does not resolve a signed executable or authorize reading it. */
export function decodeVerifierExecutableIdentity(value: unknown): VerifierExecutableIdentityV1 {
  const data = closed(value, ['kind'], ['guestToolchainManifestRef', 'guestToolchainManifestDigest', 'toolId', 'executionPath',
    'executableDigest', 'abiFingerprint', 'workspaceIdentityDigest', 'canonicalRootRelativePath', 'scriptDigest', 'interpreterIdentityRef', 'interpreterIdentityDigest']);
  if (data.kind === 'guest_toolchain') {
    closed(data, ['kind', 'guestToolchainManifestRef', 'guestToolchainManifestDigest', 'toolId', 'executionPath', 'executableDigest', 'abiFingerprint']);
    ref(data.guestToolchainManifestRef); ref(data.guestToolchainManifestDigest); ref(data.executableDigest);
    text(data.toolId); text(data.abiFingerprint);
    const executionPath = text(data.executionPath, 4096);
    try { if (normalizeAbsolutePath(executionPath) !== executionPath) mismatch(); } catch { mismatch(); }
  } else if (data.kind === 'workspace_script') {
    closed(data, ['kind', 'workspaceIdentityDigest', 'canonicalRootRelativePath', 'scriptDigest', 'interpreterIdentityRef', 'interpreterIdentityDigest']);
    ref(data.workspaceIdentityDigest); path(data.canonicalRootRelativePath); ref(data.scriptDigest);
    ref(data.interpreterIdentityRef); ref(data.interpreterIdentityDigest);
  } else mismatch();
  return data as VerifierExecutableIdentityV1;
}

/** Closed direct-argv contract only; consumers still bind its signed identity. */
export function decodeVerifierCommand(value: unknown): VerifierCommandV1 {
  const data = closed(value, ['schemaVersion', 'format', 'verifierId', 'verifierVersion', 'executable', 'argv', 'cwd', 'commandDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-verifier-command-v1') mismatch();
  text(data.verifierId); text(data.verifierVersion); decodeVerifierExecutableIdentity(data.executable);
  array(data.argv, 128).forEach(literal); path(data.cwd, true); digest(data, 'commandDigest');
  return data as VerifierCommandV1;
}

/** This validates declared restrictions, not sandbox enforcement or exclusion from SourceProjection. */
export function decodeVerifierEnvironment(value: unknown): VerifierEnvironmentV1 {
  const data = closed(value, ['schemaVersion', 'format', 'verifierId', 'verifierVersion', 'commandRef', 'commandDigest', 'variables',
    'writableEphemeralPaths', 'sourceProjectionRef', 'sourceAccess', 'networkAccess', 'sandboxProfile', 'runtimeBundleRef',
    'runtimeBundleManifestDigest', 'environmentDigest'], ['guestToolchainManifestRef', 'guestToolchainManifestDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-verifier-environment-v1' || data.sourceAccess !== 'read_only' ||
      data.networkAccess !== 'denied' || data.sandboxProfile !== 'cliq-verifier-readonly-v1') mismatch();
  text(data.verifierId); text(data.verifierVersion);
  for (const key of ['commandRef', 'commandDigest', 'sourceProjectionRef', 'runtimeBundleRef', 'runtimeBundleManifestDigest']) ref(data[key]);
  const guest = Object.hasOwn(data, 'guestToolchainManifestRef');
  if (guest !== Object.hasOwn(data, 'guestToolchainManifestDigest')) mismatch();
  if (guest) { ref(data.guestToolchainManifestRef); ref(data.guestToolchainManifestDigest); }
  let previous: string | undefined;
  for (const entry of array(data.variables, 64)) {
    const variable = closed(entry, ['name', 'value']), name = text(variable.name, 64);
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(name) || previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(name)) >= 0) mismatch();
    previous = name; literal(variable.value);
  }
  previous = undefined;
  for (const entry of array(data.writableEphemeralPaths, 32)) {
    const current = path(entry);
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(current)) >= 0) mismatch();
    previous = current;
  }
  digest(data, 'environmentDigest');
  return data as VerifierEnvironmentV1;
}

/** The frozen entries are canonical data; this does not resolve their command/environment refs. */
export function decodeVerifierSpec(value: unknown): VerifierSpec {
  const data = closed(value, ['schemaVersion', 'format', 'verifiers', 'specDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-verifier-spec-v1') mismatch();
  const ids = new Set<string>();
  for (const [index, value] of array(data.verifiers, 32).entries()) {
    const entry = closed(value, ['index', 'id', 'version', 'gate', 'commandRef', 'commandDigest', 'environmentRef', 'environmentDigest',
      'timeoutMs', 'retries', 'outputLimitBytes', 'entryDigest']);
    const id = text(entry.id); text(entry.version);
    if (entry.index !== index || ids.has(id) || !['required', 'advisory'].includes(entry.gate as string)) mismatch();
    ids.add(id);
    for (const key of ['commandRef', 'commandDigest', 'environmentRef', 'environmentDigest']) ref(entry[key]);
    integer(entry.timeoutMs, 1000, 3_600_000); integer(entry.retries, 0, 3); integer(entry.outputLimitBytes, 65_536, 16_777_216);
    digest(entry, 'entryDigest');
  }
  digest(data, 'specDigest');
  return data as VerifierSpec;
}

function verifierMeasurements(data: Record<string, unknown>, allowControllerStop = false): void {
  if (data.schemaVersion !== 1 ||
      !['exit', 'timeout', 'signal', 'spawn_error', 'sandbox_denial', 'resource_failure',
        ...(allowControllerStop ? ['controller_stop'] : [])].includes(data.terminationReason as string)) mismatch();
  text(data.runId); text(data.verifierId); text(data.verifierVersion); integer(data.attempt); integer(data.leaseEpoch, 1);
  for (const key of ['resultSourceRef', 'sourceDigestBefore', 'sourceDigestAfter', 'commandRef', 'commandDigest', 'environmentRef',
    'environmentDigest', 'stdoutRef', 'stderrRef']) ref(data[key]);
  if (Object.hasOwn(data, 'reasonCode')) text(data.reasonCode);
  if (time(data.endedAt) < time(data.startedAt) || typeof data.stdoutTruncated !== 'boolean' || typeof data.stderrTruncated !== 'boolean') mismatch();
  // Elapsed monotonic duration is independent of the canonical wall timestamps.
  integer(data.durationMs);
  if (Object.hasOwn(data, 'exitCode') !== (data.terminationReason === 'exit') ||
      Object.hasOwn(data, 'signal') !== (data.terminationReason === 'signal')) mismatch();
  if (data.terminationReason === 'exit') integer(data.exitCode, Number.MIN_SAFE_INTEGER);
  if (data.terminationReason === 'signal') text(data.signal);
}

/** The outcome matrix is data, not proof of source identity, death or quiescence.
 * The consumer must independently follow the exact result/containment/integrity refs. */
export function decodeVerificationReceipt(value: unknown): VerificationReceipt {
  const data = closed(value, ['schemaVersion', 'format', 'runId', 'verifierId', 'verifierVersion', 'attempt', 'outcome', 'resultSourceRef',
    'sourceDigestBefore', 'sourceDigestAfter', 'commandRef', 'commandDigest', 'environmentRef', 'environmentDigest', 'startedAt', 'endedAt',
    'durationMs', 'terminationReason', 'stdoutRef', 'stderrRef', 'stdoutTruncated', 'stderrTruncated', 'leaseEpoch', 'containmentEvidenceRef', 'receiptDigest'],
  ['reasonCode', 'exitCode', 'signal', 'violationEvidenceRef', 'violationEvidenceDigest']);
  if (data.format !== 'cliq-verification-receipt-v1' || !['passed', 'assertion_failed', 'infra_failed', 'source_mutation'].includes(data.outcome as string)) mismatch();
  verifierMeasurements(data, data.outcome === 'source_mutation'); ref(data.containmentEvidenceRef);
  if (data.outcome === 'source_mutation') {
    ref(data.violationEvidenceRef); ref(data.violationEvidenceDigest);
  } else {
    if (Object.hasOwn(data, 'violationEvidenceRef') || Object.hasOwn(data, 'violationEvidenceDigest') || data.sourceDigestBefore !== data.sourceDigestAfter) mismatch();
    if (data.outcome === 'infra_failed' ? data.terminationReason === 'exit' : data.terminationReason !== 'exit') mismatch();
    if (data.outcome === 'passed' && data.exitCode !== 0 || data.outcome === 'assertion_failed' && data.exitCode === 0) mismatch();
  }
  digest(data, 'receiptDigest');
  return data as VerificationReceipt;
}

/** This carries measurements only; the original StopIntent, Journal and
 * invocation/parent retirement are independently joined by the consumer. */
export function decodeVerifierStopEvidence(value: unknown): VerifierStopEvidence {
  const data = closed(value, ['schemaVersion', 'format', 'runId', 'verifierId', 'verifierVersion', 'attempt', 'resultSourceRef',
    'sourceDigestBefore', 'sourceDigestAfter', 'commandRef', 'commandDigest', 'environmentRef', 'environmentDigest', 'startedAt', 'endedAt',
    'durationMs', 'terminationReason', 'stdoutRef', 'stderrRef', 'stdoutTruncated', 'stderrTruncated', 'leaseEpoch', 'stopIntentRef', 'retirementRef', 'evidenceDigest'],
  ['reasonCode', 'exitCode', 'signal']);
  if (data.format !== 'cliq-verifier-stop-evidence-v1' || data.sourceDigestBefore !== data.sourceDigestAfter) mismatch();
  verifierMeasurements(data, true); ref(data.stopIntentRef); ref(data.retirementRef); digest(data, 'evidenceDigest');
  return data as VerifierStopEvidence;
}

export function decodeVerifierStopItem(value: unknown): VerifierStopItem {
  const data = closed(value, ['schemaVersion', 'itemId', 'runId', 'kind', 'candidateItemId', 'verifierPlanRef', 'verifierIndex', 'verifierId',
    'opId', 'attempt', 'stopIntent', 'stopIntentRef', 'containmentEvidenceRef', 'createdAt']);
  if (data.schemaVersion !== 1 || data.kind !== 'verifier_stop' ||
      !['cancelled_by_user', 'parent_cancelled', 'budget_exhausted'].includes(data.stopIntent as string)) mismatch();
  for (const key of ['itemId', 'runId', 'candidateItemId', 'verifierId', 'opId']) text(data[key]);
  for (const key of ['verifierPlanRef', 'stopIntentRef', 'containmentEvidenceRef']) ref(data[key]);
  integer(data.verifierIndex, 0, 31); integer(data.attempt); time(data.createdAt);
  return data as VerifierStopItem;
}

/** Item fields only. Its unique eligible Journal/receipt/plan owner is checked by State. */
export function decodeVerifierResultItem(value: unknown): VerifierResultItem {
  const data = closed(value, ['schemaVersion', 'itemId', 'runId', 'kind', 'candidateItemId', 'verifierPlanRef', 'verifierIndex', 'verifierId',
    'opId', 'attempt', 'outcome', 'receiptRef', 'createdAt']);
  if (data.schemaVersion !== 1 || data.kind !== 'verifier_result' ||
      !['passed', 'assertion_failed', 'infra_failed', 'source_mutation'].includes(data.outcome as string)) mismatch();
  for (const key of ['itemId', 'runId', 'candidateItemId', 'verifierId', 'opId']) text(data[key]);
  ref(data.verifierPlanRef); ref(data.receiptRef); integer(data.verifierIndex, 0, 31); integer(data.attempt); time(data.createdAt);
  return data as VerifierResultItem;
}

const repairSuffix = '). Revise the candidate and try again.';
function repairPrefix(verifierId: string): string { return `Verifier ${canonicalJsonBytes(verifierId).toString('utf8')} failed an assertion (exit `; }

/** No stdout/stderr, identity, path or evidence field is permitted in model content. */
export function decodeVerifierRepairModelContent(value: unknown): VerifierRepairModelContentV1 {
  const data = closed(value, ['schemaVersion', 'format', 'verifierId', 'outcome', 'message', 'contentDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-verifier-repair-model-content-v1' || data.outcome !== 'assertion_failed') mismatch();
  const verifierId = text(data.verifierId), message = text(data.message, 4096), prefix = repairPrefix(verifierId);
  if (!message.startsWith(prefix) || !message.endsWith(repairSuffix)) mismatch();
  const decimal = message.slice(prefix.length, -repairSuffix.length), exitCode = Number(decimal);
  if (!Number.isSafeInteger(exitCode) || exitCode === 0 || String(exitCode) !== decimal || canonicalJsonBytes(data).byteLength > 4096) mismatch();
  digest(data, 'contentDigest');
  return data as VerifierRepairModelContentV1;
}

/** Exact RFC redaction of a decoded assertion receipt; receipt authority remains the consumer's job. */
export function verifierRepairModelContent(value: unknown): VerifierRepairModelContentV1 {
  const receipt = decodeVerificationReceipt(value);
  if (receipt.outcome !== 'assertion_failed' || receipt.terminationReason !== 'exit' || receipt.exitCode === 0) mismatch();
  const content = { schemaVersion: 1 as const, format: 'cliq-verifier-repair-model-content-v1' as const, verifierId: receipt.verifierId,
    outcome: 'assertion_failed' as const, message: `${repairPrefix(receipt.verifierId)}${receipt.exitCode}${repairSuffix}`, contentDigest: '' };
  content.contentDigest = digestOmitting(content, 'contentDigest');
  return decodeVerifierRepairModelContent(content);
}

/** Audit references only. Reading and binding their exact artifacts is mandatory at consumption. */
export function decodeVerifierRepairDiagnostic(value: unknown): VerifierRepairDiagnosticV1 {
  const data = closed(value, ['schemaVersion', 'format', 'runId', 'candidateItemId', 'verifierPlanRef', 'verifierId', 'receiptRef', 'receiptDigest',
    'stdoutRef', 'stderrRef', 'redactionAlgorithm', 'modelContentRef', 'modelContentDigest', 'diagnosticDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-verifier-repair-diagnostic-v1' || data.redactionAlgorithm !== 'cliq-verifier-repair-redaction-v1') mismatch();
  text(data.runId); text(data.candidateItemId); text(data.verifierId);
  for (const key of ['verifierPlanRef', 'receiptRef', 'receiptDigest', 'stdoutRef', 'stderrRef', 'modelContentRef', 'modelContentDigest']) ref(data[key]);
  digest(data, 'diagnosticDigest');
  return data as VerifierRepairDiagnosticV1;
}

/** The ordered plan alignment and required/assertion receipt ownership are cross-artifact checks. */
export function decodeRepairDiagnosticItem(value: unknown): RepairDiagnosticItem {
  const data = closed(value, ['schemaVersion', 'itemId', 'runId', 'kind', 'candidateItemId', 'verifierPlanRef',
    'failedVerifierResultItemIds', 'diagnostics', 'repairOrdinal', 'createdAt']);
  if (data.schemaVersion !== 1 || data.kind !== 'repair_diagnostic') mismatch();
  text(data.itemId); text(data.runId); text(data.candidateItemId); ref(data.verifierPlanRef); integer(data.repairOrdinal, 1, 5); time(data.createdAt);
  const ids = array(data.failedVerifierResultItemIds, 32).map(value => text(value)), diagnostics = array(data.diagnostics, 32);
  if (!ids.length || ids.length !== diagnostics.length || new Set(ids).size !== ids.length) mismatch();
  const verifiers = new Set<string>();
  for (const value of diagnostics) {
    const entry = closed(value, ['verifierId', 'diagnosticRef', 'diagnosticDigest', 'modelContentRef', 'modelContentDigest']);
    const verifierId = text(entry.verifierId);
    if (verifiers.has(verifierId)) mismatch();
    verifiers.add(verifierId);
    for (const key of ['diagnosticRef', 'diagnosticDigest', 'modelContentRef', 'modelContentDigest']) ref(entry[key]);
  }
  return data as RepairDiagnosticItem;
}
