import { canonicalSha256 } from '../kernel/canonical.js';
import { assertArtifactRef, digestOmitting, normalizeBoundedText, parseCanonicalTime, sha256Bytes } from '../kernel/identity.js';
import type { FinalCandidateItem, VerifierPlan, VerificationClosureV1, RunResult, WorkspaceDiffV1 } from '../kernel/result.js';
import type { WorkspaceEntry } from '../kernel/types.js';
import { KernelStorageError } from './errors.js';

function mismatch(message: string): never { throw new KernelStorageError('ARTIFACT_MISMATCH', message); }
function closed(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      required.some(key => !Object.hasOwn(value, key)) ||
      Reflect.ownKeys(value).some(key => typeof key !== 'string' || !required.includes(key) && !optional.includes(key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(property => !Object.hasOwn(property, 'value') || !property.enumerable))
    mismatch('result artifact has an invalid closed shape');
  return value as Record<string, unknown>;
}
function text(value: unknown, maximum = 128): string {
  try {
    if (typeof value !== 'string' || normalizeBoundedText(value, 1, maximum) !== value) throw new TypeError();
    return value;
  } catch { return mismatch('result artifact text is not canonical or bounded'); }
}
function ref(value: unknown): string {
  if (typeof value !== 'string') mismatch('result artifact reference is invalid');
  try { assertArtifactRef(value); } catch { mismatch('result artifact reference is invalid'); }
  return value;
}
function integer(value: unknown, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum)
    mismatch('result artifact integer is outside its range');
  return value;
}
function list(value: unknown, maximum = 32): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) mismatch('result artifact list exceeds its bound');
  const properties = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(properties).length !== value.length + 1 ||
      Array.from({ length: value.length }, (_, index) => properties[String(index)]).some(property =>
        !property || !Object.hasOwn(property, 'value') || !property.enumerable)) mismatch('result artifact list is not dense enumerable data');
  return value;
}
function entryPath(value: unknown): string {
  const result = text(value, 4096);
  if (result.includes('\\') || result.split('/').some(part => !part || part === '.' || part === '..' ||
      Buffer.byteLength(part) > 255 || part.toLowerCase() === '.git'))
    mismatch('result diff path is not a canonical root-relative source path');
  return result;
}
function workspaceEntry(value: unknown, path: string): WorkspaceEntry {
  const entry = closed(value, ['path', 'kind', 'mode'], ['size', 'blobRef', 'target', 'targetDigest']);
  if (entryPath(entry.path) !== path) mismatch('result diff entry belongs to another path');
  if (entry.kind === 'directory') {
    closed(entry, ['path', 'kind', 'mode']);
    if (entry.mode !== 0o755) mismatch('result directory mode is not normalized');
  } else if (entry.kind === 'file') {
    closed(entry, ['path', 'kind', 'mode', 'size', 'blobRef']);
    if (entry.mode !== 0o644 && entry.mode !== 0o755) mismatch('result file mode is not normalized');
    integer(entry.size); ref(entry.blobRef);
  } else if (entry.kind === 'symlink') {
    closed(entry, ['path', 'kind', 'mode', 'target', 'targetDigest']);
    const target = text(entry.target, 4096);
    if (entry.mode !== 0o777 || target.startsWith('/') || target.includes('\\') || sha256Bytes(Buffer.from(target)) !== ref(entry.targetDigest))
      mismatch('result symlink target, mode or digest is invalid');
    const resolved = path.split('/').slice(0, -1);
    for (const part of target.split('/')) {
      if (!part || part === '.') continue;
      if (part === '..') {
        if (!resolved.length) mismatch('result symlink escapes the source root');
        resolved.pop();
      } else {
        if (part.toLowerCase() === '.git') mismatch('result symlink targets Git metadata');
        resolved.push(part);
      }
    }
  } else mismatch('result diff entry kind is invalid');
  return entry as WorkspaceEntry;
}

/** Closed data only. The owning reducer/recovery reader revalidates the exact
 * producer item, source manifests, diff and summary through their CAS refs. */
export function decodeFinalCandidateItem(value: unknown): FinalCandidateItem {
  const item = closed(value, ['schemaVersion', 'itemId', 'runId', 'kind', 'operation', 'producingItemId',
    'baseSourceRef', 'resultSourceRef', 'diffRef', 'summaryRef', 'sourceDigest', 'diffDigest', 'createdAt'], ['producingOpId']);
  if (item.schemaVersion !== 1 || item.kind !== 'final_candidate') mismatch('final candidate has the wrong schema');
  text(item.itemId); text(item.runId); text(item.producingItemId);
  for (const key of ['baseSourceRef', 'resultSourceRef', 'diffRef', 'summaryRef', 'sourceDigest', 'diffDigest']) ref(item[key]);
  try { parseCanonicalTime(text(item.createdAt)); } catch { mismatch('final candidate time is invalid'); }
  if (item.operation === 'agent') text(item.producingOpId);
  else if (item.operation !== 'delivery' || Object.hasOwn(item, 'producingOpId')) mismatch('final candidate producer branch is invalid');
  return item as FinalCandidateItem;
}

/** Shape, canonical entry identities, path ordering and the self-omitting JCS
 * digest; exact base/result union-path comparison is enforced by its consumer. */
export function decodeWorkspaceDiff(value: unknown): WorkspaceDiffV1 {
  const diff = closed(value, ['schemaVersion', 'format', 'baseSourceRef', 'resultSourceRef', 'operations', 'diffDigest']);
  if (diff.schemaVersion !== 1 || diff.format !== 'cliq-workspace-diff-v1') mismatch('workspace diff has the wrong schema');
  ref(diff.baseSourceRef); ref(diff.resultSourceRef); ref(diff.diffDigest);
  if (!Array.isArray(diff.operations)) mismatch('workspace diff operations must be an array');
  let previous: string | undefined;
  for (const value of diff.operations) {
    const operation = closed(value, ['path', 'kind'], ['before', 'after']);
    const path = entryPath(operation.path);
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(path)) >= 0)
      mismatch('workspace diff paths are not unique and byte-sorted');
    previous = path;
    if (operation.kind === 'add') {
      closed(operation, ['path', 'kind', 'after']); workspaceEntry(operation.after, path);
    } else if (operation.kind === 'delete') {
      closed(operation, ['path', 'kind', 'before']); workspaceEntry(operation.before, path);
    } else if (operation.kind === 'modify') {
      closed(operation, ['path', 'kind', 'before', 'after']);
      const before = workspaceEntry(operation.before, path), after = workspaceEntry(operation.after, path);
      if (canonicalSha256(before) === canonicalSha256(after)) mismatch('workspace diff modifies an unchanged entry');
    } else mismatch('workspace diff operation kind is invalid');
  }
  if (digestOmitting(diff, 'diffDigest') !== diff.diffDigest) mismatch('workspace diff digest does not rehash');
  return diff as WorkspaceDiffV1;
}

/** No execution or verification authority is created by decoding this plan. */
export function decodeVerifierPlan(value: unknown): VerifierPlan {
  const plan = closed(value, ['schemaVersion', 'runId', 'candidateItemId', 'resultSourceRef', 'verifierSpecRef',
    'verifierSpecDigest', 'entries', 'planDigest'], ['dependencyPlanRef']);
  if (plan.schemaVersion !== 1) mismatch('verifier plan has the wrong schema');
  text(plan.runId); text(plan.candidateItemId);
  for (const key of ['resultSourceRef', 'verifierSpecRef', 'verifierSpecDigest', 'planDigest']) ref(plan[key]);
  if (Object.hasOwn(plan, 'dependencyPlanRef')) ref(plan.dependencyPlanRef);
  if (!Array.isArray(plan.entries) || plan.entries.length > 32) mismatch('verifier plan entries are outside their bound');
  const ids = new Set<string>();
  for (const [index, value] of plan.entries.entries()) {
    const entry = closed(value, ['index', 'verifierId', 'verifierSpecDigest', 'verifierEntryDigest', 'commandRef',
      'commandDigest', 'environmentRef', 'environmentDigest', 'required', 'maxAttempts']);
    const id = text(entry.verifierId);
    if (integer(entry.index) !== index || ids.has(id)) mismatch('verifier plan entries are not contiguous and unique');
    ids.add(id);
    for (const key of ['verifierSpecDigest', 'verifierEntryDigest', 'commandRef', 'commandDigest', 'environmentRef', 'environmentDigest']) ref(entry[key]);
    if (entry.verifierSpecDigest !== plan.verifierSpecDigest || typeof entry.required !== 'boolean')
      mismatch('verifier plan entry differs from its frozen spec');
    integer(entry.maxAttempts, 1);
  }
  if (digestOmitting(plan, 'planDigest') !== plan.planDigest) mismatch('verifier plan digest does not rehash');
  return plan as VerifierPlan;
}

/** Local no-dependency branches only. Decoding creates neither a receipt nor
 * execution authority; the result consumer rederives every ordered disposition
 * from its owning highest eligible Journal/result/receipt graph. */
export function decodeVerificationClosure(value: unknown): VerificationClosureV1 {
  const closure = closed(value, ['schemaVersion', 'format', 'runId', 'candidateItemId', 'resultSourceRef',
    'verifierPlanRef', 'dependency', 'verification', 'closureDigest', 'createdAt']);
  if (closure.schemaVersion !== 1 || closure.format !== 'cliq-verification-closure-v1') mismatch('verification closure has the wrong schema');
  text(closure.runId); text(closure.candidateItemId);
  for (const key of ['resultSourceRef', 'verifierPlanRef', 'closureDigest']) ref(closure[key]);
  try { parseCanonicalTime(text(closure.createdAt)); } catch { mismatch('verification closure time is invalid'); }
  const dependency = closed(closure.dependency, ['kind']);
  const verification = closed(closure.verification, ['kind', 'outcome', 'entries'], ['unverifiedConsentRef']);
  if (dependency.kind !== 'none' || verification.kind !== 'local' || !['verified', 'unverified'].includes(String(verification.outcome)))
    mismatch('verification closure branch is not implemented');
  const entries = list(verification.entries), verifierIds = new Set<string>(), resultItems = new Set<string>(), receipts = new Set<string>(), ops = new Set<string>();
  let required = 0, specDigest: string | undefined;
  for (const [index, value] of entries.entries()) {
    const entry = closed(value, ['verifierIndex', 'verifierId', 'verifierSpecDigest', 'verifierEntryDigest', 'required', 'disposition']);
    const id = text(entry.verifierId), spec = ref(entry.verifierSpecDigest); ref(entry.verifierEntryDigest);
    if (integer(entry.verifierIndex) !== index || verifierIds.has(id) || typeof entry.required !== 'boolean' || specDigest !== undefined && specDigest !== spec)
      mismatch('verification closure entries are not one ordered frozen spec');
    verifierIds.add(id); specDigest = spec;
    const kind = (entry.disposition as { kind?: unknown } | null)?.kind;
    const disposition = closed(entry.disposition, ['kind', 'verifierResultItemId', 'opId', 'attempt', 'receiptRef',
      ...(kind === 'passed' ? ['completedJournalSeq'] : ['outcome', 'terminalJournalSeq'])]);
    if (kind !== 'passed' && (kind !== 'advisory_nonpassing' || entry.required ||
        !['assertion_failed', 'infra_failed'].includes(String(disposition.outcome)))) mismatch('verification closure disposition is not an eligible local result');
    const itemId = text(disposition.verifierResultItemId), opId = text(disposition.opId), receiptRef = ref(disposition.receiptRef);
    integer(disposition.attempt); integer(disposition[kind === 'passed' ? 'completedJournalSeq' : 'terminalJournalSeq'], 1);
    if (resultItems.has(itemId) || receipts.has(receiptRef) || ops.has(opId)) mismatch('verification closure reuses one result, receipt or operation');
    resultItems.add(itemId); receipts.add(receiptRef); ops.add(opId);
    if (entry.required) required++;
  }
  if (verification.outcome === 'verified') {
    if (!required || Object.hasOwn(verification, 'unverifiedConsentRef')) mismatch('verified closure must have a required pass and no unverified consent');
  } else {
    if (required) mismatch('unverified closure cannot satisfy a required gate');
    ref(verification.unverifiedConsentRef);
  }
  if (digestOmitting(closure, 'closureDigest') !== closure.closureDigest) mismatch('verification closure digest does not rehash');
  return closure as VerificationClosureV1;
}

/** RunResult intentionally has neither a format nor a self-digest. Its CAS
 * ref is its identity, and the consumer binds every field to the candidate. */
export function decodeRunResult(value: unknown): RunResult {
  const result = closed(value, ['schemaVersion', 'runId', 'baseSourceRef', 'resultSourceRef', 'diffRef',
    'verificationClosureRef', 'verificationReceiptRefs', 'summaryRef', 'createdAt']);
  if (result.schemaVersion !== 1) mismatch('Run result has the wrong schema');
  text(result.runId);
  for (const key of ['baseSourceRef', 'resultSourceRef', 'diffRef', 'verificationClosureRef', 'summaryRef']) ref(result[key]);
  const receipts = list(result.verificationReceiptRefs).map(ref);
  if (new Set(receipts).size !== receipts.length) mismatch('Run result reuses a verification receipt');
  try { parseCanonicalTime(text(result.createdAt)); } catch { mismatch('Run result time is invalid'); }
  return result as RunResult;
}
