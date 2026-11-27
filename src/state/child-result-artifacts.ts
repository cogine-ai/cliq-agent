// Deterministic child output data. No Store, recovery traversal, owner, native
// scope or settlement is reachable through this module.
import { canonicalSha256 } from '../kernel/canonical.js';
import { normalizeBoundedText } from '../kernel/identity.js';
import type { ChildPatchManifest, ChildResultModelContentV1 } from '../kernel/children.js';
import type { WorkspaceDiffV1 } from '../kernel/result.js';
import { assertControlWireJson, controlWireRecord } from '../kernel/control-wire-data.js';
import { immutableSnapshot } from '../model/immutable.js';
import { KernelStorageError } from './errors.js';
import { decodeWorkspaceDiff } from './result-artifacts.js';

function invalid(message: string): never { throw new KernelStorageError('RECOVERY_REQUIRED', `child result data ${message}`); }

/** Deterministic data only, shared with the sole child terminal transaction.
 * Its caller must validate the complete original B/S source and diff graph;
 * this function does not prove execution, retirement or patch permission. */
export function childPatchManifest(childRunId: string, diff: WorkspaceDiffV1): Readonly<ChildPatchManifest> {
  if (normalizeBoundedText(childRunId, 1, 128) !== childRunId) invalid('Run id is not canonical');
  assertControlWireJson(diff);
  const checked = decodeWorkspaceDiff(diff);
  const operations: ChildPatchManifest['operations'] = checked.operations.map(operation => {
    if (operation.kind === 'delete') return { kind: 'delete', path: operation.path,
      expectedEntryDigest: canonicalSha256(operation.before) };
    const resultEntryDigest = canonicalSha256(operation.after);
    if (operation.after.kind === 'symlink') return { kind: 'symlink', path: operation.path,
      ...(operation.kind === 'modify' ? { expectedEntryDigest: canonicalSha256(operation.before) } : {}), resultEntryDigest };
    if (operation.kind === 'add') return { kind: 'add', path: operation.path, resultEntryDigest };
    const before = operation.before, after = operation.after;
    const kind = before.kind === 'file' && after.kind === 'file' && before.blobRef === after.blobRef &&
      before.size === after.size && before.mode !== after.mode ? 'mode' as const : 'modify' as const;
    return { kind, path: operation.path, expectedEntryDigest: canonicalSha256(before), resultEntryDigest };
  });
  const core = { schemaVersion: 1 as const, childRunId, admittedForkBaseRef: checked.baseSourceRef,
    resultSourceRef: checked.resultSourceRef, diffRef: canonicalSha256(checked), operations };
  return immutableSnapshot({ ...core, patchDigest: canonicalSha256(core) });
}

/** Closed model-visible child output. Control, capability, patch and terminal
 * diagnostic bodies remain separate retained artifacts. */
export function childResultModelContent(childRunId: string, mode: 'read_only' | 'mutating',
  content: ChildResultModelContentV1['content']): Readonly<ChildResultModelContentV1> {
  if (normalizeBoundedText(childRunId, 1, 128) !== childRunId || !['read_only', 'mutating'].includes(mode))
    invalid('model content identity is invalid');
  assertControlWireJson(content);
  if (content.status === 'succeeded' || content.status === 'completed_unverified') {
    controlWireRecord(content, ['status', 'summary']);
    if (typeof content.summary !== 'string' || !content.summary.trim()) invalid('successful model content summary is empty');
  } else {
    const failed = controlWireRecord(content, ['status', 'terminalReason']);
    if (!['failed', 'cancelled'].includes(content.status) || typeof failed.terminalReason !== 'string' || !['verification_failed', 'verifier_infrastructure_failed',
      'verifier_mutated_source', 'budget_exhausted', 'runtime_failed', 'cancelled_by_user', 'parent_cancelled'].includes(failed.terminalReason))
      invalid('failed model content reason is invalid');
  }
  const core = { schemaVersion: 1 as const, format: 'cliq-child-result-model-content-v1' as const, childRunId, mode, content };
  return immutableSnapshot({ ...core, contentDigest: canonicalSha256(core) });
}
