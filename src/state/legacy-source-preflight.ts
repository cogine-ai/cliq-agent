// Read-only checks over the native holder's fixed source inventory. These are
// retained data, never process death, quiescence, recovery or write authority.
import { controlWireInteger, controlWireRecord, controlWireText } from '../kernel/control-wire-data.js';
import { normalizeCanonicalText } from '../kernel/canonical.js';
import { parseCanonicalTime } from '../kernel/identity.js';
import type { LegacySessionSourceItem, LegacySessionPreflightControls } from './legacy-source-stream.js';
import { applyRecordId, abortRecordId } from '../workspace/transactions/types.js';
import { KernelStorageError } from './errors.js';

type Data = Record<string, unknown>;
type TerminalTransaction = { id: string; sessionId: string; state: 'applied' | 'aborted';
  apply?: string; abort?: string; recordObserved: boolean };
const METADATA_BYTES = 256 * 1024 * 1024;
const SAFE = /^[A-Za-z0-9_-]{1,128}$/u;
function invalid(): never { throw new TypeError('Legacy control source differs from its fixed retained-data profile'); }
function safe(value: unknown): string { const text = controlWireText(value); if (!SAFE.test(text)) return invalid(); return text; }
function time(value: unknown, preparedAt: string): string {
  const text = controlWireText(value); if (parseCanonicalTime(text) > parseCanonicalTime(preparedAt)) return invalid(); return text;
}
function unresolved(): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', 'Legacy transactions require their original recovery or explicit abort before migration');
}
function rawText(value: unknown, maximum = 4096): void {
  if (typeof value !== 'string' || Buffer.byteLength(value) > maximum) return invalid();
  normalizeCanonicalText(value); // Validate scalars/NUL; preserve original path/prose bytes.
}
function list(value: unknown): void { if (!Array.isArray(value)) return invalid(); for (const item of value) rawText(item); }
function error(value: unknown, path: boolean): void {
  const data = controlWireRecord(value, ['stage', 'message'], path ? ['path'] : []);
  rawText(data.stage, 128); rawText(data.message, 262_144);
  if (Object.hasOwn(data, 'path')) rawText(data.path);
}
function workspaceEntry(value: unknown, id: string, preparedAt: string, recent: boolean): void {
  const data = controlWireRecord(value, recent ? ['version', 'workspaceId', 'workspaceRealPath', 'recentSessions', 'lastSeenAt'] :
    ['workspaceId', 'workspaceRealPath', 'lastSeenAt'], recent ? ['gitRootRealPath', 'activeSessionId', 'activeSessionPath', 'migratedFrom'] :
    ['gitRootRealPath', 'activeSessionId', 'activeSessionPath']);
  if (recent && data.version !== 1 || safe(data.workspaceId) !== id) return invalid();
  rawText(data.workspaceRealPath); time(data.lastSeenAt, preparedAt);
  if ((data.activeSessionId === undefined) !== (data.activeSessionPath === undefined)) return invalid();
  if (data.activeSessionId !== undefined) { safe(data.activeSessionId); rawText(data.activeSessionPath); }
  if (data.gitRootRealPath !== undefined) rawText(data.gitRootRealPath);
  if (recent) {
    if (!Array.isArray(data.recentSessions) || data.recentSessions.length > 50) return invalid();
    const ids = new Set<string>();
    for (const raw of data.recentSessions) {
      const entry = controlWireRecord(raw, ['id', 'path', 'createdAt', 'updatedAt']), id = safe(entry.id);
      if (ids.has(id)) return invalid(); ids.add(id); rawText(entry.path);
      if (time(entry.createdAt, preparedAt) > time(entry.updatedAt, preparedAt)) return invalid();
    }
    if (data.migratedFrom !== undefined) { const source = controlWireRecord(data.migratedFrom, ['path', 'migratedAt']);
      rawText(source.path); time(source.migratedAt, preparedAt); }
  }
}

/** At most one small closed record per actual transaction is retained, not
 * full Session controls or source JSON trees. One cumulative metadata budget
 * covers this entire inventory; it is never reset by source/batch/pass. */
export class LegacyControlPreflight {
  private readonly transactions = new Map<string, TerminalTransaction>();
  private metadataBytes = 0;
  private complete = false;
  constructor(private readonly preparedAt: string) { parseCanonicalTime(preparedAt); }
  private current(): void { if (this.complete) throw new TypeError('Legacy preflight already completed'); }
  private transaction(id: string): TerminalTransaction {
    const transaction = this.transactions.get(id); if (!transaction) return unresolved(); return transaction;
  }
  source(path: string, value: unknown): void {
    this.current();
    if (path === 'state.json') {
      // The much older monolithic `messages` carrier has no stable source
      // Session identity/workspace. It is explicitly unsupported, not silently
      // normalized with random ids/current time or accepted as an empty store.
      const data = controlWireRecord(value, ['version', 'updatedAt']);
      if (data.version !== 1) return invalid(); time(data.updatedAt, this.preparedAt); return;
    }
    if (path === 'workspace-index.json') {
      const data = controlWireRecord(value, ['version', 'workspaces']);
      if (data.version !== 1 || !data.workspaces || typeof data.workspaces !== 'object' || Array.isArray(data.workspaces)) return invalid();
      for (const [id, entry] of Object.entries(data.workspaces)) workspaceEntry(entry, safe(id), this.preparedAt, false);
      return;
    }
    const workspace = /^workspaces\/([A-Za-z0-9_-]{1,128})\/state\.json$/u.exec(path);
    if (workspace) { workspaceEntry(value, workspace[1]!, this.preparedAt, true); return; }
    const tx = /^tx\/(tx_[A-Za-z0-9_-]{1,124})\/(state|apply-progress|abort-progress|recovery)\.json$/u.exec(path);
    if (!tx) return invalid();
    const id = tx[1]!, kind = tx[2]!;
    if (kind === 'state') {
      const data = controlWireRecord(value, ['id', 'kind', 'state', 'workspaceId', 'sessionId', 'workspaceRealPath', 'createdAt', 'updatedAt'],
        ['diffSummary', 'diffArtifactPath', 'validators', 'blockingFailures', 'overridesApplied', 'ghostSnapshotId', 'error']);
      if (data.id !== id || data.kind !== 'edit' || !['applied', 'aborted'].includes(data.state as string)) return unresolved();
      safe(data.workspaceId); const sessionId = safe(data.sessionId); rawText(data.workspaceRealPath);
      if (time(data.createdAt, this.preparedAt) > time(data.updatedAt, this.preparedAt)) return invalid();
      if (this.transactions.has(id)) return invalid();
      // The estimate intentionally includes fixed Map/object/string overhead.
      // The native inventory independently accounts for its own full metadata.
      this.metadataBytes += 512 + 2 * (id.length + sessionId.length);
      if (this.metadataBytes > METADATA_BYTES) throw new RangeError('Legacy transaction metadata exceeds the fixed whole-import profile');
      this.transactions.set(id, { id, sessionId, state: data.state as 'applied' | 'aborted', recordObserved: false });
      if (data.diffArtifactPath !== undefined) rawText(data.diffArtifactPath);
      if (data.ghostSnapshotId !== undefined) safe(data.ghostSnapshotId);
      if (data.blockingFailures !== undefined) list(data.blockingFailures);
      if (data.error !== undefined) error(data.error, false);
      if (data.diffSummary !== undefined) {
        const diff = controlWireRecord(data.diffSummary, ['filesChanged', 'additions', 'deletions', 'creates', 'modifies', 'deletes']);
        for (const key of ['filesChanged', 'additions', 'deletions']) controlWireInteger(diff[key]);
        for (const key of ['creates', 'modifies', 'deletes']) list(diff[key]);
      }
      if (data.validators !== undefined) {
        if (!Array.isArray(data.validators)) return invalid();
        for (const raw of data.validators) {
          const validator = controlWireRecord(raw, ['name', 'severity', 'status', 'durationMs']);
          rawText(validator.name, 128);
          if (typeof validator.durationMs !== 'number' || !Number.isFinite(validator.durationMs) || validator.durationMs < 0) return invalid();
          if (!['blocking', 'advisory'].includes(validator.severity as string) || !['pass', 'fail', 'error'].includes(validator.status as string)) return invalid();
        }
      }
      if (data.overridesApplied !== undefined) {
        if (!Array.isArray(data.overridesApplied)) return invalid();
        for (const raw of data.overridesApplied) { const override = controlWireRecord(raw, ['validatorName', 'by', 'ts'], ['reason']);
          rawText(override.validatorName, 128); rawText(override.by, 128); time(override.ts, this.preparedAt);
          if (override.reason !== undefined) rawText(override.reason, 262_144); }
      }
      return;
    }
    const transaction = this.transaction(id);
    if (kind === 'apply-progress') {
      const data = controlWireRecord(value, ['phase', 'ghostSnapshotId', 'startedAt', 'filesPlanned', 'filesWritten'], ['error']);
      if (transaction.apply !== undefined) return invalid();
      if (data.phase !== 'apply-finalized' && !(data.phase === 'apply-failed-partial' && transaction.state === 'aborted')) return unresolved();
      safe(data.ghostSnapshotId); time(data.startedAt, this.preparedAt); list(data.filesPlanned); list(data.filesWritten);
      if (data.error !== undefined) error(data.error, true); transaction.apply = data.phase as string;
    } else if (kind === 'abort-progress') {
      const data = controlWireRecord(value, ['phase', 'reason', 'startedAt', 'ts']);
      if (transaction.abort !== undefined || data.phase !== 'aborted' || transaction.state !== 'aborted') return unresolved();
      if (!['validator-fail', 'user-abort', 'apply-error', 'apply-conflict', 'staging-error',
        'apply-failed-partial-restored', 'apply-failed-partial-kept'].includes(data.reason as string)) return invalid();
      if (time(data.startedAt, this.preparedAt) > time(data.ts, this.preparedAt)) return invalid(); transaction.abort = 'aborted';
    } else {
      const data = controlWireRecord(value, ['txId', 'action', 'ts'], ['warning']);
      if (data.txId !== id || !['apply-pending-reverted', 'apply-pending-orphan-discarded', 'apply-writing-partial',
        'apply-committed-stage-c', 'apply-finalized-state', 'abort-aborting-resumed', 'abort-finalized-state', 'no-op'].includes(data.action as string)) return invalid();
      time(data.ts, this.preparedAt); if (data.warning !== undefined) rawText(data.warning, 262_144);
    }
  }
  sessionItem(sessionId: string, item: LegacySessionSourceItem): void {
    this.current(); if (item.kind !== 'legacy_record') return;
    const data = item.value as Data;
    if (data.kind !== 'tx-applied' && data.kind !== 'tx-aborted') return;
    const meta = data.meta;
    if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return invalid();
    const txId = safe((meta as Data).txId), actual = this.transactions.get(txId);
    // Missing historical transaction bytes remain historical user context.
    // A retained real transaction must nevertheless close against its exact
    // Session's matching final record, not an unrelated pasted label.
    if (!actual) return;
    const recordId = actual.state === 'applied' ? applyRecordId(txId) : abortRecordId(txId);
    if (actual.sessionId !== sessionId || data.kind !== `tx-${actual.state}` || data.id !== recordId || actual.recordObserved) return unresolved();
    actual.recordObserved = true;
  }
  sessionControls(controls: LegacySessionPreflightControls): void {
    this.current(); if (controls.activeTxId !== undefined) return unresolved();
  }
  finish(): void {
    this.current();
    for (const transaction of this.transactions.values()) if (!transaction.recordObserved ||
      transaction.state === 'applied' && transaction.apply !== 'apply-finalized' ||
      transaction.state === 'aborted' && transaction.abort !== 'aborted') return unresolved();
    this.complete = true; this.transactions.clear();
  }
}
