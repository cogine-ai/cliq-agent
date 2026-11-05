import test from 'node:test';
import assert from 'node:assert/strict';
import { LegacyControlPreflight } from './legacy-source-preflight.js';
import { KernelStorageError } from './errors.js';

const at = '2026-10-02T00:00:00.000Z', createdAt = '2026-10-01T00:00:00.000Z';
function state(status: string) { return { id: 'tx_old', kind: 'edit', state: status, workspaceId: 'workspace', sessionId: 'old_session',
  workspaceRealPath: '/old/Cafe\u0301', createdAt, updatedAt: at }; }
function finalRecord(kind: 'tx-applied' | 'tx-aborted') { return { kind: 'legacy_record' as const, ordinal: 0,
  value: { id: kind === 'tx-applied' ? 'txrec_apply_tx_old' : 'txrec_abort_tx_old', ts: at, kind, role: 'user',
    content: 'Historical transaction', meta: { txId: 'tx_old' } } }; }
const recovery = (operation: () => unknown) => assert.throws(operation,
  error => error instanceof KernelStorageError && error.code === 'RECOVERY_REQUIRED');

test('complete original applied/aborted rows and final Session records pass without recovering or restoring execution', () => {
  for (const status of ['applied', 'aborted'] as const) {
    const preflight = new LegacyControlPreflight(at);
    preflight.source('state.json', { version: 1, updatedAt: at });
    preflight.source('tx/tx_old/state.json', state(status));
    preflight.source(`tx/tx_old/${status === 'applied' ? 'apply' : 'abort'}-progress.json`, status === 'applied' ?
      { phase: 'apply-finalized', ghostSnapshotId: 'old_ghost', startedAt: createdAt, filesPlanned: ['Cafe\u0301.txt'], filesWritten: ['Cafe\u0301.txt'] } :
      { phase: 'aborted', reason: 'user-abort', startedAt: createdAt, ts: at });
    preflight.sessionItem('old_session', finalRecord(status === 'applied' ? 'tx-applied' : 'tx-aborted'));
    preflight.sessionControls({ lifecycle: { status: 'idle', turn: 3 } }); preflight.finish();
    assert.throws(() => preflight.finish(), TypeError);
  }
});
test('pending, partial, mismatched and incomplete terminal spines remain recovery-required', () => {
  for (const status of ['staging', 'finalized', 'validated', 'approved', 'applied-partial']) {
    const preflight = new LegacyControlPreflight(at); recovery(() => preflight.source('tx/tx_old/state.json', state(status)));
  }
  const missing = new LegacyControlPreflight(at); missing.source('tx/tx_old/state.json', state('applied')); recovery(() => missing.finish());
  const wrong = new LegacyControlPreflight(at); wrong.source('tx/tx_old/state.json', state('applied'));
  recovery(() => wrong.sessionItem('different_session', finalRecord('tx-applied')));
  const active = new LegacyControlPreflight(at); recovery(() => active.sessionControls({ activeTxId: 'tx_old', lifecycle: { status: 'running', turn: 1 } }));
  const writing = new LegacyControlPreflight(at); writing.source('tx/tx_old/state.json', state('applied'));
  recovery(() => writing.source('tx/tx_old/apply-progress.json', { phase: 'apply-writing', ghostSnapshotId: 'ghost', startedAt: at, filesPlanned: [], filesWritten: [] }));
});
test('closed metadata accepts real historical NFD paths but refuses unknown/malformed control profiles', () => {
  const preflight = new LegacyControlPreflight(at), workspace = { workspaceId: 'workspace', workspaceRealPath: '/old/Cafe\u0301', lastSeenAt: at };
  preflight.source('workspace-index.json', { version: 1, workspaces: { workspace } });
  preflight.source('workspaces/workspace/state.json', { version: 1, ...workspace, recentSessions: [] }); preflight.finish();
  for (const [path, value] of [['state.json', { messages: [] }], ['workspace-index.json', { version: 1, workspaces: {}, extra: true }],
    ['workspaces/workspace/state.json', { version: 1, ...workspace, recentSessions: [], activeTxId: 'tx_old' }],
    ['unknown.json', {}]] as const)
    assert.throws(() => new LegacyControlPreflight(at).source(path, value));
});
