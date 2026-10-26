import { encodeControlCheckpointCursor } from '../../kernel/control-wire.js';
/** Inert wire-consumer data. Never a native/Store/installed qualification. */
import { Writable } from 'node:stream';
import { createInstalledControlSession } from '../../control/session.js';
import type { InstalledSupervisorClient } from '../../state/installed-control-client.js';
import type { RunSnapshotV1 } from '../../kernel/types.js';
export const ref = 'a'.repeat(64), at = '2026-10-26T00:00:00.000Z';
export const hello = { method: 'control.hello' as const, protocolVersion: 1 as const, serverBuild: 'inert-client-data',
  supervisorInstanceId: 'supervisor', controlSchemaRange: { min: 1 as const, max: 1 as const }, headlessSchemaRange: { min: 3, max: 3 },
  activeRuntimeBundle: { schemaVersion: 1 as const, runtimeBundleRef: ref, bundleDigest: ref, bundleVersion: 'inert' },
  enabledFeatureIds: ['supervisor.status', 'session.create', 'session.get', 'run.submit', 'run.get', 'run.attach', 'run.cancel', 'run.approve', 'run.input', 'artifact.get'] };
export function runSnapshot(): RunSnapshotV1 { return { schemaVersion: 1, operation: 'agent', latestRunItemSeq: 0, run: {
  id: 'run', sessionId: 'session', specRef: ref, status: 'queued', nextStep: 'agent', frontierRef: ref, revision: 1, leaseEpoch: 0,
  latestCheckpointId: 'checkpoint', budgetReserved: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 },
  budgetConsumed: { modelTokens: 0, costMicros: 0, toolCalls: 0, repairAttempts: 0 }, repairCount: 0, cancelRequested: false,
  createdAt: at, updatedAt: at, deadlineAt: '2026-10-27T00:00:00.000Z' } }; }
export const sessionSnapshot = () => ({ schemaVersion: 1 as const, session: { schemaVersion: 1 as const, id: 'session', workspaceIdentityRef: ref,
  contextRevision: 7, latestItemSeq: 0, contextProjectionRef: ref, createdAt: at, updatedAt: at } });
export function protocolClient(overrides: Record<string, unknown> = {}) {
  let closed = 0; const calls: Array<{ method: string; request: any }> = [];
  const client = { hello, close: async () => { closed++; },
    'session.create': async () => ({ protocolVersion: 1, ok: true, result: { method: 'session.create', snapshot: sessionSnapshot() } }),
    'session.get': async () => ({ protocolVersion: 1, ok: true, result: { method: 'session.get', snapshot: sessionSnapshot(), items: [], highWaterItemSeq: 0, nextItemSeq: 0 } }),
    'run.submit': async () => ({ protocolVersion: 1, ok: true, result: { method: 'run.submit', snapshot: runSnapshot() } }),
    'run.get': async () => ({ protocolVersion: 1, ok: true, result: { method: 'run.get', snapshot: runSnapshot(), items: [], journal: [], checkpoints: [],
      highWaterItemSeq: 0, highWaterJournalSeq: 0, highWaterCheckpointCursor: encodeControlCheckpointCursor('run', { createdAt: at, checkpointId: 'checkpoint' }), nextItemSeq: 0, nextJournalSeq: 0 } }),
    ...overrides } as Record<string, any>;
  for (const method of hello.enabledFeatureIds) {
    const original = client[method];
    if (typeof original === 'function') client[method] = async (request: any) => { calls.push({ method, request }); return original(request); };
  }
  return { session: createInstalledControlSession(client as InstalledSupervisorClient), calls, closed: () => closed };
}
export function outputStream() {
  const chunks: Buffer[] = [];
  const stream = new Writable({ write(chunk, _encoding, done) { chunks.push(Buffer.from(chunk)); done(); } });
  return { stream, bytes: () => Buffer.concat(chunks), text: () => Buffer.concat(chunks).toString('utf8') };
}
