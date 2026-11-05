import type { RunSnapshotV1, Session } from '../kernel/types.js';
import type { InstalledSessionContextPresentation } from '../control/session-context.js';
import type { InstalledControlRequestV1, InstalledControlResponseFor, InstalledControlFeature } from '../control/v1.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ClientUpdate } from './application.js';

export type ClientView = Readonly<{
  connection: 'connected' | 'disconnected' | 'closed';
  run?: RunSnapshotV1; session?: Session;
  eventSeq: number; lines: readonly string[];
  pending?: Readonly<{ method: string; requestId: string; admissionKey?: string }>;
  refusal?: Readonly<{ code: string; messageCode: string }>;
}>;
export const initialClientView = (): ClientView => Object.freeze({ connection: 'connected', eventSeq: 0, lines: [] });
/** Repository/tool text cannot issue terminal controls. Newlines and tabs
 * remain text layout; escape sequences, C0/C1 and bidi controls are visible. */
export function terminalText(value: string): string {
  return value.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
export function runHeadline(snapshot: RunSnapshotV1): string {
  const run = snapshot.run;
  if (run.status === 'succeeded') return 'Verified';
  if (run.status === 'completed_unverified') return 'Completed · unverified';
  if (run.status === 'failed' || run.status === 'cancelled') return `${run.status} · ${run.terminalReason}`;
  if (run.stopIntentRef || run.cancelRequested) return 'Stop requested · awaiting completion';
  if (run.status === 'waiting') return `Waiting · ${run.waitingReason}`;
  return run.status === 'queued' ? 'Queued' : `Running · ${run.nextStep}`;
}
export function humanResponse(request: InstalledControlRequestV1, response: InstalledControlResponseFor<InstalledControlFeature>): readonly string[] {
  if (!response.ok && request.method === 'run.submit' && response.method === 'run.submit' &&
      response.error.code === 'INVALID_REQUEST' && response.error.retryable === false &&
      response.error.messageCode === 'session.context_requires_compaction' && response.error.issues.length === 1 &&
      response.error.issues[0]?.path === 'sessionId' && response.error.issues[0].issueCode === 'session_context_requires_compaction') {
    return [`Session ${terminalText(JSON.stringify(request.sessionId))} needs compaction before a new Run can be admitted.`,
      'Use session show to inspect complete context boundaries, then session compact with a summary of a complete raw range.',
      'After compaction, submit a new Run.'];
  }
  if (!response.ok) return [`${response.error.code}: ${response.error.messageCode}`, ...(response.error.code === 'EVENT_CURSOR_EXPIRED'
    ? [`Display history before event ${response.error.earliestEventSeq} is unavailable. Snapshot revision ${response.error.snapshot.run.revision}.`,
      `Attach explicitly with --after ${response.error.earliestEventSeq - 1} to read retained events.`] : [])];
  const value = response.result;
  if ('snapshot' in value) {
    if ('run' in value.snapshot) {
      const run = value.snapshot.run, lines = [run.id, runHeadline(value.snapshot)];
      if (run.parentRunId !== undefined) lines.push(`Child of ${JSON.stringify(run.parentRunId)}`);
      if (value.method === 'run.get') lines.push(`Revision ${run.revision} · next ${run.nextStep} · Session ${run.sessionId}`,
        `Consumed ${JSON.stringify(run.budgetConsumed)} · reserved ${JSON.stringify(run.budgetReserved)}`,
        ...value.items.map(item => `Item ${item.itemSeq} · ${item.itemId} · ${item.payloadRef}`),
        ...value.journal.map(entry => `Journal ${entry.seq} · ${entry.phase} · ${entry.opId} · attempt ${entry.attempt}`),
        ...value.checkpoints.map(checkpoint => `Checkpoint ${JSON.stringify(checkpoint)}`),
        `Items through ${value.nextItemSeq}/${value.highWaterItemSeq} · Journal through ${value.nextJournalSeq}/${value.highWaterJournalSeq}`,
        ...(value.nextCheckpointCursor ? [`Checkpoint cursor: ${value.nextCheckpointCursor}`] : []));
      return lines;
    }
    return [`Session ${value.snapshot.session.id} · context ${value.snapshot.session.contextRevision}`,
      ...(value.method === 'session.get' ? [...value.items.map(item => `Item ${item.itemSeq} · ${item.kind} · ${item.itemId} · ${item.payloadRef}`),
        `Items through ${value.nextItemSeq}/${value.highWaterItemSeq}`] : [])];
  }
  if (value.method === 'run.list') return value.runs.map(snapshot => `${snapshot.run.id}  ${runHeadline(snapshot)}` +
    (snapshot.run.parentRunId === undefined ? '' : ` · child of ${JSON.stringify(snapshot.run.parentRunId)}`))
    .concat(value.nextCursor ? [`Next cursor: ${value.nextCursor}`] : []);
  if (value.method === 'session.list') return value.sessions.map(session => `${session.id}  ${terminalText(session.name ?? '')}  context ${session.contextRevision}`)
    .concat(value.nextCursor ? [`Next cursor: ${value.nextCursor}`] : []);
  if (value.method === 'authorization.list') return value.grants.map(grant => `${grant.grantId}  ${grant.state}  ${grant.targetKind}  expires ${grant.expiresAt}`)
    .concat(value.nextCursor ? [`Next cursor: ${value.nextCursor}`] : []);
  if (value.method === 'session.handoff.create') return [`JSON: ${value.json.ref}`, `Markdown: ${value.markdown.ref}`];
  if (value.method === 'run.result') return [`Result: ${value.result.ref}`, `Verification: ${value.verificationClosureRef}`];
  if (value.method === 'run.diff') return [`Diff: ${value.diff.ref}`];
  if (value.method === 'authorization.create' || value.method === 'authorization.revoke') return [`${value.grant.grantId}  ${value.grant.state}`];
  if (value.method === 'mcp.register' || value.method === 'mcp.refresh') return [
    `${JSON.stringify(value.registry.registrationId)} · registry ${value.registry.registryRevision} · ${value.registry.toolCount} tools`,
    `Manifest: ${value.registry.manifestDigest}`, 'Registration is discovery; each Run separately authorizes its exact tool calls.'];
  if (value.method === 'mcp.list') return value.registrations.map(registry =>
    `${JSON.stringify(registry.registrationId)} · registry ${registry.registryRevision} · ${registry.transport} · ${registry.toolCount} tools`);
  if (value.method === 'supervisor.status') return [`Supervisor ${value.health}`, `Queued ${value.queue.queuedRuns} · running ${value.queue.runningRuns} · capacity ${value.queue.capacity}`];
  return [request.method];
}

/** Exact whole-segment boundaries for fork/compact selection. Historical raw
 * bodies and legacy/control payloads do not enter this display projection. */
export function sessionContextLines(context: InstalledSessionContextPresentation): string[] {
  if (context.kind === 'head') return [`Context ${context.sessionId} · revision ${context.contextRevision} · through ${context.throughItemSeq} · reading boundaries`];
  if (context.kind === 'complete') return ['Context boundaries complete.',
    'Fork through a complete segment end. Compact from/to complete raw segment boundaries; resume creates a new Run.'];
  const segment = context.boundary;
  return [`${segment.fromItemSeq}–${segment.throughItemSeq} · ${segment.kind}` +
    (segment.kind === 'summary' ? ` · ${segment.retainedItemCount} retained · ${segment.summaryRef}` : '')];
}
export function reduceClientView(state: ClientView, update: ClientUpdate): ClientView {
  if (update.kind === 'connection') return immutableSnapshot({ ...state, connection: update.state });
  if (update.kind === 'pending') return immutableSnapshot({ ...state, pending: update, refusal: undefined });
  if (update.kind === 'context') {
    if (state.session && (state.session.id !== update.session.id || state.session.contextRevision > update.session.contextRevision)) return state;
    return immutableSnapshot({ ...state, session: update.session, lines: [...state.lines, ...sessionContextLines(update.context)].slice(-200) });
  }
  if (update.kind === 'transcript') {
    if (state.run && state.run.run.id !== update.runId) return state;
    // Viewport clipping does not change the retained raw item or CLI output.
    const lines = terminalText(update.text).split('\n').map(line => line.length > 2000 ? line.slice(0, 2000) + ' … [view clipped]' : line);
    return immutableSnapshot({ ...state, lines: [...state.lines, ...lines].slice(-200) });
  }
  if (update.kind === 'event') {
    const event = update.event;
    if (state.run && event.runId !== state.run.run.id || event.eventSeq <= state.eventSeq) return state;
    const text = event.type === 'progress' ? `Progress · ${event.payload.phase}` : `State · ${event.payload.status}`;
    return immutableSnapshot({ ...state, eventSeq: event.eventSeq, lines: [...state.lines, terminalText(text)].slice(-200) });
  }
  const { response, request } = update;
  if (update.origin !== 'command' && 'runId' in request && state.run && request.runId !== state.run.run.id) return state;
  const pending = 'requestId' in request && state.pending?.requestId === request.requestId ? undefined : state.pending;
  if (!response.ok) return immutableSnapshot({ ...state, pending,
    ...(response.error.code === 'EVENT_CURSOR_EXPIRED' && (!state.run || response.error.snapshot.run.id === state.run.run.id &&
      response.error.snapshot.run.revision >= state.run.run.revision) ? { run: response.error.snapshot } : {}),
    refusal: { code: response.error.code, messageCode: response.error.messageCode }, lines: [...state.lines, ...humanResponse(request, response)].slice(-200) });
  const value = response.result;
  let run = state.run, session = state.session, eventSeq = state.eventSeq;
  if ('snapshot' in value) {
    if ('run' in value.snapshot && update.origin === 'follow' && run && value.snapshot.run.id !== run.run.id) return state;
    if ('run' in value.snapshot && (!run || value.snapshot.run.id !== run.run.id || value.snapshot.run.revision >= run.run.revision)) {
      if (run?.run.id !== value.snapshot.run.id) eventSeq = 0;
      run = value.snapshot;
    } else if ('session' in value.snapshot && (!session || value.snapshot.session.id !== session.id || value.snapshot.session.contextRevision >= session.contextRevision))
      session = value.snapshot.session;
  }
  return immutableSnapshot({ ...state, run, session, eventSeq, pending, refusal: undefined,
    lines: [...state.lines, ...humanResponse(request, response)].slice(-200) });
}
