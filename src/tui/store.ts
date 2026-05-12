import type { ProviderName } from '../model/types.js';
import type { ApprovalSubject, PolicyMode } from '../policy/types.js';
import type { ModelAction } from '../protocol/model/actions.js';
import type { RuntimeEvent } from '../protocol/runtime/events.js';
import type { RuntimeErrorCode } from '../protocol/runtime/errors.js';
import type { ToolResult } from '../tools/types.js';
import {
  extractBashBody,
  formatToolResultSummary,
  previewFromAction,
  toolNameFromAction
} from './format.js';

export type TranscriptEntry =
  | { kind: 'user'; id: string; text: string }
  | { kind: 'assistant'; id: string; text: string }
  | {
      kind: 'tool';
      id: string;
      tool: string;
      status: 'running' | 'ok' | 'error';
      summary: string;
      body?: string;
      expanded?: boolean;
    }
  | { kind: 'system'; id: string; text: string };

export type ErrorEntry = {
  id: string;
  stage: 'model' | 'protocol' | 'policy' | 'tool' | 'cancel';
  message: string;
  code?: RuntimeErrorCode;
};

export type ActiveTurn = {
  modelChunks: number;
  modelChars: number;
};

export type UiApprovalDecision = 'allow' | 'deny' | 'allow-turn';

export type PendingApproval = {
  id: string;
  subject: ApprovalSubject;
};

export type UiState = {
  transcript: TranscriptEntry[];
  activeTurn: ActiveTurn | null;
  pendingApproval: PendingApproval | null;
  policy: PolicyMode;
  model: { provider: ProviderName; model: string };
  session: { id: string; cwd: string };
  errors: ErrorEntry[];
  // Monotonic counter for entry ids; kept in state so reduce() stays pure.
  nextEntryId: number;
};

export type UiAction =
  | { type: 'runtime-event'; event: RuntimeEvent }
  | { type: 'tool-hook-start'; action: ModelAction }
  | { type: 'tool-hook-end'; result: ToolResult }
  | { type: 'user-input'; text: string }
  | { type: 'system-message'; text: string }
  | { type: 'toggle-tool-body' }
  | { type: 'approval-resolve'; decision: UiApprovalDecision }
  | { type: 'session-reset' }
  | { type: 'policy-change'; mode: PolicyMode };

const MAX_ERROR_HISTORY = 20;

function assertNever(x: never): never {
  throw new Error(`unhandled discriminant: ${JSON.stringify(x as unknown)}`);
}

function mintId(state: UiState, prefix: string): { id: string; nextEntryId: number } {
  return { id: `${prefix}${state.nextEntryId}`, nextEntryId: state.nextEntryId + 1 };
}

export function createInitialState(opts: {
  policy: PolicyMode;
  model: { provider: ProviderName; model: string };
  session: { id: string; cwd: string };
}): UiState {
  return {
    transcript: [],
    activeTurn: null,
    pendingApproval: null,
    policy: opts.policy,
    model: opts.model,
    session: opts.session,
    errors: [],
    nextEntryId: 1,
  };
}

export function reduce(state: UiState, action: UiAction): UiState {
  switch (action.type) {
    case 'runtime-event':
      return reduceRuntimeEvent(state, action.event);
    case 'tool-hook-start':
      return reduceToolHookStart(state, action.action);
    case 'tool-hook-end':
      return reduceToolHookEnd(state, action.result);
    case 'user-input': {
      const { id, nextEntryId } = mintId(state, 'u');
      return {
        ...state,
        nextEntryId,
        transcript: [...state.transcript, { kind: 'user', id, text: action.text }],
      };
    }
    case 'system-message':
      return pushSystem(state, action.text);
    case 'toggle-tool-body': {
      // Spec A.10: Phase A focus is implicit-last-only — toggle the most
      // recent tool entry that has a body (bash output today; future tools
      // could grow bodies too).
      for (let i = state.transcript.length - 1; i >= 0; i -= 1) {
        const entry = state.transcript[i]!;
        if (entry.kind === 'tool' && entry.body) {
          return updateToolEntry(state, i, { expanded: !entry.expanded });
        }
      }
      return state;
    }
    case 'approval-resolve':
      // The bridge that owns the Promise resolves it before dispatching this
      // action; the reducer only clears UI state. Stage 3.3 wires the bridge.
      return state.pendingApproval ? { ...state, pendingApproval: null } : state;
    case 'session-reset':
      return {
        ...state,
        transcript: [],
        activeTurn: null,
        pendingApproval: null,
        errors: [],
      };
    case 'policy-change':
      return { ...state, policy: action.mode };
    default:
      return assertNever(action);
  }
}

function findLastRunningToolIndex(transcript: TranscriptEntry[], tool: string): number {
  for (let i = transcript.length - 1; i >= 0; i -= 1) {
    const entry = transcript[i]!;
    if (entry.kind === 'tool' && entry.tool === tool && entry.status === 'running') {
      return i;
    }
  }
  return -1;
}

function updateToolEntry(
  state: UiState,
  index: number,
  patch: Partial<Extract<TranscriptEntry, { kind: 'tool' }>>
): UiState {
  const next = [...state.transcript];
  const existing = next[index];
  if (!existing || existing.kind !== 'tool') return state;
  next[index] = { ...existing, ...patch };
  return { ...state, transcript: next };
}

function reduceToolHookStart(state: UiState, action: ModelAction): UiState {
  const tool = toolNameFromAction(action);
  const summary = previewFromAction(action);
  const idx = findLastRunningToolIndex(state.transcript, tool);
  if (idx !== -1) {
    return updateToolEntry(state, idx, { summary });
  }
  // Fallback: tool-start RuntimeEvent didn't fire (e.g. test driving hooks
  // alone). Create the running entry now.
  const { id, nextEntryId } = mintId(state, 't');
  return {
    ...state,
    nextEntryId,
    transcript: [...state.transcript, { kind: 'tool', id, tool, status: 'running', summary }],
  };
}

function reduceToolHookEnd(state: UiState, result: ToolResult): UiState {
  const summary = formatToolResultSummary(result);
  const body = extractBashBody(result);
  const idx = findLastRunningToolIndex(state.transcript, result.tool);
  const patch: Partial<Extract<TranscriptEntry, { kind: 'tool' }>> = {
    status: result.status,
    summary,
    ...(body !== undefined ? { body } : {}),
  };
  if (idx !== -1) {
    return updateToolEntry(state, idx, patch);
  }
  // Fallback: no running entry — synthesize one in its final state.
  const { id, nextEntryId } = mintId(state, 't');
  return {
    ...state,
    nextEntryId,
    transcript: [
      ...state.transcript,
      {
        kind: 'tool',
        id,
        tool: result.tool,
        status: result.status,
        summary,
        ...(body !== undefined ? { body } : {}),
      },
    ],
  };
}

function pushSystem(state: UiState, text: string): UiState {
  const { id, nextEntryId } = mintId(state, 's');
  return {
    ...state,
    nextEntryId,
    transcript: [...state.transcript, { kind: 'system', id, text }],
  };
}

function reduceRuntimeEvent(state: UiState, event: RuntimeEvent): UiState {
  switch (event.type) {
    case 'model-start':
      return {
        ...state,
        activeTurn: { modelChunks: 0, modelChars: 0 },
      };
    case 'model-progress':
      return state.activeTurn
        ? {
            ...state,
            activeTurn: { modelChunks: event.chunks, modelChars: event.chars },
          }
        : state;
    case 'model-end':
      // 'final' clears activeTurn; model-end alone is informational.
      return state;
    case 'final': {
      const { id, nextEntryId } = mintId(state, 'a');
      return {
        ...state,
        activeTurn: null,
        nextEntryId,
        transcript: [...state.transcript, { kind: 'assistant', id, text: event.message }],
      };
    }
    case 'error': {
      const { id, nextEntryId } = mintId(state, 'e');
      const entry: ErrorEntry = {
        id,
        stage: event.stage,
        message: event.message,
        code: event.code,
      };
      return {
        ...state,
        nextEntryId,
        activeTurn: null,
        errors: [...state.errors, entry].slice(-MAX_ERROR_HISTORY),
      };
    }
    case 'tool-start': {
      // Create the entry up-front; the beforeTool hook (tool-hook-start)
      // enriches it with the action preview, and afterTool (tool-hook-end)
      // finalizes status + body.
      const { id, nextEntryId } = mintId(state, 't');
      return {
        ...state,
        nextEntryId,
        transcript: [
          ...state.transcript,
          { kind: 'tool', id, tool: event.tool, status: 'running', summary: '' },
        ],
      };
    }
    case 'tool-end': {
      // Backstop finalization for setups that drive RuntimeEvent without the
      // hook bridge (e.g. tests). When the bridge is wired, the entry is
      // already non-running by the time this fires and the lookup misses.
      const idx = findLastRunningToolIndex(state.transcript, event.tool);
      if (idx === -1) return state;
      return updateToolEntry(state, idx, { status: event.status });
    }
    case 'checkpoint-created':
      return pushSystem(
        state,
        `checkpoint ${event.checkpointId} created (${event.kind})${
          event.workspaceSnapshotStatus !== 'available'
            ? ` — workspace snapshot ${event.workspaceSnapshotStatus}`
            : ''
        }`
      );
    case 'compact-start':
      return pushSystem(state, `compaction started (${event.trigger}, ${event.phase})`);
    case 'compact-end':
      return pushSystem(
        state,
        `compaction completed: ${event.estimatedTokensBefore} → ${event.estimatedTokensAfter} tokens`
      );
    case 'compact-skip':
      return pushSystem(state, `compaction skipped: ${event.reason}`);
    case 'compact-error':
      return pushSystem(
        state,
        `compaction error (${event.trigger}): ${event.message}`
      );
    case 'tx-staging-start':
      return pushSystem(
        state,
        `tx ${event.txId} staging started${event.name ? ` — ${event.name}` : ''}`
      );
    case 'tx-finalized': {
      const d = event.diffSummary;
      return pushSystem(
        state,
        `tx ${event.txId} finalized: ${d.filesChanged} files (+${d.additions}/-${d.deletions})`
      );
    }
    case 'tx-validated': {
      const v = event.validators;
      const blocking = `blocking ${v.blocking.pass}/${v.blocking.pass + v.blocking.fail}`;
      const advisory = `advisory ${v.advisory.pass}/${v.advisory.pass + v.advisory.fail}`;
      const failures = event.blockingFailures.length
        ? ` — failures: ${event.blockingFailures.join(', ')}`
        : '';
      return pushSystem(state, `tx ${event.txId} validated: ${blocking}, ${advisory}${failures}`);
    }
    case 'tx-applied': {
      const d = event.diffSummary;
      return pushSystem(
        state,
        `tx ${event.txId} applied: +${d.additions}/-${d.deletions} over ${d.filesChanged} files`
      );
    }
    case 'tx-aborted':
      return pushSystem(state, `tx ${event.txId} aborted: ${event.reason}`);
    default:
      return assertNever(event);
  }
}

export type Listener = (state: UiState) => void;

export type UiStore = {
  getState(): UiState;
  subscribe(listener: Listener): () => void;
  dispatch(action: UiAction): void;
};

export function createUiStore(initial: UiState): UiStore {
  let state = initial;
  const listeners = new Set<Listener>();

  return {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    dispatch(action) {
      state = reduce(state, action);
      for (const l of listeners) l(state);
    },
  };
}
