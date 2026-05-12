import type { ProviderName } from '../model/types.js';
import type { ApprovalSubject, PolicyMode } from '../policy/types.js';
import type { RuntimeEvent } from '../protocol/runtime/events.js';
import type { RuntimeErrorCode } from '../protocol/runtime/errors.js';

export type TranscriptEntry =
  | { kind: 'user'; id: string; text: string }
  | { kind: 'assistant'; id: string; text: string }
  | { kind: 'tool'; id: string; tool: string; status: 'running' | 'ok' | 'error'; preview?: string }
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
  | { type: 'user-input'; text: string }
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
    case 'user-input': {
      const { id, nextEntryId } = mintId(state, 'u');
      return {
        ...state,
        nextEntryId,
        transcript: [...state.transcript, { kind: 'user', id, text: action.text }],
      };
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
    // Variants below land in later stages; explicit no-op cases keep
    // assertNever exhaustiveness so a new RuntimeEvent variant fails to compile.
    case 'tool-start':
    case 'tool-end':
    case 'checkpoint-created':
    case 'compact-start':
    case 'compact-end':
    case 'compact-skip':
    case 'compact-error':
    case 'tx-staging-start':
    case 'tx-finalized':
    case 'tx-validated':
    case 'tx-applied':
    case 'tx-aborted':
      return state;
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
