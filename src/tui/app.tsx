import { Box, useApp } from 'ink';
import { useMemo, useRef, useState } from 'react';

import type { ModelPickerSnapshot } from '../model/model-picker.js';
import type { ProviderStatusReport } from '../model/provider-status.js';
import type { ProviderName } from '../model/types.js';
import type { PolicyMode } from '../policy/types.js';
import { ApprovalModal } from './components/approval-modal.js';
import { InputBar } from './components/input-bar.js';
import {
  ModelSetupFlow,
  type ModelSetupApplyRequest,
  type ModelSetupFlowProps
} from './components/model-setup-flow.js';
import { PlanProgressView } from './components/plan-progress.js';
import { PlanReviewModal } from './components/plan-review-modal.js';
import { ProviderManagement } from './components/provider-management.js';
import { SlashPalette } from './components/slash-palette.js';
import { BottomStatusBar, TopStatusBar } from './components/status-bar.js';
import { Transcript } from './components/transcript.js';
import { TuiHeader } from './components/tui-header.js';
import { useInputHistory } from './hooks/use-input-history.js';
import { useKeybindings } from './hooks/use-keybindings.js';
import { useUiStore } from './hooks/use-ui-store.js';
import { buildInputHint } from './hints.js';
import { describePolicyMode } from './mode-language.js';
import { nextPolicyMode } from './policy-rotation.js';
import { buildHelpText, completeSlash, parseSlash } from './slash.js';
import type {
  PendingPlanReview,
  TranscriptEntry,
  UiApprovalDecision,
  UiPlanDecision,
  UiState,
  UiStore
} from './store.js';

export type AppProps = {
  store: UiStore;
  onSubmit: (text: string) => void | Promise<void>;
  showModeChangeMessages?: boolean;
  onReset?: () => void | Promise<void>;
  onPolicyChange?: (mode: PolicyMode) => void | Promise<void>;
  onPlanDecision?: (
    review: PendingPlanReview,
    decision: UiPlanDecision
  ) => { message?: string; mode?: PolicyMode } | Promise<{ message?: string; mode?: PolicyMode }>;
  onCancelTurn?: () => void;
  onSkillsList?: () => string | Promise<string>;
  onSkillActivate?: (name: string) => string | Promise<string>;
  onProviderStatus?: () => ProviderStatusReport | Promise<ProviderStatusReport>;
  onModelSetupSnapshot?: () => ModelPickerSnapshot | Promise<ModelPickerSnapshot>;
  onModelSetupApply?: (request: ModelSetupApplyRequest) => void | Promise<void>;
  onModelSetupDiscoverModels?: ModelSetupFlowProps['onDiscoverModels'];
};

export function App({
  store,
  onSubmit,
  showModeChangeMessages = false,
  onReset,
  onPolicyChange,
  onPlanDecision,
  onCancelTurn,
  onSkillsList,
  onSkillActivate,
  onProviderStatus,
  onModelSetupSnapshot,
  onModelSetupApply,
  onModelSetupDiscoverModels
}: AppProps) {
  const state = useUiStore(store);
  const [input, setInput] = useState('');
  const [providerReport, setProviderReport] = useState<ProviderStatusReport | null>(null);
  const [modelSetup, setModelSetup] = useState<{ snapshot: ModelPickerSnapshot; initialProvider?: ProviderName } | null>(null);
  const [providerStatusPending, setProviderStatusPending] = useState(false);
  const planDecisionInFlightRef = useRef(false);
  const providerInteractionActiveRef = useRef(false);
  const { exit } = useApp();

  // Project the transcript down to the list of submitted user inputs in
  // chronological order. Slash commands never land in the transcript as
  // user-input (App.handleSubmit routes them to runSlash before dispatch),
  // so the recall list is naturally just plain prompts — no /help, /reset,
  // etc. cluttering ↑.
  const inputHistory = useMemo(
    () =>
      state.transcript
        .filter((entry): entry is Extract<typeof entry, { kind: 'user' }> => entry.kind === 'user')
        .map((entry) => entry.text),
    [state.transcript]
  );

  const { onHistoryPrev, onHistoryNext, resetHistoryNav } = useInputHistory({
    history: inputHistory,
    current: input,
    setValue: setInput,
  });

  function handleInputChange(next: string) {
    // Typing while inside a recall should pin the buffer back to "present"
    // so the next ↑ saves THIS draft rather than the one we recalled from.
    resetHistoryNav();
    setInput(next);
  }

  function pushSystem(text: string) {
    store.dispatch({ type: 'system-message', text });
  }

  async function handleSubmit(text: string) {
    const current = store.getState();
    if (current.activeTurn || current.pendingApproval || current.pendingPlanReview || providerInteractionActiveRef.current) {
      return;
    }
    setInput('');
    resetHistoryNav();
    if (text.startsWith('/')) {
      await runSlash(text);
      return;
    }
    store.dispatch({ type: 'user-input', text });
    try {
      await onSubmit(text);
    } catch (error) {
      store.dispatch({
        type: 'runtime-event',
        event: {
          type: 'error',
          stage: 'model',
          message: `onSubmit failed: ${error instanceof Error ? error.message : String(error)}`
        }
      });
    }
  }

  async function runSlash(raw: string) {
    const parsed = parseSlash(raw);
    switch (parsed.kind) {
      case 'exit':
        exit();
        return;
      case 'help':
        pushSystem(buildHelpText());
        return;
      case 'reset':
        try {
          await onReset?.();
          store.dispatch({ type: 'session-reset' });
          pushSystem('session reset');
        } catch (error) {
          pushSystem(`/reset failed: ${error instanceof Error ? error.message : String(error)}`);
        }
        return;
      case 'policy':
        try {
          await onPolicyChange?.(parsed.mode);
          store.dispatch({ type: 'policy-change', mode: parsed.mode });
          if (showModeChangeMessages) {
            pushSystem(`mode → ${describePolicyMode(parsed.mode).label} (${parsed.mode})`);
          }
        } catch (error) {
          pushSystem(`/policy failed: ${error instanceof Error ? error.message : String(error)}`);
        }
        return;
      case 'providers':
        try {
          if (!onProviderStatus) {
            pushSystem('No provider management handler is available in this TUI session.');
            return;
          }
          providerInteractionActiveRef.current = true;
          setProviderStatusPending(true);
          setProviderReport(await onProviderStatus());
        } catch (error) {
          providerInteractionActiveRef.current = false;
          pushSystem(`/providers failed: ${error instanceof Error ? error.message : String(error)}`);
        } finally {
          setProviderStatusPending(false);
        }
        return;
      case 'model':
        await openModelSetup();
        return;
      case 'skills':
        try {
          pushSystem(onSkillsList ? await onSkillsList() : 'No skill catalog is available in this TUI session.');
        } catch (error) {
          pushSystem(`/skills failed: ${error instanceof Error ? error.message : String(error)}`);
        }
        return;
      case 'skill':
        try {
          pushSystem(
            onSkillActivate
              ? await onSkillActivate(parsed.name)
              : `No skill activation handler is available for ${parsed.name}.`
          );
        } catch (error) {
          pushSystem(`/skill failed: ${error instanceof Error ? error.message : String(error)}`);
        }
        return;
      case 'unknown':
        pushSystem(`unknown command: ${parsed.head} (try /help)`);
        return;
      case 'invalid':
        pushSystem(parsed.reason);
        return;
      default: {
        const _exhaustive: never = parsed;
        return _exhaustive;
      }
    }
  }

  const inputDisabled =
    state.activeTurn !== null ||
    state.pendingApproval !== null ||
    state.pendingPlanReview !== null ||
    providerStatusPending ||
    providerReport !== null ||
    modelSetup !== null;
  const completion = completeSlash(input);
  const terminalWidth = process.stdout.columns ?? 80;
  const expandableTool = findLatestExpandableTool(state);
  const inputHint = state.activeTurn
    ? buildInputHint({ kind: 'active-turn', width: terminalWidth })
    : state.pendingApproval
      ? buildInputHint({
          kind: 'approval',
          allowTurn: state.pendingApproval.subject.kind === 'tool',
          width: terminalWidth
        })
      : state.pendingPlanReview
        ? buildInputHint({ kind: 'plan-review', width: terminalWidth })
        : input.startsWith('/')
          ? buildInputHint({ kind: 'slash-input', width: terminalWidth })
          : buildInputHint({
              kind: 'idle',
              hasInput: input.length > 0,
              hasExpandableTool: expandableTool !== null,
              width: terminalWidth
            });

  async function rotatePolicy() {
    // Read the current policy from the store rather than the rendered state
    // snapshot — if the user mashes Shift+Tab faster than React commits the
    // last policy-change, the closure-captured state.policy would be stale
    // and successive presses would all compute the same `next` from the old
    // value. Going through the store dispenses fresh state per keystroke.
    const current = store.getState().policy;
    const next = nextPolicyMode(current);
    if (next === current) return;
    try {
      await onPolicyChange?.(next);
      store.dispatch({ type: 'policy-change', mode: next });
      if (showModeChangeMessages) {
        pushSystem(`mode → ${describePolicyMode(next).label} (${next})`);
      }
    } catch (error) {
      pushSystem(
        `policy rotation failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  useKeybindings({
    onCtrlC: () => {
      if (providerInteractionActiveRef.current) return;
      if (store.getState().pendingApproval) {
        denyPendingApproval();
        onCancelTurn?.();
        pushSystem('cancelling…');
      } else if (store.getState().pendingPlanReview) {
        void handlePlanDecision({ type: 'cancel' });
      } else if (store.getState().activeTurn) {
        // Cancel the active turn — bridge fires AbortController.abort().
        onCancelTurn?.();
        pushSystem('cancelling…');
      } else if (input.length > 0) {
        // No active turn: vim-style clear. Diverges from readline default
        // (which exits) — explicit /exit is the exit path here.
        setInput('');
      }
      // Empty input + no active turn: ignore. /exit is the exit path.
    },
    onCtrlD: () => {
      const current = store.getState();
      if (current.activeTurn || current.pendingApproval || current.pendingPlanReview || providerInteractionActiveRef.current) return;
      if (input.length === 0) {
        exit();
      }
      // Non-empty input: ignore (matches Claude Code).
    },
    onToggleBody: () => {
      const current = store.getState();
      if (current.activeTurn || current.pendingApproval || current.pendingPlanReview || providerInteractionActiveRef.current) return;
      const target = findLatestExpandableTool(current);
      if (!target) {
        pushSystem('no tool output to expand');
        return;
      }
      store.dispatch({ type: 'toggle-tool-body' });
      pushSystem(`${target.expanded ? 'collapsed' : 'expanded'} ${target.tool} output`);
    },
    onRotatePolicy: () => {
      const current = store.getState();
      if (current.activeTurn || current.pendingApproval || current.pendingPlanReview || providerInteractionActiveRef.current) return;
      void rotatePolicy();
    }
  });

  function handleApprovalDecide(decision: UiApprovalDecision) {
    const pending = store.getState().pendingApproval;
    if (!pending) return;
    pending.resolve(decision);
    store.dispatch({ type: 'approval-resolve', id: pending.id });
  }

  function denyPendingApproval() {
    const pending = store.getState().pendingApproval;
    if (!pending) return;
    pending.resolve('deny');
    store.dispatch({ type: 'approval-resolve', id: pending.id });
  }

  async function startSyntheticTurn(text: string) {
    const current = store.getState();
    if (current.activeTurn || current.pendingApproval || current.pendingPlanReview || providerInteractionActiveRef.current) return;
    store.dispatch({ type: 'user-input', text });
    try {
      await onSubmit(text);
    } catch (error) {
      store.dispatch({
        type: 'runtime-event',
        event: {
          type: 'error',
          stage: 'model',
          message: `onSubmit failed: ${error instanceof Error ? error.message : String(error)}`
        }
      });
    }
  }

  function closeProviderManagement() {
    providerInteractionActiveRef.current = false;
    setProviderReport(null);
  }

  function closeModelSetup() {
    providerInteractionActiveRef.current = false;
    setModelSetup(null);
  }

  async function openModelSetup(initialProvider?: ProviderName) {
    try {
      if (!onModelSetupSnapshot || !onModelSetupApply) {
        pushSystem('No model setup handler is available in this TUI session.');
        return;
      }
      providerInteractionActiveRef.current = true;
      setProviderStatusPending(true);
      const snapshot = await onModelSetupSnapshot();
      setProviderReport(null);
      setModelSetup(initialProvider ? { snapshot, initialProvider } : { snapshot });
    } catch (error) {
      providerInteractionActiveRef.current = false;
      setProviderReport(null);
      pushSystem(`/model failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setProviderStatusPending(false);
    }
  }

  async function handleModelSetupApply(request: ModelSetupApplyRequest) {
    try {
      if (!onModelSetupApply) {
        throw new Error('No model setup apply handler is available in this TUI session.');
      }
      await onModelSetupApply(request);
      closeModelSetup();
    } catch (error) {
      pushSystem(`model setup failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async function handlePlanDecision(decision: UiPlanDecision) {
    if (planDecisionInFlightRef.current) return;
    const review = store.getState().pendingPlanReview;
    if (!review) return;
    planDecisionInFlightRef.current = true;
    try {
      if (!onPlanDecision) {
        throw new Error('No plan review handler is available in this TUI session.');
      }
      const result = await onPlanDecision(review, decision);
      store.dispatch({ type: 'plan-review-resolve', id: review.id });
      if (result?.mode) {
        store.dispatch({ type: 'policy-change', mode: result.mode });
      }
      pushSystem(result?.message ?? fallbackPlanDecisionMessage(decision));
      if (decision.type === 'approve') {
        await startSyntheticTurn('Execute the approved plan.');
      } else if (decision.type === 'reject') {
        await startSyntheticTurn('Revise the rejected plan and finalize a new plan for review.');
      }
    } catch (error) {
      pushSystem(`plan review failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      planDecisionInFlightRef.current = false;
    }
  }

  return (
    <Box flexDirection="column">
      <TuiHeader />
      <Transcript entries={state.transcript} activeTurn={state.activeTurn} />
      {state.planProgress && !state.pendingPlanReview ? <PlanProgressView progress={state.planProgress} /> : null}
      {state.pendingApproval ? (
        <ApprovalModal
          key={state.pendingApproval.id}
          subject={state.pendingApproval.subject}
          policy={state.policy}
          activationKey={state.pendingApproval.id}
          onDecide={handleApprovalDecide}
        />
      ) : state.pendingPlanReview ? (
        <PlanReviewModal
          key={state.pendingPlanReview.id}
          review={state.pendingPlanReview}
          activationKey={state.pendingPlanReview.id}
          onDecide={(decision) => {
            void handlePlanDecision(decision);
          }}
        />
      ) : modelSetup ? (
        <ModelSetupFlow
          snapshot={modelSetup.snapshot}
          onApply={(request) => {
            void handleModelSetupApply(request);
          }}
          onDiscoverModels={onModelSetupDiscoverModels}
          onClose={closeModelSetup}
          {...(modelSetup.initialProvider ? { initialProvider: modelSetup.initialProvider } : {})}
        />
      ) : providerReport ? (
        <ProviderManagement
          report={providerReport}
          onClose={closeProviderManagement}
          {...(onModelSetupSnapshot && onModelSetupApply
            ? {
                onConfigure: (provider) => {
                  void openModelSetup(provider);
                }
              }
            : {})}
        />
      ) : (
        <>
          {input.startsWith('/') ? <SlashPalette query={input} /> : null}
          <TopStatusBar hint={inputHint} />
          <InputBar
            value={input}
            onChange={handleInputChange}
            onSubmit={handleSubmit}
            onHistoryPrev={onHistoryPrev}
            onHistoryNext={onHistoryNext}
            disabled={inputDisabled}
            completion={completion}
            policy={state.policy}
            modelLabel={`${state.model.provider}/${state.model.model}`}
            width={terminalWidth}
          />
          <BottomStatusBar state={state} />
        </>
      )}
      {state.pendingApproval || state.pendingPlanReview ? <BottomStatusBar state={state} /> : null}
    </Box>
  );
}

function fallbackPlanDecisionMessage(decision: UiPlanDecision) {
  if (decision.type === 'approve') {
    return `plan approved; running in ${describePolicyMode(decision.targetMode).label} (${decision.targetMode})`;
  }
  if (decision.type === 'reject') {
    return 'plan rejected; continuing planning';
  }
  return 'plan review canceled';
}

function findLatestExpandableTool(state: UiState): Extract<TranscriptEntry, { kind: 'tool' }> | null {
  for (let i = state.transcript.length - 1; i >= 0; i -= 1) {
    const entry = state.transcript[i]!;
    if (entry.kind === 'tool' && entry.body) {
      return entry;
    }
  }
  return null;
}
