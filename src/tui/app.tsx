import { Box, useApp } from 'ink';
import { useMemo, useState } from 'react';

import type { PolicyMode } from '../policy/types.js';
import { ApprovalModal } from './components/approval-modal.js';
import { InputBar } from './components/input-bar.js';
import { SlashPalette } from './components/slash-palette.js';
import { StatusBar } from './components/status-bar.js';
import { Transcript } from './components/transcript.js';
import { useInputHistory } from './hooks/use-input-history.js';
import { useKeybindings } from './hooks/use-keybindings.js';
import { useUiStore } from './hooks/use-ui-store.js';
import { buildInputHint } from './hints.js';
import { describePolicyMode } from './mode-language.js';
import { nextPolicyMode } from './policy-rotation.js';
import { buildHelpText, completeSlash, parseSlash } from './slash.js';
import type { TranscriptEntry, UiApprovalDecision, UiState, UiStore } from './store.js';

export type AppProps = {
  store: UiStore;
  onSubmit: (text: string) => void | Promise<void>;
  onReset?: () => void | Promise<void>;
  onPolicyChange?: (mode: PolicyMode) => void | Promise<void>;
  onCancelTurn?: () => void;
  onSkillsList?: () => string | Promise<string>;
  onSkillActivate?: (name: string) => string | Promise<string>;
};

export function App({
  store,
  onSubmit,
  onReset,
  onPolicyChange,
  onCancelTurn,
  onSkillsList,
  onSkillActivate
}: AppProps) {
  const state = useUiStore(store);
  const [input, setInput] = useState('');
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
    if (current.activeTurn || current.pendingApproval) return;
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
          pushSystem(`mode → ${describePolicyMode(parsed.mode).label} (${parsed.mode})`);
        } catch (error) {
          pushSystem(`/policy failed: ${error instanceof Error ? error.message : String(error)}`);
        }
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

  const inputDisabled = state.activeTurn !== null || state.pendingApproval !== null;
  const completion = completeSlash(input);
  const terminalWidth = process.stdout.columns ?? 80;
  const expandableTool = findLatestExpandableTool(state);
  const inputHint = state.activeTurn
    ? buildInputHint({ kind: 'active-turn', width: terminalWidth })
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
      pushSystem(`mode → ${describePolicyMode(next).label} (${next})`);
    } catch (error) {
      pushSystem(
        `policy rotation failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  useKeybindings({
    onCtrlC: () => {
      if (store.getState().pendingApproval) {
        denyPendingApproval();
        onCancelTurn?.();
        pushSystem('cancelling…');
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
      if (current.activeTurn || current.pendingApproval) return;
      if (input.length === 0) {
        exit();
      }
      // Non-empty input: ignore (matches Claude Code).
    },
    onToggleBody: () => {
      const current = store.getState();
      if (current.activeTurn || current.pendingApproval) return;
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
      if (current.activeTurn || current.pendingApproval) return;
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

  return (
    <Box flexDirection="column">
      <Transcript entries={state.transcript} activeTurn={state.activeTurn} />
      {state.pendingApproval ? (
        <ApprovalModal
          key={state.pendingApproval.id}
          subject={state.pendingApproval.subject}
          policy={state.policy}
          activationKey={state.pendingApproval.id}
          onDecide={handleApprovalDecide}
        />
      ) : (
        <>
          {input.startsWith('/') ? <SlashPalette query={input} /> : null}
          <InputBar
            value={input}
            onChange={handleInputChange}
            onSubmit={handleSubmit}
            onHistoryPrev={onHistoryPrev}
            onHistoryNext={onHistoryNext}
            disabled={inputDisabled}
            completion={completion}
            hint={inputHint}
          />
        </>
      )}
      <StatusBar state={state} />
    </Box>
  );
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
