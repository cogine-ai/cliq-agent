import { Box, useApp } from 'ink';
import { useState } from 'react';

import type { PolicyMode } from '../policy/types.js';
import { InputBar } from './components/input-bar.js';
import { SlashPalette } from './components/slash-palette.js';
import { StatusBar } from './components/status-bar.js';
import { Transcript } from './components/transcript.js';
import { useUiStore } from './hooks/use-ui-store.js';
import { buildHelpText, completeSlash, parseSlash } from './slash.js';
import type { UiStore } from './store.js';

export type AppProps = {
  store: UiStore;
  onSubmit: (text: string) => void | Promise<void>;
  onReset?: () => void | Promise<void>;
  onPolicyChange?: (mode: PolicyMode) => void | Promise<void>;
};

export function App({ store, onSubmit, onReset, onPolicyChange }: AppProps) {
  const state = useUiStore(store);
  const [input, setInput] = useState('');
  const { exit } = useApp();

  function pushSystem(text: string) {
    store.dispatch({ type: 'system-message', text });
  }

  async function handleSubmit(text: string) {
    setInput('');
    if (text.startsWith('/')) {
      await runSlash(text);
      return;
    }
    store.dispatch({ type: 'user-input', text });
    try {
      await onSubmit(text);
    } catch (error) {
      pushSystem(`onSubmit failed: ${error instanceof Error ? error.message : String(error)}`);
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
          pushSystem(`policy mode switched to ${parsed.mode}`);
        } catch (error) {
          pushSystem(`/policy failed: ${error instanceof Error ? error.message : String(error)}`);
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

  const inputDisabled = state.activeTurn !== null;
  const completion = completeSlash(input);

  return (
    <Box flexDirection="column">
      <Transcript entries={state.transcript} activeTurn={state.activeTurn} />
      {input.startsWith('/') ? <SlashPalette query={input} /> : null}
      <InputBar
        value={input}
        onChange={setInput}
        onSubmit={handleSubmit}
        disabled={inputDisabled}
        completion={completion}
      />
      <StatusBar state={state} />
    </Box>
  );
}
