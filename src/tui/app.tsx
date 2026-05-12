import { Box } from 'ink';

import { InputBar } from './components/input-bar.js';
import { StatusBar } from './components/status-bar.js';
import { Transcript } from './components/transcript.js';
import { useUiStore } from './hooks/use-ui-store.js';
import type { UiStore } from './store.js';

export type AppProps = {
  store: UiStore;
  onSubmit: (text: string) => void | Promise<void>;
};

export function App({ store, onSubmit }: AppProps) {
  const state = useUiStore(store);

  function handleSubmit(text: string) {
    store.dispatch({ type: 'user-input', text });
    void onSubmit(text);
  }

  const inputDisabled = state.activeTurn !== null;

  return (
    <Box flexDirection="column">
      <Transcript entries={state.transcript} activeTurn={state.activeTurn} />
      <InputBar onSubmit={handleSubmit} disabled={inputDisabled} />
      <StatusBar state={state} />
    </Box>
  );
}
