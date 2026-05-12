import { useSyncExternalStore } from 'react';

import type { UiState, UiStore } from '../store.js';

export function useUiStore(store: UiStore): UiState {
  return useSyncExternalStore(store.subscribe, store.getState, store.getState);
}
