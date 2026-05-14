import { useCallback, useRef } from 'react';

export type InputHistoryHandlers = {
  // Pull the previous entry off the history stack into the input. Saves the
  // current in-progress draft on first invocation so it can be restored when
  // the user walks back down past the newest entry.
  onHistoryPrev: () => void;
  // Step toward the present. Walking past the newest entry restores the
  // saved draft and clears the navigation cursor.
  onHistoryNext: () => void;
  // Drop the saved draft + navigation cursor. Call this on submit and on any
  // user-initiated edit that should pin the buffer back to "the present".
  resetHistoryNav: () => void;
};

export function useInputHistory(opts: {
  history: readonly string[];
  current: string;
  setValue: (next: string) => void;
}): InputHistoryHandlers {
  // historyIndex === null means "at the present" — i.e. the user is editing
  // their own draft, not a recalled entry. Any non-null value indexes into
  // `history`.
  const historyIndexRef = useRef<number | null>(null);
  // The draft the user had typed before they started walking backwards.
  // Null when no recall is in progress. Restoring this on the way back down
  // is what lets users press ↑ ↓ to peek at history without losing their
  // in-progress message.
  const draftRef = useRef<string | null>(null);

  const reset = useCallback(() => {
    historyIndexRef.current = null;
    draftRef.current = null;
  }, []);

  const onHistoryPrev = useCallback(() => {
    if (opts.history.length === 0) return;
    if (historyIndexRef.current === null) {
      draftRef.current = opts.current;
      historyIndexRef.current = opts.history.length - 1;
    } else if (historyIndexRef.current > 0) {
      historyIndexRef.current -= 1;
    } else {
      // Already at the oldest entry; further ↑ is a no-op rather than
      // wrapping. Wrapping silently is disorienting in a terminal where the
      // user can't see the rest of the list.
      return;
    }
    opts.setValue(opts.history[historyIndexRef.current]!);
  }, [opts]);

  const onHistoryNext = useCallback(() => {
    if (historyIndexRef.current === null) return;
    const next = historyIndexRef.current + 1;
    if (next >= opts.history.length) {
      // Walked past the newest entry — back to the saved draft.
      const draft = draftRef.current ?? '';
      historyIndexRef.current = null;
      draftRef.current = null;
      opts.setValue(draft);
      return;
    }
    historyIndexRef.current = next;
    opts.setValue(opts.history[next]!);
  }, [opts]);

  return { onHistoryPrev, onHistoryNext, resetHistoryNav: reset };
}
