import { useInput, type Key } from 'ink';

export type KeybindingHandlers = {
  // Ctrl+C — handler decides cancel-active-turn vs clear-input via closure.
  onCtrlC?: () => void;
  // Ctrl+D — typically exits when input is empty; handler checks the context.
  onCtrlD?: () => void;
  // Ctrl+O — toggles the focused tool entry's folded body. Spec A.10 used a
  // plain 'o', but we use Ctrl+O so it never conflicts with text composition;
  // there is no focus model yet to safely interpret a bare letter.
  onToggleBody?: () => void;
  // Shift+Tab — rotates through the policy modes. Tab alone is reserved for
  // slash-completion in the input bar.
  onRotatePolicy?: () => void;
};

export function useKeybindings(handlers: KeybindingHandlers) {
  useInput((input: string, key: Key) => {
    if (key.ctrl && input === 'c') {
      handlers.onCtrlC?.();
      return;
    }
    if (key.ctrl && input === 'd') {
      handlers.onCtrlD?.();
      return;
    }
    if (key.ctrl && input === 'o') {
      handlers.onToggleBody?.();
      return;
    }
    if (isShiftTabInput(input, key)) {
      handlers.onRotatePolicy?.();
    }
  });
}

export function isShiftTabInput(input: string, key: Pick<Key, 'shift' | 'tab'>) {
  return (key.shift && key.tab) || input === '\x1b[Z' || input === '\x1b\t';
}
