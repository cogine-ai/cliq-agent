export type InputHintState =
  | { kind: 'idle'; hasInput: boolean; hasExpandableTool: boolean; width?: number }
  | { kind: 'slash-input'; width?: number }
  | { kind: 'active-turn'; width?: number }
  | { kind: 'approval'; allowTurn: boolean; width?: number }
  | { kind: 'plan-review'; width?: number };

const NARROW_WIDTH = 48;

export function buildInputHint(state: InputHintState): string {
  const narrow = (state.width ?? 80) <= NARROW_WIDTH;

  switch (state.kind) {
    case 'active-turn':
      return narrow ? 'Ctrl+C cancel' : 'Running · Ctrl+C cancel';
    case 'approval':
      return state.allowTurn
        ? narrow
          ? 'y/n/a'
          : 'Approval: y allow · n deny · a allow turn'
        : narrow
          ? 'y/n'
          : 'Approval: y allow · n deny';
    case 'plan-review':
      return narrow
        ? 'd/a/Y run · r reject · c cancel'
        : 'Plan review: d default · a accept-edits · Y yolo · r reject · c cancel';
    case 'slash-input':
      return narrow ? 'Tab complete' : 'Slash commands · Tab complete · Enter run';
    case 'idle':
      if (narrow) {
        return state.hasInput ? '/help · Shift+Tab · Ctrl+C' : '/help · Shift+Tab · Ctrl+D';
      }
      return state.hasExpandableTool
        ? 'Enter send · /help commands · Shift+Tab mode · Ctrl+O output · Ctrl+D exit'
        : 'Enter send · /help commands · Shift+Tab mode · Ctrl+D exit';
    default: {
      const _exhaustive: never = state;
      return _exhaustive;
    }
  }
}
