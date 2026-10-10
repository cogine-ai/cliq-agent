/**
 * Small, shared state language for the TUI. This is intentionally not a
 * configurable theme: named ANSI colors keep the output useful in terminals
 * with limited color support, while markers and labels carry the meaning when
 * color is unavailable.
 */
export type SemanticTone =
  | 'safe'
  | 'info'
  | 'active'
  | 'warning'
  | 'danger'
  | 'success'
  | 'error'
  | 'muted';

export type SemanticStyle = {
  color: string;
  marker: string;
  dimColor?: true;
};

export const SEMANTIC_STYLES: Readonly<Record<SemanticTone, SemanticStyle>> = Object.freeze({
  safe: Object.freeze({ color: 'green', marker: '◆' }),
  info: Object.freeze({ color: 'cyan', marker: 'i' }),
  active: Object.freeze({ color: 'cyan', marker: '▸' }),
  warning: Object.freeze({ color: 'yellow', marker: '!' }),
  danger: Object.freeze({ color: 'red', marker: '!' }),
  success: Object.freeze({ color: 'green', marker: '✓' }),
  error: Object.freeze({ color: 'red', marker: '✗' }),
  muted: Object.freeze({ color: 'gray', marker: '·' })
});

export function semanticStyle(tone: SemanticTone): SemanticStyle {
  return SEMANTIC_STYLES[tone];
}

export function semanticTextProps(tone: SemanticTone): { color: string; dimColor?: true } {
  const style = semanticStyle(tone);
  return style.dimColor ? { color: style.color, dimColor: true } : { color: style.color };
}
