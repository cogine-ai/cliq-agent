export type ContextOverflowInfo = {
  isOverflow: true;
  contextWindowTokens?: number;
  message: string;
};

const OVERFLOW_PATTERNS = [
  /context length exceeded/i,
  /context window/i,
  /maximum context/i,
  /too many tokens/i,
  /input is too long/i,
  /tokens.*exceed/i
];

export function classifyContextOverflow(error: unknown): ContextOverflowInfo | null {
  const message = error instanceof Error ? error.message : String(error);
  if (!OVERFLOW_PATTERNS.some((pattern) => pattern.test(message))) {
    return null;
  }

  const tokenMatch = message.match(/(?:context window|maximum context|limit)[^\d]{0,32}(\d{4,})/i);
  return {
    isOverflow: true,
    message,
    ...(tokenMatch ? { contextWindowTokens: Number(tokenMatch[1]) } : {})
  };
}
