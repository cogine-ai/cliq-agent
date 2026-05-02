import { MAX_STORED_TOOL_RESULT_CHARS } from '../config.js';
import type { ToolResult } from './types.js';

export function normalizeToolResultForStorage(
  result: ToolResult,
  maxChars = MAX_STORED_TOOL_RESULT_CHARS
): ToolResult {
  if (result.content.length <= maxChars) {
    return result;
  }

  const marker = `\n\n[cliq truncated tool result: originalChars=${result.content.length}]`;
  const contentBudget = Math.max(0, maxChars - marker.length);
  const prefixBudget = Math.ceil(contentBudget * 0.4);
  const suffixBudget = Math.max(0, contentBudget - prefixBudget);
  const prefix = result.content.slice(0, prefixBudget);
  const suffix = suffixBudget > 0 ? result.content.slice(-suffixBudget) : '';
  const content = `${prefix}${marker}${suffix}`.slice(0, maxChars);

  return {
    ...result,
    content,
    meta: {
      ...result.meta,
      truncated: true,
      originalChars: result.content.length,
      storedChars: content.length
    }
  };
}
