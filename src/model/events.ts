import type { ModelCompleteOptions } from './types.js';

export async function emitModelErrorEvent(options: ModelCompleteOptions | undefined, error: unknown) {
  if (options?.signal?.aborted) {
    return;
  }

  try {
    await options?.onEvent?.({
      type: 'error',
      message: error instanceof Error ? error.message : String(error)
    });
  } catch {
    // Preserve the original provider failure even if the event sink fails.
  }
}
