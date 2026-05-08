import type { Validator, ValidatorContext, ValidatorResult } from './types.js';

export async function runValidators(opts: {
  txId: string;
  registry: Validator[];
  workspaceView: string;
  realCwd: string;
  serial?: boolean;
  signal?: AbortSignal;
  onResult?: (r: ValidatorResult) => Promise<void>;
}): Promise<ValidatorResult[]> {
  const ctx: ValidatorContext = {
    txId: opts.txId,
    workspaceView: opts.workspaceView,
    realCwd: opts.realCwd,
    signal: opts.signal ?? new AbortController().signal
  };
  async function runOne(v: Validator): Promise<ValidatorResult> {
    const start = Date.now();
    let result: ValidatorResult;
    try {
      result = await v.run(ctx);
    } catch (err) {
      result = {
        name: v.name,
        severity: v.defaultSeverity,
        status: 'error',
        durationMs: Date.now() - start,
        message: err instanceof Error ? err.message : String(err)
      };
    }
    // onResult failures bubble up; they are the caller's bug rather than a
    // validator failure, so we must not silently downgrade them to status='error'.
    if (opts.onResult) await opts.onResult(result);
    return result;
  }
  if (opts.serial) {
    const results: ValidatorResult[] = [];
    for (const v of opts.registry) {
      results.push(await runOne(v));
    }
    return results;
  }
  return Promise.all(opts.registry.map(runOne));
}
