// Qualification-stage ownership only. A joined child does not substitute for
// any extractor/verifier/native assertion performed inside the original stage.
import assert from 'node:assert/strict';
import type { ChildProcess } from 'node:child_process';

async function closeWithinBound<T>(closed: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([closed, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('original extractor child did not join within two seconds')), 2000);
  })]); } finally { clearTimeout(timer); }
}

export async function joinGuestExtractionChild(child: ChildProcess, signal?: AbortSignal): Promise<void> {
  let isClosed = false;
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => child.once('close', (code, signal) => {
    isClosed = true; resolve({ code, signal });
  }));
  let refuse!: (error: Error) => void;
  const refused = new Promise<never>((_, reject) => { refuse = reject; });
  const failed = () => refuse(new Error('original extractor child failed to start'));
  const aborted = () => refuse(new Error('original extractor stage was interrupted'));
  child.once('error', failed); signal?.addEventListener('abort', aborted, { once: true });
  // An additional outer campaign cap, not an extension to the extractor's
  // existing per-operation ten-second readiness or two-second native close.
  const timer = setTimeout(() => refuse(new Error('original extractor stage exceeded its campaign bound')), 600_000);
  if (signal?.aborted) aborted();
  try {
    const exit = await Promise.race([closed, refused]);
    assert.equal(exit.code, 0, 'original extractor stage must succeed');
    assert.equal(exit.signal, null, 'original extractor stage cannot exit by signal');
  } catch (error) {
    if (!isClosed) {
      child.kill('SIGTERM');
      try { await closeWithinBound(closed); }
      catch (joinError) {
        child.kill('SIGKILL');
        try { await closeWithinBound(closed); }
        catch (uncertain) { throw new AggregateError([error, joinError, uncertain], 'extractor child retirement remains uncertain'); }
        // Joining after the hard fallback never turns the original failure or
        // missed close deadline into a successful extraction qualification.
        throw new AggregateError([error, joinError], 'original extractor child missed its close bound');
      }
    }
    throw error;
  } finally {
    clearTimeout(timer); signal?.removeEventListener('abort', aborted); child.removeListener('error', failed);
  }
}
