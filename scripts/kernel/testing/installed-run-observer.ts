type RunRead = { protocolVersion: 1; method: 'run.get'; runId: string };
type Connection<T> = { readonly supervisorInstanceId: string;
  send(request: RunRead, timeout: number): Promise<T>; close(): Promise<void> };
type Observation<T> = Readonly<{ response: T; supervisorInstanceId: string }>;

/** Ordinary read-only polling. This owns a real authenticated client, never a
 * Run, dispatch permission or recovery proof. Fresh-client replay assertions
 * deliberately remain separate from this observer. */
export function createInstalledRunObserver<T>(open: (timeout: number) => Promise<Connection<T>>) {
  let client: Connection<T> | undefined;
  let pending: Promise<Observation<T>> | undefined, closing: Promise<void> | undefined;
  let failed = false, frames = 0;
  return {
    read(runId: string, timeout = 30000): Promise<Observation<T>> {
      if (pending || closing || failed) return Promise.reject(new Error('ordinary Run observer is not available'));
      if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 30000)
        return Promise.reject(new TypeError('ordinary Run observer requires its original bounded read budget'));
      const deadline = performance.now() + timeout;
      const remaining = () => {
        const value = deadline - performance.now();
        if (value <= 0) throw new Error('ordinary Run observer read deadline expired');
        return Math.ceil(value);
      };
      pending = (async () => {
        // The factory's accepted hello is the first frame. Rotation is only
        // planned after a completed read, never a response to an I/O failure.
        if (frames === 1024) { await client!.close(); client = undefined; remaining(); }
        if (!client) { client = await open(remaining()); frames = 1; remaining(); }
        frames++;
        const response = await client.send({ protocolVersion: 1, method: 'run.get', runId }, remaining());
        remaining();
        return Object.freeze({ response, supervisorInstanceId: client.supervisorInstanceId });
      })().catch(error => { failed = true; throw error; }).finally(() => { pending = undefined; });
      return pending;
    },
    close(): Promise<void> {
      return closing ??= (async () => {
        try { await pending; } catch { /* Retain the original read failure at its caller. */ }
        await client?.close();
      })();
    }
  };
}
