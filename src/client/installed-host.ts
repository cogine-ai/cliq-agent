import type { ClientIO } from './entry.js';
import type { ClientInvocation } from './commands.js';
import { createClientApplication, type ClientUpdate } from './application.js';
import { openInstalledControlSession, type InstalledControlSession } from '../control/session.js';
import { openInstalledClientStdio } from './stdio.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime } from '../state/installed-runtime.js';
import { joinResourceOperations, ResourceRetirementError } from '../state/errors.js';
import type { CliqClient, ClientUpdateSink } from './types.js';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { openInstalledClientData, type InstalledClientData } from './installed-data.js';

export type { CliqClient, ClientUpdateSink } from './types.js';

/** Client-lifetime composition only. Protocol fixtures use the same session
 * seam; this function neither authenticates a peer nor creates server rights. */
export function createClientHostSession(session: InstalledControlSession, selected?: HeldInstalledRuntime,
  data?: InstalledClientData, ownsData = false) {
  let application: CliqClient | undefined, active: Promise<number> | undefined;
  let selectedSurface = false, stopped = false, closing: Promise<void> | undefined;
  const local = new AbortController();
  const choose = () => {
    if (stopped || selectedSurface) throw new TypeError('installed client host is closed or already has a surface');
    selectedSurface = true;
  };
  function close(): Promise<void> {
    stopped = true; local.abort();
    return closing ??= (async () => {
      const tasks = [application ? application.close() : session.close(), ...(active ? [active] : [])];
      const results = await Promise.allSettled(tasks);
      const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected')
        .map(result => result.reason).filter(error => !(error instanceof Error && error.name === 'AbortError'));
      // The local data family outlives every accepted peer/presentation task.
      // A borrowed daily-entry family belongs to that entry, not this host.
      if (ownsData) try { await data?.close(); } catch (error) { failures.push(error); }
      const retirement = failures.find(error => error instanceof ResourceRetirementError);
      if (retirement) throw retirement;
      if (failures.length) throw failures[0];
    })();
  }
  return Object.freeze({
    get hello() { return session.hello; },
    application(output: ClientUpdateSink): CliqClient {
      if (typeof output !== 'function') throw new TypeError('client output must be a borrowed update sink');
      choose(); application = createClientApplication(session, output);
      const descriptors = { ...Object.getOwnPropertyDescriptors(application),
        close: { value: close, enumerable: true, writable: false, configurable: false } };
      return Object.freeze(Object.defineProperties({}, descriptors)) as CliqClient;
    },
    run(invocation: ClientInvocation, io: ClientIO): Promise<number> {
      try { choose(); } catch (error) { return Promise.reject(error); }
      const signal = io.signal ? AbortSignal.any([io.signal, local.signal]) : local.signal;
      const pending = (async () => {
        if (!selected) throw new TypeError('a protocol session alone cannot select installed stdio');
        const owned = await openInstalledClientStdio(selected, { ...io, signal });
        let result: number | undefined, failure: unknown;
        try {
          signal.throwIfAborted();
          const { runClientInvocation } = await import('./entry.js');
          result = await runClientInvocation(session, invocation, owned.io);
        } catch (error) { failure = error; }
        try { await owned.close(); }
        catch (error) { if (failure === undefined || error instanceof ResourceRetirementError) failure = error; }
        if (failure !== undefined) throw failure;
        // Entry returned only after its output/diagnostic writers joined.
        // This additional real stdio join must also succeed before this
        // host's known sends may be acknowledged. A cancelled writer can join
        // without delivery. Ink has no per-response delivery receipt, so its
        // records remain available for explicit acknowledgement, never resend.
        const ink = invocation.kind === 'tui' || Boolean(owned.io.output.isTTY) && 'json' in invocation && !invocation.json &&
          (invocation.kind === 'attach' || (invocation.kind === 'run' || invocation.kind === 'apply') && !invocation.detach);
        if (result === 0 && !signal.aborted && !ink) await session.requests?.acknowledgeSent();
        return result!;
      })();
      active = pending; return pending;
    },
    close
  });
}

/** Borrows the actual selected installation through client join. There are no
 * key, socket, transport, loader, credential or StateOwner options. */
export async function openInstalledClientHost(selected: HeldInstalledRuntime, borrowedData?: InstalledClientData) {
  // Keep the original complete entry validation, then release its queue before
  // the session acquires the same selection's manager/native/current borrows.
  await withHeldInstalledRuntime(selected, async installed => {
    if (borrowedData && (!canonicalJsonBytes(borrowedData.stateRoot).equals(canonicalJsonBytes(installed.stateRoot)) ||
        borrowedData.sourceBundleDigest !== installed.bundleDigest))
      throw new TypeError('borrowed client data belongs to another held installation');
  });
  let data = borrowedData;
  try { return createClientHostSession(await openInstalledControlSession(selected, borrowedData ? borrowedData.requests : (async () => {
    const prepared = await openInstalledClientData(selected);
    data = prepared;
    return prepared.requests;
  })), selected, data, !borrowedData); }
  catch (error) {
    await joinResourceOperations([Promise.reject(error), !borrowedData ? data?.close() : undefined]);
    throw error;
  }
}

/** Embedded SDK entry. Closing detaches this application/session only; the
 * embedding installation owner closes its borrowed selection afterwards. */
export async function openCliqClient(selected: object, output: ClientUpdateSink = () => {}): Promise<CliqClient> {
  const host = await openInstalledClientHost(selected as HeldInstalledRuntime);
  try { return host.application(output); }
  catch (error) {
    try { await host.close(); }
    catch (retirement) { if (retirement instanceof ResourceRetirementError) throw retirement; }
    throw error;
  }
}
