import type { ClientIO } from './entry.js';
import type { ClientInvocation } from './commands.js';
import { createClientApplication, type ClientUpdate } from './application.js';
import { openInstalledControlSession, type InstalledControlSession } from '../control/session.js';
import { openInstalledClientStdio } from './stdio.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime } from '../state/installed-runtime.js';
import { ResourceRetirementError } from '../state/errors.js';
import type { CliqClient, ClientUpdateSink } from './types.js';

export type { CliqClient, ClientUpdateSink } from './types.js';

/** Client-lifetime composition only. Protocol fixtures use the same session
 * seam; this function neither authenticates a peer nor creates server rights. */
export function createClientHostSession(session: InstalledControlSession, selected?: HeldInstalledRuntime) {
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
        try {
          signal.throwIfAborted();
          const { runClientInvocation } = await import('./entry.js');
          return await runClientInvocation(session, invocation, owned.io);
        } finally { await owned.close(); }
      })();
      active = pending; return pending;
    },
    close
  });
}

/** Borrows the actual selected installation through client join. There are no
 * key, socket, transport, loader, credential or StateOwner options. */
export async function openInstalledClientHost(selected: HeldInstalledRuntime) {
  return withHeldInstalledRuntime(selected, async () => createClientHostSession(await openInstalledControlSession(selected), selected));
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
