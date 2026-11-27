import { normalizeAbsolutePath } from '../kernel/identity.js';
import type { createInstalledRuntime } from '../state/installed-runtime.js';
import { ResourceRetirementError } from '../state/errors.js';
import { runInstalledClient, type ClientIO } from './entry.js';

/** The SEA caller supplies its already composed fixed-root runtime. A path
 * only locates an installation: it never supplies a key, peer or authority. */
export async function runInstalledClientRole(runtime: Pick<ReturnType<typeof createInstalledRuntime>, 'openSelected'>, stateRoot: string,
  argv: readonly string[], io: ClientIO): Promise<number> {
  if (normalizeAbsolutePath(stateRoot) !== stateRoot) throw new TypeError('client StateRoot locator must be an absolute canonical path');
  io.signal?.throwIfAborted();
  const selected = await runtime.openSelected(stateRoot);
  let primary: unknown;
  try { io.signal?.throwIfAborted(); return await runInstalledClient(selected, argv, io); }
  catch (error) { primary = error; throw error; }
  finally {
    try { await selected.close(); }
    catch (error) { if (error instanceof ResourceRetirementError || primary === undefined) throw error; }
  }
}
