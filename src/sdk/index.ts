// No legacy CLI/runtime import and no import-time installation or discovery.
// The trusted embedding host supplies one genuine held installed selection.
import type { CliqClient, ClientUpdateSink } from '../client/types.js';
export type { CliqClient, ClientUpdateSink, ClientCommand, ClientUpdate, SessionResumeInput } from '../client/types.js';
export { ClientBusyError, ClientDisconnectedError, ClientPendingRequestError } from '../client/errors.js';
export { ControlRefusal } from '../control/errors.js';
/** The opaque object must be the actual installation handle supplied by the
 * trusted host. No structural object, signer, callback or path is accepted as
 * an authenticated installation by the underlying genuine brand check. */
export async function openCliqClient(installation: object, output?: ClientUpdateSink): Promise<CliqClient> {
  const implementation = await import('../client/installed-host.js');
  return implementation.openCliqClient(installation, output);
}
export { parseClientInvocation, clientMutation } from '../client/commands.js';
export type { ClientInvocation, RunIntent } from '../client/commands.js';
export * from '../control/v1.js';
