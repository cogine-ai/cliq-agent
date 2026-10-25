import { INSTALLED_CONTROL_FEATURES, decodeInstalledControlRequest, type InstalledControlFeature, type InstalledControlRequestV1,
  type InstalledControlResponseFor, type InstalledControlResultFor } from '../control/v1.js';
import type { HeldInstalledRuntime } from './installed-runtime.js';
import { openInstalledControlTransport } from './installed-control-transport.js';

/** Deterministically derived from the canonical connected method contract.
 * A method's presence is not a permission: hello records the actual installed
 * composition, and the Supervisor retains every per-request authority gate. */
export type InstalledSupervisorClient = Readonly<{
  hello: InstalledControlResultFor<'control.hello'>;
  close(): Promise<void>;
}> & Readonly<{ [M in InstalledControlFeature]:
  (request: Extract<InstalledControlRequestV1, { method: M }>) => Promise<InstalledControlResponseFor<M>> }>;

/** Observe/connect only. Unlike the explicit credential ensure path this does
 * not start, install, reload or recover the Supervisor. One request at a time;
 * a failed transport is never reconnected or replayed by this client. */
export async function openInstalledSupervisorClient(selected: HeldInstalledRuntime): Promise<InstalledSupervisorClient> {
  const transport = await openInstalledControlTransport(selected, 'control');
  const methods = Object.fromEntries(INSTALLED_CONTROL_FEATURES.map(method => [method,
    function(this: InstalledSupervisorClient, request: InstalledControlRequestV1) {
      if (this !== client) return Promise.reject(new TypeError('invalid installed control method receiver'));
      try {
        const candidate = decodeInstalledControlRequest(request);
        if (candidate.method !== method) throw new TypeError('installed control request method differs');
        return transport.request(candidate);
      } catch (error) { return Promise.reject(error); }
    }]));
  const client = Object.freeze({ hello: transport.hello, ...methods,
    close(this: InstalledSupervisorClient) {
      if (this !== client) return Promise.reject(new TypeError('invalid installed control client'));
      return transport.close();
    }
  }) as InstalledSupervisorClient;
  return client;
}
