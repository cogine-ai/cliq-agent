import os from 'node:os';
import path from 'node:path';
import { canonicalSha256 } from '../kernel/canonical.js';
import { normalizeAbsolutePath } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { withHeldInstalledRuntime, type HeldInstalledRuntime } from '../state/installed-runtime.js';
import { joinResourceOperations } from '../state/errors.js';
import { guestToolchainRoots } from '../state/guest-toolchain.js';
import { openPrivateClientDirectory } from './private-files.js';
import { openPendingRequests, type PendingRequestBinding } from './pending-requests.js';
import { readClientPreferences } from './preferences.js';

/** Account and installation locators only. The caller must still authenticate
 * the real selected image and server; none of these bytes grant an operation. */
export function installedClientDataPath(accountHome: string, stateRoot: PendingRequestBinding['stateRoot']): string {
  if (normalizeAbsolutePath(accountHome) !== accountHome || normalizeAbsolutePath(stateRoot.canonicalPath) !== stateRoot.canonicalPath)
    throw new TypeError('client data requires canonical account and installation locators');
  return path.join(accountHome, '.cliq', 'client-v1', 'installations', canonicalSha256(stateRoot));
}

/** One actual installed host owns these files through the complete client join.
 * Preferences and original requests are private data, never StateOwner, Trust,
 * credentials or a permission to retry. No environment home override exists. */
export async function openInstalledClientData(selected: HeldInstalledRuntime) {
  const { context, native } = await withHeldInstalledRuntime(selected, async installed => {
    const roots = guestToolchainRoots(installed.bundle);
    return { native: await installed.loadStateOwner(),
      context: immutableSnapshot({ stateRoot: installed.stateRoot, sourceBundleDigest: installed.bundleDigest,
        ...(roots.length === 1 ? { guestToolchainManifestId: roots[0]!.artifactId } : {}) }) };
  });
  const user = os.userInfo();
  if (process.platform !== 'linux' || process.geteuid?.() !== user.uid || context.stateRoot.ownerUid !== user.uid)
    throw new TypeError('installed client data belongs to another operating-system account');
  const directory = await openPrivateClientDirectory(installedClientDataPath(user.homedir, context.stateRoot), { create: true, native });
  let pending: Awaited<ReturnType<typeof openPendingRequests>> | undefined;
  try {
    pending = await openPendingRequests(directory, context);
    const requests = pending;
    let closing: Promise<void> | undefined;
    return Object.freeze({ directory, requests, stateRoot: context.stateRoot, sourceBundleDigest: context.sourceBundleDigest,
      accountHome: user.homedir,
      async commandDefaults() {
        return { preferences: await readClientPreferences(directory),
          ...(context.guestToolchainManifestId ? { guestToolchainManifestId: context.guestToolchainManifestId } : {}) };
      },
      close(): Promise<void> {
        return closing ??= (async () => {
          const [closed] = await Promise.allSettled([requests.close()]);
          await joinResourceOperations([closed.status === 'rejected' ? Promise.reject(closed.reason) : Promise.resolve(), directory.close()]);
        })();
      } });
  } catch (error) {
    await joinResourceOperations([Promise.reject(error), pending?.close(), directory.close()]);
    throw error;
  }
}

export type InstalledClientData = Awaited<ReturnType<typeof openInstalledClientData>>;
