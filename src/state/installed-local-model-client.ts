import { canonicalJsonBytes } from '../kernel/canonical.js';
import { KernelStorageError } from './errors.js';
import { runHeldInstalledLocalModelRole, type HeldInstalledRuntime } from './installed-runtime.js';
import { decodeInstalledLocalModelRequest, decodeInstalledLocalModelSummaries,
  type InstalledLocalModelRequest, type InstalledLocalModelSummary } from './local-model-operations.js';

export async function runInstalledLocalModelRequest(selected: HeldInstalledRuntime, value: InstalledLocalModelRequest,
  signal?: AbortSignal): Promise<readonly InstalledLocalModelSummary[]> {
  const request = decodeInstalledLocalModelRequest(value);
  const response = await runHeldInstalledLocalModelRole(selected, canonicalJsonBytes(request).toString('base64url'), signal);
  try {
    // The byte-bound, canonical comparison rejects duplicate keys and extra
    // bytes. The summary decoder validates every closed row and array bound.
    // The strict request parser's global entry cap is smaller than a registry.
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(response)) as unknown;
    const summaries = decodeInstalledLocalModelSummaries(data);
    if (!canonicalJsonBytes(summaries).equals(response)) throw new TypeError('noncanonical local model response');
    return summaries;
  } catch {
    throw new KernelStorageError('RECOVERY_REQUIRED', 'installed model operation returned an invalid summary');
  }
}
