import type { NormalizedRunSubmitRequest } from '../kernel/control-submit.js';
import { DEPENDENCY_LIMITS } from '../kernel/dependency.js';
import { effectiveSourceExcludes } from '../kernel/dependency-source.js';
import { KernelStorageError } from './errors.js';

/** Fixed supported request data, not a permission, native capability or a
 * promise that every plan below these ceilings fits the metadata budgets. */
export function assertInstalledDependencyRequest(request: NormalizedRunSubmitRequest): void {
  if (request.dependency.mode === 'none') return;
  const input = request.dependency;
  if (request.model.provider !== 'openai-compatible' || !input.registryEndpointIds.length || input.credentialGrantIds.length ||
      (input.maxPackages ?? DEPENDENCY_LIMITS.defaultPackages) > DEPENDENCY_LIMITS.maxPackages ||
      (input.maxDownloadBytes ?? DEPENDENCY_LIMITS.defaultDownloadBytes) > DEPENDENCY_LIMITS.maxDownloadBytes)
    throw new KernelStorageError('UNSUPPORTED_PLATFORM', 'only the fixed public single-root locked npm dependency profile is supported');
  effectiveSourceExcludes(request);
}
