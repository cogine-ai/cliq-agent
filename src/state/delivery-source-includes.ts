import type { SourceSelectorRequest } from '../kernel/control-submit.js';
import type { SourceProjectionSpec } from '../kernel/types.js';
import type { SourceIncludeAuthorizationV1 } from '../kernel/source-include.js';
import { immutableSnapshot } from '../model/immutable.js';
import { VerifierAuthorizationError } from './authorization-artifacts.js';
import { canonicalSha256 } from '../kernel/canonical.js';

/** Selection data only. The caller fully verifies B's immutable closure;
 * the existing first capture transaction independently verifies and consumes
 * each fresh grant. No caller path, old receipt or ref becomes read authority. */
export function deliverySourceIncludes(projection: SourceProjectionSpec,
  authorizations: readonly Readonly<SourceIncludeAuthorizationV1>[], grantIds: readonly string[]): readonly SourceSelectorRequest[] {
  if (authorizations.length !== projection.explicitIncludes.length || grantIds.length > 128 || new Set(grantIds).size !== grantIds.length)
    throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
  let ordinal = 0;
  const result = projection.explicitIncludes.map((selector, index) => {
    const authorization = authorizations[index]!;
    if (canonicalSha256(authorization) !== selector.authorizationRef ||
        authorization.selector.path !== selector.path || authorization.selector.scope !== selector.scope)
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    if (authorization.kind === 'builtin_nonignored') return { path: selector.path, scope: selector.scope };
    const readGrantId = grantIds[ordinal++];
    if (!readGrantId || readGrantId === authorization.authorizationGrantId)
      throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
    return { path: selector.path, scope: selector.scope, readGrantId };
  });
  if (ordinal !== grantIds.length) throw new VerifierAuthorizationError('AUTHORIZATION_REQUIRED');
  return immutableSnapshot(result);
}
