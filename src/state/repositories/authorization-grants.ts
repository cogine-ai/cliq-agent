import { canonicalJsonBytes, canonicalSha256 } from '../../kernel/canonical.js';
import type { AuthorizationGrantV1 } from '../../kernel/authorization.js';
import { decodeAuthorizationGrant, authorizationGrantCore } from '../authorization-artifacts.js';
import { KernelStorageError } from '../errors.js';
import type { SqliteConnection, SqliteDriver } from '../sqlite-driver.js';

export function readAuthorizationGrant(connection: SqliteConnection | SqliteDriver, grantId: string): AuthorizationGrantV1 | undefined {
  const row = connection.prepare('SELECT grant_id, owner_principal_id, state, row_json FROM authorization_grants WHERE grant_id = ?')
    .get<{ grant_id: string; owner_principal_id: string; state: string; row_json: string }>(grantId);
  if (!row) return undefined;
  try {
    const grant = decodeAuthorizationGrant(JSON.parse(row.row_json));
    if (grant.grantId !== row.grant_id || grant.ownerPrincipalId !== row.owner_principal_id || grant.state !== row.state ||
        canonicalJsonBytes(grant).toString() !== row.row_json) throw new TypeError('authorization columns or bytes differ');
    return grant;
  } catch (cause) { throw new KernelStorageError('RECOVERY_REQUIRED', 'authorization row has invalid retained provenance', { cause }); }
}
export function insertAuthorizationGrant(connection: SqliteConnection, grant: AuthorizationGrantV1): void {
  decodeAuthorizationGrant(grant);
  if (grant.state !== 'active') throw new TypeError('new authorization must be active');
  connection.prepare('INSERT INTO authorization_grants (grant_id, owner_principal_id, state, row_json) VALUES (?, ?, ?, ?)')
    .run(grant.grantId, grant.ownerPrincipalId, grant.state, canonicalJsonBytes(grant).toString());
}
export function consumeOrRevokeAuthorization(connection: SqliteConnection, prior: AuthorizationGrantV1, next: AuthorizationGrantV1): void {
  decodeAuthorizationGrant(prior); decodeAuthorizationGrant(next);
  if (prior.state !== 'active' || next.state === 'active' || canonicalSha256(authorizationGrantCore(prior)) !== canonicalSha256(authorizationGrantCore(next)))
    throw new TypeError('authorization transition rewrites authority or terminal state');
  const changed = connection.prepare("UPDATE authorization_grants SET state = ?, row_json = ? WHERE grant_id = ? AND owner_principal_id = ? AND state = 'active' AND row_json = ?")
    .run(next.state, canonicalJsonBytes(next).toString(), prior.grantId, prior.ownerPrincipalId, canonicalJsonBytes(prior).toString());
  if (changed.changes !== 1n) throw new KernelStorageError('REVISION_CONFLICT', 'authorization was consumed or revoked concurrently');
}
