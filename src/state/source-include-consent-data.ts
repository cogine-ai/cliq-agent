import { canonicalSha256 } from '../kernel/canonical.js';
import type { SourceSelectorRequest } from '../kernel/control-submit.js';
import type { SourceInspectionAttemptV1, SourceInspectionTarget } from '../kernel/execution.js';
import type { AuthorizationGrantV1 } from '../kernel/authorization.js';
import { assertArtifactRef } from '../kernel/identity.js';
import { readSourceIncludeArtifact } from './source-include-artifacts.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeAuthorizationConsumptionReceipt, decodeAuthorizationGrant } from './authorization-artifacts.js';
import { assertSourceIncludeConstraintScope } from './source-include-constraints.js';

/** Original immutable consent closure only. The owning reader separately
 * checks actual SQL consumption and the authenticated grant creation history.
 * No ref, receipt or snapshot can authorize another read of mutable source. */
export async function readSourceIncludeConsentSnapshots(artifacts: ArtifactCatalog,
  attempt: SourceInspectionAttemptV1, target: SourceInspectionTarget,
  selection: readonly SourceSelectorRequest[] | Readonly<{ grantIds: readonly string[] }>) {
  const selectors = 'grantIds' in selection ? undefined : selection;
  const selected = selectors?.filter(selector => selector.readGrantId !== undefined);
  const grantIds = 'grantIds' in selection ? selection.grantIds : selected!.map(selector => selector.readGrantId!);
  const refs = target.sourceReadGrantRefs;
  if (!Array.isArray(refs) || refs.length > 128 || refs.length !== grantIds.length ||
      new Set(refs).size !== refs.length || new Set(grantIds).size !== grantIds.length)
    throw new TypeError('source include snapshots differ from the original one-use selectors');
  const grants: Extract<AuthorizationGrantV1, { state: 'consumed' }>[] = [];
  for (let index = 0; index < refs.length; index++) {
    const ref = refs[index]!, selector = selected?.[index];
    assertArtifactRef(ref);
    const grant = decodeAuthorizationGrant(await readSourceIncludeArtifact(artifacts, ref));
    if (canonicalSha256(grant) !== ref || grant.state !== 'consumed' || grant.grantId !== grantIds[index] ||
        grant.ownerPrincipalId !== attempt.principalId || grant.target.kind !== 'read_scope' || grant.target.purpose !== 'source' ||
        grant.target.workspaceIdentityDigest !== attempt.workspaceIdentityDigest ||
        selector && (grant.target.canonicalRootRelativePath !== selector.path || grant.target.scope !== selector.scope) ||
        grant.consumedAt > attempt.createdAt || attempt.createdAt >= grant.expiresAt)
      throw new TypeError('source include snapshot differs from its original capture selector or interval');
    assertSourceIncludeConstraintScope(grant.target);
    const receipt = decodeAuthorizationConsumptionReceipt(await readSourceIncludeArtifact(artifacts, grant.consumptionReceiptRef));
    if (canonicalSha256(receipt) !== grant.consumptionReceiptRef || receipt.grantId !== grant.grantId ||
        receipt.ownerPrincipalId !== attempt.principalId || receipt.targetDigest !== grant.targetDigest ||
        receipt.consumedAt !== grant.consumedAt || receipt.consumer.kind !== 'source_inspection' ||
        receipt.consumer.inspectionId !== attempt.inspectionId || receipt.consumer.admissionIntentDigest !== attempt.admissionIntentDigest)
      throw new TypeError('source include snapshot lost its exact original capture receipt');
    grants.push(grant);
  }
  return Object.freeze(grants);
}
