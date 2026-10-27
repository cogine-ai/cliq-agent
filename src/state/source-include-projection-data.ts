import { canonicalSha256 } from '../kernel/canonical.js';
import { setImmediate } from 'node:timers/promises';
import type { FrozenIgnoreRulesV1, GitIndexSnapshotV1, SourceProjectionSpec, WorkspaceEntryManifest } from '../kernel/types.js';
import { createSourceClassifier } from '../workspace/source-classification.js';
import type { ArtifactCatalog } from './artifacts.js';
import { decodeSourceIncludeAuthorization, readSourceIncludeArtifact, readSourceIncludeGrantReceipt } from './source-include-artifacts.js';
import { readSourceIncludeClassification } from './source-include-classification.js';
import { decodeWorkspaceEntries } from './decoders.js';
import { decodeAuthorizationGrant } from './authorization-artifacts.js';
import { assertSourceIncludeConstraintScope, assertSourceIncludeExpectedDigest } from './source-include-constraints.js';

/** Immutable selection data only. SQL consumers independently bind these
 * original receipts/observations to the actual admitted, retired capture.
 * This function never grants permission to read a live user's workspace. */
export async function readSourceIncludeProjectionData(artifacts: Pick<ArtifactCatalog,'readBoundedBytes'|'readCanonical'|'readChunks'>,
  projection: SourceProjectionSpec, workspaceIdentityDigest: string, rules: FrozenIgnoreRulesV1,
  index?: GitIndexSnapshotV1, originalEntries?: WorkspaceEntryManifest, signal?: AbortSignal) {
  const classifier = createSourceClassifier(rules,index);
  const users: Array<{path:string;scope:'entry'|'subtree'}> = [];
  const authorizations = [];
  const observations: Array<{authorizationRef:string;observedAt:string;capturedEntriesRef:string;capturedTreeDigest:string}> = [];
  let identity: string | undefined;
  for (const selector of projection.explicitIncludes) {
    signal?.throwIfAborted();
    const authorization = decodeSourceIncludeAuthorization(await readSourceIncludeArtifact(artifacts,selector.authorizationRef));
    if (canonicalSha256(authorization) !== selector.authorizationRef || authorization.workspaceIdentityDigest !== workspaceIdentityDigest ||
        authorization.selector.path !== selector.path || authorization.selector.scope !== selector.scope)
      throw new TypeError('source include authorization differs from the exact original projection selector');
    const actualIdentity = canonicalSha256({principalId:authorization.principalId,inspectionId:authorization.inspectionId,
      runId:authorization.runId,sessionId:authorization.sessionId,workspaceIdentityRef:authorization.workspaceIdentityRef,
      workspaceIdentityDigest:authorization.workspaceIdentityDigest,admissionIntentDigest:authorization.admissionIntentDigest,
      createdAt:authorization.createdAt});
    if (identity !== undefined && identity !== actualIdentity) throw new TypeError('source includes substitute another original capture');
    identity = actualIdentity;
    // Workspace entries are the existing full typed source artifact, not an
    // inline authorization/page. Preserve its original reader contract while
    // checking the exact canonical ref and full tree independently.
    const captured = decodeWorkspaceEntries(await artifacts.readCanonical(authorization.capturedEntriesRef));
    if (canonicalSha256(captured) !== authorization.capturedEntriesRef || captured.treeDigest !== authorization.capturedTreeDigest ||
        originalEntries && canonicalSha256(originalEntries) !== authorization.capturedEntriesRef)
      throw new TypeError('source include substitutes its complete original captured entries');
    if (!captured.entries.some(entry => entry.path === selector.path))
      throw new TypeError('source include has no exact entry in its original capture');
    if (authorization.kind === 'consumed_user_read_grant') {
      const receipt = readSourceIncludeGrantReceipt(authorization,await readSourceIncludeArtifact(artifacts,authorization.consumptionReceiptRef));
      const grant = decodeAuthorizationGrant(await readSourceIncludeArtifact(artifacts,authorization.consumedGrantSnapshotRef));
      if (canonicalSha256(grant) !== authorization.consumedGrantSnapshotRef || grant.state !== 'consumed' ||
          grant.grantId !== authorization.authorizationGrantId || grant.ownerPrincipalId !== authorization.principalId ||
          grant.targetDigest !== authorization.authorizationGrantTargetDigest || grant.target.kind !== 'read_scope' ||
          grant.target.purpose !== 'source' || grant.target.workspaceIdentityDigest !== authorization.workspaceIdentityDigest ||
          grant.target.canonicalRootRelativePath !== selector.path || grant.target.scope !== selector.scope ||
          grant.consumptionReceiptRef !== authorization.consumptionReceiptRef || grant.consumedAt !== receipt.consumedAt ||
          grant.createdAt > grant.consumedAt || grant.consumedAt > authorization.createdAt || authorization.createdAt >= grant.expiresAt)
        throw new TypeError('source include lost its complete original consumed-grant constraint');
      assertSourceIncludeConstraintScope(grant.target);
      assertSourceIncludeExpectedDigest(grant.target,captured);
      if (grant.target.expectedDigest !== undefined) {
        const entry = captured.entries.find(entry => entry.path === selector.path);
        if (entry?.kind !== 'file') throw new TypeError('constrained source include has no original regular file');
        for await (const _chunk of artifacts.readChunks(entry.blobRef,entry.size)) signal?.throwIfAborted();
      }
      users.push({path:selector.path,scope:selector.scope});
    } else {
      const { evidence,entries } = await readSourceIncludeClassification(artifacts,authorization.classificationEvidenceRef);
      if (evidence.evidenceDigest !== authorization.classificationEvidenceDigest ||
          authorization.frozenIgnoreRulesRef !== projection.frozenIgnoreRulesRef ||
          authorization.frozenIgnoreRulesDigest !== projection.frozenIgnoreRulesDigest ||
          evidence.frozenIgnoreRulesRef !== projection.frozenIgnoreRulesRef || evidence.frozenIgnoreRulesDigest !== rules.rulesDigest ||
          evidence.capturedEntriesRef !== authorization.capturedEntriesRef || evidence.capturedTreeDigest !== authorization.capturedTreeDigest ||
          evidence.observedAt < authorization.createdAt ||
          ['principalId','inspectionId','runId','sessionId','workspaceIdentityRef','workspaceIdentityDigest',
            'selectorDigest','admissionIntentDigest'].some(key =>
              evidence[key as keyof typeof evidence] !== authorization[key as keyof typeof authorization]) ||
          canonicalSha256(evidence.selector) !== canonicalSha256(authorization.selector))
        throw new TypeError('source include classification differs from its original authorization and frozen rules');
      if (evidence.gitIndexRef !== undefined && (!index || evidence.gitIndexRef !== projection.classificationIndexRef ||
          evidence.gitIndexTreeObjectId !== index.indexTreeObjectId))
        throw new TypeError('source include classification substitutes another optional Git index');
      observations.push({authorizationRef:selector.authorizationRef,observedAt:evidence.observedAt,
        capturedEntriesRef:evidence.capturedEntriesRef,capturedTreeDigest:evidence.capturedTreeDigest});
      const originals = new Map(captured.entries.filter(entry => entry.path === selector.path ||
        selector.scope === 'subtree' && entry.path.startsWith(`${selector.path}/`)).map(entry => [entry.path,entry]));
      if (originals.size !== entries.length) throw new TypeError('source include classification does not exactly cover its original manifest');
      for (let ordinal=0;ordinal<entries.length;ordinal++) {
        if (ordinal % 128 === 0) { await setImmediate();signal?.throwIfAborted(); }
        const entry = entries[ordinal]!;
        if (entry.path !== selector.path && !(selector.scope === 'subtree' && entry.path.startsWith(`${selector.path}/`)))
          throw new TypeError('source include classification escapes its exact selector');
        const original = originals.get(entry.path);
        if (!original || original.kind !== entry.entryKind || canonicalSha256(original) !== entry.workspaceEntryDigest)
          throw new TypeError('source include classification differs from complete original WorkspaceEntry bytes');
        if (classifier.classify({path:entry.path,kind:entry.entryKind}) !== entry.classification)
          throw new TypeError('source include classification differs from its exact frozen matcher and index');
        if (entry.classification !== 'nonignored_in_root' && (!index || evidence.gitIndexRef !== projection.classificationIndexRef ||
            evidence.gitIndexTreeObjectId !== index.indexTreeObjectId))
          throw new TypeError('source include tracked classification has no exact original canonical Git index');
      }
    }
    authorizations.push(authorization);
  }
  return Object.freeze({users:Object.freeze(users),authorizations:Object.freeze(authorizations),observations:Object.freeze(observations)});
}
