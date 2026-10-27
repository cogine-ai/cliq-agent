import type { ArtifactRef } from './types.js';

/** Declarative retained data only. A typed value or a published CAS object
 * does not supply permission to read a live workspace or consume a grant. */
type SourceIncludeAuthorizationBase = {
  schemaVersion: 1;
  format: 'cliq-source-include-authorization-v1';
  principalId: string;
  inspectionId: string;
  runId: string;
  sessionId: string;
  workspaceIdentityRef: ArtifactRef;
  workspaceIdentityDigest: string;
  selector: { path: string; scope: 'entry' | 'subtree' };
  selectorDigest: string;
  admissionIntentDigest: string;
  capturedEntriesRef: ArtifactRef;
  capturedTreeDigest: string;
  createdAt: string;
  authorizationDigest: string;
};

export type SourceIncludeAuthorizationV1 = SourceIncludeAuthorizationBase & (
  | {
      kind: 'builtin_nonignored';
      frozenIgnoreRulesRef: ArtifactRef;
      frozenIgnoreRulesDigest: string;
      classification: 'tracked_or_nonignored_in_root';
      classificationEvidenceRef: ArtifactRef;
      classificationEvidenceDigest: string;
    }
  | {
      kind: 'consumed_user_read_grant';
      authorizationGrantId: string;
      authorizationGrantTargetDigest: string;
      consumedGrantSnapshotRef: ArtifactRef;
      consumptionReceiptRef: ArtifactRef;
      consumptionReceiptDigest: string;
    }
);
