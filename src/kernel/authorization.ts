import type { ArtifactRef } from './types.js';

export type AuthorizationGrantTargetV1 =
  | { kind: 'read_scope'; purpose: 'source'; workspaceIdentityDigest: string;
      canonicalRootRelativePath: string; scope: 'entry' | 'subtree'; expectedDigest?: string }
  | { kind: 'execution_identity_read'; purpose: 'verifier'; identity:
      | { kind: 'guest_toolchain'; guestToolchainManifestRef: ArtifactRef; manifestDigest: string;
          toolId: string; executionPath: string; executableDigest: string }
      | { kind: 'workspace_script'; workspaceIdentityDigest: string; canonicalRootRelativePath: string;
          scriptDigest: string; interpreterIdentityRef: ArtifactRef; interpreterIdentityDigest: string } }
  | { kind: 'execution_identity_read'; purpose: 'mcp_stdio'; identity:
      | { kind: 'guest_toolchain'; guestToolchainManifestRef: ArtifactRef; manifestDigest: string;
          toolId: string; executionPath: string; executableDigest: string }
      | { kind: 'runtime_bundle_executable'; runtimeBundleRef: ArtifactRef; runtimeBundleManifestDigest: string;
          executableId: string; executionPath: string; executableDigest: string } }
  | { kind: 'verifier_execution'; verifierId: string; verifierRequestCoreDigest: string;
      executionIdentityGrantId: string; executionIdentityTargetDigest: string;
      maxCandidateGenerations: number; maxAttemptsPerCandidate: number }
  | { kind: 'dependency_install_scripts'; workspaceIdentityDigest: string;
      lockfilePath: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock'; lockfileDigest: string };

export type AuthorizationGrantBaseV1 = {
  schemaVersion: 1; grantId: string; ownerPrincipalId: string;
  channelIdentityRef: ArtifactRef; channelIdentityDigest: string;
  sourceRequestId: string; sourceRequestDigest: string;
  target: AuthorizationGrantTargetV1; targetDigest: string; maxUses: 1;
  rowVersion: number; createdAt: string; expiresAt: string; grantCoreDigest: string;
};
export type AuthorizationGrantV1 = AuthorizationGrantBaseV1 & (
  | { state: 'active'; useCount: 0; consumptionReceiptRef?: never; consumedAt?: never;
      revokedByRequestId?: never; revokedAt?: never; rowDigest: string }
  | { state: 'consumed'; useCount: 1; consumptionReceiptRef: ArtifactRef; consumedAt: string;
      revokedByRequestId?: never; revokedAt?: never; rowDigest: string }
  | { state: 'revoked'; useCount: 0; consumptionReceiptRef?: never; consumedAt?: never;
      revokedByRequestId: string; revokedAt: string; rowDigest: string }
);
export type AuthorizationConsumptionReceiptV1 = {
  schemaVersion: 1; grantId: string; ownerPrincipalId: string; targetDigest: string;
  consumer:
    | { kind: 'run_admission'; runId: string; admissionIntentDigest: string }
    | { kind: 'mcp_registration'; registrationId: string; registryRevision: number }
    | { kind: 'authorization_derivation'; derivedGrantId: string };
  consumedAt: string; receiptDigest: string;
};
export type AuthorizationGrantSummaryV1 = {
  schemaVersion: 1; grantId: string; state: AuthorizationGrantV1['state'];
  targetKind: AuthorizationGrantTargetV1['kind'];
  purpose: 'source' | 'verifier' | 'mcp_stdio' | 'dependency_install_scripts';
  targetDigest: string; useCount: 0 | 1; rowVersion: number; createdAt: string; expiresAt: string;
  consumedAt?: string; revokedAt?: string;
};

/** The implemented public identity-read branch. Other RFC decisions are
 * refused explicitly until their complete consumers exist. */
export type VerifierIdentityCreateRequest = {
  protocolVersion: 1; method: 'authorization.create'; requestId: string; requestDigest: string; ttlMs?: number;
  decision: { kind: 'execution_identity_read'; purpose: 'verifier';
    target: { kind: 'guest_toolchain'; guestToolchainManifestId: string; toolId: string } };
};
export type AuthorizationRevokeRequest = {
  protocolVersion: 1; method: 'authorization.revoke'; requestId: string; requestDigest: string; grantId: string;
};
export type AuthorizationResponse = { protocolVersion: 1; ok: true; result:
  | { method: 'authorization.create'; grant: AuthorizationGrantSummaryV1 }
  | { method: 'authorization.revoke'; disposition: 'revoked' | 'already_revoked' | 'already_consumed'; grant: AuthorizationGrantSummaryV1 }
};
