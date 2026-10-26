/** Inert signed data and retained evidence. No value here grants execution. */
export type SignedKernelSchemaV1 = {
  schemaVersion: 1;
  format: 'cliq-signed-kernel-schema-v1';
  applicationId: number;
  stateSchemaVersion: 8;
  schemaManifest: {
    schemaVersion: 1; format: 'cliq-kernel-schema-manifest-v1'; applicationId: number;
    userVersion: 8; schemaDigest: string; manifestDigest: string;
  };
  ddl: string;
  catalog: Array<{ type: string; name: string; tbl_name: string; sql: string | null }>;
  catalogDigest: string;
  profileDigest: string;
};

export type SignedSchemaConversionV1 = {
  schemaVersion: 1;
  format: 'cliq-signed-schema-conversion-v1';
  conversion: 'retired_signed_7_to_8';
  source: {
    kind: 'recognized_generated_schema_v1';
    runtimeBundleRef: string; runtimeBundleManifestDigest: string;
    supervisorEntryId: string; supervisorEntryVersion: string; supervisorExecutableDigest: string;
    schemaManifestRef: string; schemaManifestDigest: string;
    schemaDigest: string; catalogDigest: string;
  };
  targetSchemaRef: string;
  targetSchemaDigest: string;
  statements: string;
  statementsDigest: string;
  profileDigest: string;
};

export type RuntimeUpgradeReceiptV1 = {
  schemaVersion: 1; format: 'cliq-runtime-upgrade-receipt-v1';
  sourceOwnerEpoch: number; sourceOwnerRowDigest: string;
  sourceRuntimeBundleRef: string; sourceRuntimeBundleManifestDigest: string;
  sourceGenerationRef: string; sourceGenerationDigest: string;
  targetRuntimeBundleRef: string; targetRuntimeBundleManifestDigest: string;
  conversionRef: string; conversionDigest: string;
  targetSchemaRef: string; targetSchemaDigest: string;
  sourceSchemaVersion: 7; targetSchemaVersion: 8;
  stateRootIdentityRef: string; stateRootIdentityDigest: string;
  stateLockIdentityRef: string; stateLockIdentityDigest: string;
  retirementRef: string; retirementDigest: string;
  installation: { kind: 'not_installed' } | InstalledUpgradeSourceV1;
  targetOwner: {
    ownerEpoch: number; supervisorInstanceId: string;
    processIdentityRef: string; processIdentityDigest: string;
    instanceNonceDigest: string; acquiredAt: string;
  };
  receiptDigest: string;
};

export type RuntimeUpgradeRetirementV1 = {
  schemaVersion: 1; format: 'cliq-retired-runtime-cut-v1';
  sourceOwnerEpoch: number; sourceOwnerRowDigest: string;
  sourceProcessIdentityRef: string; sourceProcessIdentityDigest: string;
  sourceProcessObservation: 'absent_or_start_token_mismatch';
  resourceIndexRefs: Record<RuntimeUpgradeResourceFamilyV1, string>;
  totalRowCount: number;
  sourceDataVersion: number; sourceTotalChanges: number;
  observedAt: string;
  retirementDigest: string;
};

export type RuntimeUpgradeResourceFamilyV1 = 'run_terminal' | 'worker_launch' | 'workspace_generation' | 'source_inspection';
export type RuntimeUpgradeResourceIndexV1 = {
  schemaVersion: 1; format: 'cliq-upgrade-resource-index-v1';
  family: RuntimeUpgradeResourceFamilyV1;
  sourceOwnerEpoch: number; sourceOwnerRowDigest: string;
  rowCount: number; pageCount: number; pageRefs: string[];
  orderedRefsDigest: string; indexDigest: string;
};
export type RuntimeUpgradeResourcePageV1 = {
  schemaVersion: 1; format: 'cliq-upgrade-resource-ref-page-v1';
  family: RuntimeUpgradeResourceFamilyV1;
  sourceOwnerEpoch: number; sourceOwnerRowDigest: string;
  pageIndex: number; firstOrdinal: number; rowRefs: string[]; pageDigest: string;
};

export type InstalledUpgradeIdentityV1 = {
  deviceId: string; fileId: string; ownerUid: number; ownerGid: number; mode: number;
};
export type InstalledUpgradeSourceV1 = {
  kind: 'held_installed_stage';
  stageName: string;
  stageIdentity: InstalledUpgradeIdentityV1;
  runtimeIdentity: InstalledUpgradeIdentityV1;
  targetBundleIdentity: InstalledUpgradeIdentityV1;
  originalActiveIdentity: InstalledUpgradeIdentityV1;
  originalBootstrapIdentity: InstalledUpgradeIdentityV1;
  stagedActiveIdentity: InstalledUpgradeIdentityV1;
  stagedBootstrapIdentity: InstalledUpgradeIdentityV1;
  sourceBundleDigest: string;
  targetBundleDigest: string;
  targetModelAuthorityRef?: string;
  originalActiveDigest: string;
  originalBootstrapDigest: string;
  originalKeeper: {
    pid: number; processStartToken: string; locatorDigest: string;
    bootIdentityHex: string; observedAt: string; readyIdentity: InstalledUpgradeIdentityV1;
  };
};
