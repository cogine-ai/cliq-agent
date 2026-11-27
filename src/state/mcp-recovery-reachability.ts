// Purpose-specific data edges only. Complete original parent context is
// mandatory; unsupported or missing context invalidates the whole GC walk.
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireRef } from '../kernel/control-wire-data.js';
import { assertBoundedJsonValue } from '../kernel/json.js';
import { decodeMcpAdminProbeTarget, decodeMcpMutationRequest, decodeMcpRegistryRevision,
  type McpAdminProbeTargetV1, type McpAdminProbeResultV1, type McpRegisterRequestV1 } from '../kernel/mcp.js';
import { decodeMcpRecoveryAdapterManifest, decodeMcpRecoveryPredicate, decodeMcpRecoveryStatusRequestTemplate,
  decodeMcpRetryRiskConsent, decodeMcpRetrySafetyAssertion, mcpRetryRequestFromAssertion,
  mcpServerExecutionIdentityDigest, mcpProfileSigningIdentityDigest, type McpRecoveryAdapterManifestV1 } from '../kernel/mcp-recovery.js';
import type { CoreRetentionArtifactPurpose } from '../kernel/retention-purpose.js';
import { requireEqual, type ReleaseTrustKey, type RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { selectMcpRecoveryProfile, verifyMcpRecoveryAdapterAuthority } from '../policy/mcp-recovery-authority.js';

export const MCP_RECOVERY_REACHABILITY_PURPOSES = ['mcp_retry_risk_consent', 'mcp_retry_safety_assertion',
  'mcp_recovery_adapter_manifest', 'mcp_recovery_status_template', 'mcp_recovery_static_arguments', 'mcp_recovery_predicate'] as const;
export type McpRecoveryReachabilityPurpose = typeof MCP_RECOVERY_REACHABILITY_PURPOSES[number];
// The original raw Admin result has its own closed production decoder. The
// graph owner must implement that purpose too, or reject the whole walk.
export type McpRecoveryDependencyPurpose = 'mcp_admin_probe_result';
type Edge = Readonly<{ ref: string; purpose: CoreRetentionArtifactPurpose | McpRecoveryReachabilityPurpose | McpRecoveryDependencyPurpose }>;
type AdapterContext = Readonly<{ bundle: RuntimeBundleManifest; releaseKeys: readonly ReleaseTrustKey[]; adapterRef: string }>;
export type McpRecoveryReachabilityContext =
  Readonly<{ kind: 'original_retry'; request: McpRegisterRequestV1; target: McpAdminProbeTargetV1; consent: unknown; assertion: unknown }> |
  (AdapterContext & Readonly<{ kind: 'adapter' }>) |
  (AdapterContext & Readonly<{ kind: 'template'; manifest: McpRecoveryAdapterManifestV1; target: McpAdminProbeTargetV1;
    result: McpAdminProbeResultV1; registryRevision: number }>) |
  (AdapterContext & Readonly<{ kind: 'profile_member'; manifest: McpRecoveryAdapterManifestV1; profileId: string;
    memberRef: string; memberKind: 'static_arguments' | 'completed' | 'failed' }>);
export class UnsupportedMcpRecoveryReachability extends TypeError {
  constructor() { super('unsupported or incomplete original MCP recovery retention context'); }
}
function unsupported(): never { throw new UnsupportedMcpRecoveryReachability(); }
function adapter(context: AdapterContext, manifestValue: unknown) {
  const manifest = decodeMcpRecoveryAdapterManifest(manifestValue);
  return verifyMcpRecoveryAdapterAuthority({ bundle: context.bundle, releaseKeys: context.releaseKeys,
    adapterId: manifest.adapterId, adapterRef: context.adapterRef, manifest });
}
export function readMcpRecoveryArtifactEdges(purpose: McpRecoveryReachabilityPurpose, value: unknown,
  context?: McpRecoveryReachabilityContext): readonly Edge[] {
  if (!context) unsupported();
  assertControlWireJson(value);
  const edges: Edge[] = [], add = (ref: string, use: Edge['purpose']) => edges.push({ ref: controlWireRef(ref), purpose: use });
  if (purpose === 'mcp_retry_risk_consent' || purpose === 'mcp_retry_safety_assertion') {
    if (context.kind !== 'original_retry') unsupported();
    const target = decodeMcpAdminProbeTarget(context.target), request = decodeMcpMutationRequest(context.request);
    const consent = decodeMcpRetryRiskConsent(context.consent), assertion = decodeMcpRetrySafetyAssertion(context.assertion);
    if (request.method !== 'mcp.register' || target.method !== 'mcp.register' || target.originalRequestRef !== canonicalSha256(request) ||
        target.registrationId !== request.registrationId || consent.ownerPrincipalId !== target.ownerPrincipalId || assertion.ownerPrincipalId !== target.ownerPrincipalId ||
        consent.registrationId !== target.registrationId || assertion.registrationId !== target.registrationId || consent.serverToolName !== assertion.serverToolName ||
        consent.recoveryRequestDigest !== assertion.recoveryRequestDigest || consent.channelIdentityRef !== target.channelIdentityRef ||
        consent.channelIdentityDigest !== target.channelIdentityDigest || consent.createdAt !== target.createdAt) unsupported();
    const selected = target.requestedToolRecovery.filter(item => item.toolName === consent.serverToolName), original = request.toolRecovery[consent.serverToolName];
    const recovery = selected[0]?.recovery;
    if (selected.length !== 1 || recovery?.kind !== 'retry' || original?.kind !== 'retry' ||
        canonicalSha256(consent) !== recovery.explicitRiskConsentRef || consent.consentDigest !== recovery.explicitRiskConsentDigest ||
        canonicalSha256(assertion) !== recovery.safetyAssertionRef || assertion.assertionDigest !== recovery.safetyAssertionDigest ||
        assertion.idempotencyKeyJsonPointer !== recovery.idempotencyKeyJsonPointer) unsupported();
    requireEqual(mcpRetryRequestFromAssertion(assertion), original, 'MCP retention original normalized retry request');
    requireEqual(value, purpose === 'mcp_retry_risk_consent' ? consent : assertion, 'MCP retention complete original retry artifact');
    if (purpose === 'mcp_retry_risk_consent') add(consent.channelIdentityRef, 'control_channel');
  } else if (purpose === 'mcp_recovery_adapter_manifest') {
    if (context.kind !== 'adapter') unsupported();
    const manifest = adapter(context, value);
    add(manifest.executableDigest, 'image_bytes');
    for (const profile of manifest.profiles) {
      add(profile.staticArgumentsRef, 'mcp_recovery_static_arguments');
      add(profile.completedPredicateRef, 'mcp_recovery_predicate'); add(profile.failedPredicateRef, 'mcp_recovery_predicate');
    }
  } else if (purpose === 'mcp_recovery_status_template') {
    if (context.kind !== 'template') unsupported();
    const template = decodeMcpRecoveryStatusRequestTemplate(value), manifest = adapter(context, context.manifest);
    const profile = selectMcpRecoveryProfile({ bundle: context.bundle, target: context.target, result: context.result, manifest, serverToolName: template.serverToolName });
    const target = decodeMcpAdminProbeTarget(context.target), selection = target.requestedToolRecovery.find(item => item.toolName === template.serverToolName)?.recovery;
    if (selection?.kind !== 'reconcile' || selection.bundledAdapterId !== manifest.adapterId || template.adapterRef !== context.adapterRef ||
        template.adapterDigest !== manifest.adapterDigest || template.profileId !== profile.profileId || template.profileDigest !== profile.profileDigest ||
        template.registrationId !== target.registrationId || template.registryRevision !== context.registryRevision ||
        template.adminProbeTargetRef !== canonicalSha256(target) || template.adminProbeTargetDigest !== target.targetDigest ||
        template.probeResultRef !== canonicalSha256(context.result) || template.probeResultDigest !== context.result.resultDigest ||
        template.serverExecutionIdentityDigest !== mcpServerExecutionIdentityDigest(target.resolvedTransport) ||
        template.profileSigningIdentityDigest !== mcpProfileSigningIdentityDigest(target.resolvedTransport) ||
        template.idempotencyKeyJsonPointer !== selection.idempotencyKeyJsonPointer) unsupported();
    for (const name of ['initializeDigest', 'capabilityDigest', 'probedToolsListDigest', 'effectToolInterfaceDigest', 'statusOperationName', 'statusOperationSemantics',
      'statusToolInterfaceDigest', 'statusInputSchemaDigest', 'statusOutputSchemaDigest', 'staticArgumentsRef', 'staticArgumentsDigest'] as const)
      if (template[name] !== profile[name]) unsupported();
    add(template.adapterRef, 'mcp_recovery_adapter_manifest'); add(template.adminProbeTargetRef, 'mcp_admin_probe_target');
    add(template.probeResultRef, 'mcp_admin_probe_result'); add(template.staticArgumentsRef, 'mcp_recovery_static_arguments');
    add(template.statusInputSchemaDigest, 'opaque_blob'); add(template.statusOutputSchemaDigest, 'opaque_blob');
  } else if (purpose === 'mcp_recovery_static_arguments' || purpose === 'mcp_recovery_predicate') {
    if (context.kind !== 'profile_member') unsupported();
    const manifest = adapter(context, context.manifest), profiles = manifest.profiles.filter(profile => profile.profileId === context.profileId), profile = profiles[0];
    if (profiles.length !== 1 || !profile || context.memberRef !== canonicalSha256(value)) unsupported();
    if (purpose === 'mcp_recovery_static_arguments') {
      assertBoundedJsonValue(value, 'MCP original static status arguments');
      if (context.memberKind !== 'static_arguments' || profile.staticArgumentsRef !== context.memberRef || value === null || typeof value !== 'object' || Array.isArray(value)) unsupported();
    } else {
      const predicate = decodeMcpRecoveryPredicate(value);
      if (context.memberKind === 'static_arguments') unsupported();
      const expected = context.memberKind === 'completed' ? { ref: profile.completedPredicateRef, digest: profile.completedPredicateDigest }
        : { ref: profile.failedPredicateRef, digest: profile.failedPredicateDigest };
      if (context.memberRef !== expected.ref || predicate.predicateDigest !== expected.digest) unsupported();
    }
  } else unsupported();
  return edges;
}
/** Additional fixed recovery edges of already-typed parent artifacts. The
 * caller continues to walk all of each parent's existing non-recovery edges. */
export function readMcpRecoveryParentEdges(purpose: 'mcp_admin_probe_target' | 'mcp_registry_revision', value: unknown): readonly Edge[] {
  const edges: Edge[] = [], add = (ref: string, use: Edge['purpose']) => edges.push({ ref: controlWireRef(ref), purpose: use });
  if (purpose === 'mcp_admin_probe_target') {
    const target = decodeMcpAdminProbeTarget(value);
    for (const item of target.requestedToolRecovery) if (item.recovery.kind === 'retry') {
      add(item.recovery.explicitRiskConsentRef, 'mcp_retry_risk_consent'); add(item.recovery.safetyAssertionRef, 'mcp_retry_safety_assertion');
    }
  } else if (purpose === 'mcp_registry_revision') {
    const registry = decodeMcpRegistryRevision(value);
    for (const tool of registry.tools) {
      if (tool.recovery.kind === 'retry') { add(tool.recovery.explicitRiskConsentRef, 'mcp_retry_risk_consent'); add(tool.recovery.safetyAssertionRef, 'mcp_retry_safety_assertion'); }
      else if (tool.recovery.kind === 'reconcile') {
        add(tool.recovery.adapterRef, 'mcp_recovery_adapter_manifest'); add(tool.recovery.statusRequestTemplateRef, 'mcp_recovery_status_template');
        add(tool.recovery.completedPredicateRef, 'mcp_recovery_predicate'); add(tool.recovery.failedPredicateRef, 'mcp_recovery_predicate');
      }
    }
  } else unsupported();
  return edges;
}
