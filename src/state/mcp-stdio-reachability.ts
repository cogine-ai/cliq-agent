// Explicit data edges for retention. This module never opens a native owner,
// StateOwner, input, scope, grant, release fence or current cleanup capability.
import type { CoreRetentionArtifactPurpose } from '../kernel/retention-purpose.js';
import { sha256Bytes } from '../kernel/identity.js';
import { assertControlWireJson, controlWireRecord, controlWireRef } from '../kernel/control-wire-data.js';
import { decodeMcpServerLaunchPreparation, decodeMcpServerLaunchRequest, decodeMcpServerLaunchTarget, decodeMcpServerOperationGrant,
  decodeMcpServerPolicyChannelEvidence, decodeMcpServerApprovalWait, decodeMcpServerApprovalDecision, decodeMcpServerPolicyDecisionItem,
  decodeMcpServerLaunchFailure, decodeMcpServerFailedStoppedItem } from '../kernel/mcp-server-authorization.js';
import { decodeMcpServerInstanceIdentity, decodeMcpServerLaunchReceipt, decodeMcpServerStoppedItem, decodeMcpStdioCapture,
  decodeMcpStdioCaptureData } from '../kernel/mcp-stdio.js';
import { decodeManualInvocationWait, decodeManualAbandonAttestation, decodeToolAbandonedItem } from '../kernel/mcp.js';
import { decodeMcpInboundMessageData } from '../kernel/mcp-wire.js';
import { parseJsonStrict } from '../kernel/json.js';
import { requireEqual } from '../policy/runtime-authority.js';
import { decodeMcpStdioExecutableIdentity } from './mcp-server-policy.js';
import { decodeMcpStdioRunCaptureRoot, decodeMcpStdioUnusableResponseData } from './mcp-stdio-history.js';
import { decodeMcpStdioAdminCleanupRoot } from './mcp-registration.js';
import { decodeManualDispatchClosureData } from './manual-reconciliation.js';
import { decodeMcpStdioLifecycleData, decodeMcpStdioCleanupData } from './native-owner.js';
import { decodeMcpStdioRecipeData } from './mcp-stdio-recipe.js';

export const MCP_STDIO_REACHABILITY_PURPOSES = [
  'mcp.stdio.launch_preparation', 'mcp.stdio.launch_request', 'mcp.stdio.launch_target', 'mcp.stdio.operation_grant',
  'mcp.stdio.policy_evidence', 'mcp.stdio.approval_wait', 'mcp.stdio.approval_decision', 'mcp.stdio.policy_item',
  'mcp.stdio.executable_identity', 'mcp.stdio.instance_identity', 'mcp.stdio.launch_receipt', 'mcp.stdio.launch_failure',
  'mcp.stdio.stopped_item', 'mcp.stdio.run_capture', 'mcp.stdio.capture', 'mcp.stdio.unusable_response',
  'mcp.stdio.admin_cleanup_root', 'mcp.stdio.native_launch_raw', 'mcp.stdio.native_launch_projection',
  'mcp.stdio.native_cleanup_raw', 'mcp.stdio.native_cleanup_projection', 'mcp.stdio.recipe_bytes',
  'mcp.stdio.manual_wait', 'mcp.stdio.manual_attestation', 'mcp.stdio.abandoned_item', 'mcp.stdio.manual_dispatch_closure'
] as const;
export type McpStdioReachabilityPurpose = typeof MCP_STDIO_REACHABILITY_PURPOSES[number];
export type McpStdioArtifactEdge = Readonly<{ ref: string; purpose: McpStdioReachabilityPurpose | CoreRetentionArtifactPurpose }>;
export type McpStdioReachabilityContext = Readonly<{ kind: 'native_launch_projection' | 'native_cleanup_projection' | 'capture'; rawBytes: Buffer }> |
  Readonly<{ kind: 'unusable_response'; safeMessageBytes: Buffer }>;
export class UnsupportedMcpStdioReachability extends TypeError {
  constructor() { super('unsupported or incomplete MCP stdio retention purpose/context'); }
}

/** The caller still checks every original parent→child binding with the
 * retained production semantic reader. Edges and successful decoding alone
 * never authorize deletion, execution, receipt promotion or current cleanup. */
export function readMcpStdioArtifactEdges(purpose: McpStdioReachabilityPurpose, value: unknown,
  context?: McpStdioReachabilityContext): readonly McpStdioArtifactEdge[] {
  if (!Buffer.isBuffer(value)) assertControlWireJson(value);
  const edges: McpStdioArtifactEdge[] = [];
  const add = (ref: string, use: McpStdioArtifactEdge['purpose']) => { edges.push({ ref: controlWireRef(ref), purpose: use }); };
  const nativeClosure = (data: ReturnType<typeof decodeMcpServerLaunchReceipt>['nativeClosure']) => {
    add(data.lifecycleRawRef, 'mcp.stdio.native_launch_raw'); add(data.lifecycleProjectionRef, 'mcp.stdio.native_launch_projection');
    if (data.kind === 'linux_successor_cleanup') { add(data.cleanupRawRef, 'mcp.stdio.native_cleanup_raw'); add(data.cleanupProjectionRef, 'mcp.stdio.native_cleanup_projection'); }
  };
  const binding = (data: ReturnType<typeof decodeMcpStdioLifecycleData>['binding']) => {
    add(data.targetRef, data.kind === 'run' ? 'mcp_server_launch_target' : 'mcp_admin_probe_target');
    add(data.plannedContainmentRef, data.kind === 'run' ? 'mcp_server_containment_plan' : 'process_containment_plan'); add(data.sandboxLaunchSpecRef, 'sandbox_launch_spec');
    if (data.kind === 'run') {
      add(data.registryRef, 'mcp_registry_revision'); add(data.toolRequestRef, 'tool_request'); add(data.requestRef, 'mcp.stdio.launch_request');
      add(data.grantRef, 'mcp_server_operation_grant');
    } else add(data.probePayloadCoreRef, 'mcp_admin_probe_core');
  };
  const launchBinding = (data: ReturnType<typeof decodeMcpStdioRunCaptureRoot>['launch']) => {
    add(data.registryRef, 'mcp_registry_revision'); add(data.toolRequestRef, 'tool_request'); add(data.requestRef, 'mcp.stdio.launch_request');
    add(data.targetRef, 'mcp_server_launch_target'); add(data.grantRef, 'mcp_server_operation_grant');
    add(data.plannedContainmentRef, 'mcp_server_containment_plan'); add(data.sandboxLaunchSpecRef, 'sandbox_launch_spec');
  };
  switch (purpose) {
    case 'mcp.stdio.launch_preparation': {
      const data = decodeMcpServerLaunchPreparation(value);
      add(data.registryRef, 'mcp_registry_revision'); add(data.toolRequestRef, 'tool_request'); add(data.requestRef, 'mcp.stdio.launch_request');
      add(data.targetRef, 'mcp_server_launch_target'); add(data.grantRef, 'mcp_server_operation_grant'); add(data.nativeRecipeRef, 'mcp.stdio.recipe_bytes');
      add(data.plannedContainmentRef, 'mcp_server_containment_plan'); add(data.sandboxLaunchSpecRef, 'sandbox_launch_spec'); break;
    }
    case 'mcp.stdio.launch_request': {
      const data = decodeMcpServerLaunchRequest(value); add(data.frontierRef, 'run_frontier'); add(data.assemblyRef, 'run_assembly');
      add(data.registryRevisionRef, 'mcp_registry_revision'); add(data.toolRequestRef, 'tool_request'); add(data.targetRef, 'mcp_server_launch_target'); break;
    }
    case 'mcp.stdio.launch_target': {
      const data = decodeMcpServerLaunchTarget(value); add(data.registryRevisionRef, 'mcp_registry_revision'); add(data.toolRequestRef, 'tool_request');
      add(data.executableIdentityRef, 'mcp.stdio.executable_identity'); break;
    }
    case 'mcp.stdio.operation_grant': {
      const data = decodeMcpServerOperationGrant(value); add(data.policyRef, 'run_policy'); add(data.frontierRef, 'run_frontier');
      add(data.requestRef, 'mcp.stdio.launch_request'); add(data.targetRef, 'mcp_server_launch_target'); add(data.provenance.channelEvidenceRef, 'mcp.stdio.policy_evidence');
      if (data.provenance.kind === 'user_approval') { add(data.provenance.waitingSubjectRef, 'mcp.stdio.approval_wait'); add(data.provenance.decisionRef, 'mcp.stdio.approval_decision'); } break;
    }
    case 'mcp.stdio.policy_evidence': {
      const data = decodeMcpServerPolicyChannelEvidence(value); add(data.policyRef, 'run_policy'); add(data.frontierRef, 'run_frontier');
      add(data.requestRef, 'mcp.stdio.launch_request'); add(data.targetRef, 'mcp_server_launch_target'); add(data.namedAction.registryRevisionRef, 'mcp_registry_revision'); break;
    }
    case 'mcp.stdio.approval_wait': {
      const data = decodeMcpServerApprovalWait(value); add(data.frontierRef, 'run_frontier'); add(data.subject.registryRevisionRef, 'mcp_registry_revision');
      add(data.subject.target, 'mcp_server_launch_target'); add(data.subject.policyChannelEvidenceRef, 'mcp.stdio.policy_evidence'); break;
    }
    case 'mcp.stdio.approval_decision': {
      const data = decodeMcpServerApprovalDecision(value); add(data.channelIdentityRef, 'control_channel'); add(data.waitingSubjectRef, 'mcp.stdio.approval_wait');
      add(data.frontierRef, 'run_frontier'); add(data.subject.registryRevisionRef, 'mcp_registry_revision'); add(data.subject.target, 'mcp_server_launch_target');
      add(data.subject.policyChannelEvidenceRef, 'mcp.stdio.policy_evidence'); break;
    }
    case 'mcp.stdio.policy_item': {
      const data = decodeMcpServerPolicyDecisionItem(value); add(data.policyChannelEvidenceRef, 'mcp.stdio.policy_evidence');
      add(data.decisionRef, data.decisionSource === 'interactive_approval' ? 'mcp.stdio.approval_decision' : 'mcp.stdio.policy_evidence');
      if (data.decisionSource === 'interactive_approval') add(data.waitingSubjectRef, 'mcp.stdio.approval_wait');
      if (data.decision === 'allow') add(data.grantRef, 'mcp_server_operation_grant'); else add(data.denialOutcome.outcomeItemRef, 'continuation_item'); break;
    }
    case 'mcp.stdio.executable_identity': {
      const data = decodeMcpStdioExecutableIdentity(value); add(data.runtimeBundleRef, 'runtime_bundle'); add(data.executableDigest, 'image_bytes'); break;
    }
    case 'mcp.stdio.instance_identity': {
      const data = decodeMcpServerInstanceIdentity(value); add(data.registryRevisionRef, 'mcp_registry_revision'); add(data.sandboxLaunchSpecRef, 'sandbox_launch_spec');
      add(data.processContainmentRef, 'process_containment'); break;
    }
    case 'mcp.stdio.launch_receipt': {
      const data = decodeMcpServerLaunchReceipt(value); add(data.instanceIdentityRef, 'mcp.stdio.instance_identity'); add(data.budgetSettlementRef, 'budget_settlement');
      add(data.containmentDeathEvidenceRef, 'process_containment_death'); nativeClosure(data.nativeClosure); break;
    }
    case 'mcp.stdio.launch_failure': {
      const data = decodeMcpServerLaunchFailure(value); add(data.requestRef, 'mcp.stdio.launch_request'); add(data.targetRef, 'mcp_server_launch_target');
      add(data.grantRef, 'mcp_server_operation_grant'); add(data.sandboxLaunchSpecRef, 'sandbox_launch_spec'); nativeClosure(data.nativeClosure);
      if (data.instance === 'initialized') add(data.instanceIdentityRef, 'mcp.stdio.instance_identity');
      if (data.closure === 'containment_dead') { add(data.processContainmentRef, 'process_containment'); add(data.containmentDeathEvidenceRef, 'process_containment_death'); }
      else add(data.noSpawnEvidenceRef, 'process_containment_no_spawn');
      if (data.disposition === 'owning_call_not_dispatched' && data.owningCallClosureCause.kind === 'stop_intent')
        add(data.owningCallClosureCause.stopIntentRef, 'agent_stop'); break;
    }
    case 'mcp.stdio.stopped_item': {
      const disposition = (value as { disposition?: unknown } | null)?.disposition;
      const data = disposition === 'owning_call_unknown' || disposition === 'owning_call_not_dispatched' ? decodeMcpServerFailedStoppedItem(value) : decodeMcpServerStoppedItem(value);
      add(data.serverManifestRef, 'mcp_registry_revision'); add(data.instanceIdentityRef, 'mcp.stdio.instance_identity'); add(data.containmentEvidenceRef, 'process_containment_death');
      if ('disposition' in data) add(data.launchFailureRef, 'mcp.stdio.launch_failure'); else add(data.launchReceiptRef, 'mcp.stdio.launch_receipt'); break;
    }
    case 'mcp.stdio.run_capture': {
      const data = decodeMcpStdioRunCaptureRoot(value); launchBinding(data.launch); add(data.binding.instanceIdentityRef, 'mcp.stdio.instance_identity');
      add(data.binding.requestRef, 'tool_request'); add(data.binding.targetRef, 'tool_target'); add(data.binding.grantRef, 'tool_operation_grant');
      for (const item of data.captures) add(controlWireRef(controlWireRecord(item, ['phase', 'captureRef']).captureRef), 'mcp.stdio.capture');
      for (const item of data.unusableResponses ?? []) add(controlWireRef(controlWireRecord(item, ['phase', 'ref']).ref), 'mcp.stdio.unusable_response'); break;
    }
    case 'mcp.stdio.capture': {
      const data = decodeMcpStdioCapture(value); if (context?.kind !== 'capture') throw new UnsupportedMcpStdioReachability();
      const decoded = decodeMcpStdioCaptureData({ bytes: context.rawBytes, termination: data.termination, expectedId: data.expectedId });
      if (decoded.rawFinitePrefixDigest !== data.rawResponseRef ||
          context.rawBytes.length !== data.rawFinitePrefixBytes || decoded.responseLineEndOffset !== data.responseLineEndOffset || decoded.receivedTailBytes !== data.receivedTailBytes)
        throw new TypeError('MCP stdio retained capture differs from its complete actual finite prefix');
      add(data.rawResponseRef, 'opaque_blob'); break;
    }
    case 'mcp.stdio.unusable_response': {
      const data = decodeMcpStdioUnusableResponseData(value); if (context?.kind !== 'unusable_response') throw new UnsupportedMcpStdioReachability();
      if (sha256Bytes(context.safeMessageBytes) !== data.safeMessageRef || context.safeMessageBytes.length !== data.safeMessageBytes) throw new TypeError('MCP retained safe message bytes changed');
      const decoded = decodeMcpInboundMessageData(parseJsonStrict(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(context.safeMessageBytes)));
      if ((decoded.kind !== 'result' && decoded.kind !== 'error') || decoded.id !== data.expectedId) throw new TypeError('MCP retained safe message lost its matching response');
      add(controlWireRef(data.safeMessageRef), 'opaque_blob'); break; // Omitted unsafe raw digest is deliberately not an edge.
    }
    case 'mcp.stdio.admin_cleanup_root': {
      const data = decodeMcpStdioAdminCleanupRoot(value); add(data.cleanupRawRef, 'mcp.stdio.native_cleanup_raw'); add(data.cleanupProjectionRef, 'mcp.stdio.native_cleanup_projection'); break;
    }
    case 'mcp.stdio.native_launch_raw':
    case 'mcp.stdio.native_launch_projection': {
      let bytes: Buffer;
      if (purpose === 'mcp.stdio.native_launch_raw') { if (!Buffer.isBuffer(value)) throw new UnsupportedMcpStdioReachability(); bytes = value; }
      else { if (context?.kind !== 'native_launch_projection') throw new UnsupportedMcpStdioReachability(); bytes = context.rawBytes; }
      const data = decodeMcpStdioLifecycleData(bytes);
      if (purpose === 'mcp.stdio.native_launch_projection') requireEqual(value, data, 'MCP complete original native raw/projection retention pair');
      binding(data.binding); for (const image of [data.images.server, data.images.client, data.images.isolation]) add(image.digest, 'image_bytes');
      add(data.images.recipe.digest, 'mcp.stdio.recipe_bytes'); break;
    }
    case 'mcp.stdio.native_cleanup_raw':
    case 'mcp.stdio.native_cleanup_projection': {
      let bytes: Buffer;
      if (purpose === 'mcp.stdio.native_cleanup_raw') { if (!Buffer.isBuffer(value)) throw new UnsupportedMcpStdioReachability(); bytes = value; }
      else { if (context?.kind !== 'native_cleanup_projection') throw new UnsupportedMcpStdioReachability(); bytes = context.rawBytes; }
      const data = decodeMcpStdioCleanupData(bytes);
      if (purpose === 'mcp.stdio.native_cleanup_projection') requireEqual(value, data, 'MCP complete separate current native cleanup raw/projection retention pair');
      binding(data.originalBinding); break;
    }
    case 'mcp.stdio.recipe_bytes': {
      if (!Buffer.isBuffer(value)) throw new UnsupportedMcpStdioReachability(); const data = decodeMcpStdioRecipeData(value); add(data.serverDigest, 'image_bytes'); break;
    }
    case 'mcp.stdio.manual_wait': { const data = decodeManualInvocationWait(value); add(data.frontierRef, 'run_frontier'); break; }
    case 'mcp.stdio.manual_attestation': {
      const data = decodeManualAbandonAttestation(value); add(data.channelIdentityRef, 'control_channel'); add(data.waitingSubjectRef, 'mcp.stdio.manual_wait');
      add(data.frontierRef, 'run_frontier'); add(data.operationRequestRef, 'tool_request'); add(data.targetRef, 'tool_target'); add(data.ambiguityEvidenceRef, 'broker_ambiguity'); break;
    }
    case 'mcp.stdio.abandoned_item': { const data = decodeToolAbandonedItem(value); add(data.attestationRef, 'mcp.stdio.manual_attestation'); break; }
    case 'mcp.stdio.manual_dispatch_closure': {
      const data = decodeManualDispatchClosureData(value); add(data.inspectorIdentityRef, 'supervisor_inspector');
      if (data.kind === 'broker_process_domain_dead') add(data.deathEvidenceRef, 'broker_process_domain_death'); break;
    }
    default: throw new UnsupportedMcpStdioReachability();
  }
  return Object.freeze(edges.map(edge => Object.freeze(edge)));
}
