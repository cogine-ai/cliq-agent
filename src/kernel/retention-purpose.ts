// Semantic use selected by a closed production parent, never inferred from a
// catalog schemaKind, filename, arbitrary JSON key or hash-looking string.
// This finite vocabulary supplies no authority or coverage/completeness proof.
export const CORE_RETENTION_ARTIFACT_PURPOSES = [
  'agent_stop',
  'tool_request', 'mcp_registry_revision', 'mcp_server_launch_target', 'mcp_server_operation_grant',
  'mcp_server_containment_plan', 'sandbox_launch_spec', 'process_containment',
  'process_containment_death', 'process_containment_no_spawn', 'budget_settlement',
  'runtime_bundle', 'image_bytes', 'opaque_blob',
  'run_frontier', 'run_assembly', 'run_policy', 'control_channel', 'supervisor_inspector',
  'broker_ambiguity', 'broker_process_domain_death', 'continuation_item', 'tool_target',
  'tool_operation_grant', 'mcp_admin_probe_target', 'mcp_admin_probe_core', 'process_containment_plan',
  'mcp_admin_native_lifecycle_raw', 'mcp_admin_native_lifecycle_projection',
  'mcp_admin_current_retirement_raw', 'mcp_admin_current_retirement_projection',
  'workspace_identity', 'repository_identity', 'session_context_projection', 'session_context_page',
  'session_raw_context_payload', 'session_compaction', 'session_summary_text'
] as const;
export type CoreRetentionArtifactPurpose = typeof CORE_RETENTION_ARTIFACT_PURPOSES[number];
export type CoreRetentionArtifactEdge = Readonly<{ ref: string; purpose: CoreRetentionArtifactPurpose }>;
