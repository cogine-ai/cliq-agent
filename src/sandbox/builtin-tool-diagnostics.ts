// Closed inert work labels only. No resource identity, timing or authority.
export const BUILTIN_EXECUTION_PHASES = Object.freeze([
  'tool_select', 'tool_prepare', 'tool_claim_spec', 'tool_claim', 'tool_claim_data', 'tool_claim_live',
  'tool_script_closure', 'tool_edit_closure', 'tool_native_parent', 'tool_native_recipe',
  'tool_native_guest_open', 'tool_native_guest_identity', 'tool_native_claim_identity',
  'tool_native_inputs', 'tool_native_create', 'tool_native_inputs_join', 'tool_native_ack_interface',
  'tool_native_guest_join', 'tool_native_ready', 'tool_native_containment', 'tool_native_process',
  'tool_native_error_guest_join', 'tool_native_error_controller_join',
  'tool_process_observe', 'tool_release', 'tool_result', 'tool_capture', 'tool_received',
  'tool_received_capture_publish', 'tool_received_checkpoint_retirement',
  'tool_received_capture_read', 'tool_received_diagnostic_publish',
  'tool_received_observation_publish', 'tool_received_complete_tool',
  'tool_error_revoke', 'tool_error_history', 'tool_error_evidence', 'tool_error_unknown'
] as const);
export type BuiltinExecutionPhase = typeof BUILTIN_EXECUTION_PHASES[number];
export type NativeBuiltinInvocationPhase = Extract<BuiltinExecutionPhase, `tool_native_${string}`>;
const phases: ReadonlySet<string> = new Set(BUILTIN_EXECUTION_PHASES);
export function isBuiltinExecutionPhase(value: unknown): value is BuiltinExecutionPhase {
  return typeof value === 'string' && phases.has(value);
}
