import { types } from 'node:util';
import { ResourceRetirementError } from './errors.js';

// Fixed diagnostics only. No request, identifier, path, exception text, time,
// retry permission or evidence of an upgrade operation is carried here.
export const INSTALLED_RUNTIME_UPGRADE_PHASES = ['read_schema', 'recover_selection', 'source_open', 'source_services',
  'source_control', 'stage_original', 'stage_source', 'stage_cas', 'stage_owner_history', 'stage_native',
  'stop_original', 'stop_observe_original', 'stop_load_platform', 'stop_supervisor_request', 'stop_supervisor_decode',
  'stop_supervisor_death', 'stop_keeper_request', 'stop_keeper_decode', 'stop_keeper_death', 'credential_exclusion', 'conversion', 'publish_selection', 'target_open', 'target_services',
  'target_control', 'output', 'unknown'] as const;
export type InstalledRuntimeUpgradePhase = typeof INSTALLED_RUNTIME_UPGRADE_PHASES[number];
// Only native task statuses reachable by the fixed manager/upgrade recipe.
// A raw/remote string is never transformed or copied into an output marker.
const platformCodes = Object.freeze({
  platform_timeout: 'NATIVE_PLATFORM_TIMEOUT', platform_cancelled: 'NATIVE_PLATFORM_CANCELLED',
  platform_busy: 'NATIVE_PLATFORM_BUSY', invalid_platform_request: 'NATIVE_PLATFORM_INVALID_REQUEST',
  platform_worker_unavailable: 'NATIVE_PLATFORM_WORKER_UNAVAILABLE',
  platform_main_thread_required: 'NATIVE_PLATFORM_MAIN_THREAD_REQUIRED',
  platform_user_unavailable: 'NATIVE_PLATFORM_USER_UNAVAILABLE',
  platform_bus_unavailable: 'NATIVE_PLATFORM_BUS_UNAVAILABLE', platform_bus_identity: 'NATIVE_PLATFORM_BUS_IDENTITY',
  platform_bus_changed: 'NATIVE_PLATFORM_BUS_CHANGED', platform_service_identity: 'NATIVE_PLATFORM_SERVICE_IDENTITY',
  platform_service_changed: 'NATIVE_PLATFORM_SERVICE_CHANGED', platform_shape_mismatch: 'NATIVE_PLATFORM_SHAPE_MISMATCH',
  platform_observation_changed: 'NATIVE_PLATFORM_OBSERVATION_CHANGED', platform_inventory_bound: 'NATIVE_PLATFORM_INVENTORY_BOUND',
  platform_store_unavailable: 'NATIVE_PLATFORM_STORE_UNAVAILABLE', manager_profile_unsupported: 'NATIVE_MANAGER_PROFILE_UNSUPPORTED',
  manager_profile_bound: 'NATIVE_MANAGER_PROFILE_BOUND', process_identity_unavailable: 'NATIVE_PROCESS_IDENTITY_UNAVAILABLE'
} as const);
const nativeCodes = Object.freeze({ ERR_CLIQ_RESOURCE_RETIREMENT: 'NATIVE_RESOURCE_RETIREMENT',
  ERR_CLIQ_CREDENTIAL_SCOPE: 'NATIVE_CREDENTIAL_SCOPE_REFUSED', ERR_CLIQ_CREDENTIAL_BUSY: 'NATIVE_CREDENTIAL_BUSY',
  ERR_DLOPEN_FAILED: 'DLOPEN_FAILED' } as const);
const originalCodes = ['ARTIFACT_MISMATCH', 'RECOVERY_REQUIRED', 'LEASE_FENCED', 'STATE_TRANSITION_INVALID',
  'UNSUPPORTED_PLATFORM', 'CLOCK_UNTRUSTED', 'BUDGET_EXHAUSTED', 'ENOENT', 'EACCES', 'unclassified'] as const;
const codes = [...originalCodes,
  'NATIVE_PLATFORM_REFUSED', 'TYPE_ERROR', 'SYNTAX_ERROR', 'RANGE_ERROR', 'AGGREGATE_ERROR', 'ERROR',
  ...Object.values(platformCodes), ...Object.values(nativeCodes)] as const;
const bridgedNativeRetirements = new WeakSet<object>();

/** Failure-only bridge for the actual signed upgrade stop producer. It grants
 * no resource/join authority and never evaluates a native error's text/cause.
 * The owning caller retains the real scope, records sticky retirement failure
 * and joins the exact original native cancellation producer. */
export function installedUpgradeRetirementFailure(error: unknown): ResourceRetirementError | undefined {
  if (!error || typeof error !== 'object' || types.isProxy(error) || !types.isNativeError(error)) return;
  if (error instanceof ResourceRetirementError) return error;
  const code = Object.getOwnPropertyDescriptor(error, 'code');
  if (!code || !('value' in code) || code.value !== 'ERR_CLIQ_RESOURCE_RETIREMENT') return;
  const failure = new ResourceRetirementError('installed upgrade native stop resources did not retire', error);
  bridgedNativeRetirements.add(failure);
  return failure;
}

const prefix = 'CLIQ_INSTALLED_UPGRADE_FAILURE_V1:';
const markers = new Map(INSTALLED_RUNTIME_UPGRADE_PHASES.flatMap(phase => codes.map(code => {
  const marker = `${prefix}${phase}:${code}`; return [marker, marker] as const;
})));

export function installedRuntimeUpgradeFailureMarker(phase: unknown, error: unknown): string {
  const fixedPhase = typeof phase === 'string' && (INSTALLED_RUNTIME_UPGRADE_PHASES as readonly string[]).includes(phase) ? phase : 'unknown';
  let code: string = 'unclassified';
  if (typeof error === 'object' && error !== null && !types.isProxy(error)) {
    if (bridgedNativeRetirements.has(error)) return `${prefix}${fixedPhase}:NATIVE_RESOURCE_RETIREMENT\n`;
    const property = Object.getOwnPropertyDescriptor(error, 'code');
    if (property && 'value' in property && typeof property.value === 'string' &&
        (originalCodes as readonly string[]).includes(property.value)) code = property.value;
    else if (types.isNativeError(error)) {
      // Inspect only own data descriptors and exact error prototypes. No name,
      // message, stack, cause, inherited field or getter is ever evaluated.
      const native = property && 'value' in property && typeof property.value === 'string' ? property.value : undefined;
      if (native === 'ERR_CLIQ_CREDENTIAL_PLATFORM') {
        const status = Object.getOwnPropertyDescriptor(error, 'platformCode');
        code = status && 'value' in status && typeof status.value === 'string' && Object.hasOwn(platformCodes, status.value)
          ? platformCodes[status.value as keyof typeof platformCodes] : 'NATIVE_PLATFORM_REFUSED';
      } else if (native && Object.hasOwn(nativeCodes, native)) code = nativeCodes[native as keyof typeof nativeCodes];
      else {
        const prototype = Object.getPrototypeOf(error);
        if (prototype === TypeError.prototype) code = 'TYPE_ERROR';
        else if (prototype === SyntaxError.prototype) code = 'SYNTAX_ERROR';
        else if (prototype === RangeError.prototype) code = 'RANGE_ERROR';
        else if (prototype === AggregateError.prototype) code = 'AGGREGATE_ERROR';
        else if (prototype === Error.prototype) code = 'ERROR';
      }
    }
  }
  return `${prefix}${fixedPhase}:${code}\n`;
}

/** Read only the original source's exact fixed line after the caller's complete
 * secret scan. Duplicate/foreign lines never replace the actual exit refusal. */
export function readInstalledRuntimeUpgradeFailureMarker(bytes: Buffer): Buffer | undefined {
  if (types.isProxy(bytes) || !Buffer.isBuffer(bytes) || bytes.length > 2 * 1024 * 1024) return undefined;
  let found: string | undefined, position = 0;
  while (position < bytes.length) {
    const newline = bytes.indexOf(10, position), end = newline < 0 ? bytes.length : newline;
    const length = end - position;
    if (length >= prefix.length && length <= 128) {
      const value = bytes.subarray(position, end).toString('utf8'), fixed = markers.get(value);
      if (fixed) { if (found !== undefined) return undefined; found = fixed; }
    }
    position = end + 1;
  }
  return found === undefined ? undefined : Buffer.from(found + '\n');
}
