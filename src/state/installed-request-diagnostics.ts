import { types } from 'node:util';
import { CONTROL_METHODS_V1, type ControlMethodV1 } from '../kernel/control-wire.js';
import { KernelStorageError, ResourceRetirementError, type KernelStorageErrorCode } from './errors.js';

export const INSTALLED_REQUEST_FAILURE_BOUNDARIES = Object.freeze([
  'request_validation', 'adapter_dispatch', 'pre_current', 'exchange', 'response_decode', 'post_current', 'adapter_output', 'unobserved',
] as const);
export const INSTALLED_REQUEST_FAILURE_KINDS = Object.freeze([
  'kernel_storage', 'resource_retirement', 'type_error', 'assertion', 'error', 'non_error',
] as const);
export const INSTALLED_REQUEST_FAILURE_CODES = Object.freeze([
  'ADMISSION_KEY_CONFLICT', 'REQUEST_ID_CONFLICT', 'ARTIFACT_MISMATCH', 'AGENT_HANDOFF_PENDING',
  'MODEL_RETRY_PENDING', 'BUDGET_EXHAUSTED', 'EVENT_CURSOR_EXPIRED', 'INVALID_REQUEST', 'LEASE_FENCED',
  'NOT_FOUND', 'RECOVERY_REQUIRED', 'REVISION_CONFLICT', 'STATE_TRANSITION_INVALID', 'UNSUPPORTED_PLATFORM',
] as const satisfies readonly KernelStorageErrorCode[]);
type Boundary = typeof INSTALLED_REQUEST_FAILURE_BOUNDARIES[number];
type Kind = typeof INSTALLED_REQUEST_FAILURE_KINDS[number];
export type InstalledRequestFailure = Readonly<{ method: ControlMethodV1 | 'unrecognized';
  boundary: Boundary; kind: Kind; code: KernelStorageErrorCode | null }>;
const methods: ReadonlySet<string> = new Set(CONTROL_METHODS_V1);
const boundaries: ReadonlySet<string> = new Set(INSTALLED_REQUEST_FAILURE_BOUNDARIES);
const kinds: ReadonlySet<string> = new Set(INSTALLED_REQUEST_FAILURE_KINDS);
const codes: ReadonlySet<string> = new Set(INSTALLED_REQUEST_FAILURE_CODES);

/** Closed diagnostic data, never a refusal, status, deadline or authority. */
export function decodeInstalledRequestFailure(value: unknown): InstalledRequestFailure {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('invalid fixed request failure');
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== 4 || !['method', 'boundary', 'kind', 'code'].every(key =>
    Object.hasOwn(fields, key) && 'value' in fields[key]! && fields[key]!.enumerable)) throw new TypeError('invalid fixed request failure fields');
  const method: unknown = fields.method!.value, boundary: unknown = fields.boundary!.value;
  const kind: unknown = fields.kind!.value, code: unknown = fields.code!.value;
  if (typeof method !== 'string' || method !== 'unrecognized' && !methods.has(method) ||
      typeof boundary !== 'string' || !boundaries.has(boundary) || typeof kind !== 'string' || !kinds.has(kind) ||
      (kind === 'kernel_storage' ? typeof code !== 'string' || !codes.has(code) : code !== null) ||
      method === 'unrecognized' && boundary !== 'request_validation' && boundary !== 'unobserved')
    throw new TypeError('invalid fixed request failure values');
  return Object.freeze({ method, boundary, kind, code }) as InstalledRequestFailure;
}

/** Observe native Error brands and own data properties only. Messages,
 * causes, stacks, foreign objects and accessors never enter the projection. */
export function classifyInstalledRequestError(error: unknown): Readonly<{ kind: Kind; code: KernelStorageErrorCode | null }> {
  try {
    if (!error || typeof error !== 'object' || types.isProxy(error) || !types.isNativeError(error))
      return Object.freeze({ kind: 'non_error', code: null });
    let prototype = Object.getPrototypeOf(error);
    for (let depth = 0; prototype !== null; depth++) {
      if (depth === 8 || types.isProxy(prototype)) return Object.freeze({ kind: 'non_error', code: null });
      prototype = Object.getPrototypeOf(prototype);
    }
    if (error instanceof ResourceRetirementError) return Object.freeze({ kind: 'resource_retirement', code: null });
    const code = Object.getOwnPropertyDescriptor(error, 'code');
    if (error instanceof KernelStorageError && code && 'value' in code && typeof code.value === 'string' && codes.has(code.value))
      return Object.freeze({ kind: 'kernel_storage', code: code.value as KernelStorageErrorCode });
    if (code && 'value' in code && code.value === 'ERR_ASSERTION') return Object.freeze({ kind: 'assertion', code: null });
    return Object.freeze({ kind: error instanceof TypeError ? 'type_error' : 'error', code: null });
  } catch { return Object.freeze({ kind: 'non_error', code: null }); }
}

const observers = new Set<(value: InstalledRequestFailure) => void>();
/** Trusted composition observes inert data synchronously. Each observer is
 * contained individually; it cannot replace or escape the original failure. */
export function observeInstalledRequestFailures(observer: (value: InstalledRequestFailure) => void): () => void {
  if (typeof observer !== 'function' || types.isProxy(observer)) throw new TypeError('request failure observer must be a fixed function');
  observers.add(observer); return () => { observers.delete(observer); };
}
export function beginInstalledRequestDiagnostic(method: ControlMethodV1 | 'unrecognized') {
  if (!observers.size || method !== 'unrecognized' && !methods.has(method)) return;
  let boundary: Boundary = method === 'unrecognized' ? 'request_validation' : 'pre_current';
  let emitted = false;
  return Object.freeze({ at(value: Boundary) { if (boundaries.has(value)) boundary = value; }, failure(error: unknown) {
    if (emitted) return; emitted = true;
    try {
      const observation = decodeInstalledRequestFailure({ method, boundary, ...classifyInstalledRequestError(error) });
      for (const observer of [...observers]) try { observer(observation); } catch { /* Diagnosis cannot decide an operation. */ }
    } catch { /* Missing diagnostic data never changes the original failure. */ }
  } });
}
