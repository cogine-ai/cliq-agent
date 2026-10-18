import type { SandboxResourceSpec } from './execution.js';
import type { RunSpec } from './types.js';
import { canonicalJsonBytes, canonicalSha256 } from './canonical.js';
import { assertAdmissionKey, assertArtifactRef, assertRequestId, normalizeAbsolutePath, normalizeBoundedText } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { assertControlWireJson } from './control-wire-data.js';

export const DEFAULT_RUN_BUDGETS: {
  wallTimeMs: number;
  modelTokens: number;
  costMicros: number;
  toolCalls: number;
  repairAttempts: number;
  childDepth: number;
  childConcurrency: number;
} = {
  wallTimeMs: 86_400_000,
  modelTokens: 2_000_000,
  costMicros: 10_000_000,
  toolCalls: 1_000,
  repairAttempts: 2,
  childDepth: 2,
  childConcurrency: 4
};


// Resource defaults are data, not the signed empty-root filesystem recipe or
// a Workspace Trust / tool permission decision.
export const DEFAULT_SANDBOX_RESOURCES: Readonly<SandboxResourceSpec> = Object.freeze({
  maxProcesses: 256, memoryBytes: 4 * 1024 ** 3, cpuQuotaMicrosPerSecond: 400_000,
  maxOpenFiles: 1024, maxSingleFileBytes: 256 * 1024 ** 2, maxGenerationBytes: 20 * 1024 ** 3,
  maxInvocationOutputBytes: 16 * 1024 ** 2, maxIpcFrameBytes: 16 * 1024 ** 2, maxQueuedIpcBytes: 64 * 1024 ** 2,
});


function requireBudgetField(value: number, label: string, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${label} is outside ${min}..${max}`);
  }
  return value;
}

export function mergeBudgets(
  overrides?: Partial<typeof DEFAULT_RUN_BUDGETS>
): typeof DEFAULT_RUN_BUDGETS {
  const budgets = { ...DEFAULT_RUN_BUDGETS, ...overrides };
  return {
    wallTimeMs: requireBudgetField(budgets.wallTimeMs, 'wallTimeMs', 1_000, 2_592_000_000),
    modelTokens: requireBudgetField(budgets.modelTokens, 'modelTokens', 1, 100_000_000),
    costMicros: requireBudgetField(budgets.costMicros, 'costMicros', 1, 1_000_000_000_000),
    toolCalls: requireBudgetField(budgets.toolCalls, 'toolCalls', 1, 1_000_000),
    repairAttempts: requireBudgetField(budgets.repairAttempts, 'repairAttempts', 0, 64),
    childDepth: requireBudgetField(budgets.childDepth, 'childDepth', 0, 8),
    childConcurrency: requireBudgetField(budgets.childConcurrency, 'childConcurrency', 1, 64)
  };
}

/** Exact inline control contract. Internal capture refs are never client input. */
export type SourceSelectorRequest = { path: string; scope: 'entry' | 'subtree'; readGrantId?: string };
export type NonSecretLiteralRequest = { kind: 'non_secret_literal'; value: string };
export type VerifierRequest = {
  id: string; version: string; required: boolean;
  executable: { kind: 'toolchain'; toolId: string } | { kind: 'workspace_script'; path: string; expectedDigest?: string };
  argv: NonSecretLiteralRequest[]; cwd: string; env: Record<string, NonSecretLiteralRequest>;
  writableEphemeralPaths: string[]; identityReadGrantId: string; executionGrantId?: string;
  timeoutMs?: number; retries?: number; outputLimitBytes?: number;
};
export type DependencyRequest = { mode: 'none' } | {
  mode: 'locked'; registryEndpointIds: string[]; credentialGrantIds: string[]; allowInstallScripts: boolean;
  installScriptsGrantId?: string; maxPackages?: number; maxDownloadBytes?: number;
};
export type RunModelRequest = { provider: 'ollama'; model: string } | {
  provider: 'openai' | 'anthropic' | 'openrouter' | 'openai-compatible' | 'zhipu'; model: string;
  endpoint: { kind: 'registered'; endpointRegistrationId: string }; modelCredentialGrantIds: string[];
};
export type RunSubmitRequest = {
  protocolVersion: 1; requestId: string; requestDigest: string; method: 'run.submit'; admissionKey: string;
  sessionId: string; expectedContextRevision: number; workspacePath: string; objective: string;
  model: RunModelRequest; policyMode: 'default' | 'accept-edits' | 'plan' | 'yolo';
  budgets?: Partial<RunSpec['budgets']>; sandboxResources?: Partial<SandboxResourceSpec>;
  verifiers: VerifierRequest[]; dependency: DependencyRequest;
  sourceIncludes: SourceSelectorRequest[]; sourceExcludes: Array<Omit<SourceSelectorRequest, 'readGrantId'>>;
  maxChangedPaths?: number; maxChangedBytes?: number;
  registeredMcpServerIds: string[]; skillIds: string[]; allowUnverified: boolean;
};
export type NormalizedRunSubmitRequest = Omit<RunSubmitRequest,
  'budgets' | 'sandboxResources' | 'maxChangedPaths' | 'maxChangedBytes'> & {
  budgets: RunSpec['budgets']; sandboxResources: SandboxResourceSpec;
  maxChangedPaths: number; maxChangedBytes: number;
};

export class InvalidRunSubmitRequestError extends TypeError {}
function invalid(message: string): never { throw new InvalidRunSubmitRequestError(message); }
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid('inline member must be a plain object');
  const result = value as Record<string, unknown>;
  if (required.some(key => !Object.hasOwn(result, key)) ||
      Object.keys(result).some(key => !required.includes(key) && !optional.includes(key))) invalid('inline object has unknown or missing fields');
  if (Object.values(result).some(member => member === undefined)) invalid('inline object cannot contain undefined');
  return result;
}
function text(value: unknown, maximum = 128, minimum = 1): string {
  if (typeof value !== 'string') invalid('inline text must be a string');
  return normalizeBoundedText(value, minimum, maximum);
}
function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) invalid('inline integer is outside its accepted bounds');
  return value as number;
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') invalid('inline boolean must be a boolean');
  return value;
}
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) invalid('inline discriminator is invalid');
  return value as T;
}
function array<T>(value: unknown, maximum: number, decode: (value: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > maximum) invalid('inline array is outside its accepted bounds');
  return value.map(decode);
}
function ids(value: unknown, maximum: number, minimum = 0): string[] {
  const result = array(value, maximum, item => text(item));
  if (result.length < minimum || new Set(result).size !== result.length) invalid('inline ids must be unique and satisfy their count bound');
  return result;
}
function relative(value: unknown, root = false): string {
  const result = text(value, 4096);
  if (root && result === '.') return result;
  if (result.includes('\\') || result.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255))
    invalid('inline path must be an exact canonical root-relative path');
  return result;
}
function literal(value: unknown) {
  const data = object(value, ['kind', 'value']);
  if (data.kind !== 'non_secret_literal') invalid('only explicit non-secret literals are accepted');
  return { kind: 'non_secret_literal' as const, value: text(data.value, 8192, 0) };
}
function selector(value: unknown, include: boolean): SourceSelectorRequest {
  const data = object(value, ['path', 'scope'], include ? ['readGrantId'] : []);
  return { path: relative(data.path), scope: choice(data.scope, ['entry', 'subtree']),
    ...(Object.hasOwn(data, 'readGrantId') ? { readGrantId: text(data.readGrantId) } : {}) };
}
function verifier(value: unknown): VerifierRequest {
  const data = object(value, ['id', 'version', 'required', 'executable', 'argv', 'cwd', 'env',
    'writableEphemeralPaths', 'identityReadGrantId'], ['executionGrantId', 'timeoutMs', 'retries', 'outputLimitBytes']);
  const command = object(data.executable, ['kind'], ['toolId', 'path', 'expectedDigest']);
  let executable: VerifierRequest['executable'];
  if (command.kind === 'toolchain') {
    object(command, ['kind', 'toolId']); executable = { kind: 'toolchain', toolId: text(command.toolId) };
  } else {
    object(command, ['kind', 'path'], ['expectedDigest']);
    if (command.kind !== 'workspace_script') invalid('unsupported verifier executable kind');
    const expectedDigest = Object.hasOwn(command, 'expectedDigest') ? text(command.expectedDigest, 64) : undefined;
    if (expectedDigest !== undefined) assertArtifactRef(expectedDigest);
    executable = { kind: 'workspace_script', path: relative(command.path), ...(expectedDigest === undefined ? {} : { expectedDigest }) };
  }
  if (!data.env || typeof data.env !== 'object' || Array.isArray(data.env)) invalid('verifier env must be an object');
  const names = Object.keys(data.env);
  object(data.env, [], names);
  if (names.length > 64 || names.some(name => !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u.test(name))) invalid('verifier env names are invalid');
  const env = Object.fromEntries(names.sort().map(name => [name, literal((data.env as Record<string, unknown>)[name])]));
  const writableEphemeralPaths = array(data.writableEphemeralPaths, 32, item => relative(item));
  if (new Set(writableEphemeralPaths).size !== writableEphemeralPaths.length) invalid('verifier writable paths must be unique');
  return { id: text(data.id), version: text(data.version), required: boolean(data.required), executable,
    argv: array(data.argv, 128, literal), cwd: relative(data.cwd, true), env, writableEphemeralPaths,
    identityReadGrantId: text(data.identityReadGrantId),
    ...(Object.hasOwn(data, 'executionGrantId') ? { executionGrantId: text(data.executionGrantId) } : {}),
    ...(Object.hasOwn(data, 'timeoutMs') ? { timeoutMs: integer(data.timeoutMs, 1) } : {}),
    ...(Object.hasOwn(data, 'retries') ? { retries: integer(data.retries, 0) } : {}),
    ...(Object.hasOwn(data, 'outputLimitBytes') ? { outputLimitBytes: integer(data.outputLimitBytes, 1) } : {}) };
}
function dependency(value: unknown): DependencyRequest {
  const data = object(value, ['mode'], ['registryEndpointIds', 'credentialGrantIds', 'allowInstallScripts',
    'installScriptsGrantId', 'maxPackages', 'maxDownloadBytes']);
  if (data.mode === 'none') { object(data, ['mode']); return { mode: 'none' }; }
  object(data, ['mode', 'registryEndpointIds', 'credentialGrantIds', 'allowInstallScripts'],
    ['installScriptsGrantId', 'maxPackages', 'maxDownloadBytes']);
  if (data.mode !== 'locked') invalid('unsupported dependency mode');
  const allowInstallScripts = boolean(data.allowInstallScripts);
  if (!allowInstallScripts && Object.hasOwn(data, 'installScriptsGrantId')) invalid('install-script grant requires an install-script request');
  return { mode: 'locked', registryEndpointIds: ids(data.registryEndpointIds, 128, 1), credentialGrantIds: ids(data.credentialGrantIds, 32), allowInstallScripts,
    ...(Object.hasOwn(data, 'installScriptsGrantId') ? { installScriptsGrantId: text(data.installScriptsGrantId) } : {}),
    ...(Object.hasOwn(data, 'maxPackages') ? { maxPackages: integer(data.maxPackages, 1) } : {}),
    ...(Object.hasOwn(data, 'maxDownloadBytes') ? { maxDownloadBytes: integer(data.maxDownloadBytes, 1) } : {}) };
}
function model(value: unknown): RunModelRequest {
  const data = object(value, ['provider', 'model'], ['endpoint', 'modelCredentialGrantIds']);
  if (data.provider === 'ollama') { object(data, ['provider', 'model']); return { provider: 'ollama', model: text(data.model) }; }
  object(data, ['provider', 'model', 'endpoint', 'modelCredentialGrantIds']);
  const endpoint = object(data.endpoint, ['kind', 'endpointRegistrationId']);
  if (endpoint.kind !== 'registered') invalid('model endpoint must name a registration');
  return { provider: choice(data.provider, ['openai', 'anthropic', 'openrouter', 'openai-compatible', 'zhipu']), model: text(data.model),
    endpoint: { kind: 'registered', endpointRegistrationId: text(endpoint.endpointRegistrationId) },
    modelCredentialGrantIds: ids(data.modelCredentialGrantIds, 32, 1) };
}
const RESOURCE_DEFAULTS = DEFAULT_SANDBOX_RESOURCES;
const RESOURCE_RANGES: Record<keyof SandboxResourceSpec, readonly [number, number]> = {
  maxProcesses: [1, 1024], memoryBytes: [256 * 1024 ** 2, 32 * 1024 ** 3], cpuQuotaMicrosPerSecond: [10_000, 1_600_000],
  maxOpenFiles: [64, 8192], maxSingleFileBytes: [1024 ** 2, 16 * 1024 ** 3], maxGenerationBytes: [256 * 1024 ** 2, 100 * 1024 ** 3],
  maxInvocationOutputBytes: [64 * 1024, 64 * 1024 ** 2], maxIpcFrameBytes: [16 * 1024 ** 2, 16 * 1024 ** 2], maxQueuedIpcBytes: [64 * 1024 ** 2, 64 * 1024 ** 2] };
function resourceOptions(value: unknown): SandboxResourceSpec {
  const data = value === undefined ? {} : object(value, [], Object.keys(RESOURCE_DEFAULTS));
  const result = { ...RESOURCE_DEFAULTS };
  for (const key of Object.keys(result) as Array<keyof SandboxResourceSpec>) {
    const [minimum, maximum] = RESOURCE_RANGES[key];
    result[key] = integer(Object.hasOwn(data, key) ? data[key] : result[key], minimum, maximum);
  }
  return result;
}
function boundedJson(value: unknown, depth = 0, total = { members: 0 }): void {
  if (depth > 32) invalid('inline JSON exceeds its depth bound');
  if (value && typeof value === 'object') {
    if (Array.isArray(value)) {
      total.members += value.length;
      for (let index = 0; index < value.length; index++) {
        if (!Object.hasOwn(value, index)) invalid('inline JSON cannot contain sparse arrays');
        boundedJson(value[index], depth + 1, total);
      }
    } else {
      const keys = Object.keys(value); total.members += keys.length;
      if (total.members > 10_000) invalid('inline JSON exceeds its member bound');
      for (const key of keys) boundedJson((value as Record<string, unknown>)[key], depth + 1, total);
    }
  }
  if (total.members > 10_000) invalid('inline JSON exceeds its member bound');
}

/** Request identity retains the original JCS values, before normalization or
 * defaults. Only the admission intent uses the normalized/defaulted request.
 * No resolved capture ref is accepted or mixed into either domain. */
export function normalizeRunSubmitRequest(value: unknown): {
  request: NormalizedRunSubmitRequest; originalRequest: object; originalRequestDigest: string;
} {
  try {
    assertControlWireJson(value);
    boundedJson(value);
    const data = object(value, ['protocolVersion', 'requestId', 'requestDigest', 'method', 'admissionKey', 'sessionId',
      'expectedContextRevision', 'workspacePath', 'objective', 'model', 'policyMode', 'verifiers', 'dependency',
      'sourceIncludes', 'sourceExcludes', 'registeredMcpServerIds', 'skillIds', 'allowUnverified'],
    ['budgets', 'sandboxResources', 'maxChangedPaths', 'maxChangedBytes']);
    if (data.protocolVersion !== 1 || data.method !== 'run.submit') invalid('expected protocol-v1 run.submit');
    const requestId = text(data.requestId), admissionKey = text(data.admissionKey), requestDigest = text(data.requestDigest, 64);
    assertRequestId(requestId); assertAdmissionKey(admissionKey); assertArtifactRef(requestDigest);
    const budgets = data.budgets === undefined ? undefined : object(data.budgets, [], Object.keys(DEFAULT_RUN_BUDGETS));
    const verifiers = array(data.verifiers, 32, verifier), allowUnverified = boolean(data.allowUnverified);
    if (new Set(verifiers.map(gate => gate.id)).size !== verifiers.length) invalid('verifier ids must be unique');
    if (verifiers.some(gate => gate.required) === allowUnverified) invalid('allowUnverified must match the absence of required verifiers');
    const core = { protocolVersion: 1 as const, requestId, method: 'run.submit' as const, admissionKey,
      sessionId: text(data.sessionId), expectedContextRevision: integer(data.expectedContextRevision, 1),
      workspacePath: normalizeAbsolutePath(text(data.workspacePath, 4096)), objective: text(data.objective, 262_144),
      model: model(data.model), policyMode: choice(data.policyMode, ['default', 'accept-edits', 'plan', 'yolo']),
      verifiers, dependency: dependency(data.dependency), sourceIncludes: array(data.sourceIncludes, 128, item => selector(item, true)),
      sourceExcludes: array(data.sourceExcludes, 128, item => selector(item, false)), registeredMcpServerIds: ids(data.registeredMcpServerIds, 128),
      skillIds: ids(data.skillIds, 64), allowUnverified,
      ...(budgets === undefined ? {} : { budgets: Object.fromEntries(Object.keys(budgets).map(key => [key, integer(budgets[key], 0)])) }),
      ...(data.sandboxResources === undefined ? {} : { sandboxResources: object(data.sandboxResources, [], Object.keys(RESOURCE_DEFAULTS)) }),
      ...(data.maxChangedPaths === undefined ? {} : { maxChangedPaths: integer(data.maxChangedPaths, 0, 100_000) }),
      ...(data.maxChangedBytes === undefined ? {} : { maxChangedBytes: integer(data.maxChangedBytes, 0, 4 * 1024 ** 3) }) };
    const { requestDigest: _wireDigest, ...originalCore } = data;
    const originalRequest = { ...originalCore, requestDigest };
    if (canonicalJsonBytes(originalRequest).length > 1_048_576) invalid('inline request exceeds 1 MiB');
    if (canonicalSha256(originalCore) !== requestDigest) invalid('inline requestDigest does not match canonical request bytes');
    const request = { ...core, requestDigest, budgets: (() => { try { return mergeBudgets(budgets); } catch (cause) {
      if (cause instanceof TypeError) throw new InvalidRunSubmitRequestError(cause.message); throw cause;
    } })(), sandboxResources: resourceOptions(data.sandboxResources),
      maxChangedPaths: core.maxChangedPaths ?? 10_000, maxChangedBytes: core.maxChangedBytes ?? 512 * 1024 ** 2 };
    return immutableSnapshot({ request, originalRequest, originalRequestDigest: requestDigest });
  } catch (cause) {
    if (cause instanceof InvalidRunSubmitRequestError) throw cause;
    throw new InvalidRunSubmitRequestError('invalid inline run.submit request', { cause });
  }
}
