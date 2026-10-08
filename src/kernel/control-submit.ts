import type { SandboxResourceSpec } from './execution.js';
import type { RunSpec } from './types.js';

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
