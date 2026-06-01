import type { PartialModelConfig } from './config.js';
import { getProviderCatalogEntry, type ConfigSourceLabel } from './catalog/index.js';
import { discoverOllamaModels as defaultDiscoverOllamaModels, selectDefaultOllamaModel, type OllamaModelSummary } from './providers/ollama-discovery.js';
import { getModelProvider, isProviderName, listModelProviders } from './registry.js';
import type { ProviderName } from './types.js';

export type ProviderConfigState = 'configured' | 'not-configured' | 'unavailable';

export type ProviderStatusIssueCode =
  | 'missing-api-key'
  | 'missing-base-url'
  | 'missing-model'
  | 'local-models-missing'
  | 'local-service-unavailable';

export type ProviderStatusIssue = {
  code: ProviderStatusIssueCode;
  message: string;
  requirement: string;
  envVar?: string;
};

export type ProviderStatus = {
  provider: ProviderName;
  displayName: string;
  current: boolean;
  state: ProviderConfigState;
  sources: ConfigSourceLabel[];
  issues: ProviderStatusIssue[];
  setup: string[];
  model?: string;
  baseUrl?: string;
  modelCount?: number;
};

export type ProviderCredentialPersistence = {
  mode: 'external-only';
  supportsManagedCredentials: false;
  message: string;
};

export type ProviderStatusReport = {
  activeProvider: ProviderName;
  activeModel?: string;
  providers: ProviderStatus[];
  credentialPersistence: ProviderCredentialPersistence;
};

export type BuildProviderStatusReportOptions = {
  workspace: {
    model?: PartialModelConfig;
  };
  cli: PartialModelConfig;
  env?: Record<string, string | undefined>;
  discoverOllamaModels?: (baseUrl: string) => Promise<OllamaModelSummary[]>;
};

export type ProviderValidationResult =
  | {
      ok: true;
      provider: ProviderName;
      state: 'configured';
      sources: ConfigSourceLabel[];
    }
  | {
      ok: false;
      provider: ProviderName;
      state: Exclude<ProviderConfigState, 'configured'>;
      issues: ProviderStatusIssue[];
    };

export type ProviderSetupSummary = {
  provider: ProviderName;
  displayName: string;
  state: ProviderConfigState;
  instructions: string[];
  issues: ProviderStatusIssue[];
  credentialPersistence: ProviderCredentialPersistence;
};

const SOURCE_ORDER: ConfigSourceLabel[] = ['ENV', 'Workspace', 'Global', 'Managed credential', 'CLI', 'Local service'];

function firstDefined(...values: Array<string | undefined | null>): string | undefined {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== '') {
      return value;
    }
  }
  return undefined;
}

function envModelConfig(env: Record<string, string | undefined>): PartialModelConfig {
  return {
    ...(env.CLIQ_MODEL_PROVIDER ? { provider: env.CLIQ_MODEL_PROVIDER } : {}),
    ...(env.CLIQ_MODEL ? { model: env.CLIQ_MODEL } : {}),
    ...(env.CLIQ_MODEL_BASE_URL ? { baseUrl: env.CLIQ_MODEL_BASE_URL } : {}),
    ...(env.CLIQ_MODEL_STREAMING ? { streaming: env.CLIQ_MODEL_STREAMING } : {})
  };
}

function hasModelFields(config: PartialModelConfig | undefined) {
  return Boolean(config?.provider || config?.model || config?.baseUrl || config?.streaming);
}

function configAppliesToProvider(
  config: PartialModelConfig | undefined,
  provider: ProviderName,
  activeProvider: ProviderName
) {
  if (!hasModelFields(config)) return false;
  if (config?.provider !== undefined) {
    return config.provider === provider;
  }
  return provider === activeProvider;
}

function providerFromRaw(raw: string | undefined): ProviderName | undefined {
  if (raw === undefined || raw === '') return undefined;
  if (!isProviderName(raw)) {
    throw new Error(`Unknown model provider: ${raw}`);
  }
  return raw;
}

function resolveActiveProvider(
  cli: PartialModelConfig,
  workspace: PartialModelConfig | undefined,
  env: Record<string, string | undefined>
) {
  return (
    providerFromRaw(firstDefined(cli.provider, workspace?.provider, env.CLIQ_MODEL_PROVIDER)) ??
    'ollama'
  );
}

function sourceValue(
  config: PartialModelConfig | undefined,
  provider: ProviderName,
  activeProvider: ProviderName,
  key: 'model' | 'baseUrl'
) {
  return configAppliesToProvider(config, provider, activeProvider) ? config?.[key] : undefined;
}

function envApiKeyNames(provider: ProviderName): string[] {
  if (provider === 'openai-compatible') {
    return ['CLIQ_MODEL_API_KEY', 'OPENAI_COMPATIBLE_API_KEY'];
  }
  const apiKeyEnv = getModelProvider(provider).apiKeyEnv;
  return apiKeyEnv ? [apiKeyEnv] : [];
}

function hasEnvApiKey(provider: ProviderName, env: Record<string, string | undefined>) {
  return envApiKeyNames(provider).some((key) => Boolean(env[key]));
}

function addSource(sources: Set<ConfigSourceLabel>, source: ConfigSourceLabel) {
  sources.add(source);
}

function orderedSources(sources: Set<ConfigSourceLabel>): ConfigSourceLabel[] {
  return SOURCE_ORDER.filter((source) => sources.has(source));
}

function configuredSourcesForProvider(opts: {
  provider: ProviderName;
  activeProvider: ProviderName;
  cli: PartialModelConfig;
  workspace: PartialModelConfig | undefined;
  envConfig: PartialModelConfig;
  env: Record<string, string | undefined>;
}) {
  const sources = new Set<ConfigSourceLabel>();
  if (hasEnvApiKey(opts.provider, opts.env) || configAppliesToProvider(opts.envConfig, opts.provider, opts.activeProvider)) {
    addSource(sources, 'ENV');
  }
  if (configAppliesToProvider(opts.workspace, opts.provider, opts.activeProvider)) {
    addSource(sources, 'Workspace');
  }
  if (configAppliesToProvider(opts.cli, opts.provider, opts.activeProvider)) {
    addSource(sources, 'CLI');
  }
  return orderedSources(sources);
}

function issue(code: ProviderStatusIssueCode, requirement: string, message: string, envVar?: string): ProviderStatusIssue {
  return {
    code,
    requirement,
    message,
    ...(envVar ? { envVar } : {})
  };
}

function providerSetup(provider: ProviderName): string[] {
  return [...(getProviderCatalogEntry(provider)?.setup.primary ?? [])];
}

function resolveProviderModel(opts: {
  provider: ProviderName;
  activeProvider: ProviderName;
  cli: PartialModelConfig;
  workspace: PartialModelConfig | undefined;
  envConfig: PartialModelConfig;
  ollamaModels?: OllamaModelSummary[];
}) {
  const providerDef = getModelProvider(opts.provider);
  return firstDefined(
    sourceValue(opts.cli, opts.provider, opts.activeProvider, 'model'),
    sourceValue(opts.workspace, opts.provider, opts.activeProvider, 'model'),
    sourceValue(opts.envConfig, opts.provider, opts.activeProvider, 'model'),
    providerDef.getDefaultModel(),
    opts.provider === 'ollama' ? selectDefaultOllamaModel(opts.ollamaModels ?? []) : undefined
  );
}

function resolveProviderBaseUrl(opts: {
  provider: ProviderName;
  activeProvider: ProviderName;
  cli: PartialModelConfig;
  workspace: PartialModelConfig | undefined;
  envConfig: PartialModelConfig;
}) {
  const providerDef = getModelProvider(opts.provider);
  return firstDefined(
    sourceValue(opts.cli, opts.provider, opts.activeProvider, 'baseUrl'),
    sourceValue(opts.workspace, opts.provider, opts.activeProvider, 'baseUrl'),
    sourceValue(opts.envConfig, opts.provider, opts.activeProvider, 'baseUrl'),
    providerDef.defaultBaseUrl
  );
}

function buildRemoteProviderStatus(opts: {
  provider: ProviderName;
  activeProvider: ProviderName;
  cli: PartialModelConfig;
  workspace: PartialModelConfig | undefined;
  envConfig: PartialModelConfig;
  env: Record<string, string | undefined>;
}): ProviderStatus {
  const providerDef = getModelProvider(opts.provider);
  const model = resolveProviderModel(opts);
  const baseUrl = resolveProviderBaseUrl(opts);
  const issues: ProviderStatusIssue[] = [];

  if (providerDef.requiresApiKey && !hasEnvApiKey(opts.provider, opts.env)) {
    issues.push(
      issue(
        'missing-api-key',
        providerDef.apiKeyEnv ?? 'API key',
        `${providerDef.displayName} requires ${providerDef.apiKeyEnv ?? 'an API key'}.`,
        providerDef.apiKeyEnv
      )
    );
  }
  if (!baseUrl) {
    issues.push(issue('missing-base-url', 'base URL', `${providerDef.displayName} requires a base URL.`));
  }
  if (!model) {
    issues.push(issue('missing-model', 'model', `${providerDef.displayName} requires a model id.`));
  }

  const state: ProviderConfigState = issues.length === 0 ? 'configured' : 'not-configured';
  return {
    provider: opts.provider,
    displayName: providerDef.displayName,
    current: opts.provider === opts.activeProvider,
    state,
    sources: state === 'configured' ? configuredSourcesForProvider(opts) : [],
    issues,
    setup: providerSetup(opts.provider),
    ...(model ? { model } : {}),
    ...(baseUrl ? { baseUrl } : {})
  };
}

async function buildOllamaProviderStatus(opts: {
  activeProvider: ProviderName;
  cli: PartialModelConfig;
  workspace: PartialModelConfig | undefined;
  envConfig: PartialModelConfig;
  discoverOllamaModels: (baseUrl: string) => Promise<OllamaModelSummary[]>;
}): Promise<ProviderStatus> {
  const providerDef = getModelProvider('ollama');
  const baseUrl = resolveProviderBaseUrl({ ...opts, provider: 'ollama' });
  const setup = providerSetup('ollama');
  let models: OllamaModelSummary[];
  try {
    models = await opts.discoverOllamaModels(baseUrl ?? providerDef.defaultBaseUrl);
  } catch (error) {
    return {
      provider: 'ollama',
      displayName: providerDef.displayName,
      current: opts.activeProvider === 'ollama',
      state: 'unavailable',
      sources: [],
      issues: [
        issue(
          'local-service-unavailable',
          'local service',
          `Ollama local service is unavailable: ${error instanceof Error ? error.message : String(error)}`
        )
      ],
      setup,
      ...(baseUrl ? { baseUrl } : {})
    };
  }

  const model = resolveProviderModel({ ...opts, provider: 'ollama', ollamaModels: models });
  if (models.length === 0) {
    return {
      provider: 'ollama',
      displayName: providerDef.displayName,
      current: opts.activeProvider === 'ollama',
      state: 'not-configured',
      sources: ['Local service'],
      issues: [issue('local-models-missing', 'local model', 'Ollama is reachable, but no local models are installed.')],
      setup,
      ...(baseUrl ? { baseUrl } : {})
    };
  }

  return {
    provider: 'ollama',
    displayName: providerDef.displayName,
    current: opts.activeProvider === 'ollama',
    state: 'configured',
    sources: ['Local service'],
    issues: [],
    setup,
    modelCount: models.length,
    ...(model ? { model } : {}),
    ...(baseUrl ? { baseUrl } : {})
  };
}

function sortProviders(activeProvider: ProviderName, providers: ProviderStatus[]) {
  const stateRank: Record<ProviderConfigState, number> = {
    configured: 0,
    'not-configured': 1,
    unavailable: 2
  };
  return [...providers].sort((left, right) => {
    if (left.provider === activeProvider) return -1;
    if (right.provider === activeProvider) return 1;
    const stateDelta = stateRank[left.state] - stateRank[right.state];
    if (stateDelta !== 0) return stateDelta;
    return 0;
  });
}

export async function buildProviderStatusReport({
  workspace,
  cli,
  env = process.env,
  discoverOllamaModels = defaultDiscoverOllamaModels
}: BuildProviderStatusReportOptions): Promise<ProviderStatusReport> {
  const envConfig = envModelConfig(env);
  const activeProvider = resolveActiveProvider(cli, workspace.model, env);
  const providers = await Promise.all(
    listModelProviders().map((provider) =>
      provider.name === 'ollama'
        ? buildOllamaProviderStatus({
            activeProvider,
            cli,
            workspace: workspace.model,
            envConfig,
            discoverOllamaModels
          })
        : buildRemoteProviderStatus({
            provider: provider.name,
            activeProvider,
            cli,
            workspace: workspace.model,
            envConfig,
            env
          })
    )
  );
  const sorted = sortProviders(activeProvider, providers);
  return {
    activeProvider,
    ...(sorted.find((provider) => provider.provider === activeProvider)?.model
      ? { activeModel: sorted.find((provider) => provider.provider === activeProvider)?.model }
      : {}),
    providers: sorted,
    credentialPersistence: {
      mode: 'external-only',
      supportsManagedCredentials: false,
      message:
        'Cliq does not store provider secrets in this slice. Use environment variables or non-secret workspace model settings.'
    }
  };
}

export function formatProviderStateLabel(state: ProviderConfigState) {
  if (state === 'configured') return 'Configured';
  if (state === 'not-configured') return 'Not configured';
  return 'Unavailable';
}

function plural(count: number, singular: string) {
  return count === 1 ? `${count} ${singular}` : `${count} ${singular}s`;
}

export function formatProviderStatusRow(status: ProviderStatus): string {
  const parts: string[] = [];
  if (status.current) parts.push('Current');
  parts.push(formatProviderStateLabel(status.state));

  if (status.sources.length > 0) {
    parts.push(status.sources.join(', '));
  }

  if (status.state === 'unavailable') {
    parts.push('local service unavailable');
  } else if (status.state === 'not-configured' && status.issues.length > 0) {
    parts.push(`needs ${status.issues.map((current) => current.requirement).join(', ')}`);
  }

  if (status.modelCount !== undefined) {
    parts.push(plural(status.modelCount, 'model'));
  }
  if (status.model) {
    parts.push(`using ${status.model}`);
  }

  return `${status.displayName.padEnd(18)} ${parts.join(' · ')}`;
}

export function formatProviderStatusReport(report: ProviderStatusReport): string {
  return [
    'Providers:',
    ...report.providers.map(formatProviderStatusRow),
    '',
    `Credential storage: ${report.credentialPersistence.message}`
  ].join('\n');
}

export function validateProviderStatus(
  report: ProviderStatusReport,
  provider: ProviderName = report.activeProvider
): ProviderValidationResult {
  const status = report.providers.find((candidate) => candidate.provider === provider);
  if (!status) {
    throw new Error(`Unknown model provider: ${provider}`);
  }
  if (status.state === 'configured') {
    return {
      ok: true,
      provider,
      state: 'configured',
      sources: status.sources
    };
  }
  return {
    ok: false,
    provider,
    state: status.state,
    issues: status.issues
  };
}

export function buildProviderSetupSummary(
  report: ProviderStatusReport,
  provider: ProviderName = report.activeProvider
): ProviderSetupSummary {
  const status = report.providers.find((candidate) => candidate.provider === provider);
  if (!status) {
    throw new Error(`Unknown model provider: ${provider}`);
  }
  return {
    provider,
    displayName: status.displayName,
    state: status.state,
    instructions: [...status.setup],
    issues: [...status.issues],
    credentialPersistence: report.credentialPersistence
  };
}
