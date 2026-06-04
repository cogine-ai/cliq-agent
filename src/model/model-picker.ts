import { getProviderAuthEntry, type ProviderAuthStore } from './auth-store.js';
import { listModelCatalogEntries } from './catalog/index.js';
import type { PartialModelConfig } from './config.js';
import { formatProviderStateLabel, type ProviderConfigState, type ProviderStatusReport } from './provider-status.js';
import type { OllamaModelSummary } from './providers/ollama-discovery.js';
import type { ProviderName } from './types.js';

export type ModelRowLabel =
  | 'Current'
  | 'Startup default'
  | 'Provider default'
  | 'Catalog'
  | 'Provider API'
  | 'Local'
  | 'Configured'
  | 'Custom';

export type ModelPickerProviderRow = {
  provider: ProviderName;
  displayName: string;
  state: ProviderConfigState;
  stateLabel: string;
  current: boolean;
  issues: string[];
};

export type ModelPickerModelRow = {
  kind: 'model' | 'custom';
  provider: ProviderName;
  model: string;
  displayName: string;
  labels: ModelRowLabel[];
};

export type ModelPickerSnapshot = {
  selectedProvider: ProviderName;
  providers: ModelPickerProviderRow[];
  modelsByProvider: Partial<Record<ProviderName, ModelPickerModelRow[]>>;
};

export function buildModelPickerSnapshot(opts: {
  report: ProviderStatusReport;
  auth: ProviderAuthStore;
  currentModel: { provider: ProviderName; model: string };
  workspaceModel?: PartialModelConfig;
  cliModel?: PartialModelConfig;
  env?: Record<string, string | undefined>;
  ollamaModels?: OllamaModelSummary[];
}): ModelPickerSnapshot {
  const providers: ModelPickerProviderRow[] = opts.report.providers.map((provider) => ({
    provider: provider.provider,
    displayName: provider.displayName,
    state: provider.state,
    stateLabel: formatProviderStateLabel(provider.state),
    current: provider.provider === opts.currentModel.provider,
    issues: provider.issues.map((issue) => issue.requirement)
  }));

  const modelsByProvider: Partial<Record<ProviderName, ModelPickerModelRow[]>> = {};
  for (const provider of opts.report.providers) {
    modelsByProvider[provider.provider] = buildModelRowsForProvider({
      provider: provider.provider,
      auth: opts.auth,
      currentModel: opts.currentModel,
      workspaceModel: opts.workspaceModel ?? {},
      cliModel: opts.cliModel ?? {},
      env: opts.env ?? process.env,
      ollamaModels: opts.ollamaModels ?? []
    });
  }

  return {
    selectedProvider: opts.currentModel.provider,
    providers,
    modelsByProvider
  };
}

function buildModelRowsForProvider(opts: {
  provider: ProviderName;
  auth: ProviderAuthStore;
  currentModel: { provider: ProviderName; model: string };
  workspaceModel: PartialModelConfig;
  cliModel: PartialModelConfig;
  env: Record<string, string | undefined>;
  ollamaModels: OllamaModelSummary[];
}): ModelPickerModelRow[] {
  const rows = new Map<string, ModelPickerModelRow>();
  const add = (
    model: string | undefined,
    displayName: string | undefined,
    source: Exclude<ModelRowLabel, 'Current' | 'Startup default' | 'Provider default' | 'Custom'>
  ) => {
    if (!model) return;
    const existing = rows.get(model);
    if (existing) {
      if (!existing.labels.includes(source)) existing.labels.push(source);
      return;
    }
    rows.set(model, {
      kind: 'model',
      provider: opts.provider,
      model,
      displayName: displayName ?? model,
      labels: [source]
    });
  };

  for (const entry of listModelCatalogEntries(opts.provider)) {
    add(entry.model, entry.displayName, 'Catalog');
  }

  if (opts.provider === 'ollama') {
    for (const model of opts.ollamaModels) {
      add(model.name, model.name, 'Local');
    }
  }

  for (const model of configuredModelIds(opts)) {
    add(model, model, 'Configured');
  }

  const authEntry = getProviderAuthEntry(opts.auth, opts.provider);
  const isPersistedAuthEntry = Boolean(
    authEntry &&
      !authEntry.transient &&
      (authEntry.model || authEntry.baseUrl || authEntry.streaming || (authEntry.apiKey && !authEntry.transientApiKey))
  );
  for (const row of rows.values()) {
    const labels: ModelRowLabel[] = [];
    if (opts.currentModel.provider === opts.provider && opts.currentModel.model === row.model) {
      labels.push('Current');
    }
    if (isPersistedAuthEntry && opts.auth.activeProvider === opts.provider && authEntry?.model === row.model) {
      labels.push('Startup default');
    }
    if (isPersistedAuthEntry && opts.auth.activeProvider !== opts.provider && authEntry?.model === row.model) {
      labels.push('Provider default');
    }
    for (const label of row.labels) {
      if (!labels.includes(label)) labels.push(label);
    }
    row.labels = labels;
  }

  return [
    ...rows.values(),
    {
      kind: 'custom',
      provider: opts.provider,
      model: '',
      displayName: 'Custom model id',
      labels: ['Custom']
    }
  ];
}

function configuredModelIds(opts: {
  provider: ProviderName;
  auth: ProviderAuthStore;
  workspaceModel: PartialModelConfig;
  cliModel: PartialModelConfig;
  env: Record<string, string | undefined>;
}) {
  const ids = new Set<string>();
  const addIfProviderApplies = (config: PartialModelConfig | undefined) => {
    if (!config?.model) return;
    if (config.provider === undefined || config.provider === opts.provider) ids.add(config.model);
  };

  addIfProviderApplies(opts.cliModel);
  addIfProviderApplies(opts.workspaceModel);
  if (
    opts.env.CLIQ_MODEL &&
    (opts.env.CLIQ_MODEL_PROVIDER === undefined || opts.env.CLIQ_MODEL_PROVIDER === opts.provider)
  ) {
    ids.add(opts.env.CLIQ_MODEL);
  }

  const authEntry = getProviderAuthEntry(opts.auth, opts.provider);
  if (authEntry?.model) ids.add(authEntry.model);
  return [...ids];
}
