import type { ModelCapabilities, ProviderName } from '../types.js';

export type ProviderKind = 'hosted-api' | 'local-runtime' | 'openai-compatible' | 'aggregator';

export type ConfigSourceLabel = 'ENV' | 'Workspace' | 'Global' | 'Managed credential' | 'CLI' | 'Local service';

export type ProviderAuth =
  | {
      kind: 'api-key';
      envVar: string;
      required: boolean;
    }
  | {
      kind: 'none';
    };

export type ModelListSourceKind = 'snapshot' | 'ollama-tags' | 'provider-api' | 'user-config';

export type ModelListSource = {
  kind: ModelListSourceKind;
  description: string;
};

export type CatalogSourceKind =
  | 'static'
  | 'pi'
  | 'openclaw'
  | 'openrouter'
  | 'cliq-overlay'
  | 'ollama-show'
  | 'ollama-unavailable'
  | 'workspace-override'
  | 'overflow-error'
  | 'unknown';

export type CatalogSourceConfidence = 'high' | 'medium' | 'low';

export type CatalogSource = {
  kind: CatalogSourceKind;
  confidence: CatalogSourceConfidence;
  upstreamProvider?: string;
  upstreamModelId?: string;
  fetchedAt?: string;
};

export type ContextWindowSourceKind = 'ollama-show-model-info' | 'ollama-show-parameters' | 'ollama-ps';

export type ContextWindowSource = {
  kind: ContextWindowSourceKind;
  contextWindow: number;
  confidence: CatalogSourceConfidence;
};

export type ProviderCatalogEntry = {
  id: ProviderName;
  displayName: string;
  kind: ProviderKind;
  auth: ProviderAuth;
  configSources: ConfigSourceLabel[];
  setup: {
    primary: string[];
    docsUrl?: string;
  };
  modelListSource: ModelListSource;
  defaultModelId?: string;
  visibleModelLimit?: number;
  source: CatalogSource;
};

export type ModelCatalogEntry = {
  provider: ProviderName;
  model: string;
  displayName: string;
  capabilities: ModelCapabilities;
  routing?: {
    api: string;
    baseUrl?: string;
  };
  pricing?: {
    input: number;
    output: number;
    cacheRead: number;
    cacheWrite: number;
  };
  compat?: Record<string, unknown>;
  source: CatalogSource;
  contextWindowSources?: ContextWindowSource[];
};

export type CatalogSnapshot = {
  version: 1;
  generatedAt: string;
  providers: ProviderCatalogEntry[];
  models: ModelCatalogEntry[];
};
