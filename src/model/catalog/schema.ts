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

export type ModelListSourceKind = 'snapshot' | 'ollama-tags' | 'provider-api' | 'user-config' | 'curated-local';

export type ModelListSource = {
  kind: ModelListSourceKind;
  description: string;
};

export type CatalogSourceKind =
  | 'static'
  | 'pi'
  | 'openclaw'
  | 'openrouter'
  | 'cliq-models'
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

export type ManagedRuntimePlatform = {
  os: 'darwin' | 'linux' | 'win32';
  arch: 'arm64' | 'x64';
};

export type ManagedRuntimeInstallationChannel = {
  kind: 'managed-binary' | 'existing-user-ollama';
  displayName: string;
  versionRequirement?: string;
};

export type ManagedRuntimeOwnershipMode = 'cliq-managed' | 'existing-user-ollama' | 'unsupported';

export type ManagedRuntimeCatalog = {
  id: string;
  engine: 'ollama-derived';
  managedDistribution: {
    name: string;
    version: string;
  };
  supportedPlatforms: ManagedRuntimePlatform[];
  installationChannels: ManagedRuntimeInstallationChannel[];
  compatibility: {
    ollamaApi: 'native-chat';
    minimumOllamaVersion: string;
  };
  ownershipModes: ManagedRuntimeOwnershipMode[];
  endpoint: {
    defaultBaseUrl: string;
    port?: number;
    socketPath?: string;
  };
};

export type CliqModelVisibility = 'recommended' | 'experimental' | 'hidden' | 'deprecated' | 'disabled';

export type CliqModelArtifactSource =
  | {
      type: 'hugging-face-gguf';
      repository: string;
      filename: string;
      revision?: string;
      url: string;
    }
  | {
      type: 'ollama-library';
      model: string;
      manifestDigest: string;
      url: string;
    };

export type CliqModelChecksum = {
  algorithm: 'sha256' | 'ollama-blob-digest';
  value: string;
};

export type CliqModelCatalogMetadata = {
  selectable: true;
  visibility: CliqModelVisibility;
  family: string;
  baseModel: string;
  parameterSize: string;
  quantization: string;
  artifact: {
    source: CliqModelArtifactSource;
    checksum: CliqModelChecksum;
    downloadSizeBytes: number;
    diskSizeBytes: number;
    license: {
      name: string;
      url?: string;
    };
  };
  requirements: {
    recommendedRamBytes: number;
    recommendedVramBytes?: number;
  };
  runtimeOptions: {
    contextWindow: number;
    numGpuLayers?: number;
  };
  runtimeImport: {
    runtimeId: string;
    targetModelTag: string;
    sourceModelTag?: string;
    modelfileTemplate?: string[];
    instructions: string[];
  };
  prompts: {
    disk: string;
    license: string;
    checksum: string;
  };
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
  runtime?: ManagedRuntimeCatalog;
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
  cliqModel?: CliqModelCatalogMetadata;
  source: CatalogSource;
  contextWindowSources?: ContextWindowSource[];
};

export type CatalogSnapshot = {
  version: 1;
  generatedAt: string;
  providers: ProviderCatalogEntry[];
  models: ModelCatalogEntry[];
};
