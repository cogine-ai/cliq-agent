import type { CatalogSnapshot } from './schema.js';

export const CATALOG_SNAPSHOT = {
  version: 1,
  generatedAt: '2026-06-01T00:00:00.000Z',
  providers: [
    {
      id: 'openrouter',
      displayName: 'OpenRouter',
      kind: 'aggregator',
      auth: { kind: 'api-key', envVar: 'OPENROUTER_API_KEY', required: true },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set OPENROUTER_API_KEY or configure an OpenRouter credential.'],
        docsUrl: 'https://openrouter.ai/docs'
      },
      modelListSource: {
        kind: 'snapshot',
        description: 'Static CLIQ catalog generated from upstream metadata.'
      },
      defaultModelId: 'anthropic/claude-sonnet-4.6',
      visibleModelLimit: 12,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'anthropic',
      displayName: 'Anthropic',
      kind: 'hosted-api',
      auth: { kind: 'api-key', envVar: 'ANTHROPIC_API_KEY', required: true },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set ANTHROPIC_API_KEY, then choose an Anthropic model.'],
        docsUrl: 'https://docs.anthropic.com'
      },
      modelListSource: {
        kind: 'snapshot',
        description: 'Static CLIQ catalog generated from upstream metadata.'
      },
      defaultModelId: 'claude-sonnet-4-20250514',
      visibleModelLimit: 8,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'openai',
      displayName: 'OpenAI',
      kind: 'hosted-api',
      auth: { kind: 'api-key', envVar: 'OPENAI_API_KEY', required: true },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set OPENAI_API_KEY, then choose an OpenAI model.'],
        docsUrl: 'https://platform.openai.com/docs'
      },
      modelListSource: {
        kind: 'snapshot',
        description: 'Static CLIQ catalog generated from upstream metadata.'
      },
      defaultModelId: 'gpt-5.2',
      visibleModelLimit: 8,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'openai-compatible',
      displayName: 'OpenAI-compatible',
      kind: 'openai-compatible',
      auth: { kind: 'api-key', envVar: 'CLIQ_MODEL_API_KEY', required: false },
      configSources: ['ENV', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Set a base URL and model id for the OpenAI-compatible endpoint.']
      },
      modelListSource: {
        kind: 'user-config',
        description: 'User or workspace configuration supplies the model id.'
      },
      visibleModelLimit: 0,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'ollama',
      displayName: 'Ollama',
      kind: 'local-runtime',
      auth: { kind: 'none' },
      configSources: ['Local service', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: ['Run Ollama locally and pull a model such as qwen3.5:4b.'],
        docsUrl: 'https://ollama.com'
      },
      modelListSource: {
        kind: 'ollama-tags',
        description: 'Local Ollama /api/tags discovery.'
      },
      visibleModelLimit: 8,
      source: { kind: 'cliq-overlay', confidence: 'high' }
    },
    {
      id: 'cliq-models',
      displayName: 'Cliq Models',
      kind: 'local-runtime',
      auth: { kind: 'none' },
      configSources: ['Local service', 'Workspace', 'Global', 'CLI'],
      setup: {
        primary: [
          'Choose a curated Cliq Models entry before using the managed local runtime.',
          'Cliq Models v1 does not mirror arbitrary Ollama tags or Hugging Face repositories.'
        ]
      },
      modelListSource: {
        kind: 'curated-local',
        description: 'Cliq-managed curated local model allowlist.'
      },
      visibleModelLimit: 8,
      runtime: {
        id: 'cliq-managed-ollama',
        engine: 'ollama-derived',
        managedDistribution: {
          name: 'Cliq Managed Ollama Runtime',
          version: '0.11.x'
        },
        supportedPlatforms: [
          { os: 'darwin', arch: 'arm64' },
          { os: 'darwin', arch: 'x64' },
          { os: 'linux', arch: 'arm64' },
          { os: 'linux', arch: 'x64' },
          { os: 'win32', arch: 'x64' }
        ],
        installationChannels: [
          {
            kind: 'managed-binary',
            displayName: 'Cliq-managed runtime bundle',
            versionRequirement: '0.11.x'
          },
          {
            kind: 'existing-user-ollama',
            displayName: 'Existing user Ollama service',
            versionRequirement: '>=0.11.0'
          }
        ],
        compatibility: {
          ollamaApi: 'native-chat',
          minimumOllamaVersion: '0.11.0'
        },
        ownershipModes: ['cliq-managed', 'existing-user-ollama', 'unsupported'],
        endpoint: {
          defaultBaseUrl: 'http://localhost:11434',
          port: 11434
        }
      },
      source: { kind: 'cliq-models', confidence: 'high' }
    }
  ],
  models: [
    {
      provider: 'openrouter',
      model: 'anthropic/claude-sonnet-4.6',
      displayName: 'Claude Sonnet 4.6 via OpenRouter',
      capabilities: {
        input: ['text'],
        output: ['text'],
        streaming: true,
        reasoning: true,
        toolCalling: true,
        contextWindow: 200_000,
        maxOutputTokens: 64_000
      },
      routing: {
        api: 'openai-completions',
        baseUrl: 'https://openrouter.ai/api/v1'
      },
      pricing: {
        input: 3,
        output: 15,
        cacheRead: 0.3,
        cacheWrite: 3.75
      },
      source: {
        kind: 'pi',
        confidence: 'medium',
        upstreamProvider: 'openrouter',
        upstreamModelId: 'anthropic/claude-sonnet-4.6'
      }
    },
    {
      provider: 'anthropic',
      model: 'claude-sonnet-4-20250514',
      displayName: 'Claude Sonnet 4',
      capabilities: {
        input: ['text', 'image'],
        output: ['text'],
        streaming: true,
        reasoning: true,
        toolCalling: true,
        contextWindow: 200_000,
        maxOutputTokens: 64_000
      },
      routing: {
        api: 'anthropic-messages',
        baseUrl: 'https://api.anthropic.com'
      },
      pricing: {
        input: 3,
        output: 15,
        cacheRead: 0.3,
        cacheWrite: 3.75
      },
      source: {
        kind: 'pi',
        confidence: 'medium',
        upstreamProvider: 'anthropic',
        upstreamModelId: 'claude-sonnet-4-20250514'
      }
    },
    {
      provider: 'openai',
      model: 'gpt-5.2',
      displayName: 'GPT-5.2',
      capabilities: {
        input: ['text', 'image'],
        output: ['text'],
        streaming: true,
        reasoning: true,
        toolCalling: true,
        contextWindow: 128_000,
        maxOutputTokens: 16_384
      },
      routing: {
        api: 'openai-responses',
        baseUrl: 'https://api.openai.com/v1'
      },
      pricing: {
        input: 1.75,
        output: 14,
        cacheRead: 0.175,
        cacheWrite: 0
      },
      source: {
        kind: 'pi',
        confidence: 'medium',
        upstreamProvider: 'openai',
        upstreamModelId: 'gpt-5.2'
      }
    },
    {
      provider: 'cliq-models',
      model: 'qwen2.5-coder-3b-instruct-q4-k-m',
      displayName: 'Qwen2.5 Coder 3B Instruct Q4_K_M',
      capabilities: {
        input: ['text'],
        output: ['text'],
        streaming: true,
        reasoning: true,
        toolCalling: false,
        contextWindow: 32_768,
        maxOutputTokens: 4096
      },
      routing: {
        api: 'ollama-chat',
        baseUrl: 'http://localhost:11434'
      },
      cliqModel: {
        selectable: true,
        visibility: 'recommended',
        family: 'Qwen2.5 Coder',
        baseModel: 'Qwen2.5-Coder-3B-Instruct',
        parameterSize: '3.09B',
        quantization: 'Q4_K_M',
        artifact: {
          source: {
            type: 'hugging-face-gguf',
            repository: 'Qwen/Qwen2.5-Coder-3B-Instruct-GGUF',
            filename: 'qwen2.5-coder-3b-instruct-q4_k_m.gguf',
            revision: '0176a16b23a3b49e84001eb37c99b0e5d5939492',
            url: 'https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/resolve/0176a16b23a3b49e84001eb37c99b0e5d5939492/qwen2.5-coder-3b-instruct-q4_k_m.gguf'
          },
          checksum: {
            algorithm: 'sha256',
            value: '724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7'
          },
          downloadSizeBytes: 2_100_000_000,
          diskSizeBytes: 2_300_000_000,
          license: {
            name: 'Qwen Research License',
            url: 'https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/blob/main/LICENSE'
          }
        },
        requirements: {
          recommendedRamBytes: 8_000_000_000,
          recommendedVramBytes: 0
        },
        runtimeOptions: {
          contextWindow: 32_768
        },
        runtimeImport: {
          runtimeId: 'cliq-managed-ollama',
          targetModelTag: 'cliq/qwen2.5-coder:3b-instruct-q4-k-m',
          modelfileTemplate: [
            'FROM ./qwen2.5-coder-3b-instruct-q4_k_m.gguf',
            'PARAMETER num_ctx 32768',
            'SYSTEM You are a helpful coding assistant.'
          ],
          instructions: [
            'Download the GGUF artifact and verify its SHA-256 digest before import.',
            'Create the managed Ollama model from the Modelfile template and verified GGUF file.'
          ]
        },
        prompts: {
          disk: 'Download requires about 2.1 GB and about 2.3 GB of local disk after import.',
          license: 'Show the Qwen Research License before download and require user acknowledgement.',
          checksum: 'Verify SHA-256 724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7 before import.'
        }
      },
      source: {
        kind: 'cliq-models',
        confidence: 'high',
        upstreamProvider: 'huggingface',
        upstreamModelId: 'Qwen/Qwen2.5-Coder-3B-Instruct-GGUF/qwen2.5-coder-3b-instruct-q4_k_m.gguf'
      }
    },
    {
      provider: 'cliq-models',
      model: 'qwen2.5-coder-3b-instruct-ollama-q4-k-m',
      displayName: 'Qwen2.5 Coder 3B Instruct via Ollama Library',
      capabilities: {
        input: ['text'],
        output: ['text'],
        streaming: true,
        reasoning: true,
        toolCalling: false,
        contextWindow: 32_768,
        maxOutputTokens: 4096
      },
      routing: {
        api: 'ollama-chat',
        baseUrl: 'http://localhost:11434'
      },
      cliqModel: {
        selectable: true,
        visibility: 'experimental',
        family: 'Qwen2.5 Coder',
        baseModel: 'qwen2.5-coder:3b-instruct',
        parameterSize: '3.09B',
        quantization: 'Q4_K_M',
        artifact: {
          source: {
            type: 'ollama-library',
            model: 'qwen2.5-coder:3b-instruct',
            manifestDigest: 'f72c60cabf62',
            url: 'https://ollama.com/library/qwen2.5-coder:3b-instruct'
          },
          checksum: {
            algorithm: 'ollama-blob-digest',
            value: '4a188102020e'
          },
          downloadSizeBytes: 1_900_000_000,
          diskSizeBytes: 2_100_000_000,
          license: {
            name: 'Qwen Research License',
            url: 'https://ollama.com/library/qwen2.5-coder:3b-instruct'
          }
        },
        requirements: {
          recommendedRamBytes: 8_000_000_000,
          recommendedVramBytes: 0
        },
        runtimeOptions: {
          contextWindow: 32_768
        },
        runtimeImport: {
          runtimeId: 'cliq-managed-ollama',
          sourceModelTag: 'qwen2.5-coder:3b-instruct',
          targetModelTag: 'cliq/qwen2.5-coder:3b-instruct-q4-k-m',
          instructions: [
            'Pull the approved Ollama library model qwen2.5-coder:3b-instruct.',
            'Verify the resolved model layer digest before exposing the Cliq-managed alias.',
            'Create or alias the managed tag cliq/qwen2.5-coder:3b-instruct-q4-k-m.'
          ]
        },
        prompts: {
          disk: 'Download requires about 1.9 GB and about 2.1 GB of local disk after import.',
          license: 'Show the Qwen Research License from the Ollama library manifest before download.',
          checksum: 'Verify Ollama model blob digest 4a188102020e before exposing the managed alias.'
        }
      },
      source: {
        kind: 'cliq-models',
        confidence: 'high',
        upstreamProvider: 'ollama-library',
        upstreamModelId: 'qwen2.5-coder:3b-instruct'
      }
    }
  ]
} satisfies CatalogSnapshot;
