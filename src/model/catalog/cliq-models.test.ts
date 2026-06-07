import assert from 'node:assert/strict';
import test from 'node:test';

import {
  getProviderCatalogEntry,
  isSelectableCliqModel,
  listCliqModelCatalogEntries,
  parseCliqModelCatalogEntry,
  resolveModelMetadata
} from './index.js';
import type { ModelCatalogEntry } from './schema.js';

test('cliq-models provider describes a managed Ollama-derived runtime separately from raw Ollama', () => {
  const cliqModels = getProviderCatalogEntry('cliq-models');
  const rawOllama = getProviderCatalogEntry('ollama');

  assert.ok(cliqModels);
  assert.equal(cliqModels.displayName, 'Cliq Models');
  assert.equal(cliqModels.kind, 'local-runtime');
  assert.equal(cliqModels.modelListSource.kind, 'curated-local');
  assert.equal(cliqModels.runtime?.engine, 'ollama-derived');
  assert.equal(cliqModels.runtime?.managedDistribution.name, 'Cliq Managed Ollama Runtime');
  assert.equal(cliqModels.runtime?.compatibility.ollamaApi, 'native-chat');
  assert.deepEqual(cliqModels.runtime?.ownershipModes, ['cliq-managed', 'existing-user-ollama', 'unsupported']);
  assert.equal(cliqModels.runtime?.endpoint.defaultBaseUrl, 'http://localhost:11434');
  assert.ok(cliqModels.runtime?.supportedPlatforms.some((platform) => platform.os === 'darwin' && platform.arch === 'arm64'));
  assert.ok(cliqModels.runtime?.installationChannels.some((channel) => channel.kind === 'managed-binary'));

  assert.equal(rawOllama?.modelListSource.kind, 'ollama-tags');
  assert.equal(rawOllama?.runtime, undefined);
});

test('cliq-models catalog exposes a curated selectable allowlist with setup metadata', () => {
  const entries = listCliqModelCatalogEntries();
  assert.equal(entries.length >= 2, true);

  const sourceTypes = new Set(entries.map((entry) => entry.cliqModel.artifact.source.type));
  assert.equal(sourceTypes.has('hugging-face-gguf'), true);
  assert.equal(sourceTypes.has('ollama-library'), true);

  for (const entry of entries) {
    const parsed = parseCliqModelCatalogEntry(entry);
    assert.equal(parsed.ok, true, parsed.ok ? undefined : parsed.issues.join('\n'));
    if (!parsed.ok) continue;

    assert.equal(parsed.entry.provider, 'cliq-models');
    assert.equal(parsed.entry.cliqModel.selectable, true);
    assert.equal(parsed.entry.cliqModel.runtimeImport.runtimeId, 'cliq-managed-ollama');
    assert.match(parsed.entry.cliqModel.runtimeImport.targetModelTag, /^cliq\//);
    assert.ok(parsed.entry.cliqModel.artifact.downloadSizeBytes > 0);
    assert.ok(parsed.entry.cliqModel.artifact.diskSizeBytes >= parsed.entry.cliqModel.artifact.downloadSizeBytes);
    assert.ok(parsed.entry.cliqModel.artifact.license.name.length > 0);
    assert.ok(parsed.entry.cliqModel.prompts.disk.length > 0);
    assert.ok(parsed.entry.cliqModel.prompts.license.length > 0);
    assert.ok(parsed.entry.cliqModel.prompts.checksum.length > 0);
  }

  assert.equal(isSelectableCliqModel('qwen2.5-coder-3b-instruct-q4-k-m'), true);
  assert.equal(isSelectableCliqModel('qwen2.5-coder-3b-instruct-ollama-q4-k-m'), true);
  assert.equal(isSelectableCliqModel('qwen3:4b'), false);
  assert.equal(resolveModelMetadata('cliq-models', 'qwen3:4b'), null);
  assert.equal(resolveModelMetadata('ollama', 'qwen2.5-coder-3b-instruct-q4-k-m'), null);
});

test('cliq-models parser rejects malformed local catalog records', () => {
  const valid = resolveModelMetadata('cliq-models', 'qwen2.5-coder-3b-instruct-q4-k-m');
  assert.ok(valid?.cliqModel);

  const invalidChecksum: ModelCatalogEntry = {
    ...valid,
    cliqModel: {
      ...valid.cliqModel,
      artifact: {
        ...valid.cliqModel.artifact,
        downloadSizeBytes: 0,
        checksum: {
          algorithm: 'sha256',
          value: 'not-a-sha'
        }
      }
    }
  };

  const parsed = parseCliqModelCatalogEntry(invalidChecksum);
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.deepEqual(parsed.issues, [
    'cliqModel.artifact.downloadSizeBytes must be a positive integer',
    'cliqModel.artifact.checksum.value must be a 64 character hex SHA-256 digest'
  ]);

  const hostedModel = resolveModelMetadata('openai', 'gpt-5.2');
  assert.ok(hostedModel);
  const hostedParsed = parseCliqModelCatalogEntry(hostedModel);
  assert.equal(hostedParsed.ok, false);
  if (hostedParsed.ok) return;
  assert.deepEqual(hostedParsed.issues, [
    'provider must be cliq-models',
    'cliqModel metadata is required'
  ]);
});
