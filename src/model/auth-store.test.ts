import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  authFilePath,
  formatProviderAuthSummary,
  loadProviderAuthStore,
  upsertProviderAuth
} from './auth-store.js';

test('upsertProviderAuth writes a local auth file without exposing secrets in summaries', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-auth-'));
  try {
    const store = await upsertProviderAuth(
      {
        provider: 'openai',
        apiKey: 'sk-secret',
        model: 'gpt-5.2',
        baseUrl: 'https://user:pass@example.test/v1?token=secret#fragment'
      },
      { cliqHome: home }
    );

    assert.equal(store.activeProvider, 'openai');
    assert.equal(store.providers.openai?.apiKey, 'sk-secret');
    assert.equal(store.providers.openai?.model, 'gpt-5.2');

    const target = authFilePath(home);
    const raw = await readFile(target, 'utf8');
    assert.match(raw, /"version": 1/);
    assert.match(raw, /"apiKey": "sk-secret"/);

    const mode = (await stat(target)).mode & 0o777;
    assert.equal(mode, 0o600);

    const loaded = await loadProviderAuthStore({ cliqHome: home });
    assert.deepEqual(loaded, store);

    const summary = formatProviderAuthSummary(store, 'openai');
    assert.match(summary, /OpenAI credential saved/);
    assert.match(summary, /model gpt-5\.2/);
    assert.match(summary, /base URL configured/);
    assert.doesNotMatch(summary, /sk-secret/);
    assert.doesNotMatch(summary, /user:pass|token=secret|fragment|example\.test/);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('loadProviderAuthStore returns an empty store when auth.json is missing', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-auth-empty-'));
  try {
    assert.deepEqual(await loadProviderAuthStore({ cliqHome: home }), {
      version: 1,
      providers: {}
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('loadProviderAuthStore tightens broad auth file permissions before reading', async () => {
  if (process.platform === 'win32') {
    return;
  }
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-auth-perms-'));
  try {
    const target = authFilePath(home);
    await writeFile(
      target,
      JSON.stringify({
        version: 1,
        providers: {
          openai: {
            apiKey: 'sk-secret'
          }
        }
      }),
      { mode: 0o644 }
    );
    await chmod(target, 0o644);

    const loaded = await loadProviderAuthStore({ cliqHome: home });
    assert.equal(loaded.providers.openai?.apiKey, 'sk-secret');
    const mode = (await stat(target)).mode & 0o777;
    assert.equal(mode, 0o600);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('upsertProviderAuth preserves concurrent updates for different providers', async () => {
  const home = await mkdtemp(path.join(tmpdir(), 'cliq-auth-concurrent-'));
  try {
    await Promise.all([
      upsertProviderAuth({ provider: 'openai', apiKey: 'sk-openai', model: 'gpt-5.2' }, { cliqHome: home }),
      upsertProviderAuth({ provider: 'anthropic', apiKey: 'sk-anthropic', model: 'claude-sonnet-4-20250514' }, { cliqHome: home })
    ]);

    const loaded = await loadProviderAuthStore({ cliqHome: home });
    assert.equal(loaded.providers.openai?.apiKey, 'sk-openai');
    assert.equal(loaded.providers.openai?.model, 'gpt-5.2');
    assert.equal(loaded.providers.anthropic?.apiKey, 'sk-anthropic');
    assert.equal(loaded.providers.anthropic?.model, 'claude-sonnet-4-20250514');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
