import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { ModelPickerSnapshot } from '../../model/model-picker.js';
import { ModelSetupFlow, type ModelSetupApplyRequest } from './model-setup-flow.js';

const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

function makeSnapshot(overrides: Partial<ModelPickerSnapshot> = {}): ModelPickerSnapshot {
  const snapshot: ModelPickerSnapshot = {
    selectedProvider: 'ollama',
    providers: [
      {
        provider: 'ollama',
        displayName: 'Ollama',
        state: 'configured',
        stateLabel: 'Configured',
        current: true,
        issues: []
      },
      {
        provider: 'openai',
        displayName: 'OpenAI',
        state: 'configured',
        stateLabel: 'Configured',
        current: false,
        issues: []
      }
    ],
    modelsByProvider: {
      ollama: [
        {
          kind: 'model',
          provider: 'ollama',
          model: 'qwen3.5:4b',
          displayName: 'qwen3.5:4b',
          labels: ['Current', 'Local']
        }
      ],
      openai: [
        {
          kind: 'model',
          provider: 'openai',
          model: 'gpt-5.2',
          displayName: 'GPT-5.2',
          labels: ['Startup default', 'Catalog']
        }
      ]
    }
  };
  return { ...snapshot, ...overrides };
}

test('model setup flow opens provider step first with current runtime provider selected', async () => {
  const { lastFrame } = render(
    <ModelSetupFlow snapshot={makeSnapshot()} onApply={() => {}} onClose={() => {}} />
  );
  await flush();
  const frame = lastFrame() ?? '';
  assert.match(frame, /Model setup/);
  assert.match(frame, /> Ollama\s+Configured/);
  assert.match(frame, /Provider step: Enter\/Right models/);
});

test('model setup flow moves to model step with Enter and applies current session with Enter', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin } = render(
    <ModelSetupFlow
      snapshot={makeSnapshot()}
      onApply={(request) => {
        applied.push(request);
      }}
      onClose={() => {}}
    />
  );

  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('\r');
  await flush();

  assert.deepEqual(applied, [{ provider: 'ollama', model: 'qwen3.5:4b', persist: false }]);
});

test('model setup flow saves startup default with Space', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin } = render(
    <ModelSetupFlow
      snapshot={makeSnapshot()}
      onApply={(request) => {
        applied.push(request);
      }}
      onClose={() => {}}
    />
  );

  await flush();
  stdin.write('\r');
  await flush();
  stdin.write(' ');
  await flush();

  assert.deepEqual(applied, [{ provider: 'ollama', model: 'qwen3.5:4b', persist: true }]);
});

test('model setup flow opens custom model input with c', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin } = render(
    <ModelSetupFlow
      snapshot={makeSnapshot()}
      onApply={(request) => {
        applied.push(request);
      }}
      onClose={() => {}}
    />
  );

  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('c');
  await flush();
  stdin.write('custom-model');
  await flush();
  stdin.write('\r');
  await flush();

  assert.deepEqual(applied, [{ provider: 'ollama', model: 'custom-model', persist: false }]);
});

test('model setup flow allows q in custom model input without closing', async () => {
  const applied: ModelSetupApplyRequest[] = [];
  let closed = false;
  const { stdin } = render(
    <ModelSetupFlow
      snapshot={makeSnapshot()}
      onApply={(request) => {
        applied.push(request);
      }}
      onClose={() => {
        closed = true;
      }}
    />
  );

  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('c');
  await flush();
  stdin.write('q');
  await flush();
  stdin.write('wen-custom');
  await flush();
  stdin.write('\r');
  await flush();

  assert.equal(closed, false);
  assert.deepEqual(applied, [{ provider: 'ollama', model: 'qwen-custom', persist: false }]);
});

test('model setup flow masks API key input and never renders the secret', async () => {
  const snapshot = makeSnapshot({
    selectedProvider: 'openai',
    providers: [
      {
        provider: 'openai',
        displayName: 'OpenAI',
        state: 'not-configured',
        stateLabel: 'Not configured',
        current: true,
        issues: ['OPENAI_API_KEY']
      }
    ],
    modelsByProvider: { openai: [] }
  });
  const { stdin, lastFrame } = render(
    <ModelSetupFlow snapshot={snapshot} onApply={() => {}} onClose={() => {}} />
  );

  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('sk-secret');
  await flush();

  const frame = lastFrame() ?? '';
  assert.match(frame, /\*{4,}/);
  assert.doesNotMatch(frame, /sk-secret/);
});

test('model setup flow requires explicit confirmation before saving a required API key', async () => {
  const snapshot = makeSnapshot({
    selectedProvider: 'openai',
    providers: [
      {
        provider: 'openai',
        displayName: 'OpenAI',
        state: 'not-configured',
        stateLabel: 'Not configured',
        current: true,
        issues: ['OPENAI_API_KEY']
      }
    ],
    modelsByProvider: {
      openai: [
        {
          kind: 'model',
          provider: 'openai',
          model: 'gpt-5.2',
          displayName: 'GPT-5.2',
          labels: ['Catalog']
        }
      ]
    }
  });
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin, lastFrame } = render(
    <ModelSetupFlow
      snapshot={snapshot}
      onApply={(request) => {
        applied.push(request);
      }}
      onClose={() => {}}
    />
  );

  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('sk-secret');
  await flush();
  stdin.write('\r');
  await flush();

  assert.deepEqual(applied, []);
  assert.match(lastFrame() ?? '', /GPT-5\.2/);
  assert.doesNotMatch(lastFrame() ?? '', /sk-secret/);

  stdin.write(' ');
  await flush();

  assert.deepEqual(applied, []);
  assert.match(lastFrame() ?? '', /Save API key/i);
  assert.doesNotMatch(lastFrame() ?? '', /sk-secret/);

  stdin.write(' ');
  await flush();

  assert.deepEqual(applied, [
    { provider: 'openai', model: 'gpt-5.2', apiKey: 'sk-secret', persist: true }
  ]);
});

test('model setup flow configures OpenAI-compatible base URL, direct model id, and optional key', async () => {
  const snapshot = makeSnapshot({
    selectedProvider: 'openai-compatible',
    providers: [
      {
        provider: 'openai-compatible',
        displayName: 'OpenAI-compatible',
        state: 'not-configured',
        stateLabel: 'Not configured',
        current: true,
        issues: ['base URL', 'model']
      }
    ],
    modelsByProvider: { 'openai-compatible': [] }
  });
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin, lastFrame } = render(
    <ModelSetupFlow
      snapshot={snapshot}
      onApply={(request) => {
        applied.push(request);
      }}
      onClose={() => {}}
    />
  );

  await flush();
  stdin.write('\r');
  await flush();
  assert.match(lastFrame() ?? '', /base URL/);

  stdin.write('http://localhost:4000/v1');
  await flush();
  stdin.write('\r');
  await flush();
  assert.match(lastFrame() ?? '', /model id/);

  stdin.write('direct-model-id');
  await flush();
  stdin.write('\r');
  await flush();
  assert.match(lastFrame() ?? '', /optional API key/i);
  assert.deepEqual(applied, []);

  stdin.write('sk-compatible');
  await flush();
  assert.doesNotMatch(lastFrame() ?? '', /sk-compatible/);
  stdin.write(' ');
  await flush();

  assert.deepEqual(applied, []);
  assert.match(lastFrame() ?? '', /Save API key/i);
  assert.doesNotMatch(lastFrame() ?? '', /sk-compatible/);

  stdin.write(' ');
  await flush();

  assert.deepEqual(applied, [
    {
      provider: 'openai-compatible',
      baseUrl: 'http://localhost:4000/v1',
      model: 'direct-model-id',
      apiKey: 'sk-compatible',
      persist: true
    }
  ]);
});

test('model setup flow discovers selectable models after OpenAI-compatible base URL entry', async () => {
  const snapshot = makeSnapshot({
    selectedProvider: 'openai-compatible',
    providers: [
      {
        provider: 'openai-compatible',
        displayName: 'OpenAI-compatible',
        state: 'not-configured',
        stateLabel: 'Not configured',
        current: true,
        issues: ['base URL', 'model']
      }
    ],
    modelsByProvider: { 'openai-compatible': [] }
  });
  const discovered: Array<{ provider: string; baseUrl?: string; apiKey?: string }> = [];
  const applied: ModelSetupApplyRequest[] = [];
  const { stdin, lastFrame } = render(
    <ModelSetupFlow
      snapshot={snapshot}
      onApply={(request) => {
        applied.push(request);
      }}
      onDiscoverModels={async (request) => {
        discovered.push(request);
        return [
          {
            kind: 'model',
            provider: 'openai-compatible',
            model: 'local-coder:latest',
            displayName: 'local-coder:latest',
            labels: ['Provider API']
          }
        ];
      }}
      onClose={() => {}}
    />
  );

  await flush();
  stdin.write('\r');
  await flush();
  stdin.write('http://localhost:4000/v1');
  await flush();
  stdin.write('\r');
  await flush();

  assert.deepEqual(discovered, [{ provider: 'openai-compatible', baseUrl: 'http://localhost:4000/v1' }]);
  assert.match(lastFrame() ?? '', /local-coder:latest/);
  assert.doesNotMatch(lastFrame() ?? '', /Enter openai-compatible model id/);

  stdin.write('\r');
  await flush();

  assert.deepEqual(applied, []);
  assert.match(lastFrame() ?? '', /optional API key/i);

  stdin.write('\r');
  await flush();

  assert.deepEqual(applied, [
    {
      provider: 'openai-compatible',
      baseUrl: 'http://localhost:4000/v1',
      model: 'local-coder:latest',
      persist: false
    }
  ]);
});
