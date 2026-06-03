import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';
import { render as inkRender } from 'ink';
import type { ReactElement } from 'react';

import { ModelSetupRequiredError } from '../model/config.js';
import type { ModelPickerSnapshot } from '../model/model-picker.js';
import type { ModelSetupApplyRequest } from './components/model-setup-flow.js';
import { mountProviderSetupAndWait, ProviderSetup, type ProviderSetupResult } from './provider-setup.js';

type RenderedModelSetup = ReactElement<{
  onApply: (request: ModelSetupApplyRequest) => void | Promise<void>;
  onClose: () => void;
}>;

const error = new ModelSetupRequiredError({
  reason: 'no-local-model',
  provider: 'ollama',
  baseUrl: 'http://localhost:11434'
});

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
    }
  ],
  modelsByProvider: {
    ollama: [
      {
        kind: 'model',
        provider: 'ollama',
        model: 'qwen3.5:4b',
        displayName: 'qwen3.5:4b',
        labels: ['Current']
      }
    ]
  }
};

function createFakeRender(autoExit = false) {
  let resolveExit!: () => void;
  const exitPromise = autoExit
    ? Promise.resolve()
    : new Promise<void>((resolve) => {
        resolveExit = resolve;
      });
  let element: ReactElement | null = null;
  let unmounts = 0;
  const fakeRender = ((nextElement: ReactElement) => {
    element = nextElement;
    return {
      waitUntilExit: async () => {
        await exitPromise;
      },
      unmount: () => {
        unmounts += 1;
        resolveExit?.();
      }
    } as ReturnType<typeof inkRender>;
  }) as typeof inkRender;

  return {
    fakeRender,
    get element() {
      return element;
    },
    get unmounts() {
      return unmounts;
    }
  };
}

test('provider setup screen renders provider-first setup guidance', () => {
  const { lastFrame } = render(<ProviderSetup error={error} />);
  const frame = lastFrame() ?? '';

  assert.match(frame, /Cliq needs a model provider before chat can start/i);
  assert.match(frame, /Provider configuration/i);
  assert.match(frame, /Model selection/i);
  assert.match(frame, /Local Ollama/i);
  assert.match(frame, /ollama pull qwen3\.5:4b/);
  assert.match(frame, /OpenAI/i);
  assert.match(frame, /Anthropic/i);
  assert.match(frame, /OpenRouter/i);
  assert.match(frame, /Press Enter or q to exit/i);
  assert.doesNotMatch(frame, /cliq>/);
});

test('mountProviderSetupAndWait non-interactive path returns null after the setup screen exits', async () => {
  const fake = createFakeRender(true);

  const result = await mountProviderSetupAndWait(error, undefined, fake.fakeRender);

  assert.equal(result, null);
  assert.ok(fake.element);
  assert.equal(fake.unmounts, 0);
});

test('mountProviderSetupAndWait interactive path returns the onApply result', async () => {
  const fake = createFakeRender();
  const applied: ModelSetupApplyRequest[] = [];
  const expected: ProviderSetupResult = { version: 1, activeProvider: 'ollama', providers: { ollama: { model: 'qwen3.5:4b' } } };
  const promise = mountProviderSetupAndWait(
    error,
    {
      snapshot,
      onApply: (request) => {
        applied.push(request);
        return expected;
      }
    },
    fake.fakeRender
  );

  const element = fake.element as RenderedModelSetup;
  await element.props.onApply({ provider: 'ollama', model: 'qwen3.5:4b', persist: false });

  assert.deepEqual(applied, [{ provider: 'ollama', model: 'qwen3.5:4b', persist: false }]);
  assert.equal(fake.unmounts, 1);
  assert.equal(await promise, expected);
});

test('mountProviderSetupAndWait interactive close returns null', async () => {
  const fake = createFakeRender();
  const promise = mountProviderSetupAndWait(
    error,
    {
      snapshot,
      onApply: () => {
        throw new Error('should not apply');
      }
    },
    fake.fakeRender
  );

  const element = fake.element as RenderedModelSetup;
  element.props.onClose();

  assert.equal(fake.unmounts, 1);
  assert.equal(await promise, null);
});

test('mountProviderSetupAndWait closes and propagates interactive apply failures', async () => {
  const fake = createFakeRender();
  const promise = mountProviderSetupAndWait(
    error,
    {
      snapshot,
      onApply: () => {
        throw new Error('apply failed');
      }
    },
    fake.fakeRender
  );

  const element = fake.element as RenderedModelSetup;
  await element.props.onApply({ provider: 'ollama', model: 'qwen3.5:4b', persist: false });

  assert.equal(fake.unmounts, 1);
  await assert.rejects(promise, /apply failed/);
});
