import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { ModelSetupRequiredError } from '../model/config.js';
import { ProviderSetup } from './provider-setup.js';

test('provider setup screen renders provider-first setup guidance', () => {
  const error = new ModelSetupRequiredError({
    reason: 'no-local-model',
    provider: 'ollama',
    baseUrl: 'http://localhost:11434'
  });

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
