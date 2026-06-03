import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { ProviderStatusReport } from '../../model/provider-status.js';
import { ProviderManagement } from './provider-management.js';

const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

const report: ProviderStatusReport = {
  activeProvider: 'openai',
  activeModel: 'gpt-workspace',
  providers: [
    {
      provider: 'openai',
      displayName: 'OpenAI',
      current: true,
      state: 'configured',
      sources: ['ENV', 'Workspace'],
      issues: [],
      setup: ['Set OPENAI_API_KEY, then choose an OpenAI model.'],
      model: 'gpt-workspace',
      baseUrl: 'https://api.openai.com/v1'
    },
    {
      provider: 'openrouter',
      displayName: 'OpenRouter',
      current: false,
      state: 'not-configured',
      sources: [],
      issues: [
        {
          code: 'missing-api-key',
          requirement: 'OPENROUTER_API_KEY',
          message: 'OpenRouter requires OPENROUTER_API_KEY.',
          envVar: 'OPENROUTER_API_KEY'
        }
      ],
      setup: ['Set OPENROUTER_API_KEY or configure an OpenRouter credential.']
    }
  ],
  credentialPersistence: {
    mode: 'local-auth-file',
    supportsManagedCredentials: true,
    message: 'Cliq can store provider API keys in the local user auth file.'
  }
};

async function waitForActiveInput(lastFrame: () => string | undefined) {
  let frame = lastFrame() ?? '';
  for (let attempt = 0; attempt < 5 && /Waiting for fresh input/.test(frame); attempt += 1) {
    await flush();
    frame = lastFrame() ?? '';
  }
  return frame;
}

test('ProviderManagement renders selectable provider rows and credential guidance', async () => {
  const { lastFrame } = render(<ProviderManagement report={report} onClose={() => {}} />);
  const frame = await waitForActiveInput(lastFrame);

  assert.match(frame, /Provider management/);
  assert.match(frame, /> OpenAI\s+Current · Configured · ENV, Workspace · using gpt-workspace/);
  assert.match(frame, /OpenRouter\s+Not configured · needs OPENROUTER_API_KEY/);
  assert.match(frame, /Enter details/);
});

test('ProviderManagement detail view uses human-readable state labels and setup guidance', async () => {
  const { stdin, lastFrame } = render(<ProviderManagement report={report} onClose={() => {}} />);
  await waitForActiveInput(lastFrame);

  stdin.write('j');
  await flush();
  stdin.write('\r');
  await flush();
  await flush();

  const frame = lastFrame() ?? '';
  assert.match(frame, /OpenRouter/);
  assert.match(frame, /state:\s+Not configured/);
  assert.doesNotMatch(frame, /state:\s+not-configured/);
  assert.match(frame, /Requirements/);
  assert.match(frame, /OPENROUTER_API_KEY/);
  assert.match(frame, /Setup/);
  assert.match(frame, /Cliq can store provider API keys in the local user auth file/);
  assert.match(frame, /\[b\]ack/);
});
