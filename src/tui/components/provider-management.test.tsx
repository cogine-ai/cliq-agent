import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { ProviderStatusReport } from '../../model/provider-status.js';
import type { ProviderName } from '../../model/types.js';
import { ProviderManagement } from './provider-management.js';

const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

const report: ProviderStatusReport = {
  activeProvider: 'openai',
  activeModel: 'gpt-5.2',
  providers: [
    {
      provider: 'openai',
      displayName: 'OpenAI',
      current: true,
      state: 'configured',
      sources: ['ENV'],
      issues: [],
      setup: [],
      model: 'gpt-5.2',
      baseUrl: 'https://api.openai.com/v1'
    }
  ],
  credentialPersistence: {
    mode: 'local-auth-file',
    supportsManagedCredentials: true,
    message: 'Local auth file'
  }
};

async function waitUntilActive(lastFrame: () => string | undefined) {
  let frame = lastFrame() ?? '';
  for (let i = 0; i < 5 && /Waiting for fresh input/.test(frame); i += 1) {
    await flush();
    frame = lastFrame() ?? '';
  }
}

test('provider management detail configure action calls onConfigure with the selected provider', async () => {
  const configured: ProviderName[] = [];
  const { stdin, lastFrame } = render(
    <ProviderManagement
      report={report}
      onClose={() => {}}
      onConfigure={(provider) => {
        configured.push(provider);
      }}
    />
  );

  await flush();
  await waitUntilActive(lastFrame);
  stdin.write('\r');
  await flush();

  assert.match(lastFrame() ?? '', /\[c\]onfigure/);

  stdin.write('c');
  await flush();

  assert.deepEqual(configured, ['openai']);
});

test('provider management detail hides configure action when no onConfigure handler is provided', async () => {
  let closed = false;
  const { stdin, lastFrame } = render(
    <ProviderManagement
      report={report}
      onClose={() => {
        closed = true;
      }}
    />
  );

  await flush();
  await waitUntilActive(lastFrame);
  stdin.write('\r');
  await flush();

  const detailFrame = lastFrame() ?? '';
  assert.doesNotMatch(detailFrame, /\[c\]onfigure/);

  stdin.write('c');
  await flush();

  assert.equal(closed, false);
  assert.match(lastFrame() ?? '', /OpenAI/);
});
