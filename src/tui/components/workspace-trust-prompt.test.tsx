import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { WorkspaceTrustPrompt } from './workspace-trust-prompt.js';

const flush = () => new Promise<void>((r) => setImmediate(r));

test('workspace trust ink prompt renders path and honours y/n/escape decisions', async () => {
  const canonical = '/canonical/project';
  const calls: boolean[] = [];
  const trusted = render(
    <WorkspaceTrustPrompt workspaceRealPath={canonical} cwdLabel="/via/symlink" onDecided={(v) => calls.push(v)} />
  );

  assert.match(trusted.lastFrame() ?? '', /canonical: \/canonical\/project/);

  trusted.stdin.write('y');
  await flush();
  assert.deepEqual(calls, [true]);

  const denyN = render(
    <WorkspaceTrustPrompt workspaceRealPath={canonical} onDecided={(v) => calls.push(v)} />
  );
  denyN.stdin.write('n');
  await flush();
  assert.deepEqual(calls.slice(-1), [false]);
});
