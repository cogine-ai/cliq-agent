import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import { PlanProgressView } from './plan-progress.js';

test('PlanProgressView renders approved-plan execution tracker state', () => {
  const { lastFrame } = render(
    <PlanProgressView
      progress={{
        planId: 'plan_1',
        title: 'Ship tracker',
        path: '/tmp/progress.json',
        items: [
          { id: 'item_1', title: 'Inspect', status: 'completed', activeForm: 'Inspecting' },
          { id: 'item_2', title: 'Implement', status: 'in_progress', activeForm: 'Implementing' },
          { id: 'item_3', title: 'Verify', status: 'pending', activeForm: 'Verifying' }
        ]
      }}
    />
  );

  const frame = lastFrame() ?? '';
  assert.match(frame, /Plan progress/);
  assert.match(frame, /1\/3 done/);
  assert.match(frame, /\[x\] Inspect/);
  assert.match(frame, /\[>\] Implement/);
  assert.match(frame, /Implementing/);
  assert.match(frame, /\[ \] Verify/);
});
