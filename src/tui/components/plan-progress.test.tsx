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
  assert.match(frame, /· Implementing\.\.\./);
  assert.match(frame, /1\/3 done/);
  assert.match(frame, /1 pending/);
  assert.match(frame, /✓ Inspect/);
  assert.match(frame, /■ Implement/);
  assert.match(frame, /Implementing/);
  assert.match(frame, /□ Verify/);
});

test('PlanProgressView collapses long plans around the active item', () => {
  const { lastFrame } = render(
    <PlanProgressView
      progress={{
        planId: 'plan_1',
        title: 'Long tracker',
        path: '/tmp/progress.json',
        items: [
          { id: 'item_1', title: 'One', status: 'completed', activeForm: 'One' },
          { id: 'item_2', title: 'Two', status: 'completed', activeForm: 'Two' },
          { id: 'item_3', title: 'Three', status: 'completed', activeForm: 'Three' },
          { id: 'item_4', title: 'Four', status: 'completed', activeForm: 'Four' },
          { id: 'item_5', title: 'Five', status: 'in_progress', activeForm: 'Doing five' },
          { id: 'item_6', title: 'Six', status: 'pending', activeForm: 'Six' },
          { id: 'item_7', title: 'Seven', status: 'pending', activeForm: 'Seven' }
        ]
      }}
    />
  );

  const frame = lastFrame() ?? '';
  assert.doesNotMatch(frame, /✓ One/);
  assert.match(frame, /■ Five/);
  assert.match(frame, /\.\.\. \+2 completed/);
});
