import assert from 'node:assert/strict';
import test from 'node:test';

import { createSession } from '../session/store.js';
import { planTool } from './plan.js';

test('planTool.supports validates plan action shapes', () => {
  assert.equal(planTool.supports({ plan: { op: 'draft', title: 'T', content: '## Plan' } }), true);
  assert.equal(planTool.supports({ plan: { op: 'update', planId: 'plan_1', content: '## Plan' } }), true);
  assert.equal(planTool.supports({ plan: { op: 'finalize', planId: 'plan_1' } }), true);

  assert.equal(planTool.supports({ plan: { op: 'draft', title: 'T' } } as never), false);
  assert.equal(planTool.supports({ plan: { op: 'approve', planId: 'plan_1' } } as never), false);
  assert.equal(planTool.supports({ plan: null } as never), false);
});

test('planTool.execute does not treat malformed plan ops as finalize', async () => {
  const result = await planTool.execute(
    { plan: { op: 'approve', planId: 'plan_1' } } as never,
    { cwd: process.cwd(), session: createSession(process.cwd()) }
  );

  assert.equal(result.status, 'error');
  assert.equal(result.meta.op, 'approve');
  assert.match(result.content, /unsupported plan op: approve/);
});
