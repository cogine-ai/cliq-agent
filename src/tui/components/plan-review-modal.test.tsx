import assert from 'node:assert/strict';
import { test } from 'node:test';

import { render } from 'ink-testing-library';

import type { PendingPlanReview, UiPlanDecision } from '../store.js';
import { PlanReviewModal } from './plan-review-modal.js';

const flush = () => new Promise<void>((r) => setImmediate(r));

const review: PendingPlanReview = {
  id: 'pr_1',
  planId: 'plan_1',
  title: 'Implement Plan Mode',
  contentMarkdown: '## Steps\n- Persist the plan\n- Review it',
  path: '/tmp/.cliq/plans/ws/sess/plan_1/plan.json'
};

test('renders finalized plan content and deliberate approval choices', () => {
  const { lastFrame } = render(<PlanReviewModal review={review} onDecide={() => {}} />);
  const frame = lastFrame() ?? '';
  assert.match(frame, /Plan review/);
  assert.match(frame, /Implement Plan Mode/);
  assert.match(frame, /Persist the plan/);
  assert.match(frame, /\[d\]efault Run/);
  assert.match(frame, /\[a\]ccept-edits Run/);
  assert.match(frame, /\[Y\]OLO Run/);
  assert.match(frame, /dangerous/);
});

test('ignores buffered input until active and requires uppercase Y for yolo approval', async () => {
  const calls: UiPlanDecision[] = [];
  const { stdin } = render(
    <PlanReviewModal
      review={review}
      onDecide={(decision) => {
        calls.push(decision);
      }}
    />
  );

  stdin.write('d');
  await flush();
  assert.equal(calls.length, 0);

  stdin.write('y');
  await flush();
  assert.equal(calls.length, 0);

  stdin.write('Y');
  await flush();
  assert.deepEqual(calls, [{ type: 'approve', targetMode: 'yolo' }]);
});

test('maps review hotkeys to decisions', async () => {
  const calls: UiPlanDecision[] = [];
  const decide = (decision: UiPlanDecision) => {
    calls.push(decision);
  };

  const defaultRun = render(<PlanReviewModal review={review} onDecide={decide} />);
  await flush();
  defaultRun.stdin.write('d');
  await flush();

  const acceptEdits = render(<PlanReviewModal review={review} onDecide={decide} />);
  await flush();
  acceptEdits.stdin.write('a');
  await flush();

  const reject = render(<PlanReviewModal review={review} onDecide={decide} />);
  await flush();
  reject.stdin.write('r');
  await flush();

  const cancel = render(<PlanReviewModal review={review} onDecide={decide} />);
  await flush();
  cancel.stdin.write('c');
  await flush();

  assert.deepEqual(calls, [
    { type: 'approve', targetMode: 'default' },
    { type: 'approve', targetMode: 'accept-edits' },
    { type: 'reject' },
    { type: 'cancel' }
  ]);
});
