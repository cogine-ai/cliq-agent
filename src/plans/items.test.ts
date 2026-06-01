import assert from 'node:assert/strict';
import test from 'node:test';

import {
  extractPlanItems,
  isPlanItem,
  isPlanItemStatus,
  isPlanProgressItem,
  normalizePlanItems,
  normalizePlanProgressItems,
  normalizeStoredPlanItems,
  normalizeStoredPlanProgressItems,
  progressItemsFromPlanItems
} from './items.js';

test('isPlanItemStatus accepts only known execution states', () => {
  assert.equal(isPlanItemStatus('pending'), true);
  assert.equal(isPlanItemStatus('in_progress'), true);
  assert.equal(isPlanItemStatus('completed'), true);
  assert.equal(isPlanItemStatus('unknown'), false);
  assert.equal(isPlanItemStatus(null), false);
});

test('isPlanItem rejects unsafe ids and empty titles', () => {
  assert.equal(isPlanItem({ id: 'item_1', title: 'Inspect', status: 'pending' }), true);
  assert.equal(isPlanItem({ id: '../escape', title: 'Inspect', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item 1', title: 'Inspect', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: '   ', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: 'Inspect', status: 'pending', notes: 1 }), false);
});

test('extractPlanItems maps markdown checklist markers to item status', () => {
  const markdown = [
    '## Steps',
    '- Pending step',
    '- [~] In progress step',
    '- [x] Completed step',
    '- [X] Also completed',
    '- [-] Dash in progress',
    '1. Numbered step',
    '* [ ] Checkbox with star list'
  ].join('\n');

  assert.deepEqual(extractPlanItems(markdown), [
    { id: 'item_1', title: 'Pending step', status: 'pending' },
    { id: 'item_2', title: 'In progress step', status: 'in_progress' },
    { id: 'item_3', title: 'Completed step', status: 'completed' },
    { id: 'item_4', title: 'Also completed', status: 'completed' },
    { id: 'item_5', title: 'Dash in progress', status: 'in_progress' },
    { id: 'item_6', title: 'Numbered step', status: 'pending' },
    { id: 'item_7', title: 'Checkbox with star list', status: 'pending' }
  ]);
});

test('normalizePlanItems prefers explicit items and drops invalid entries', () => {
  const markdown = '## Steps\n- Ignored when explicit items are provided';
  assert.deepEqual(
    normalizePlanItems(
      [
        { id: 'inspect', title: 'Inspect code', status: 'completed' },
        { title: '   ' },
        { title: 'Ship', status: 'not-a-status' as never },
        { title: '[x] Strip checkbox prefix', notes: '  keep me  ' }
      ],
      markdown
    ),
    [
      { id: 'inspect', title: 'Inspect code', status: 'completed' },
      { id: 'item_4', title: 'Strip checkbox prefix', status: 'pending', notes: 'keep me' }
    ]
  );
});

test('normalizePlanItems falls back to markdown extraction when input is omitted', () => {
  assert.deepEqual(normalizePlanItems(undefined, '- [~] Update plan\n- Run tests'), [
    { id: 'item_1', title: 'Update plan', status: 'in_progress' },
    { id: 'item_2', title: 'Run tests', status: 'pending' }
  ]);
});

test('normalizeStoredPlanItems keeps valid stored snapshots and otherwise re-parses markdown', () => {
  assert.deepEqual(
    normalizeStoredPlanItems(
      [{ id: 'inspect', title: ' Inspect ', status: 'pending', notes: '  notes  ' }],
      '- fallback'
    ),
    [{ id: 'inspect', title: 'Inspect', status: 'pending', notes: 'notes' }]
  );
  assert.deepEqual(normalizeStoredPlanItems([{ id: 'bad id', title: 'X', status: 'pending' }], '- Fallback'), [
    { id: 'item_1', title: 'Fallback', status: 'pending' }
  ]);
});

test('progressItemsFromPlanItems seeds pending execution tracker rows with active forms', () => {
  assert.deepEqual(progressItemsFromPlanItems([{ id: 'fix', title: 'Fix parser', status: 'completed', notes: 'done' }]), [
    {
      id: 'fix',
      title: 'Fix parser',
      status: 'pending',
      activeForm: 'Fixing parser',
      notes: 'done'
    }
  ]);
  assert.deepEqual(progressItemsFromPlanItems([{ id: 'custom', title: 'Custom verb task', status: 'pending' }]), [
    {
      id: 'custom',
      title: 'Custom verb task',
      status: 'pending',
      activeForm: 'Working on Custom verb task'
    }
  ]);
});

test('normalizePlanProgressItems and isPlanProgressItem enforce activeForm', () => {
  assert.deepEqual(
    normalizePlanProgressItems([
      { id: 'inspect', title: 'Inspect', status: 'in_progress', activeForm: 'Inspecting' },
      { title: 'Missing active form', status: 'pending' } as never,
      { title: 'Blank active form', status: 'pending', activeForm: '   ' }
    ]),
    [{ id: 'inspect', title: 'Inspect', status: 'in_progress', activeForm: 'Inspecting' }]
  );
  assert.equal(
    isPlanProgressItem({ id: 'inspect', title: 'Inspect', status: 'pending', activeForm: '   ' }),
    false
  );
});

test('normalizeStoredPlanProgressItems returns null for invalid stored progress', () => {
  assert.equal(
    normalizeStoredPlanProgressItems([
      { id: 'inspect', title: 'Inspect', status: 'pending', activeForm: 'Inspecting' }
    ])?.length,
    1
  );
  assert.equal(normalizeStoredPlanProgressItems([{ id: 'inspect', title: 'Inspect', status: 'pending' }]), null);
});
