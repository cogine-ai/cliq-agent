import assert from 'node:assert/strict';
import test from 'node:test';

import {
  activeFormForTitle,
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

test('isPlanItemStatus accepts only pending, in_progress, and completed', () => {
  assert.equal(isPlanItemStatus('pending'), true);
  assert.equal(isPlanItemStatus('in_progress'), true);
  assert.equal(isPlanItemStatus('completed'), true);
  assert.equal(isPlanItemStatus('unknown'), false);
  assert.equal(isPlanItemStatus(null), false);
});

test('isPlanItem rejects unsafe ids, blank titles, and invalid statuses', () => {
  assert.equal(isPlanItem({ id: 'item_1', title: 'Inspect', status: 'pending' }), true);
  assert.equal(isPlanItem({ id: 'item_1', title: 'Inspect', status: 'pending', notes: 'detail' }), true);
  assert.equal(isPlanItem({ id: '../escape', title: 'Inspect', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: '   ', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: 'Inspect', status: 'blocked' }), false);
  assert.equal(isPlanItem(null), false);
});

test('extractPlanItems parses bullet, ordered, and checkbox list lines', () => {
  const markdown = [
    '## Steps',
    '- [ ] Draft plan',
    '* [x] Review plan',
    '+ [~] Implement tracker',
    '1. [X] Ship release',
    '2) Run tests',
    'not a list item'
  ].join('\n');

  assert.deepEqual(extractPlanItems(markdown), [
    { id: 'item_1', title: 'Draft plan', status: 'pending' },
    { id: 'item_2', title: 'Review plan', status: 'completed' },
    { id: 'item_3', title: 'Implement tracker', status: 'in_progress' },
    { id: 'item_4', title: 'Ship release', status: 'completed' },
    { id: 'item_5', title: 'Run tests', status: 'pending' }
  ]);
});

test('extractPlanItems strips inline checkbox markers from titles', () => {
  assert.deepEqual(extractPlanItems('- [ ] [x] Double marker'), [
    { id: 'item_1', title: 'Double marker', status: 'pending' }
  ]);
});

test('normalizePlanItems prefers explicit items and falls back to markdown extraction', () => {
  assert.deepEqual(
    normalizePlanItems(
      [
        { title: ' [x] Explicit item ' },
        { id: 'bad id!', title: 'Ignored unsafe id', status: 'pending' },
        { title: '   ' },
        { title: 'Ship', status: 'completed', notes: ' ready ' }
      ],
      '## Ignored when explicit\n- Fallback'
    ),
    [
      { id: 'item_1', title: 'Explicit item', status: 'pending' },
      { id: 'item_2', title: 'Ignored unsafe id', status: 'pending' },
      { id: 'item_4', title: 'Ship', status: 'completed', notes: 'ready' }
    ]
  );

  assert.deepEqual(normalizePlanItems(undefined, '- Inspect\n- Implement'), [
    { id: 'item_1', title: 'Inspect', status: 'pending' },
    { id: 'item_2', title: 'Implement', status: 'pending' }
  ]);
});

test('normalizeStoredPlanItems keeps valid stored items and re-extracts when shape is invalid', () => {
  assert.deepEqual(
    normalizeStoredPlanItems(
      [{ id: 'inspect', title: 'Inspect', status: 'completed', notes: 'done' }],
      '- Should not be used'
    ),
    [{ id: 'inspect', title: 'Inspect', status: 'completed', notes: 'done' }]
  );

  assert.deepEqual(normalizeStoredPlanItems([{ id: 'bad id', title: 'X', status: 'pending' }], '- Recovered'), [
    { id: 'item_1', title: 'Recovered', status: 'pending' }
  ]);
});

test('normalizePlanProgressItems drops invalid progress rows', () => {
  assert.deepEqual(
    normalizePlanProgressItems([
      { title: 'Inspect code', activeForm: 'Inspecting code' },
      { title: 'Implement', status: 'in_progress', activeForm: '   ' },
      { title: 'Verify', status: 'completed', activeForm: 'Verifying' }
    ]),
    [
      { id: 'item_1', title: 'Inspect code', status: 'pending', activeForm: 'Inspecting code' },
      { id: 'item_3', title: 'Verify', status: 'completed', activeForm: 'Verifying' }
    ]
  );
});

test('progressItemsFromPlanItems seeds pending execution rows with active forms', () => {
  assert.deepEqual(
    progressItemsFromPlanItems([
      { id: 'inspect', title: 'Inspect code', status: 'completed' },
      { id: 'ship', title: 'Ship custom milestone', status: 'in_progress', notes: 'tracked' }
    ]),
    [
      { id: 'inspect', title: 'Inspect code', status: 'pending', activeForm: 'Inspecting code' },
      {
        id: 'ship',
        title: 'Ship custom milestone',
        status: 'pending',
        activeForm: 'Working on Ship custom milestone',
        notes: 'tracked'
      }
    ]
  );
});

test('activeFormForTitle maps known verbs and falls back for unknown titles', () => {
  assert.equal(activeFormForTitle('Inspect code'), 'Inspecting code');
  assert.equal(activeFormForTitle('implement tracker'), 'Implementing tracker');
  assert.equal(activeFormForTitle('FIX regression'), 'Fixing regression');
  assert.equal(activeFormForTitle('Ship custom milestone'), 'Working on Ship custom milestone');
  assert.equal(activeFormForTitle('  test suite  '), 'Testing suite');
});

test('isPlanProgressItem requires a non-empty activeForm string', () => {
  assert.equal(
    isPlanProgressItem({ id: 'item_1', title: 'Inspect', status: 'pending', activeForm: 'Inspecting' }),
    true
  );
  assert.equal(isPlanProgressItem({ id: 'item_1', title: 'Inspect', status: 'pending', activeForm: '' }), false);
  assert.equal(isPlanProgressItem({ id: 'item_1', title: 'Inspect', status: 'pending', activeForm: '   ' }), false);
  assert.equal(isPlanProgressItem({ id: 'item_1', title: 'Inspect', status: 'pending' }), false);
});

test('normalizeStoredPlanProgressItems returns null for invalid stored progress', () => {
  assert.equal(normalizeStoredPlanProgressItems(null), null);
  assert.equal(
    normalizeStoredPlanProgressItems([{ id: 'item_1', title: 'Inspect', status: 'pending', activeForm: '' }]),
    null
  );
  assert.deepEqual(
    normalizeStoredPlanProgressItems([
      { id: 'inspect', title: 'Inspect', status: 'pending', activeForm: 'Inspecting' }
    ]),
    [{ id: 'inspect', title: 'Inspect', status: 'pending', activeForm: 'Inspecting' }]
  );
});
