import assert from 'node:assert/strict';
import test from 'node:test';

import {
  extractPlanItems,
  isPlanItem,
  normalizePlanItems,
  normalizeStoredPlanItems
} from './items.js';

test('extractPlanItems parses checklist markers from bullets and numbered lists', () => {
  const markdown = [
    '- [ ] Pending task',
    '* [x] Done task',
    '+ [~] In progress',
    '1. [X] Another done',
    '2) plain item',
    'not a list line'
  ].join('\n');

  assert.deepEqual(extractPlanItems(markdown), [
    { id: 'item_1', title: 'Pending task', status: 'pending' },
    { id: 'item_2', title: 'Done task', status: 'completed' },
    { id: 'item_3', title: 'In progress', status: 'in_progress' },
    { id: 'item_4', title: 'Another done', status: 'completed' },
    { id: 'item_5', title: 'plain item', status: 'pending' }
  ]);
});

test('normalizePlanItems drops invalid explicit items but keeps valid ones', () => {
  assert.deepEqual(
    normalizePlanItems(
      [
        { title: 'Valid' },
        { title: '   ' },
        { title: 'Bad status', status: 'unknown' as never },
        { title: '[x] Strip checkbox', status: 'completed' }
      ],
      ''
    ),
    [
      { id: 'item_1', title: 'Valid', status: 'pending' },
      { id: 'item_4', title: 'Strip checkbox', status: 'completed' }
    ]
  );
});

test('normalizePlanItems assigns generated ids when explicit ids are unsafe', () => {
  assert.deepEqual(normalizePlanItems([{ id: 'bad id!', title: 'Bad id' }], ''), [
    { id: 'item_1', title: 'Bad id', status: 'pending' }
  ]);
});

test('normalizePlanItems extracts from markdown when explicit items are omitted', () => {
  assert.deepEqual(normalizePlanItems(undefined, '## Steps\n- [ ] Ship'), [
    { id: 'item_1', title: 'Ship', status: 'pending' }
  ]);
});

test('normalizeStoredPlanItems preserves valid stored items and trims notes', () => {
  assert.deepEqual(
    normalizeStoredPlanItems(
      [{ id: 'ship', title: ' Ship ', status: 'pending', notes: '  after review  ' }],
      'ignored markdown'
    ),
    [{ id: 'ship', title: 'Ship', status: 'pending', notes: 'after review' }]
  );
});

test('normalizeStoredPlanItems re-extracts from markdown when stored items are invalid', () => {
  assert.deepEqual(
    normalizeStoredPlanItems([{ id: 'bad id!', title: 'x', status: 'pending' }], '- [ ] From markdown'),
    [{ id: 'item_1', title: 'From markdown', status: 'pending' }]
  );
});

test('isPlanItem requires safe ids and non-empty titles', () => {
  assert.equal(isPlanItem({ id: 'item_1', title: 'Task', status: 'pending' }), true);
  assert.equal(isPlanItem({ id: 'bad id', title: 'Task', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: '   ', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: 'Task', status: 'unknown' }), false);
});
