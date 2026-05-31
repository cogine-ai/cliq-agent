import assert from 'node:assert/strict';
import test from 'node:test';

import {
  extractPlanItems,
  isPlanItem,
  isPlanProgressItem,
  normalizePlanItems,
  normalizeStoredPlanItems,
  progressItemsFromPlanItems
} from './items.js';

test('extractPlanItems maps markdown list markers and checkbox states to plan items', () => {
  const markdown = [
    '## Steps',
    '- [ ] Pending task',
    '- [x] Done task',
    '- [X] Also done',
    '- [~] In progress tilde',
    '- [-] In progress dash',
    '* Plain bullet',
    '1. Numbered step',
    '2) Alternate numbering',
    '',
    'Not a list item'
  ].join('\n');

  assert.deepEqual(extractPlanItems(markdown), [
    { id: 'item_1', title: 'Pending task', status: 'pending' },
    { id: 'item_2', title: 'Done task', status: 'completed' },
    { id: 'item_3', title: 'Also done', status: 'completed' },
    { id: 'item_4', title: 'In progress tilde', status: 'in_progress' },
    { id: 'item_5', title: 'In progress dash', status: 'in_progress' },
    { id: 'item_6', title: 'Plain bullet', status: 'pending' },
    { id: 'item_7', title: 'Numbered step', status: 'pending' },
    { id: 'item_8', title: 'Alternate numbering', status: 'pending' }
  ]);
});

test('normalizePlanItems prefers explicit items and strips embedded checkbox markers from titles', () => {
  assert.deepEqual(
    normalizePlanItems(
      [
        { id: 'inspect', title: '[x] Inspect code', status: 'completed' },
        { title: '  Ship it  ', notes: ' after review ' },
        { title: '   ' },
        { title: 'Bad', status: 'blocked' as never }
      ],
      '## Fallback\n- Ignored when explicit items are provided'
    ),
    [
      { id: 'inspect', title: 'Inspect code', status: 'completed' },
      { id: 'item_2', title: 'Ship it', status: 'pending', notes: 'after review' }
    ]
  );

  assert.deepEqual(normalizePlanItems(undefined, '## Steps\n- From markdown'), [
    { id: 'item_1', title: 'From markdown', status: 'pending' }
  ]);
});

test('normalizeStoredPlanItems keeps valid stored items and falls back to markdown extraction', () => {
  assert.deepEqual(
    normalizeStoredPlanItems(
      [
        { id: 'ship', title: '  Ship it  ', status: 'pending', notes: 'ready' },
        { id: 'item_2', title: 'Fallback id', status: 'completed' }
      ],
      '## Ignored when stored items are valid'
    ),
    [
      { id: 'ship', title: 'Ship it', status: 'pending', notes: 'ready' },
      { id: 'item_2', title: 'Fallback id', status: 'completed' }
    ]
  );

  assert.deepEqual(normalizeStoredPlanItems([{ id: 'bad id', title: 'Nope', status: 'pending' }], '- Recovered from markdown'), [
    { id: 'item_1', title: 'Recovered from markdown', status: 'pending' }
  ]);
});

test('isPlanItem and isPlanProgressItem reject unsafe ids and incomplete progress rows', () => {
  assert.equal(isPlanItem({ id: 'item_1', title: 'Ok', status: 'pending' }), true);
  assert.equal(isPlanItem({ id: '../escape', title: 'Nope', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: '   ', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: 'Ok', status: 'blocked' }), false);

  assert.equal(
    isPlanProgressItem({
      id: 'item_1',
      title: 'Ok',
      status: 'in_progress',
      activeForm: 'Working'
    }),
    true
  );
  assert.equal(
    isPlanProgressItem({
      id: 'item_1',
      title: 'Ok',
      status: 'in_progress',
      activeForm: '   '
    }),
    false
  );
});

test('progressItemsFromPlanItems seeds pending progress rows with verb-aware active forms', () => {
  assert.deepEqual(progressItemsFromPlanItems([{ id: 'fix', title: 'Fix regression', status: 'pending' }]), [
    {
      id: 'fix',
      title: 'Fix regression',
      status: 'pending',
      activeForm: 'Fixing regression'
    }
  ]);

  assert.deepEqual(progressItemsFromPlanItems([{ id: 'custom', title: 'Custom verb task', status: 'completed' }]), [
    {
      id: 'custom',
      title: 'Custom verb task',
      status: 'pending',
      activeForm: 'Working on Custom verb task'
    }
  ]);
});
