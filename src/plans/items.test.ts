import assert from 'node:assert/strict';
import test from 'node:test';

import {
  extractPlanItems,
  isPlanItem,
  isPlanProgressItem,
  normalizePlanItems,
  normalizePlanProgressItems,
  normalizeStoredPlanItems,
  normalizeStoredPlanProgressItems,
  progressItemsFromPlanItems
} from './items.js';

test('extractPlanItems maps markdown checklist markers to plan item statuses', () => {
  const markdown = [
    '## Steps',
    '- [ ] Pending task',
    '- [x] Done task',
    '- [X] Also done',
    '- [~] In progress task',
    '- [-] Also in progress',
    '1. Numbered pending',
    '* Star bullet'
  ].join('\n');

  assert.deepEqual(extractPlanItems(markdown), [
    { id: 'item_1', title: 'Pending task', status: 'pending' },
    { id: 'item_2', title: 'Done task', status: 'completed' },
    { id: 'item_3', title: 'Also done', status: 'completed' },
    { id: 'item_4', title: 'In progress task', status: 'in_progress' },
    { id: 'item_5', title: 'Also in progress', status: 'in_progress' },
    { id: 'item_6', title: 'Numbered pending', status: 'pending' },
    { id: 'item_7', title: 'Star bullet', status: 'pending' }
  ]);
});

test('normalizePlanItems prefers explicit items and drops invalid entries', () => {
  const markdown = '## Steps\n- Fallback from markdown';
  assert.deepEqual(
    normalizePlanItems(
      [
        { id: 'inspect', title: 'Inspect code', status: 'completed' },
        { title: '  [x] Strip checkbox prefix  ' },
        { title: '   ' },
        { id: 'bad/id', title: 'Unsafe id falls back to index' },
        { title: 'Bad status', status: 'done' as never }
      ],
      markdown
    ),
    [
      { id: 'inspect', title: 'Inspect code', status: 'completed' },
      { id: 'item_2', title: 'Strip checkbox prefix', status: 'pending' },
      { id: 'item_4', title: 'Unsafe id falls back to index', status: 'pending' }
    ]
  );
});

test('normalizePlanItems falls back to markdown extraction when items are omitted', () => {
  assert.deepEqual(normalizePlanItems(undefined, '- [~] Update tracker'), [
    { id: 'item_1', title: 'Update tracker', status: 'in_progress' }
  ]);
});

test('normalizeStoredPlanItems keeps valid stored items and ignores malformed arrays', () => {
  const stored = [
    { id: 'ship', title: 'Ship it', status: 'pending', notes: '  trimmed  ' },
    { id: 'item_2', title: 'Missing id uses index', status: 'completed' }
  ];
  assert.deepEqual(normalizeStoredPlanItems(stored, '## ignored when valid'), [
    { id: 'ship', title: 'Ship it', status: 'pending', notes: 'trimmed' },
    { id: 'item_2', title: 'Missing id uses index', status: 'completed' }
  ]);
  assert.deepEqual(normalizeStoredPlanItems([{ id: '../evil', title: 'Nope', status: 'pending' }], '- Fallback'), [
    { id: 'item_1', title: 'Fallback', status: 'pending' }
  ]);
});

test('isPlanItem and isPlanProgressItem reject unsafe ids and incomplete payloads', () => {
  assert.equal(isPlanItem({ id: 'item_1', title: 'Ok', status: 'pending' }), true);
  assert.equal(isPlanItem({ id: '../escape', title: 'Nope', status: 'pending' }), false);
  assert.equal(isPlanItem({ id: 'item_1', title: '   ', status: 'pending' }), false);
  assert.equal(isPlanProgressItem({ id: 'item_1', title: 'Ok', status: 'pending', activeForm: 'Working' }), true);
  assert.equal(isPlanProgressItem({ id: 'item_1', title: 'Ok', status: 'pending', activeForm: '   ' }), false);
});

test('normalizePlanProgressItems requires activeForm and drops incomplete rows', () => {
  assert.deepEqual(
    normalizePlanProgressItems([
      { id: 'fix', title: 'Fix bug', status: 'in_progress', activeForm: 'Fixing bug' },
      { title: 'Add tests', status: 'pending' } as never,
      { title: '   ', status: 'pending', activeForm: 'Nope' }
    ]),
    [{ id: 'fix', title: 'Fix bug', status: 'in_progress', activeForm: 'Fixing bug' }]
  );
});

test('progressItemsFromPlanItems seeds pending execution rows with active forms', () => {
  assert.deepEqual(progressItemsFromPlanItems([{ id: 'run', title: 'Run tests', status: 'pending', notes: 'ci' }]), [
    { id: 'run', title: 'Run tests', status: 'pending', activeForm: 'Running tests', notes: 'ci' }
  ]);
  assert.deepEqual(progressItemsFromPlanItems([{ id: 'item_1', title: 'Document API', status: 'pending' }]), [
    { id: 'item_1', title: 'Document API', status: 'pending', activeForm: 'Working on Document API' }
  ]);
});

test('normalizeStoredPlanProgressItems returns null for invalid stored progress', () => {
  const valid = [{ id: 'item_1', title: 'Inspect', status: 'pending', activeForm: 'Inspecting' }];
  assert.deepEqual(normalizeStoredPlanProgressItems(valid), [
    { id: 'item_1', title: 'Inspect', status: 'pending', activeForm: 'Inspecting' }
  ]);
  assert.equal(normalizeStoredPlanProgressItems([{ id: 'item_1', title: 'Inspect', status: 'pending' }]), null);
  assert.equal(normalizeStoredPlanProgressItems('nope'), null);
});
