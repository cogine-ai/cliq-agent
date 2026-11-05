import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalSha256 } from '../kernel/canonical.js';
import { legacyContextVisibleText } from '../kernel/legacy-context.js';
import { decodeLegacyArtifactSource, projectLegacyPlanSource, projectLegacyHandoffSource, validateLegacyPlanProgress } from './legacy-source-artifacts.js';

const root = '/old/cliq', at = '2026-10-02T00:00:00.000Z', createdAt = '2026-10-01T00:00:00.000Z';
const planPath = 'plans/workspace/session/plan/plan.json';
function plan() { return { id: 'plan', sessionId: 'session', workspaceId: 'workspace', status: 'approved',
  title: 'Cafe\u0301', contentMarkdown: 'Historical plan', items: [{ id: 'item_1', title: 'First', status: 'completed' }],
  createdAt, updatedAt: at, approvedAt: at, approvedTargetMode: 'yolo',
  paths: { json: `${root}/${planPath}`, markdown: `${root}/plans/workspace/session/plan/plan.md` } }; }
function project(value: unknown, markdown?: string) { return projectLegacyPlanSource({ sourcePath: planPath,
  value, legacyRootPath: root, publicationPreparedAt: at, ...(markdown === undefined ? {} : { markdown }) }); }

test('plan status remains historical context and an actual draft Markdown sibling uses the original pure item extractor', () => {
  const approved = project(plan(), 'A draft sibling cannot replace finalized content');
  assert.equal(approved.payload.kind, 'legacy_plan');
  if (approved.payload.kind !== 'legacy_plan') return assert.fail();
  assert.equal(approved.payload.content.title, 'Café'); assert.equal(approved.payload.content.contentMarkdown, 'Historical plan');
  assert.equal(approved.payload.content.status, 'approved');
  assert(!legacyContextVisibleText(approved.payload).includes('approvedTargetMode'));
  assert(!Object.hasOwn(approved.payload.content, 'paths')); assert.equal(approved.payloadRef, canonicalSha256(approved.payload));
  const draftSource = Object.fromEntries(Object.entries(plan()).filter(([key]) => key !== 'items'));
  const draft = project({ ...draftSource, status: 'draft' }, '- [x] Done\n- [ ] Remaining');
  assert.equal(draft.payload.kind, 'legacy_plan');
  if (draft.payload.kind === 'legacy_plan') assert.deepEqual(draft.payload.content.items,
    [{ id: 'item_1', title: 'Done', status: 'completed' }, { id: 'item_2', title: 'Remaining', status: 'pending' }]);
});
test('plan path/Session/workspace links, causal time and explicit malformed items are never normalized away', () => {
  for (const change of [{ sessionId: 'other' }, { workspaceId: 'other' }, { id: 'other' }, { extra: true },
    { createdAt: '2026-10-03T00:00:00.000Z' }, { approvedAt: '2026-09-01T00:00:00.000Z' },
    { paths: { ...plan().paths, markdown: '/foreign/plan.md' } }, { items: [{ id: 'x', title: 'bad', status: 'surprise' }] },
    { items: [{ id: 'x', title: 'one', status: 'pending' }, { id: 'x', title: 'duplicate', status: 'completed' }] }])
    assert.throws(() => project({ ...plan(), ...change }));
});
test('progress validates without producing portable plan payload or recovering an active action', () => {
  const sourcePath = 'plans/workspace/session/plan/progress.json';
  const value = { planId: 'plan', sessionId: 'session', workspaceId: 'workspace', title: 'Progress',
    items: [{ id: 'item_1', title: 'First', status: 'in_progress', activeForm: 'Doing first' }],
    createdAt, updatedAt: at, paths: { json: `${root}/${sourcePath}` } };
  assert.equal(validateLegacyPlanProgress({ sourcePath, value, legacyRootPath: root, publicationPreparedAt: at }), undefined);
  assert.throws(() => validateLegacyPlanProgress({ sourcePath, value: { ...value, sessionId: 'other' }, legacyRootPath: root, publicationPreparedAt: at }));
  assert.throws(() => project(value));
});
test('handoff imports only the original summary and refuses foreign paths, malformed raw JSON and time', () => {
  const sourcePath = 'handoffs/old_handoff/handoff.json', value = { id: 'old_handoff', createdAt, sessionId: 'session', checkpointId: 'old_checkpoint',
    summarySource: 'active-compaction', provider: 'deepseek', model: 'old-model', summaryMarkdown: 'Cafe\u0301 summary',
    paths: { json: `${root}/${sourcePath}`, markdown: `${root}/handoffs/old_handoff/HANDOFF.md` } };
  const projected = projectLegacyHandoffSource({ sourcePath, value: decodeLegacyArtifactSource(Buffer.from(JSON.stringify(value))),
    legacyRootPath: root, publicationPreparedAt: at });
  assert.equal(projected.payload.kind, 'legacy_handoff');
  assert.deepEqual(projected.payload.content, { handoffId: 'old_handoff', createdAt, summarySource: 'active-compaction', summaryMarkdown: 'Café summary' });
  for (const change of [{ id: 'foreign' }, { createdAt: '2026-10-03T00:00:00.000Z' }, { summarySource: 'system' },
    { paths: { ...value.paths, json: '/foreign/handoff.json' } }])
    assert.throws(() => projectLegacyHandoffSource({ sourcePath, value: { ...value, ...change }, legacyRootPath: root, publicationPreparedAt: at }));
  assert.throws(() => decodeLegacyArtifactSource(Buffer.from('{"id":"first","id":"second"}')));
  assert.throws(() => decodeLegacyArtifactSource(Buffer.from([0xc0, 0x80])));
});
