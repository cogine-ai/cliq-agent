// Execute the production data-only eligibility predicate. Inert Journal
// projections below are neither accepted Runs, claims nor native death proof.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import ts from 'typescript';
import { KernelStorageError } from './errors.js';

type Row = { opId: string; phase: string; attempt: number; grantRef?: string };
async function eligibility() {
  const source = ts.createSourceFile('verifier-execution.ts', await readFile(new URL('./verifier-execution.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const matches: ts.FunctionDeclaration[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'eligibleAttempt') matches.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(matches.length, 1, 'use the single actual pre-worker and pre-prepare eligibility predicate');
  const code = ts.transpileModule(matches[0]!.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const check = new Function('KernelStorageError', `${code}; return eligibleAttempt;`)(KernelStorageError) as (input: unknown) => { prior?: Row; uses: number };
  const pending = (rows: Row[], outcome?: string, maxAttempts = 2) => check({ request: { opId: 'inert-current-op' }, journal: rows,
    frontier: { nextVerifierIndex: 0 }, progress: { entries: [{ ...(outcome ? { receipt: { outcome } } : {}) }] }, target: { maxAttempts } });
  return { source: source.text, pending };
}
const rows = (phases: readonly string[], attempt = 0, grantRef = 'inert-original-grant'): Row[] =>
  phases.map(phase => ({ opId: 'inert-current-op', phase, attempt, grantRef }));

test('permission selection and physical preparation both execute the same eligibility gate', async () => {
  const f = await eligibility();
  assert.equal(f.pending([]).prior, undefined); assert.equal(f.pending([]).uses, 0);
  const settled = rows(['prepared', 'failed']);
  assert.equal(f.pending(settled).prior, settled[0]); assert.equal(f.pending(settled).uses, 0);
  assert.match(f.source, /const selected = await cut\(input.expectedRunRevision, signal\);\s+eligibleAttempt\(selected\);/u);
  assert.match(f.source, /const \{ prior, previous, priorProgress, uses \} = eligibleAttempt\(selected\);/u);
});

test('a new permission never makes prepared, claimed, UNKNOWN, claimed-failed or completed non-infrastructure work eligible', async () => {
  const f = await eligibility();
  for (const phases of [['prepared'], ['prepared', 'dispatch_claimed'], ['prepared', 'dispatch_claimed', 'unknown'],
    ['prepared', 'dispatch_claimed', 'failed']]) assert.throws(() => f.pending(rows(phases)), { code: 'STATE_TRANSITION_INVALID' });
  for (const outcome of ['passed', 'assertion_failed', 'source_mutation'])
    assert.throws(() => f.pending(rows(['prepared', 'dispatch_claimed', 'completed']), outcome), { code: 'STATE_TRANSITION_INVALID' });
  assert.equal(f.pending(rows(['prepared', 'dispatch_claimed', 'completed']), 'infra_failed').uses, 1);
});

test('the exact op attempt ceiling counts original claims across changed grants and cannot reset at reapproval', async () => {
  const f = await eligibility(), first = rows(['prepared', 'dispatch_claimed', 'completed']);
  const second = rows(['prepared', 'dispatch_claimed', 'completed'], 1, 'inert-new-approval-grant');
  assert.throws(() => f.pending([...first, ...second], 'infra_failed'), { code: 'STATE_TRANSITION_INVALID' });
  assert.equal(f.pending([...first, ...rows(['prepared', 'failed'], 1, 'inert-expired-unclaimed')], 'infra_failed').uses, 1);
  const foreign = rows(['prepared', 'dispatch_claimed', 'unknown']).map(row => ({ ...row, opId: 'inert-other-op' }));
  assert.equal(f.pending([...foreign, ...first], 'infra_failed').uses, 1, 'the separate full Run gate owns unrelated operations');
});

test('an expired old grant cannot shadow the new exact approval or renew itself on restart', async () => {
  const source = ts.createSourceFile('verifier-execution.ts', await readFile(new URL('./verifier-execution.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const declarations: ts.FunctionDeclaration[] = [];
  const visit = (node: ts.Node) => { if (ts.isFunctionDeclaration(node) && node.name?.text === 'chooseGrant') declarations.push(node); ts.forEachChild(node, visit); };
  visit(source); assert.equal(declarations.length, 1);
  const code = ts.transpileModule(declarations[0]!.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const old = { grant: { expiresAt: '2026-10-31T00:00:01.000Z' }, evidence: { exact: 'old-ask' } };
  const fresh = { grant: { expiresAt: '2026-10-31T00:00:10.000Z' }, evidence: { exact: 'new-ask' } };
  const items = [{ kind: 'policy_decision', subjectKind: 'verifier_launch', opId: 'op', decisionSource: 'interactive_approval',
    decision: 'allow', grantRef: 'fresh' }];
  const reads = { mapReads: async (rows: readonly unknown[], fn: (row: unknown) => Promise<unknown>) => Promise.all(rows.map(fn)) };
  const select = new Function('permissionContext', 'readCanonicalArtifact', 'grantFor', 'readHighestPreparedAttempt',
    'readVerifierTemplateForRun', 'verifierCandidateOrdinal', 'driver', 'runId', 'artifacts', 'spec', `${code};return chooseGrant;`)(
      (selected: unknown) => selected, async () => items[0], async (_selected: unknown, ref: string) => ref === 'fresh' ? fresh : old,
      () => ({ grantRef: 'old' }), async () => undefined, async () => 0, undefined, 'inert-run', reads, undefined) as
      (selected: unknown, at: string) => Promise<{ grant?: unknown; evidence: unknown }>;
  const selected = { items: [{ payloadRef: 'inert-item' }], request: { opId: 'op' }, target: { verifierIndex: 0 },
    run: { deadlineAt: '2026-10-31T00:01:00.000Z' }, evaluator: { evaluate: () => ({ effectiveDisposition: 'ask' }) } };
  assert.equal((await select(selected, '2026-10-31T00:00:02.000Z')).grant, fresh.grant);
  const expired = await select(selected, '2026-10-31T00:00:10.000Z'); assert.equal(expired.grant, undefined);
  assert.deepEqual(expired.evidence, { effectiveDisposition: 'ask' });
  assert.equal((await select({ ...selected, evaluator: { evaluate: () => ({ effectiveDisposition: 'deny' }) } },
    '2026-10-31T00:00:02.000Z')).grant, undefined, 'explicit deny wins before any old/new grant or template');
});

test('a proved advisory skip advances both selection and predecessor validation even after an older settled infrastructure result', async () => {
  const source = ts.createSourceFile('verifier-recovery.ts', await readFile(new URL('./verifier-recovery.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
  const predicates: ts.ArrowFunction[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isArrowFunction(node) && node.getText(source).includes('entry.planEntry.maxAttempts') &&
        node.getText(source).includes('entry.receipt')) predicates.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source); assert.equal(predicates.length, 2, 'exercise both actual recovery decisions');
  const cut = { journal: [{ opId: 'inert-op', phase: 'dispatch_claimed' }] };
  const entry = { planEntry: { maxAttempts: 2 }, terminalJournal: { opId: 'inert-op' }, receipt: { outcome: 'infra_failed' } };
  for (const predicate of predicates) {
    const code = ts.transpileModule(`const pending = ${predicate.getText(source)};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
    const pending = new Function('cut', `${code};return pending;`)(cut) as (entry: unknown) => boolean;
    assert.equal(pending(entry), true);
    assert.equal(pending({ ...entry, disposition: { kind: 'advisory_skipped' } }), false);
    assert.equal(pending({ ...entry, receipt: undefined, disposition: { kind: 'advisory_skipped' } }), false);
    assert.equal(pending({ ...entry, receipt: { outcome: 'passed' }, disposition: { kind: 'passed' } }), false);
  }
});
