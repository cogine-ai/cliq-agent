// Execute only the original synchronous guards and scheduling method over
// inert data and real SQLite. No StateOwner, accepted Run, worker/native proof
// or execution capability is created. A positive selector must reach the real
// closure-reader boundary, where this powerless fixture deliberately refuses.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import { exactKeys } from '../policy/runtime-authority.js';
import { KernelStorageError } from './errors.js';

const source = ts.createSourceFile('run-execution.ts', await readFile(new URL('./run-execution.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true);
let revision: ts.VariableDeclaration | undefined, retirement: ts.PropertyAssignment | undefined;
const visit = (node: ts.Node) => {
  if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'revision') { assert.equal(revision, undefined); revision = node; }
  if (ts.isPropertyAssignment(node) && node.name.getText(source) === 'resumeCurrentRetirement') { assert.equal(retirement, undefined); retirement = node; }
  ts.forEachChild(node, visit);
};
visit(source); assert(revision && retirement);
const script = ts.transpileModule(`const ${revision.getText(source)};\nglobalThis.resume = ${retirement.initializer.getText(source)};`,
  { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;

function fixture(options: { closed?: boolean; closing?: boolean; cleanupFailure?: unknown; pending?: unknown; receivedCompletion?: unknown;
  currentRevision?: number; ownerFailure?: Error } = {}) {
  const database = new DatabaseSync(':memory:');
  database.exec('CREATE TABLE workspace_generations (run_id TEXT NOT NULL, phase TEXT NOT NULL)');
  const events: string[] = [], original = Object.freeze({ revision: options.currentRevision ?? 1, dataOnly: true });
  const fullReaderFailure = new Error('the original full closure is unavailable in this data-only fixture');
  const context = vm.createContext({ exactKeys, KernelStorageError, AbortController,
    closed: options.closed ?? false, isClosing: () => options.closing ?? false, cleanupFailure: options.cleanupFailure,
    pending: options.pending, receivedCompletion: options.receivedCompletion, runId: 'data-run', owner: Symbol('no-StateOwner'),
    readRun: () => { events.push('revision_read'); return original; },
    assertActiveStateOwner: () => { events.push('owner_check'); if (options.ownerFailure) throw options.ownerFailure; },
    driver: { prepare(sql: string) { events.push('quarantine_select'); return database.prepare(sql); } },
    artifacts: { withReadSignal() { events.push('read_scope'); return Object.freeze({ dataOnly: true }); } },
    retirementPhase: () => {}, readRecoveryClosure: async () => { events.push('full_closure'); throw fullReaderFailure; },
    ownOperation: (work: Promise<unknown>) => { events.push('owned_join'); return work; }, operationAbort: undefined });
  vm.runInContext(script, context);
  return { database, events, original, fullReaderFailure, resume: context.resume as (input: unknown) => Promise<unknown> };
}

test('negative retirement scheduling still runs every original scope, revision and owner guard before SQL', async () => {
  const ownerFailure = new KernelStorageError('LEASE_FENCED', 'the original owner guard refused');
  const cases = [
    [{}, { expectedRunRevision: 1, extra: true }, 'INVALID_REQUEST'],
    [{}, { expectedRunRevision: 0 }, 'INVALID_REQUEST'],
    [{ closed: true }, { expectedRunRevision: 1 }, 'LEASE_FENCED'],
    [{ closing: true }, { expectedRunRevision: 1 }, 'LEASE_FENCED'],
    [{ cleanupFailure: new Error('retirement remains uncertain') }, { expectedRunRevision: 1 }, 'RECOVERY_REQUIRED'],
    [{ pending: Promise.resolve() }, { expectedRunRevision: 1 }, 'REVISION_CONFLICT'],
    [{ receivedCompletion: Symbol('original-result') }, { expectedRunRevision: 1 }, 'REVISION_CONFLICT'],
    [{ currentRevision: 2 }, { expectedRunRevision: 1 }, 'REVISION_CONFLICT'],
    [{ ownerFailure }, { expectedRunRevision: 1 }, 'LEASE_FENCED'],
  ] as const;
  for (const [options, input, code] of cases) {
    const f = fixture(options);
    try {
      await assert.rejects(f.resume(input), { code });
      assert(!f.events.includes('quarantine_select') && !f.events.includes('full_closure') && !f.events.includes('owned_join'));
    } finally { f.database.close(); }
  }
});

test('no same-Run quarantine returns only the checked data cut without a recovery read or native task', async () => {
  const f = fixture();
  try {
    f.database.prepare('INSERT INTO workspace_generations VALUES (?,?)').run('other-run', 'quarantined');
    f.database.prepare('INSERT INTO workspace_generations VALUES (?,?)').run('data-run', 'sealed');
    assert.equal(await f.resume({ expectedRunRevision: 1 }), f.original);
    assert.deepEqual(f.events, ['revision_read', 'owner_check', 'quarantine_select', 'revision_read']);
  } finally { f.database.close(); }
});

test('every quarantine still enters the original full closure and a negative selection is never cached', async () => {
  const f = fixture();
  try {
    assert.equal(await f.resume({ expectedRunRevision: 1 }), f.original);
    f.events.length = 0;
    f.database.prepare('INSERT INTO workspace_generations VALUES (?,?)').run('data-run', 'quarantined');
    await assert.rejects(f.resume({ expectedRunRevision: 1 }), error => error === f.fullReaderFailure);
    assert.deepEqual(f.events, ['revision_read', 'owner_check', 'quarantine_select', 'read_scope', 'full_closure', 'owned_join']);
  } finally { f.database.close(); }
});
