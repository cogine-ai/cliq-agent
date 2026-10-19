// Refusal-only authority checks. Structural data is not a delivery/native proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, mkdtemp, realpath, rename, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { digestOmitting, sha256Bytes } from '../kernel/identity.js';
import { canonicalSha256 } from '../kernel/canonical.js';
import { publicationDirectoryIdentityDigest, type PublicationPathObservationV1 } from '../kernel/publication.js';
import type { ArtifactCatalog } from './artifacts.js';
import type { SqliteDriver } from './sqlite-driver.js';
import type { StateOwnerContext } from './state-owner.js';
import { closeOwnedPublicationFinalization, commitOwnedPublicationFinalization, isOwnedPublicationSessionConflict, prepareOwnedPublicationFinalization,
  openPublicationProjectionGate, readOwnedPublicationFinalizationMetadata, validateOwnedPublicationFinalization } from './publication-finalization.js';
import { prepareOwnedPublicationGenerationSeal } from './publication-finalization.js';
import { handoffOwnedPublicationResult, handoffOwnedReconciledPublicationResult, prepareOwnedPublicationReceivedResult, readOwnedPublicationReceivedResult } from './publication-finalization.js';
import { assertPublicationUnknownSettlementAssociation } from './publication-finalization.js';
import { KernelStorageError } from './errors.js';
import { loadRunResult, readOwnedPublicationResultPlan } from './run-result.js';
import { loadNativeStateOwner } from './native-owner.js';
import { ZERO_BUDGET } from './rows.js';
import type { BudgetSettlementV1, InvocationJournalEntry } from '../kernel/types.js';

test('reconciled last-result accounting retains exactly the original pessimistic UNKNOWN settlement', () => {
  // Pure data association, not a Run, SQL claim, receipt or recovery authority.
  const charge = { ...ZERO_BUDGET, toolCalls: 1 }, ref = 'a'.repeat(64), now = '2026-10-19T00:00:00.000Z';
  const prepared: InvocationJournalEntry = { runId: 'data-only-run', opId: 'data-only-op', opKind: 'publish', seq: 1,
    phase: 'prepared', attempt: 0, leaseEpoch: 1, target: ref, requestRef: ref, grantRef: ref,
    replayClass: 'reconcile', budgetDelta: charge, timestamp: now };
  const claim: InvocationJournalEntry = { ...prepared, seq: 2, phase: 'dispatch_claimed', dispatchId: 'data-only-dispatch',
    supervisorInstanceId: 'data-only-supervisor', stateOwnerEpoch: 1 };
  const settlement: BudgetSettlementV1 = { schemaVersion: 1, format: 'cliq-budget-settlement-v1', runId: prepared.runId,
    opId: prepared.opId, attempt: 0, preparedJournalSeq: prepared.seq, terminalJournalSeq: 3, terminalPhase: 'unknown',
    reserved: charge, consumed: charge, released: charge, budgetConsumedBefore: ZERO_BUDGET, budgetConsumedAfter: charge,
    budgetReservedBefore: charge, budgetReservedAfter: ZERO_BUDGET, settledAt: now, settlementDigest: '' };
  settlement.settlementDigest = digestOmitting(settlement, 'settlementDigest');
  const unknown: InvocationJournalEntry = { ...claim, seq: 3, phase: 'unknown', budgetDelta: charge,
    budgetSettlementRef: canonicalSha256(settlement), evidenceRef: ref, evidenceDigest: ref };
  assert.doesNotThrow(() => assertPublicationUnknownSettlementAssociation(prepared, claim, unknown, settlement));
  for (const change of [{ terminalPhase: 'completed' }, { terminalJournalSeq: 4 }, { preparedJournalSeq: 2 },
    { settledAt: '2026-10-19T00:00:00.001Z' }, { runId: 'another-run' }, { opId: 'another-op' }, { attempt: 1 },
    { consumed: ZERO_BUDGET, budgetConsumedAfter: ZERO_BUDGET }]) {
    const altered = { ...settlement, ...change }; altered.settlementDigest = digestOmitting(altered, 'settlementDigest');
    const matchingRef = { ...unknown, budgetSettlementRef: canonicalSha256(altered) };
    assert.throws(() => assertPublicationUnknownSettlementAssociation(prepared, claim, matchingRef, altered as BudgetSettlementV1));
  }
  for (const change of [{ budgetSettlementRef: 'b'.repeat(64) }, { phase: 'failed' }, { dispatchId: 'another-dispatch' },
    { stateOwnerEpoch: 2 }, { leaseEpoch: 2 }, { seq: 2 }, { timestamp: '2026-10-19T00:00:00.001Z' }, { budgetDelta: ZERO_BUDGET }])
    assert.throws(() => assertPublicationUnknownSettlementAssociation(prepared, claim, { ...unknown, ...change } as InvocationJournalEntry, settlement));
});

test('received handoff and read-only result reject structural producers before SQLite or artifact access', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('forged producer must not reach SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('forged producer must not reach CAS'); } }) as ArtifactCatalog;
  const hostile = Object.defineProperty({}, 'native', { get() { assert.fail('forged producer properties must not be read'); } });
  await assert.rejects(handoffOwnedPublicationResult(driver, artifacts, {} as StateOwnerContext, {}, hostile as never), /exact original invocation owner/);
  await assert.rejects(handoffOwnedReconciledPublicationResult(driver, artifacts, {} as StateOwnerContext, {}, hostile as never),
    /genuine same-execution publication inspection result/u);
  await assert.rejects(prepareOwnedPublicationReceivedResult(driver, artifacts, {} as StateOwnerContext, {}, hostile as never), /genuine same-owner original task/);
  assert.throws(() => readOwnedPublicationReceivedResult(driver, artifacts, {} as StateOwnerContext, {}, hostile as never),
    /genuine same-execution received publication result/);
});

async function physical(t: import('node:test').TestContext) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'cliq-terminal-projection-')));
  const root = (await loadNativeStateOwner()).openWorkspaceRoot(directory);
  t.after(async () => { root.close(); await rm(directory, { recursive: true, force: true }); });
  return { directory, root };
}
async function directoryDescriptors(directory: string): Promise<string[]> {
  const info = await stat(directory, { bigint: true }), result: string[] = [];
  const fds = process.platform === 'linux' ? '/proc/self/fd' : '/dev/fd';
  for (const fd of await readdir(fds)) try {
    const selected = await stat(path.join(fds, fd), { bigint: true });
    if (info.dev === selected.dev && info.ino === selected.ino) result.push(fd);
  } catch (error) { if (!['ENOENT', 'EBADF'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error; }
  return result.sort();
}

// Actual readonly descriptor tests only: no Run, claim, proof or StateOwner is
// manufactured, and no passing component case is Linux delivery qualification.
test('terminal metadata inventory has one global 2/3 bound including unselected entries and joins on refusal', async t => {
  const f = await physical(t);
  await mkdir(path.join(f.directory, 'd')); await writeFile(path.join(f.directory, 'd', 'a'), 'a');
  await writeFile(path.join(f.directory, 'd', 'b'), 'b');
  const before = await directoryDescriptors(f.directory);
  const controller = new AbortController();
  await assert.rejects(openPublicationProjectionGate(f.root, [], ['d/a'], controller.signal, 2), /metadata inventory exceeds/);
  assert.deepEqual(await directoryDescriptors(f.directory), before);
  const gate = await openPublicationProjectionGate(f.root, [], ['d/a'], controller.signal, 3);
  gate.assertHeld(); gate.close(); gate.close();
  assert.throws(() => gate.assertHeld(), /joined/);
  assert.deepEqual(await directoryDescriptors(f.directory), before);
});

test('terminal metadata gate is iterative through actual nested directories and never follows a symlink gap', async t => {
  const f = await physical(t), depth = 256, relative = Array(depth).fill('d').join('/');
  await mkdir(path.join(f.directory, relative), { recursive: true });
  await symlink('not-present', path.join(f.directory, relative, 'link'));
  const gate = await openPublicationProjectionGate(f.root, [{ kind: 'symlink', path: `${relative}/link`, mode: 0o777, target: 'not-present',
    targetDigest: sha256Bytes(Buffer.from('not-present')) }], [`${relative}/missing/leaf`, `${relative}/link/leaf`], new AbortController().signal, depth + 1);
  try {
    const absent = gate.observe(`${relative}/missing/leaf`, 'a'.repeat(64));
    assert.equal(absent.ancestorPath, `${relative}/missing`); assert.equal(absent.observation.state.kind, 'absent');
    const linked = gate.observe(`${relative}/link/leaf`, 'a'.repeat(64));
    assert.equal(linked.ancestorPath, `${relative}/link`); assert.equal(linked.observation.state.kind, 'symlink');
    gate.assertHeld();
  } finally { gate.close(); }
});

test('actual terminal metadata descriptors refuse a same-path directory type flip and still join', async t => {
  const f = await physical(t); await mkdir(path.join(f.directory, 'd'));
  const before = await directoryDescriptors(f.directory);
  const gate = await openPublicationProjectionGate(f.root, [], ['d/missing'], new AbortController().signal, 2);
  try {
    await rename(path.join(f.directory, 'd'), path.join(f.directory, 'original'));
    await writeFile(path.join(f.directory, 'd'), 'external replacement');
    assert.throws(() => gate.assertHeld(), /changed|identity|snapshot/);
  } finally { gate.close(); }
  assert.deepEqual(await directoryDescriptors(f.directory), before);
});

test('global metadata yields include unselected entries so cancellation joins the actual cursor', async t => {
  const f = await physical(t);
  for (let index = 0; index < 140; index++) await writeFile(path.join(f.directory, `unselected-${index}`), '');
  const before = await directoryDescriptors(f.directory), controller = new AbortController();
  const aborted = new Error('original cancellation');
  const stopping = setImmediate().then(() => controller.abort(aborted));
  const running = openPublicationProjectionGate(f.root, [], [], controller.signal, 140);
  await assert.rejects(running, error => error === aborted);
  await stopping;
  assert.deepEqual(await directoryDescriptors(f.directory), before);
});

test('readonly projection rejects structural roots before data and never accepts a cap above the original source bound', async t => {
  const f = await physical(t), hostile = Object.defineProperty({}, Symbol.iterator, { get() { assert.fail('opaque root must be checked first'); } });
  await assert.rejects(openPublicationProjectionGate({} as never, hostile as never, hostile as never, {} as never), /native source workspace/);
  const before = await directoryDescriptors(f.directory);
  for (const limit of [0, 100_001, Infinity, 1.5])
    await assert.rejects(openPublicationProjectionGate(f.root, [], [], new AbortController().signal, limit), /fixed source capture bound/);
  assert.deepEqual(await directoryDescriptors(f.directory), before);
});

test('actual partial projection uses the final abort observation and truthfully anchors a deleted descendant behind a file', async t => {
  const f = await physical(t), digest = 'a'.repeat(64);
  const raw = { ...f.root.identity, mode: f.root.mode };
  const topology = { rootIdentity: { ...raw, identityDigest: publicationDirectoryIdentityDigest(digest, raw) }, directories: [] } as never;
  const parent = await stat(f.directory, { bigint: true });
  const absent: PublicationPathObservationV1 = { location: { kind: 'workspace', path: 'created' }, state: { kind: 'absent' },
    parentDeviceId: String(parent.dev), parentFileId: String(parent.ino), parentLinkCount: Number(parent.nlink) };
  // Only a readonly component observation: no publication/retirement proof is
  // inferred from this fixture's filesystem changes or supplied map.
  const gate = await openPublicationProjectionGate(f.root, [], ['created'], new AbortController().signal);
  try { gate.assertOriginalObservations(topology, new Map([['created', absent]]), digest); }
  finally { gate.close(); }
  await writeFile(path.join(f.directory, 'anchor'), 'kept', { mode: 0o600 });
  const blocking = await openPublicationProjectionGate(f.root,
    [{ kind: 'file', path: 'anchor', mode: 0o644, size: 4, blobRef: sha256Bytes(Buffer.from('kept')) }],
    ['anchor/deleted'], new AbortController().signal);
  try {
    const actual = blocking.observe('anchor/deleted', digest);
    assert.equal(actual.ancestorPath, 'anchor'); assert.equal(actual.observation.state.kind, 'file');
    assert.deepEqual(actual.observation.location, { kind: 'workspace', path: 'anchor' });
    const anchor = await stat(path.join(f.directory, 'anchor'), { bigint: true });
    assert.equal(actual.observation.entryDeviceId, String(anchor.dev));
    assert.equal(actual.observation.entryFileId, String(anchor.ino));
    assert.deepEqual(actual.observation.state, { kind: 'file', mode: 0o600, digest: sha256Bytes(Buffer.from('kept')) });
    // The derived target has no direct directory parent. Consume only its
    // real anchor observation, including original raw mode/content/identity.
    blocking.assertOriginalObservations(topology, new Map([['anchor', actual.observation]]), digest);
    assert.throws(() => blocking.assertOriginalObservations(topology, new Map([['anchor', {
      ...actual.observation, entryFileId: `${actual.observation.entryFileId}0` }]]), digest), /substituted.*inode/);
  } finally { blocking.close(); }
});

test('terminal publication refuses structural owners and plans before SQL, CAS or data getters', async () => {
  const driver = Object.defineProperty({}, 'prepare', { get() { assert.fail('structural owner reached SQLite'); } }) as SqliteDriver;
  const artifacts = Object.defineProperty({}, 'readCanonical', { get() { assert.fail('structural owner reached CAS'); } }) as ArtifactCatalog;
  const owner = {} as StateOwnerContext;
  const hostile = Object.defineProperty({}, 'runId', { get() { assert.fail('structural data getter reached'); } });
  await assert.rejects(prepareOwnedPublicationFinalization(driver, artifacts, owner, {}, hostile as never, hostile as never),
    /genuine same-execution received publication result/);
  await assert.rejects(prepareOwnedPublicationGenerationSeal(driver, artifacts, owner, {}, hostile as never), /exact original invocation owner/);
  for (const value of [{}, hostile]) {
    assert.throws(() => readOwnedPublicationFinalizationMetadata(driver, owner, value as never), /genuine original publication finalization/);
    assert.throws(() => validateOwnedPublicationFinalization(driver, owner, value as never, driver, hostile as never),
      /genuine original publication finalization/);
    assert.throws(() => commitOwnedPublicationFinalization(driver, owner, value as never, driver, hostile as never, hostile as never, ''),
      /genuine original publication finalization/);
    assert.throws(() => closeOwnedPublicationFinalization(driver, owner, value as never), /genuine original publication finalization/);
    assert.throws(() => readOwnedPublicationResultPlan(driver, owner, value as never), /genuine original publication result plan/);
    const result = loadRunResult(driver, artifacts, owner, { run: { id: 'structural' } as never, spec: {} as never, principalId: 'structural' });
    await assert.rejects(result.prepareOwnedPublicationResult({}, value as never), /genuine original publication finalization/);
  }
  assert.equal(isOwnedPublicationSessionConflict(driver, owner, hostile as never,
    new KernelStorageError('REVISION_CONFLICT', 'not an original Session mismatch')), false);
  assert.equal(isOwnedPublicationSessionConflict(driver, owner, hostile as never, hostile), false);
});
