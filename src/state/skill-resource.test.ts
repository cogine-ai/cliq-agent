import assert from 'node:assert/strict';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { canonicalSha256 } from '../kernel/canonical.js';
import type { LocalControlChannelIdentityV1, LocalPrincipalIdentityV1, ToolResultPayloadV1, ToolResultItem } from '../kernel/types.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { createAgentFixture } from './testing/agent-fixtures.js';
import { disposeFixture, uuidv7 } from './testing/fixtures.js';
import { batch } from './testing/tool-calls.js';
import { publishInProcessChannel, openStateStore } from './store.js';
import { loadNativeStateOwner } from './native-owner.js';
import { captureInstalledSkills } from './skill-source.js';
import { captureInstalledWorkspaceInstructions } from './installed-run.js';
import { decodeSkillResourceReceipt } from './skill-resource-data.js';
import { BUILTIN_POLICY_RULES } from '../policy/tool-policy.js';
import { retireFixtureToolSelection } from './testing/tool-effects.js';
import { quiescedToolCheckpoint } from './testing/tool-effects.js';
import { KERNEL_DATABASE_FILENAME } from '../config.js';
import { openSqliteDriver } from './sqlite-driver.js';
import type { ContinuationItem } from '../kernel/types.js';

async function fixture(t: TestContext, options: { disposition?: 'ask' | 'deny'; empty?: boolean; toolCalls?: number } = {}) {
  let directory = '', rawRef = '';
  const permissionSource = { schemaVersion: 1, format: 'cliq-offline-session-rule-data-v1', selectedAction: 'skill_resource', disposition: options.disposition ?? 'allow' };
  const fixture = await createAgentFixture('skill-resource-local', options.toolCalls === undefined ? undefined : { toolCalls: options.toolCalls }, { tools: ['skill_resource'], mode: 'yolo',
    ...(options.disposition ? { rules: [{ ruleId: 'session:skill-resource', order: BUILTIN_POLICY_RULES.length, source: 'session' as const,
      sourceRef: canonicalSha256(permissionSource), channel: 'named-action' as const, pattern: 'skill_resource *', disposition: options.disposition }] } : {}),
    freezeSkills: async (store, workspace, assembly) => {
    assert(workspace.kind === 'live');
    if (options.disposition) await store.artifacts.publishCanonical(permissionSource, permissionSource.format);
    const channel = await publishInProcessChannel(store), identity = await store.artifacts.readCanonical<LocalControlChannelIdentityV1>(channel.channelIdentityRef),
      principal = await store.artifacts.readCanonical<LocalPrincipalIdentityV1>(identity.principalIdentityRef);
    directory = path.join(workspace.canonicalRootPath, '.cliq/skills/example');
    await mkdir(path.join(directory, 'assets'), { recursive: true, mode: 0o700 });
    await writeFile(path.join(directory, 'SKILL.md'), '---\nname: example\ndescription: Frozen local read.\n---\nRead [the data](assets/data.txt).\n', { mode: 0o644 });
    const bytes = options.empty ? Buffer.alloc(0) : Buffer.from('0123456789\n');
    await writeFile(path.join(directory, 'assets/data.txt'), bytes, { mode: 0o644 });
    const home = path.join(store.stateRoot, 'component-skill-home');
    await mkdir(path.join(home, '.cliq'), { recursive: true, mode: 0o700 }); await mkdir(path.join(home, '.agents/skills'), { recursive: true, mode: 0o700 });
    const native = await loadNativeStateOwner(), roots = [native.openWorkspaceRoot(workspace.canonicalRootPath), native.openWorkspaceRoot(path.join(home, '.cliq')), native.openWorkspaceRoot(home)];
    try {
      const instructions = await captureInstalledWorkspaceInstructions(roots[0]!, store.artifacts, workspace, canonicalSha256(workspace));
      const selected = await captureInstalledSkills({ artifacts: store.artifacts, requestedSkillIds: ['example'], workspaceRoot: roots[0]!,
        workspaceIdentity: workspace, workspaceIdentityRef: canonicalSha256(workspace), userRoots: [{ root: roots[1]!, prefix: 'skills' }, { root: roots[2]!, prefix: '.agents/skills' }],
        actualUserHome: home, principal, principalRef: identity.principalIdentityRef,
        bundle: await store.artifacts.readCanonical<RuntimeBundleManifest>(assembly.runtime.runtimeBundleRef), bundleRef: assembly.runtime.runtimeBundleRef });
      rawRef = (await store.artifacts.publishBytes(bytes, 'application/octet-stream', 'cliq-skill-source-file-v1')).ref;
      return { ...assembly.instructions, workspaceInstructionsRef: instructions.ref, workspaceInstructionsDigest: instructions.value.manifestDigest, skills: selected.skills };
    } finally { roots.reverse().forEach(root => root.close()); }
  } });
  t.after(() => disposeFixture(fixture));
  return { ...fixture, directory, rawRef };
}

test('recovery verifies selected raw resources before any tool call and never falls back to the still-present source', async t => {
  const value = await fixture(t), before = await value.store.readRecoveryClosure(value.runId);
  const assembly = await value.store.artifacts.readCanonical<import('../kernel/types.js').RunAssemblyV1>(before.runSpec.assemblyRef);
  const manifest = await value.store.artifacts.readCanonical<import('../kernel/skill.js').SkillManifestV1>(assembly.instructions.skills[0]!.manifestRef);
  const source = await value.store.artifacts.readCanonical<import('../kernel/skill.js').SkillSourceIdentityV1>(manifest.sourceIdentityRef);
  const database = openSqliteDriver(path.join(value.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    for (const ref of [assembly.instructions.skills[0]!.manifestRef, manifest.sourceIdentityRef, manifest.instructionRef, ...source.files.map(file => file.rawBytesRef)]) {
      const recorded = database.prepare('SELECT byte_length FROM artifacts WHERE ref=?').get<{ byte_length: bigint }>(ref);
      assert(recorded, 'ordinary admission must register its complete frozen skill graph');
      assert.equal(Number(recorded.byte_length), (await value.store.artifacts.readBytes(ref)).length);
    }
  } finally { database.close(); }
  const retained = path.join(value.stateRoot, 'original-unread-skill-raw');
  await rename(path.join(value.stateRoot, 'cas', value.rawRef), retained);
  try { await assert.rejects(value.store.readRecoveryClosure(value.runId), { code: 'RECOVERY_REQUIRED' }); }
  finally { await rename(retained, path.join(value.stateRoot, 'cas', value.rawRef)); }
  assert.deepEqual(await value.store.readRecoveryClosure(value.runId), before);
  await rm(value.directory, { recursive: true });
  assert.deepEqual(await value.store.readRecoveryClosure(value.runId), before);
});

test('ordinary Run reads two frozen ranges with one local charge each, no native claim and the same parent worker', async t => {
  const value = await fixture(t);
  await batch(value, [{ name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset: 0, length: 4 } },
    { name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset: 4, length: 65536 } }]);
  const original = await value.store.readRecoveryClosure(value.runId); await rm(value.directory, { recursive: true });
  for (let index = 0; index < 2; index++) {
    const run = value.store.getRun(value.runId), selected = await value.agent.prepareTool({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch });
    assert.equal(selected.disposition, 'skill_resource_required');
    await value.agent.readSkillResource({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch });
    const cut = await value.store.readRecoveryClosure(value.runId), rows = cut.journal.filter(row => row.opKind === 'skill_resource');
    assert.equal(rows.length, (index + 1) * 3); assert(rows.every(row => row.leaseEpoch === 0 && row.attempt === 0 && row.sandboxLaunchSpecRef === undefined && row.brokerFenceTokenDigest === undefined));
    assert.equal(cut.run.budgetConsumed.toolCalls, original.run.budgetConsumed.toolCalls + index + 1);
    assert.equal(cut.run.activeWorkerLaunchId, original.run.activeWorkerLaunchId); assert.equal(cut.run.leaseEpoch, original.run.leaseEpoch);
    assert.equal(cut.latestCheckpoint.workspaceStateRef, original.latestCheckpoint.workspaceStateRef);
    const receipt = decodeSkillResourceReceipt(await value.store.artifacts.readCanonical(rows.at(-1)!.resultRef!));
    assert.equal(receipt.value.kind, 'range'); if (receipt.value.kind !== 'range') assert.fail('actual selected file should produce a range');
    assert.equal(Buffer.from(receipt.value.output.bytesBase64, 'base64').toString(), index === 0 ? '0123' : '456789\n');
    assert.equal(receipt.value.output.eof, index === 1);
  }
  await assert.rejects(value.agent.readSkillResource({ expectedRunRevision: value.store.getRun(value.runId).revision, leaseEpoch: value.leaseEpoch }));
  const before = await value.store.readRecoveryClosure(value.runId);
  await value.store.close(); value.store = await openStateStore(value.stateRoot, value.signed);
  assert.deepEqual((await value.store.readRecoveryClosure(value.runId)).journal, before.journal);
  const retained = path.join(value.stateRoot, 'original-skill-raw'); await rename(path.join(value.stateRoot, 'cas', value.rawRef), retained);
  try { await assert.rejects(value.store.readRecoveryClosure(value.runId)); }
  finally { await rename(retained, path.join(value.stateRoot, 'cas', value.rawRef)); }
  assert.deepEqual((await value.store.readRecoveryClosure(value.runId)).journal, before.journal);
});

test('unselected ids, unselected paths and past-EOF offsets are exact charged read refusals, with no host fallback', async t => {
  const value = await fixture(t);
  await batch(value, [{ name: 'skill_resource', input: { skillId: 'other', canonicalRelativePath: 'assets/data.txt', offset: 0, length: 1 } },
    { name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'not-selected.txt', offset: 0, length: 1 } },
    { name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset: 12, length: 1 } }]);
  for (const code of ['SKILL_NOT_SELECTED', 'SKILL_RESOURCE_NOT_FOUND', 'SKILL_RESOURCE_RANGE_INVALID']) {
    const run = value.store.getRun(value.runId);
    await value.agent.readSkillResource({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch });
    const cut = await value.store.readRecoveryClosure(value.runId), completed = cut.journal.filter(row => row.opKind === 'skill_resource' && row.phase === 'completed');
    const receipt = decodeSkillResourceReceipt(await value.store.artifacts.readCanonical(completed.at(-1)!.resultRef!));
    assert.deepEqual(receipt.value, { kind: 'error', code });
    const items = await value.store.artifacts.mapReads(cut.items, item => value.store.artifacts.readCanonical(item.payloadRef));
    const item = items.filter((item): item is ToolResultItem => !!item && typeof item === 'object' && Reflect.get(item, 'kind') === 'tool_result').at(-1)!;
    const payload = await value.store.artifacts.readCanonical<ToolResultPayloadV1>(item.resultRef);
    assert.equal(payload.outcome, 'executed'); assert.equal(payload.outcome === 'executed' && payload.source, 'skill_resource');
  }
  assert.equal(value.store.getRun(value.runId).budgetConsumed.toolCalls, 3);
});

test('an empty original resource produces real empty EOF through the same ordinary local effect', async t => {
  const value = await fixture(t, { empty: true });
  await batch(value, [{ name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset: 0, length: 65536 } }]);
  const run = value.store.getRun(value.runId); await value.agent.readSkillResource({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch });
  const cut = await value.store.readRecoveryClosure(value.runId), receipt = decodeSkillResourceReceipt(await value.store.artifacts.readCanonical(cut.journal.at(-1)!.resultRef!));
  assert.equal(receipt.value.kind, 'range'); if (receipt.value.kind !== 'range') assert.fail('real empty resource must have an EOF range');
  assert.deepEqual(receipt.value.output, { schemaVersion: 1, skillId: 'example', canonicalRelativePath: 'assets/data.txt', kind: 'text',
    byteCount: 0, offset: 0, bytesBase64: '', nextOffset: 0, eof: true });
});

test('a separate read ask survives restart, uses the original authenticated approval and creates no replacement worker', async t => {
  const value = await fixture(t, { disposition: 'ask' });
  await batch(value, [{ name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset: 0, length: 3 } }]);
  let run = value.store.getRun(value.runId), selection = await value.agent.prepareTool({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch });
  assert.equal(selection.disposition, 'retirement_required'); if (selection.disposition !== 'retirement_required') assert.fail('ask must retire its original worker');
  await retireFixtureToolSelection(value, selection);
  run = value.store.getRun(value.runId); selection = await value.agent.prepareTool({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch });
  assert.equal(selection.disposition, 'approval_required'); if (selection.disposition !== 'approval_required') assert.fail('ask must register its own wait');
  const waited = await value.agent.waitForToolApproval({ expectedRunRevision: run.revision, waitingOnRef: selection.waitingOnRef });
  const before = await value.store.readRecoveryClosure(value.runId); await value.store.close(); value.store = await openStateStore(value.stateRoot, value.signed);
  value.agent = await value.store.loadAgentRun({ runId: value.runId, material: value.authority.material, releaseKeys: value.signed.releaseKeys });
  const request = { requestId: uuidv7(), expectedRunRevision: waited.run.revision, waitingOnRef: waited.waitingOnRef,
    decision: 'allow' as const, ...await publishInProcessChannel(value.store) };
  const approved = await value.agent.approveTool(request);
  await value.agent.readSkillResource({ expectedRunRevision: approved.run.revision, leaseEpoch: approved.run.leaseEpoch });
  const after = await value.store.readRecoveryClosure(value.runId);
  assert.equal(after.run.activeWorkerLaunchId, undefined); assert.deepEqual(after.workerLaunches, before.workerLaunches);
  assert.equal(after.journal.filter(row => row.opKind === 'skill_resource').length, 3);
  assert.deepEqual((await value.agent.approveTool({ ...request, ...await publishInProcessChannel(value.store) })).response, approved.response);
});

test('read denial never creates a local claim or tool charge and cannot be bypassed by the local reducer', async t => {
  const value = await fixture(t, { disposition: 'deny' });
  await batch(value, [{ name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset: 0, length: 3 } }]);
  const run = value.store.getRun(value.runId);
  await assert.rejects(value.agent.readSkillResource({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch }));
  const denied = await value.agent.prepareTool({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch }); assert.equal(denied.disposition, 'denied');
  const cut = await value.store.readRecoveryClosure(value.runId);
  assert.equal(cut.run.budgetConsumed.toolCalls, run.budgetConsumed.toolCalls); assert.equal(cut.journal.filter(row => row.opKind === 'skill_resource').length, 0);
});

test('a real SQL effect failure rolls the complete triplet, continuation and charge back before a single successful retry', async t => {
  const value = await fixture(t);
  await batch(value, [{ name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset: 0, length: 4 } }]);
  const before = await value.store.readRecoveryClosure(value.runId), writer = openSqliteDriver(path.join(value.stateRoot, KERNEL_DATABASE_FILENAME));
  try {
    writer.exec("CREATE TRIGGER reject_skill_effect BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT,'injected skill effect failure'); END");
    await assert.rejects(value.agent.readSkillResource({ expectedRunRevision: before.run.revision, leaseEpoch: before.run.leaseEpoch }));
    assert.deepEqual(await value.store.readRecoveryClosure(value.runId), before);
    writer.exec('DROP TRIGGER reject_skill_effect');
    await value.agent.readSkillResource({ expectedRunRevision: before.run.revision, leaseEpoch: before.run.leaseEpoch });
    const after = await value.store.readRecoveryClosure(value.runId);
    assert.equal(after.journal.filter(row => row.opKind === 'skill_resource').length, 3);
    assert.equal(after.run.budgetConsumed.toolCalls, before.run.budgetConsumed.toolCalls + 1);
  } finally { writer.close(); }
});

test('real cancellation during durable output publication leaves no local claim, result or charge and drains through original Stop', async t => {
  const value = await fixture(t);
  await batch(value, [{ name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset: 0, length: 4 } }]);
  const before = await value.store.readRecoveryClosure(value.runId), publish = value.store.artifacts.publishBytes.bind(value.store.artifacts);
  let stopped: Awaited<ReturnType<typeof value.agent.cancelRun>> | undefined;
  const spy = t.mock.method(value.store.artifacts, 'publishBytes', async (...args: Parameters<typeof publish>) => {
    const result = await publish(...args);
    if (!stopped && args[2] === 'cliq-skill-resource-read-v1') stopped = await value.agent.cancelRun({ requestId: uuidv7(),
      expectedRunRevision: value.store.getRun(value.runId).revision, ...await publishInProcessChannel(value.store) });
    return result;
  });
  try { await assert.rejects(value.agent.readSkillResource({ expectedRunRevision: before.run.revision, leaseEpoch: before.run.leaseEpoch })); }
  finally { spy.mock.restore(); }
  assert(stopped); const retained = await value.store.readRecoveryClosure(value.runId);
  assert.equal(retained.run.stopIntentRef, stopped.run.stopIntentRef); assert.equal(retained.journal.filter(row => row.opKind === 'skill_resource').length, 0);
  assert.deepEqual(retained.run.budgetConsumed, before.run.budgetConsumed);
  const proof = await quiescedToolCheckpoint(value, stopped.checkpointId);
  await value.agent.commitTerminalStop({ expectedRunRevision: retained.run.revision, checkpoint: proof.checkpoint });
  const terminal = await value.store.readRecoveryClosure(value.runId); assert.equal(terminal.run.status, 'cancelled');
  assert.deepEqual(terminal.run.budgetConsumed, before.run.budgetConsumed);
});

test('the original resource budget Stop closes only the unperformed suffix and preserves the already charged read', async t => {
  const value = await fixture(t, { toolCalls: 1 });
  await batch(value, [0, 1].map(offset => ({ name: 'skill_resource', input: { skillId: 'example', canonicalRelativePath: 'assets/data.txt', offset, length: 1 } })));
  let run = value.store.getRun(value.runId); await value.agent.readSkillResource({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch });
  const before = await value.store.readRecoveryClosure(value.runId); run = before.run;
  await assert.rejects(value.agent.readSkillResource({ expectedRunRevision: run.revision, leaseEpoch: run.leaseEpoch }), { code: 'BUDGET_EXHAUSTED' });
  const stopped = await value.agent.stopForResourceFailure({ expectedRunRevision: run.revision });
  const proof = await quiescedToolCheckpoint(value, stopped.checkpointId);
  await value.agent.commitTerminalStop({ expectedRunRevision: stopped.run.revision, checkpoint: proof.checkpoint });
  const after = await value.store.readRecoveryClosure(value.runId); assert.equal(after.run.terminalReason, 'budget_exhausted');
  assert.deepEqual(after.journal, before.journal); assert.equal(after.run.budgetConsumed.toolCalls, 1);
  const items = await value.store.artifacts.mapReads(after.items, row => value.store.artifacts.readCanonical<ContinuationItem>(row.payloadRef));
  assert.deepEqual(items.filter(item => item.kind === 'tool_result').map(item => [item.index, item.outcome]), [[0, 'executed'], [1, 'cancelled']]);
});
