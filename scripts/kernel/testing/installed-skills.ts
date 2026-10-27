// Qualification composition and read-only assertions over actual installed
// public cuts. These values cannot create a Run, grant, Journal or death proof.
import assert from 'node:assert/strict';
import { chown, lstat, mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJsonBytes, canonicalSha256 } from '../../../src/kernel/canonical.js';
import { identityHash, sha256Bytes } from '../../../src/kernel/identity.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { decodeSkillManifest, decodeSkillSourceIdentity } from '../../../src/kernel/skill.js';
import { decodeSkillResourceReceipt, skillResourceCheckpointId, skillResourceDispatchId } from '../../../src/state/skill-resource-data.js';
import { skillInstruction } from '../../../src/state/skill-data.js';
import { validateFrozenSkillResourceGraph } from '../../../src/skills/resources.js';
import { installedToolsCalls } from './installed-tools-result.js';

export const INSTALLED_SKILLS_PROFILE = 'verifier_ten_with_three_scope_frozen_skills_v1';
const skills = [
  { id: 'owned-user-skill', scope: 'user', file: 'assets/data.txt', kind: 'text', bytes: 'original user skill resource\n', instruction: 'Use the frozen [user bytes](assets/data.txt).', directory: '.cliq/skills/owned-user-skill' },
  { id: 'owned-bundled-skill', scope: 'bundled', file: 'scripts/inspect.py', kind: 'executable-disabled', bytes: 'raise SystemExit("SKILL_BYTES_MUST_NOT_EXECUTE")\n', instruction: 'Read the frozen [script as data](scripts/inspect.py).', directory: '' },
  { id: 'owned-workspace-skill', scope: 'workspace', file: 'assets/data.txt', kind: 'text', bytes: 'original workspace skill resource\n', instruction: 'Use the frozen [workspace bytes](assets/data.txt).', directory: '.cliq/skills/owned-workspace-skill' }
] as const;
export const installedSkillIds = () => skills.map(skill => skill.id);
const markdown = (skill: typeof skills[number]) => `---\nname: ${skill.id}\ndescription: Owned frozen ${skill.scope} qualification data.\n---\n${skill.instruction}\n`;
export const installedBundledSkill = () => [{ skillId: skills[1].id, files: [
  { canonicalRelativePath: 'SKILL.md', bytes: Buffer.from(markdown(skills[1])) },
  { canonicalRelativePath: skills[1].file, bytes: Buffer.from(skills[1].bytes) }
] }];
export function installedToolsAndSkillsCalls(before: string, after: string) {
  return [...installedToolsCalls(before, after), ...skills.map((skill, index) => ({ callId: `owned-installed-skill-${index}`, name: 'skill_resource',
    input: { skillId: skill.id, canonicalRelativePath: skill.file, offset: 0, length: 65536 } }))];
}

/** Only the owned disposable qualification workspace/home are modified. The
 * product itself must discover/capture them through its normal held roots. */
export async function createInstalledSkillSources(home: string, workspace: string, uid: number, gid: number): Promise<() => Promise<void>> {
  const roots: string[] = [];
  for (const skill of skills.filter(skill => skill.scope !== 'bundled')) {
    const base = skill.scope === 'user' ? home : workspace;
    let directory = base;
    for (const component of skill.directory.split('/')) {
      directory = path.join(directory, component);
      try { await mkdir(directory, { mode: 0o700 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
      const held = await lstat(directory); assert(held.isDirectory() && !held.isSymbolicLink());
      await chown(directory, uid, gid);
    }
    roots.push(directory);
    const dataDirectory = path.join(directory, 'assets'); await mkdir(dataDirectory, { mode: 0o700 }); await chown(dataDirectory, uid, gid);
    for (const [name, bytes] of [['SKILL.md', markdown(skill)], [skill.file, skill.bytes]]) {
      const filename = path.join(directory, name!); await writeFile(filename, bytes!, { flag: 'wx', mode: 0o644 }); await chown(filename, uid, gid);
    }
  }
  // Called only after the actual public admission response. Reconnect, model
  // and resource reads must subsequently use retained original CAS bytes.
  return async () => { for (const directory of roots) await rm(directory, { recursive: true }); };
}

export function assertInstalledSkillPrompt(body: Record<string, any>, final: boolean): void {
  assert.equal(body.messages[0]?.role, 'system'); const system = body.messages[0].content;
  assert.equal(typeof system, 'string'); let previous = -1;
  for (const skill of skills) {
    const block = canonicalJsonBytes({ format: 'cliq-skill-instruction-prompt-v1', skillId: skill.id, sourceScope: skill.scope,
      instructionUtf8: skill.instruction }).toString('utf8');
    const index = system.indexOf(block); assert(index > previous); assert.equal(system.indexOf(block, index + 1), -1); previous = index;
  }
  if (final) for (const [index, skill] of skills.entries()) {
    const replies = body.messages.filter((message: any) => message.role === 'tool' && message.tool_call_id === `owned-installed-skill-${index}`);
    assert.equal(replies.length, 1);
    const content = parseJsonStrict(replies[0].content) as Record<string, any>;
    assert.equal(content.kind, 'range');
    assert.equal(Buffer.from(content.output.bytesBase64, 'base64').toString('utf8'), skill.bytes);
  }
}

export type InstalledSkillsEvidence = { qualified: true; selectedSkills: 3; sourceScopes: ['user', 'bundled', 'workspace']; localReads: 3;
  rawSourcesAndReferenceGraphChecked: true; exactPromptOrder: true; mutableSourcesDeletedAfterAdmission: true;
  executableDisabledBytesReadOnly: true; everyLocalClaimCompletedOnce: true; zeroNativeLeaseAndFields: true;
  unchangedWorkspaceAndWorker: true; originalGrantAndCheckpointBound: true; recoveryAfterRestartChecked: true };

export async function assertInstalledSkillsOutcome(input: { cut: Record<string, any>; readCas(ref: string): Promise<Buffer> }): Promise<InstalledSkillsEvidence> {
  const { cut } = input, run = cut.snapshot.run;
  const object = async (ref: string): Promise<Record<string, any>> => {
    const bytes = await input.readCas(ref); assert.equal(sha256Bytes(bytes), ref);
    const value = parseJsonStrict(new TextDecoder('utf8', { fatal: true }).decode(bytes)); assert(canonicalJsonBytes(value).equals(bytes)); return value as Record<string, any>;
  };
  const spec = await object(run.specRef), assembly = await object(spec.assemblyRef);
  assert.deepEqual(assembly.instructions.skills.map((value: any) => value.skillId), installedSkillIds());
  const items = await Promise.all(cut.items.map((row: any) => object(row.payloadRef))), batch = items.find(item => item.kind === 'assistant_tool_batch'); assert(batch);
  const rows = cut.journal.filter((row: any) => row.opKind === 'skill_resource'); assert.equal(rows.length, 9);
  let originalLease: number | undefined;
  for (const [index, skill] of skills.entries()) {
    const selection = assembly.instructions.skills[index], manifest = decodeSkillManifest(await object(selection.manifestRef));
    assert.equal(manifest.manifestDigest, selection.manifestDigest); assert.equal(manifest.sourceScope, skill.scope);
    const source = decodeSkillSourceIdentity(await object(manifest.sourceIdentityRef)); assert.equal(source.sourceIdentityDigest, manifest.sourceIdentityDigest);
    const files = new Map<string, Buffer>();
    for (const file of source.files) { const bytes = await input.readCas(file.rawBytesRef); assert.equal(bytes.length, file.rawByteCount); assert.equal(sha256Bytes(bytes), file.rawBytesDigest); files.set(file.canonicalRelativePath, bytes); }
    assert(files.get('SKILL.md')!.equals(Buffer.from(markdown(skill)))); assert(files.get(skill.file)!.equals(Buffer.from(skill.bytes)));
    validateFrozenSkillResourceGraph(files, manifest.resources.map(resource => resource.canonicalRelativePath));
    assert.equal(canonicalSha256(await object(manifest.instructionRef)), canonicalSha256(skillInstruction(skill.id, files.get('SKILL.md')!)));
    assert.equal(source.sourceScope, skill.scope);
    if (source.sourceScope === 'bundled') {
      assert.equal(source.runtimeBundleRef, assembly.runtime.runtimeBundleRef); assert.equal(source.runtimeBundleManifestDigest, assembly.runtime.runtimeBundleManifestDigest);
    }
    const callId = `owned-installed-skill-${index}`, opId = identityHash('cliq-tool-operation-v1', run.id, batch.itemId, callId);
    const group = rows.filter((row: any) => row.opId === opId); assert.deepEqual(group.map((row: any) => row.phase), ['prepared', 'dispatch_claimed', 'completed']);
    const [prepared, claim, completed] = group;
    assert(group.every((row: any) => row.attempt === 0 && row.leaseEpoch === 0 && row.localCommittedAt === prepared.localCommittedAt && row.timestamp === prepared.timestamp));
    for (const row of group) for (const field of ['sandboxLaunchSpecRef', 'sandboxLaunchSpecDigest', 'brokerFenceTokenDigest', 'processContainmentRef', 'containmentPlanRef']) assert.equal(row[field], undefined);
    assert.equal(claim.dispatchId, skillResourceDispatchId(run.id, opId, prepared.requestRef));
    const receipt = decodeSkillResourceReceipt(await object(completed.resultRef)), request = await object(prepared.requestRef), grant = await object(prepared.grantRef);
    assert.equal(receipt.requestRef, prepared.requestRef); assert.equal(receipt.grantRef, prepared.grantRef); assert.equal(receipt.targetRef, prepared.target);
    assert.equal(receipt.assemblyRef, spec.assemblyRef); assert.equal(receipt.callIndex, 19 + index); assert.equal(grant.maxDispatchedAttempts, 1);
    assert.equal(receipt.value.kind, 'range'); if (receipt.value.kind !== 'range') assert.fail('selected resource must be available');
    assert.equal(receipt.value.output.kind, skill.kind); assert.equal(receipt.value.output.byteCount, Buffer.byteLength(skill.bytes));
    assert.equal(receipt.value.output.offset, 0); assert.equal(receipt.value.output.eof, true);
    assert.equal(Buffer.from(receipt.value.output.bytesBase64, 'base64').toString(), skill.bytes);
    const sourceCp = cut.checkpoints.find((value: any) => value.id === receipt.sourceCheckpointId), effectCp = cut.checkpoints.find((value: any) => value.id === skillResourceCheckpointId(run.id, opId));
    assert(sourceCp && effectCp); assert.equal(effectCp.workspaceStateRef, sourceCp.workspaceStateRef); assert.equal(effectCp.journalSeq, completed.seq);
    const snapshot = await object(receipt.originalRunSnapshotRef); assert.equal(snapshot.latestCheckpointId, sourceCp.id);
    assert.equal(snapshot.activeWorkerLaunchId, undefined); assert.equal(snapshot.specRef, run.specRef);
    assert.equal(snapshot.waitingOnRef, undefined); assert.equal(snapshot.stopIntentRef, undefined);
    originalLease ??= snapshot.leaseEpoch; assert.equal(snapshot.leaseEpoch, originalLease);
    assert.equal(request.targetRef ?? request.target, prepared.target); assert.equal(request.opId, opId);
  }
  assert.equal(run.budgetConsumed.toolCalls, 20); assert.equal(run.budgetReserved.toolCalls, 0);
  return { qualified: true, selectedSkills: 3, sourceScopes: ['user', 'bundled', 'workspace'], localReads: 3,
    rawSourcesAndReferenceGraphChecked: true, exactPromptOrder: true, mutableSourcesDeletedAfterAdmission: true,
    executableDisabledBytesReadOnly: true, everyLocalClaimCompletedOnce: true, zeroNativeLeaseAndFields: true,
    unchangedWorkspaceAndWorker: true, originalGrantAndCheckpointBound: true, recoveryAfterRestartChecked: true };
}
