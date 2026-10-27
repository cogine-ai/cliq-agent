// Immutable CAS data and deterministic projections only. These helpers never
// authorize an operation, acquire a lease or claim process/death evidence.
import { canonicalSha256 } from '../kernel/canonical.js';
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import { digestOmitting, identityHash, parseCanonicalTime } from '../kernel/identity.js';
import { decodeSkillResourceInput, decodeSkillResourceOutput, type SkillResourceInputV1, type SkillResourceOutputV1 } from '../kernel/skill.js';
import type { RunAssemblyV1 } from '../kernel/types.js';
import { immutableSnapshot } from '../model/immutable.js';
import type { ArtifactCatalog } from './artifacts.js';
import { frozenSkillResourceRange, readFrozenSkillData, readSkillAssemblyBinding } from './skill-data.js';

export type SkillResourceValue = { kind: 'range'; output: Readonly<SkillResourceOutputV1> }
  | { kind: 'error'; code: 'SKILL_NOT_SELECTED' | 'SKILL_RESOURCE_NOT_FOUND' | 'SKILL_RESOURCE_RANGE_INVALID' };
export type SkillResourceReceiptV1 = {
  schemaVersion: 1; format: 'cliq-skill-resource-read-v1'; runId: string; opId: string; assemblyRef: string;
  requestRef: string; targetRef: string; grantRef: string; batchItemId: string; callId: string; callIndex: number;
  originalRunSnapshotRef: string; sourceCheckpointId: string; sourceJournalSeq: number;
  inspectorIdentityRef: string; inspectorIdentityDigest: string; preparedAt: string; value: SkillResourceValue; receiptDigest: string;
};
export const skillResourceCheckpointId = (runId: string, opId: string) => identityHash('cliq-skill-resource-checkpoint-v1', runId, opId);
export const skillResourceDispatchId = (runId: string, opId: string, requestRef: string) => identityHash('cliq-skill-resource-local-claim-v1', runId, opId, requestRef);

/** An unknown selection/path is an ordinary deterministic read refusal. A
 * missing/corrupt CAS object or uncertain reader close always propagates. */
export async function readSkillResourceValue(artifacts: ArtifactCatalog, assembly: RunAssemblyV1,
  request: Readonly<SkillResourceInputV1>): Promise<Readonly<SkillResourceValue>> {
  const input = decodeSkillResourceInput(request), selected = assembly.instructions.skills;
  if (selected.length > 64 || new Set(selected.map(value => value.skillId)).size !== selected.length)
    throw new TypeError('skill selection is not the original unique ordered assembly');
  const binding = await readSkillAssemblyBinding(artifacts, assembly), selection = selected.find(value => value.skillId === input.skillId);
  if (!selection) return Object.freeze({ kind: 'error', code: 'SKILL_NOT_SELECTED' });
  const data = await readFrozenSkillData(artifacts, selection, binding);
  const resource = data.manifest.resources.find(value => value.canonicalRelativePath === input.canonicalRelativePath);
  if (!resource) return Object.freeze({ kind: 'error', code: 'SKILL_RESOURCE_NOT_FOUND' });
  const bytes = data.files.get(resource.canonicalRelativePath)!;
  if (input.offset > bytes.length) return Object.freeze({ kind: 'error', code: 'SKILL_RESOURCE_RANGE_INVALID' });
  return Object.freeze({ kind: 'range', output: frozenSkillResourceRange(data, input) });
}

export function decodeSkillResourceValue(value: unknown): Readonly<SkillResourceValue> {
  assertControlWireJson(value); const data = controlWireRecord(value, ['kind'], ['output', 'code']);
  if (data.kind === 'range') {
    controlWireRecord(data, ['kind', 'output']); decodeSkillResourceOutput(data.output);
  } else if (data.kind === 'error') {
    controlWireRecord(data, ['kind', 'code']);
    if (!['SKILL_NOT_SELECTED', 'SKILL_RESOURCE_NOT_FOUND', 'SKILL_RESOURCE_RANGE_INVALID'].includes(data.code as string))
      throw new TypeError('unknown skill resource refusal');
  } else throw new TypeError('unknown skill resource result');
  return immutableSnapshot(data) as SkillResourceValue;
}

export function decodeSkillResourceReceipt(value: unknown): Readonly<SkillResourceReceiptV1> {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'runId', 'opId', 'assemblyRef', 'requestRef', 'targetRef', 'grantRef',
    'batchItemId', 'callId', 'callIndex', 'originalRunSnapshotRef', 'sourceCheckpointId', 'sourceJournalSeq',
    'inspectorIdentityRef', 'inspectorIdentityDigest', 'preparedAt', 'value', 'receiptDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-skill-resource-read-v1' || digestOmitting(data, 'receiptDigest') !== data.receiptDigest)
    throw new TypeError('invalid skill resource receipt');
  for (const field of ['runId', 'opId', 'batchItemId', 'callId', 'sourceCheckpointId']) controlWireText(data[field]);
  for (const field of ['assemblyRef', 'requestRef', 'targetRef', 'grantRef', 'originalRunSnapshotRef', 'inspectorIdentityRef', 'inspectorIdentityDigest', 'receiptDigest'])
    controlWireRef(data[field]);
  controlWireInteger(data.callIndex, 0, Number.MAX_SAFE_INTEGER); controlWireInteger(data.sourceJournalSeq, 0, Number.MAX_SAFE_INTEGER);
  parseCanonicalTime(controlWireText(data.preparedAt)); decodeSkillResourceValue(data.value);
  return immutableSnapshot(data) as SkillResourceReceiptV1;
}

export function skillResourceReceipt(core: Omit<SkillResourceReceiptV1, 'receiptDigest'>): Readonly<SkillResourceReceiptV1> {
  return decodeSkillResourceReceipt({ ...core, receiptDigest: canonicalSha256(core) });
}
