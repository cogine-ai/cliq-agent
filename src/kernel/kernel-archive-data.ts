// Fixed original-connection archive preparation data. Plain records never
// prove an Owner, EX gate, archive birth, committed SQL or physical backup.
import { assertControlWireJson, controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { digestOmitting, normalizeAbsolutePath, parseCanonicalTime } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';

export type KernelRollbackDrainingControlV1 = Readonly<{
  schemaVersion: 1; format: 'cliq-kernel-rollback-control-v1'; phase: 'rollback_draining'; controlRevision: 1;
  migrationId: string; archiveId: string; kernelGenerationId: string;
  stateRootIdentityRef: string; stateRootIdentityDigest: string; stateRootCanonicalAbsolutePath: string;
  requestRef: string; requestDigest: string; originalImportControlRef: string; originalImportControlDigest: string;
  originalKernelAuthorityRef: string; originalKernelAuthorityDigest: string;
  preparedAt: string; controlDigest: string;
}>;
export function decodeKernelRollbackDrainingControl(value: unknown): Readonly<KernelRollbackDrainingControlV1> {
  assertControlWireJson(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'phase', 'controlRevision', 'migrationId', 'archiveId',
    'kernelGenerationId', 'stateRootIdentityRef', 'stateRootIdentityDigest', 'stateRootCanonicalAbsolutePath', 'requestRef', 'requestDigest',
    'originalImportControlRef', 'originalImportControlDigest', 'originalKernelAuthorityRef', 'originalKernelAuthorityDigest', 'preparedAt', 'controlDigest']);
  const invalid = () => { throw new TypeError('rollback draining control differs from its fixed original-generation contract'); };
  if (data.schemaVersion !== 1 || data.format !== 'cliq-kernel-rollback-control-v1' || data.phase !== 'rollback_draining' ||
      controlWireInteger(data.controlRevision, 1, 1) !== 1) invalid();
  for (const key of ['migrationId', 'archiveId', 'kernelGenerationId'])
    if (!/^[A-Za-z0-9_-]{43}$/u.test(controlWireText(data[key], 43))) invalid();
  for (const [key, entry] of Object.entries(data)) if (key.endsWith('Ref') || key.endsWith('Digest')) controlWireRef(entry);
  const root = controlWireText(data.stateRootCanonicalAbsolutePath, 4096);
  if (normalizeAbsolutePath(root) !== root) invalid();
  parseCanonicalTime(controlWireText(data.preparedAt));
  if (digestOmitting(data, 'controlDigest') !== data.controlDigest) invalid();
  return immutableSnapshot(data) as KernelRollbackDrainingControlV1;
}
