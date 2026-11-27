// Closed retained data only. These decoders confer no filesystem, Trust,
// policy, signature, execution, StateOwner or Checkpoint authority.
import { types } from 'node:util';
import type { ArtifactRef } from './types.js';
import { controlWireInteger, controlWireRecord, controlWireRef, controlWireText } from './control-wire-data.js';
import { digestOmitting } from './identity.js';
import { immutableSnapshot } from '../model/immutable.js';

export const SKILL_RESOURCE_COUNT = 128;
export const SKILL_RESOURCE_BYTES = 16 * 1024 * 1024;
export const SKILL_RESOURCE_RANGE_BYTES = 65536;
export type SkillSourceFileBytesV1 = { canonicalRelativePath: string; rawBytesRef: ArtifactRef; rawBytesDigest: string; rawByteCount: number };
export type DescriptorCapturedSkillSourceFileV1 = SkillSourceFileBytesV1 & {
  fileDescriptor: { deviceId: string; fileId: string; ownerUid: number; mode: 384 | 420 | 448 | 493; linkCount: 1 };
  sourceEntryDigest: string;
};
export type BundledSkillSourceFileV1 = SkillSourceFileBytesV1 & { sourceEntryDigest: string };
export type BundledSkillClosureV1 = { schemaVersion: 1; format: 'cliq-bundled-skill-closure-v1'; skillId: string;
  files: SkillSourceFileBytesV1[]; closureDigest: string };
export type SkillSourceIdentityBaseV1 = { schemaVersion: 1; format: 'cliq-skill-source-identity-v1'; skillId: string; sourceIdentityDigest: string };
export type SkillSourceIdentityV1 = SkillSourceIdentityBaseV1 & (
  | { sourceScope: 'workspace'; workspaceIdentityRef: ArtifactRef; workspaceIdentityDigest: string;
      files: DescriptorCapturedSkillSourceFileV1[];
      rootDescriptor: { canonicalRootRelativePath: string; deviceId: string; fileId: string; ownerUid: number; mode: 448 | 493 } }
  | { sourceScope: 'user'; ownerPrincipalId: string; principalIdentityRef: ArtifactRef; principalIdentityDigest: string;
      files: DescriptorCapturedSkillSourceFileV1[];
      rootDescriptor: { canonicalAbsolutePath: string; deviceId: string; fileId: string; ownerUid: number; mode: 448 } }
  | { sourceScope: 'bundled'; runtimeBundleRef: ArtifactRef; runtimeBundleManifestDigest: string;
      bundleEntryId: string; bundleEntryVersion: string; bundledClosureRef: ArtifactRef; bundledClosureDigest: string;
      files: BundledSkillSourceFileV1[] }
);
export type SkillResourceKind = 'text' | 'schema' | 'template' | 'executable-disabled';
export type SkillManifestV1 = { schemaVersion: 1; format: 'cliq-skill-manifest-v1'; skillId: string;
  sourceScope: 'bundled' | 'user' | 'workspace'; sourceIdentityRef: ArtifactRef; sourceIdentityDigest: string;
  instructionRef: ArtifactRef; instructionDigest: string;
  resources: Array<{ canonicalRelativePath: string; kind: SkillResourceKind; contentRef: ArtifactRef; contentDigest: string }>;
  manifestDigest: string };
export type SkillResourceInputV1 = { skillId: string; canonicalRelativePath: string; offset: number; length: number };
export type SkillResourceOutputV1 = { schemaVersion: 1; skillId: string; canonicalRelativePath: string; kind: SkillResourceKind;
  byteCount: number; offset: number; bytesBase64: string; nextOffset: number; eof: boolean };

function invalid(): never { throw new TypeError('invalid closed frozen skill data'); }
function plain(value: unknown, depth = 0, remaining = { count: 10000 }): void {
  if (--remaining.count < 0 || depth > 32) invalid();
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (typeof value !== 'object' || types.isProxy(value) ||
      !Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const fields = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(fields)) {
    if (Array.isArray(value) && key === 'length') continue;
    const field = fields[key as string]!;
    if (typeof key !== 'string' || !field.enumerable || !Object.hasOwn(field, 'value')) invalid();
    plain(field.value, depth + 1, remaining);
  }
  if (Array.isArray(value) && (Object.keys(value).length !== value.length ||
      Object.keys(value).some((key, index) => key !== String(index)))) invalid();
}
export function canonicalSkillPath(value: unknown): string {
  const text = controlWireText(value, 4096);
  if (text.includes('\\') || text.startsWith('/') || /^[A-Za-z]:/u.test(text) ||
      text.split('/').some(part => !part || part === '.' || part === '..' || Buffer.byteLength(part) > 255)) invalid();
  return text;
}
export function canonicalSkillId(value: unknown): string {
  const id = controlWireText(value);
  if (canonicalSkillPath(id).includes('/')) invalid();
  return id;
}
function decimal(value: unknown) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value) || BigInt(value) > 18446744073709551615n) invalid();
}
function descriptor(value: unknown, file: boolean): void {
  const data = controlWireRecord(value, file ? ['deviceId', 'fileId', 'ownerUid', 'mode', 'linkCount'] : ['deviceId', 'fileId', 'ownerUid', 'mode']);
  decimal(data.deviceId); decimal(data.fileId); controlWireInteger(data.ownerUid, 0, 0xffff_ffff);
  if (!(file ? [384, 420, 448, 493] : [448, 493]).includes(data.mode as number) || file && data.linkCount !== 1) invalid();
}
function selfDigest(data: Record<string, unknown>, name: string) {
  controlWireRef(data[name]); if (digestOmitting(data, name) !== data[name]) invalid();
}
function sourceFiles(value: unknown, captured: boolean | undefined): void {
  if (!Array.isArray(value) || value.length < 1 || value.length > SKILL_RESOURCE_COUNT + 1) invalid();
  let previous: Buffer | undefined, instruction = false, resourceBytes = 0;
  const paths = new Set<string>();
  for (const item of value) {
    const data = controlWireRecord(item, ['canonicalRelativePath', 'rawBytesRef', 'rawBytesDigest', 'rawByteCount',
      ...(captured === undefined ? [] : ['sourceEntryDigest']), ...(captured ? ['fileDescriptor'] : [])]);
    const path = canonicalSkillPath(data.canonicalRelativePath), bytes = Buffer.from(path);
    if (previous && Buffer.compare(previous, bytes) >= 0) invalid(); previous = bytes;
    const segments = path.split('/');
    if (segments.slice(0, -1).some((_, index) => paths.has(segments.slice(0, index + 1).join('/')))) invalid();
    paths.add(path);
    controlWireRef(data.rawBytesRef); if (data.rawBytesDigest !== data.rawBytesRef) invalid();
    controlWireInteger(data.rawByteCount, path === 'SKILL.md' ? 1 : 0, path === 'SKILL.md' ? 1048576 : SKILL_RESOURCE_BYTES);
    if (path === 'SKILL.md') instruction = true;
    else if ((resourceBytes += data.rawByteCount as number) > SKILL_RESOURCE_BYTES) invalid();
    if (captured !== undefined) controlWireRef(data.sourceEntryDigest);
    if (captured) descriptor(data.fileDescriptor, true);
  }
  if (!instruction) invalid();
}
export function decodeBundledSkillClosure(value: unknown): Readonly<BundledSkillClosureV1> {
  plain(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'skillId', 'files', 'closureDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-bundled-skill-closure-v1') invalid();
  canonicalSkillId(data.skillId); sourceFiles(data.files, undefined); selfDigest(data, 'closureDigest');
  return immutableSnapshot(data) as unknown as BundledSkillClosureV1;
}
export function decodeSkillSourceIdentity(value: unknown): Readonly<SkillSourceIdentityV1> {
  plain(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const scope = (value as Record<string, unknown>).sourceScope;
  const base = ['schemaVersion', 'format', 'skillId', 'sourceScope', 'sourceIdentityDigest', 'files'];
  const data = controlWireRecord(value, [...base, ...(scope === 'workspace' ? ['workspaceIdentityRef', 'workspaceIdentityDigest', 'rootDescriptor']
    : scope === 'user' ? ['ownerPrincipalId', 'principalIdentityRef', 'principalIdentityDigest', 'rootDescriptor']
      : scope === 'bundled' ? ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'bundleEntryId', 'bundleEntryVersion', 'bundledClosureRef', 'bundledClosureDigest'] : [])]);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-skill-source-identity-v1' || !['workspace', 'user', 'bundled'].includes(scope as string)) invalid();
  canonicalSkillId(data.skillId); sourceFiles(data.files, scope !== 'bundled');
  if (scope === 'bundled') {
    for (const key of ['runtimeBundleRef', 'runtimeBundleManifestDigest', 'bundledClosureRef', 'bundledClosureDigest']) controlWireRef(data[key]);
    controlWireText(data.bundleEntryId); controlWireText(data.bundleEntryVersion);
  } else {
    const pathKey = scope === 'workspace' ? 'canonicalRootRelativePath' : 'canonicalAbsolutePath';
    const root = controlWireRecord(data.rootDescriptor, [pathKey, 'deviceId', 'fileId', 'ownerUid', 'mode']);
    const { [pathKey]: path, ...physical } = root; descriptor(physical, false);
    if (scope === 'workspace') {
      canonicalSkillPath(path); controlWireRef(data.workspaceIdentityRef); controlWireRef(data.workspaceIdentityDigest);
    } else {
      const absolute = controlWireText(path, 4096); if (!absolute.startsWith('/') || absolute === '/' || root.mode !== 448) invalid();
      canonicalSkillPath(absolute.slice(1)); controlWireText(data.ownerPrincipalId);
      controlWireRef(data.principalIdentityRef); controlWireRef(data.principalIdentityDigest);
    }
    for (const file of data.files as DescriptorCapturedSkillSourceFileV1[]) {
      if (file.fileDescriptor.ownerUid !== root.ownerUid || file.fileDescriptor.deviceId !== root.deviceId) invalid();
      const common = { sourceScope: scope, ...(scope === 'workspace' ? { workspaceIdentityDigest: data.workspaceIdentityDigest }
        : { principalIdentityDigest: data.principalIdentityDigest }), rootDescriptor: root,
        canonicalRelativePath: file.canonicalRelativePath, fileDescriptor: file.fileDescriptor,
        rawBytesRef: file.rawBytesRef, rawBytesDigest: file.rawBytesDigest, rawByteCount: file.rawByteCount };
      if (file.sourceEntryDigest !== digestOmitting({ ...common, sourceEntryDigest: file.sourceEntryDigest }, 'sourceEntryDigest')) invalid();
    }
  }
  if (scope === 'bundled') for (const file of data.files as BundledSkillSourceFileV1[]) {
    const common = { sourceScope: scope, bundledClosureDigest: data.bundledClosureDigest, canonicalRelativePath: file.canonicalRelativePath,
      rawBytesRef: file.rawBytesRef, rawBytesDigest: file.rawBytesDigest, rawByteCount: file.rawByteCount };
    if (file.sourceEntryDigest !== digestOmitting({ ...common, sourceEntryDigest: file.sourceEntryDigest }, 'sourceEntryDigest')) invalid();
  }
  selfDigest(data, 'sourceIdentityDigest'); return immutableSnapshot(data) as unknown as SkillSourceIdentityV1;
}
export function decodeSkillManifest(value: unknown): Readonly<SkillManifestV1> {
  plain(value);
  const data = controlWireRecord(value, ['schemaVersion', 'format', 'skillId', 'sourceScope', 'sourceIdentityRef', 'sourceIdentityDigest',
    'instructionRef', 'instructionDigest', 'resources', 'manifestDigest']);
  if (data.schemaVersion !== 1 || data.format !== 'cliq-skill-manifest-v1' || !['workspace', 'user', 'bundled'].includes(data.sourceScope as string)) invalid();
  canonicalSkillId(data.skillId);
  for (const key of ['sourceIdentityRef', 'sourceIdentityDigest', 'instructionRef', 'instructionDigest']) controlWireRef(data[key]);
  if (!Array.isArray(data.resources) || data.resources.length > SKILL_RESOURCE_COUNT) invalid();
  let previous: Buffer | undefined;
  for (const item of data.resources) {
    const resource = controlWireRecord(item, ['canonicalRelativePath', 'kind', 'contentRef', 'contentDigest']);
    const path = canonicalSkillPath(resource.canonicalRelativePath), bytes = Buffer.from(path);
    if (path === 'SKILL.md' || previous && Buffer.compare(previous, bytes) >= 0) invalid(); previous = bytes;
    if (!['text', 'schema', 'template', 'executable-disabled'].includes(resource.kind as string)) invalid();
    controlWireRef(resource.contentRef); if (resource.contentDigest !== resource.contentRef) invalid();
  }
  selfDigest(data, 'manifestDigest'); return immutableSnapshot(data) as unknown as SkillManifestV1;
}
export function decodeSkillResourceInput(value: unknown): Readonly<SkillResourceInputV1> {
  plain(value); const data = controlWireRecord(value, ['skillId', 'canonicalRelativePath', 'offset', 'length']);
  canonicalSkillId(data.skillId); if (canonicalSkillPath(data.canonicalRelativePath) === 'SKILL.md') invalid();
  controlWireInteger(data.offset, 0, SKILL_RESOURCE_BYTES); controlWireInteger(data.length, 1, SKILL_RESOURCE_RANGE_BYTES);
  return immutableSnapshot(data) as unknown as SkillResourceInputV1;
}
export function decodeSkillResourceOutput(value: unknown): Readonly<SkillResourceOutputV1> {
  plain(value); const data = controlWireRecord(value, ['schemaVersion', 'skillId', 'canonicalRelativePath', 'kind', 'byteCount',
    'offset', 'bytesBase64', 'nextOffset', 'eof']);
  if (data.schemaVersion !== 1 || !['text', 'schema', 'template', 'executable-disabled'].includes(data.kind as string)) invalid();
  canonicalSkillId(data.skillId); if (canonicalSkillPath(data.canonicalRelativePath) === 'SKILL.md') invalid();
  const size = controlWireInteger(data.byteCount, 0, SKILL_RESOURCE_BYTES), offset = controlWireInteger(data.offset, 0, size);
  controlWireInteger(data.nextOffset, offset, size);
  if (typeof data.bytesBase64 !== 'string' || data.bytesBase64.length > 87384) invalid();
  const bytes = Buffer.from(data.bytesBase64, 'base64');
  if (bytes.length > SKILL_RESOURCE_RANGE_BYTES || bytes.toString('base64') !== data.bytesBase64 ||
      data.nextOffset !== offset + bytes.length || data.eof !== (data.nextOffset === size) || !bytes.length && !data.eof) invalid();
  return immutableSnapshot(data) as unknown as SkillResourceOutputV1;
}
