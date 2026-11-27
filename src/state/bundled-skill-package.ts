// Signed-package construction data only. This helper neither selects a user
// path nor signs a release, imports a resource or creates execution authority.
import { types } from 'node:util';
import { canonicalJsonBytes, canonicalSha256 } from '../kernel/canonical.js';
import { identityHash, sha256Bytes } from '../kernel/identity.js';
import { canonicalSkillId, canonicalSkillPath, decodeBundledSkillClosure } from '../kernel/skill.js';
import { validateFrozenSkillResourceGraph } from '../skills/resources.js';
import { skillInstruction } from './skill-data.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';

export type BundledSkillPackageInput = Readonly<{ skillId: string;
  files: readonly Readonly<{ canonicalRelativePath: string; bytes: Uint8Array }>[] }>;
type Content = { entryId: string; role: 'skill_bundle' | 'bundle_object'; relativePath: string; executable: false; bytes: Buffer };
const byteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength')!.get!;
function invalid(): never { throw new TypeError('bundled skill package data is not an exact bounded reference closure'); }
function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length || Reflect.ownKeys(fields).some(key => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some(key => !fields[key]?.enumerable || !Object.hasOwn(fields[key]!, 'value'))) invalid();
  return Object.fromEntries(keys.map(key => [key, fields[key]!.value]));
}
function array(value: unknown, maximum: number): readonly unknown[] {
  if (!value || typeof value !== 'object' || types.isProxy(value) || !Array.isArray(value) || value.length > maximum) invalid();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== value.length + 1 || Array.from({ length: value.length }, (_, index) => String(index))
    .some(key => !fields[key]?.enumerable || !Object.hasOwn(fields[key]!, 'value'))) invalid();
  return value;
}

/** Per-skill maxima remain inside the original aggregate RuntimeBundle caps.
 * The package's final validateBundle owns the original global 65-root limit. */
export function buildBundledSkillPackageData(input: readonly BundledSkillPackageInput[]) {
  const contents = new Map<string, Content>(), roots: RuntimeBundleManifest['structuredArtifacts'] = [], ids = new Set<string>();
  for (const value of array(input, 64)) {
    const selected = record(value, ['skillId', 'files']), id = canonicalSkillId(selected.skillId);
    if (ids.has(id)) invalid(); ids.add(id);
    const raw = new Map<string, Buffer>(); let resourceBytes = 0;
    for (const value of array(selected.files, 129)) {
      const file = record(value, ['canonicalRelativePath', 'bytes']), name = canonicalSkillPath(file.canonicalRelativePath);
      if (raw.has(name) || !file.bytes || typeof file.bytes !== 'object' || types.isProxy(file.bytes) || !types.isUint8Array(file.bytes)) invalid();
      const length = Reflect.apply(byteLength, file.bytes, []) as number;
      if (length > (name === 'SKILL.md' ? 1048576 : 16 * 1048576)) invalid();
      if (name !== 'SKILL.md' && (resourceBytes += length) > 16 * 1048576) invalid();
      const copy = Buffer.alloc(length); Uint8Array.prototype.set.call(copy, file.bytes); raw.set(name, copy);
    }
    const files = [...raw].sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right))).map(([name, bytes]) =>
      ({ canonicalRelativePath: name, rawBytesRef: sha256Bytes(bytes), rawBytesDigest: sha256Bytes(bytes), rawByteCount: bytes.length }));
    const core = { schemaVersion: 1 as const, format: 'cliq-bundled-skill-closure-v1' as const, skillId: id, files };
    const closure = decodeBundledSkillClosure({ ...core, closureDigest: canonicalSha256(core) });
    skillInstruction(id, raw.get('SKILL.md')!);
    validateFrozenSkillResourceGraph(raw, files.filter(file => file.canonicalRelativePath !== 'SKILL.md').map(file => file.canonicalRelativePath));
    for (const file of files) {
      const bytes = raw.get(file.canonicalRelativePath)!, entryId = identityHash('runtime-bundle-object-v1', file.rawBytesRef);
      if (!contents.has(entryId)) contents.set(entryId, { entryId, role: 'bundle_object',
        relativePath: `objects/sha256/${file.rawBytesRef.slice(0, 2)}/${file.rawBytesRef}`, executable: false, bytes });
    }
    const bytes = canonicalJsonBytes(closure), ref = sha256Bytes(bytes), entryId = `bundled_skill:${id}`;
    if (bytes.length > 1048576 || contents.has(entryId)) invalid();
    contents.set(entryId, { entryId, role: 'skill_bundle', relativePath: `skills/${id}/closure.json`, executable: false, bytes });
    roots.push({ kind: 'bundled_skill', artifactId: id, rootEntryId: entryId, artifactRef: ref, semanticDigest: closure.closureDigest,
      memberRefs: [...new Set(files.map(file => file.rawBytesRef))].sort() });
  }
  roots.sort((left, right) => Buffer.compare(Buffer.from(left.artifactId), Buffer.from(right.artifactId)));
  return { contents: [...contents.values()], roots };
}
