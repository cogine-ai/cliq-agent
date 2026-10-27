// Signed declaration validation only. The installer/retained reader owns the
// actual complete member reads; these functions mint no read or execute right.
import { canonicalSha256 } from '../kernel/canonical.js';
import { canonicalSkillId, decodeBundledSkillClosure, type BundledSkillClosureV1 } from '../kernel/skill.js';
import { controlWireRecord, controlWireRef, controlWireText } from '../kernel/control-wire-data.js';
import type { RuntimeBundleManifest } from '../policy/runtime-authority.js';
import { sha256Bytes } from '../kernel/identity.js';
import { skillResourceReferences, validateFrozenSkillReferenceEdges } from '../skills/resources.js';

type Root = RuntimeBundleManifest['structuredArtifacts'][number];
type Entry = RuntimeBundleManifest['entries'][number];
function invalid(): never { throw new TypeError('bundled skill differs from its exact signed closure'); }

export function bundledSkillRoots(bundle: RuntimeBundleManifest): readonly Root[] {
  const roots = bundle.structuredArtifacts.filter(root => root.kind === 'bundled_skill');
  if (roots.length > 64 || new Set(roots.map(root => root.artifactId)).size !== roots.length ||
      new Set(roots.map(root => root.rootEntryId)).size !== roots.length) invalid();
  for (const root of roots) {
    controlWireRecord(root, ['kind', 'artifactId', 'rootEntryId', 'artifactRef', 'semanticDigest', 'memberRefs']);
    canonicalSkillId(root.artifactId); controlWireText(root.rootEntryId); controlWireRef(root.artifactRef); controlWireRef(root.semanticDigest);
    const entries = bundle.entries.filter(entry => entry.entryId === root.rootEntryId), entry = entries[0];
    if (entries.length !== 1 || !entry || entry.role !== 'skill_bundle' || entry.executable || entry.digest !== root.artifactRef ||
        entry.byteCount < 1 || entry.byteCount > 1048576 || !Array.isArray(root.memberRefs) || root.memberRefs.length < 1 || root.memberRefs.length > 129 ||
        root.memberRefs.some((ref, index) => { controlWireRef(ref); return ref === root.artifactRef || index > 0 && ref <= root.memberRefs[index - 1]!; })) invalid();
  }
  if (bundle.entries.some(entry => entry.role === 'skill_bundle' && !roots.some(root => root.rootEntryId === entry.entryId))) invalid();
  return roots;
}

export function bundledSkillMembers(bundle: RuntimeBundleManifest, root: Root, value: unknown): readonly Entry[] {
  const closure = decodeBundledSkillClosure(value);
  if (bundledSkillRoots(bundle).filter(candidate => canonicalSha256(candidate) === canonicalSha256(root)).length !== 1 || closure.skillId !== root.artifactId ||
      closure.closureDigest !== root.semanticDigest || canonicalSha256(closure) !== root.artifactRef ||
      canonicalSha256([...new Set(closure.files.map(file => file.rawBytesRef))].sort()) !== canonicalSha256(root.memberRefs)) invalid();
  return closure.files.map(file => {
    const entries = bundle.entries.filter(entry => entry.digest === file.rawBytesRef), entry = entries[0];
    if (entries.length !== 1 || !entry || entry.role !== 'bundle_object' || entry.executable || entry.byteCount !== file.rawByteCount) invalid();
    return entry;
  });
}

export function bundledSkillMemberRoles(bundle: RuntimeBundleManifest, closures: ReadonlyMap<string, BundledSkillClosureV1>) {
  const instructions = new Set<string>(), resources = new Set<string>();
  for (const root of bundledSkillRoots(bundle)) {
    const closure = closures.get(root.artifactRef); if (!closure) invalid(); bundledSkillMembers(bundle, root, closure);
    for (const file of closure.files) (file.canonicalRelativePath === 'SKILL.md' ? instructions : resources).add(file.rawBytesRef);
  }
  return { instructions, resources };
}

/** Reference semantics after the owning installer/seed reader's full signed
 * member verification. Opaque bytes are not parsed as a program or JSON. Only
 * one textual resource body is retained at a time; this is no read permit. */
export async function validateBundledSkillReferences(closures: ReadonlyMap<string, BundledSkillClosureV1>,
  readTextualMember: (ref: string, byteCount: number) => Promise<Buffer>): Promise<void> {
  for (const closure of closures.values()) {
    const edges = new Map<string, readonly string[]>();
    for (const file of closure.files) {
      const name = file.canonicalRelativePath;
      let dependencies: readonly string[] = [];
      if (name === 'SKILL.md' || /\.(?:md|json)$/iu.test(name)) {
        const bytes = await readTextualMember(file.rawBytesRef, file.rawByteCount);
        if (bytes.length !== file.rawByteCount || sha256Bytes(bytes) !== file.rawBytesDigest) invalid();
        dependencies = skillResourceReferences(name, bytes);
      }
      edges.set(name, dependencies);
    }
    validateFrozenSkillReferenceEdges(edges, closure.files.filter(file => file.canonicalRelativePath !== 'SKILL.md').map(file => file.canonicalRelativePath));
  }
}
