import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildBundledSkillPackageData } from './installed-skill-package.js';
import { canonicalSha256 } from '../../../src/kernel/canonical.js';
import { decodeBundledSkillClosure } from '../../../src/kernel/skill.js';
import { parseJsonStrict } from '../../../src/kernel/json.js';
import { mkdtemp, mkdir, writeFile, readdir, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { canonicalJsonBytes } from '../../../src/kernel/canonical.js';
import { sha256Bytes } from '../../../src/kernel/identity.js';
import { buildInstalledSupervisorPackage } from './installed-supervisor-package.js';
const skill = (id: string, body: string) => Buffer.from(`---\nname: ${id}\ndescription: Frozen package.\n---\n${body}\n`);
test('bundled package construction retains exact raw bytes and independent closure/semantic identities without executing code', () => {
  const source = skill('example', '[guide](references/guide.md)\nscripts/extract.py'), script = Buffer.from('throw new Error("must never execute");\n');
  const built = buildBundledSkillPackageData([{ skillId: 'example', files: [{ canonicalRelativePath: 'scripts/extract.py', bytes: script },
    { canonicalRelativePath: 'SKILL.md', bytes: source }, { canonicalRelativePath: 'references/guide.md', bytes: Buffer.from('Reference text.') }] }]);
  assert.equal(built.roots.length, 1); assert.equal(built.contents.length, 4); assert(built.contents.every(entry => !entry.executable));
  const root = built.roots[0]!, entry = built.contents.find(entry => entry.entryId === root.rootEntryId)!;
  const closure = decodeBundledSkillClosure(parseJsonStrict(entry.bytes.toString()));
  assert.notEqual(root.artifactRef, root.semanticDigest); assert.equal(root.artifactRef, canonicalSha256(closure));
  assert.deepEqual(closure.files.map(file => file.canonicalRelativePath), ['SKILL.md', 'references/guide.md', 'scripts/extract.py']);
  const raw = closure.files.find(file => file.canonicalRelativePath === 'scripts/extract.py')!;
  assert(built.contents.find(entry => entry.relativePath.endsWith(raw.rawBytesRef))!.bytes.equals(script));
});
test('package construction refuses undeclared/missing resources, unsafe paths, duplicate ids and non-string metadata', () => {
  const base = { skillId: 'example', files: [{ canonicalRelativePath: 'SKILL.md', bytes: skill('example', '[guide](references/guide.md)') },
    { canonicalRelativePath: 'references/guide.md', bytes: Buffer.from('Reference.') }] };
  assert.throws(() => buildBundledSkillPackageData([{ ...base, files: base.files.slice(0, 1) }]));
  assert.throws(() => buildBundledSkillPackageData([{ ...base, files: [...base.files, { canonicalRelativePath: 'orphan.txt', bytes: Buffer.from('unselected') }] }]));
  assert.throws(() => buildBundledSkillPackageData([base, base]));
  assert.throws(() => buildBundledSkillPackageData([{ ...base, files: [{ canonicalRelativePath: '../SKILL.md', bytes: skill('example', 'Text.') }] }]));
  assert.throws(() => buildBundledSkillPackageData([{ ...base, files: [{ canonicalRelativePath: 'SKILL.md', bytes: skill('example', 'Text.') },
    { canonicalRelativePath: 'orphan.txt', bytes: Buffer.alloc(16 * 1048576 + 1) }] }]));
  assert.throws(() => buildBundledSkillPackageData([{ ...base, files: [{ canonicalRelativePath: 'SKILL.md', bytes: skill('example', 'Text.') },
    { canonicalRelativePath: 'first.bin', bytes: Buffer.alloc(16 * 1048576) }, { canonicalRelativePath: 'second.bin', bytes: Buffer.alloc(1) }] }]));
  let traps = 0;
  const proxy = new Proxy(base, { get() { traps++; throw new Error('no trap'); }, ownKeys() { traps++; throw new Error('no trap'); } });
  assert.throws(() => buildBundledSkillPackageData([proxy])); assert.equal(traps, 0);
  assert.throws(() => buildBundledSkillPackageData([{ skillId: 'example', files: [{ canonicalRelativePath: 'SKILL.md',
    bytes: Buffer.from('---\nname: example\ndescription: Data.\nmetadata:\n  nested: [not, strings]\n---\nBody.') }] }]));
});

test('the pure planner copies actual typed bytes without invoking decorated-view accessors', () => {
  let traps = 0; const source = skill('example', 'The instruction body.');
  const original = Buffer.from(source);
  for (const name of ['byteLength', 'length', 'buffer', 'constructor']) Object.defineProperty(source, name, { configurable: true,
    get() { traps++; throw new Error('data view getter must not run'); } });
  const value = buildBundledSkillPackageData([{ skillId: 'example', files: [{ canonicalRelativePath: 'SKILL.md', bytes: source }] }]);
  assert.equal(traps, 0); assert(value.contents.some(entry => entry.role === 'bundle_object' && entry.bytes.equals(original)));
});

test('the data-only source7 packaging guard refuses a new skill option before importing or building any old product', async () => {
  // A bounded source-verifier fixture, not an original signed product, SQL7
  // genesis, release root or upgrade qualification. Nothing is executed.
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'cliq-skill-old-recipe-'));
  try {
    const root = path.join(directory, 'source'); await mkdir(path.join(root, 'src'), { recursive: true });
    const bytes = Buffer.from('export const KERNEL_STATE_SCHEMA_VERSION = 7;\n');
    await writeFile(path.join(root, 'src/config.ts'), bytes, { mode: 0o444 });
    const inventory = canonicalJsonBytes({ inventory: [{ path: 'src/config.ts', mode: '100644', size: bytes.length, sha256: sha256Bytes(bytes) }] });
    const manifestPath = path.join(directory, 'inventory.json'); await writeFile(manifestPath, inventory, { mode: 0o400 });
    await assert.rejects(buildInstalledSupervisorPackage(directory, 'complete', undefined,
      { source: { root, manifestPath, manifestSha256: sha256Bytes(inventory) }, bundledSkills: [] }), /original schema7 product/u);
    assert.deepEqual((await readdir(directory)).sort(), ['inventory.json', 'source']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
