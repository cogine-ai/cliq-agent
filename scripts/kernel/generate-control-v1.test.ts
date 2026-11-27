import assert from 'node:assert/strict';
import { appendFile, copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { checkControlV1, controlSourceManifest, renderControlV1 } from './generate-control-v1.js';

test('a real change to a canonical public declaration fails generated-check until regeneration', async () => {
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-control-generated-'));
  try {
    const manifest = controlSourceManifest(root);
    for (const name of Object.keys(manifest.sources)) {
      await mkdir(path.dirname(path.join(directory, name)), { recursive: true });
      await copyFile(path.join(root, name), path.join(directory, name));
    }
    await mkdir(path.join(directory, 'src/control'), { recursive: true });
    await copyFile(path.join(root, 'src/control/v1.ts'), path.join(directory, 'src/control/v1.ts'));
    checkControlV1(directory);
    await appendFile(path.join(directory, 'src/kernel/authorization.ts'), '\n// ordinary source drift fixture, not authority\n');
    assert.throws(() => checkControlV1(directory), /generated_control_v1_is_stale/u);
    await writeFile(path.join(directory, 'src/control/v1.ts'), renderControlV1(directory));
    checkControlV1(directory);
    await appendFile(path.join(directory, 'src/kernel/types.ts'), "\nexport type { Fixture } from './control-extra.js';\n");
    await writeFile(path.join(directory, 'src/kernel/control-extra.ts'), 'export type Fixture = { fixtureOnly: true };\n');
    assert.throws(() => checkControlV1(directory), /generated_control_v1_is_stale/u);
    assert(Object.hasOwn(controlSourceManifest(directory).sources, 'src/kernel/control-extra.ts'),
      'a new transitive public type source must not silently escape the source digest');
    await writeFile(path.join(directory, 'src/control/v1.ts'), renderControlV1(directory));
    checkControlV1(directory);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('a custom root and changed method constants never inherit another repository method metadata', async () => {
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-control-method-source-'));
  try {
    for (const name of Object.keys(controlSourceManifest(root).sources)) {
      await mkdir(path.dirname(path.join(directory, name)), { recursive: true });
      await copyFile(path.join(root, name), path.join(directory, name));
    }
    await mkdir(path.join(directory, 'src/control'), { recursive: true });
    await writeFile(path.join(directory, 'package.json'), '{"type":"module"}\n');
    await writeFile(path.join(directory, 'src/control/v1.ts'), renderControlV1(directory));
    checkControlV1(directory);
    const { readFile } = await import('node:fs/promises');
    const wire = path.join(directory, 'src/kernel/control-wire.ts');
    const bytes = await readFile(wire, 'utf8');
    // Actual ordinary source-byte edits, not a forged authority or decoder.
    const changed = bytes.replace("['control.hello', 'session.create'", "['fixture.declared', 'control.hello', 'session.create'")
      .replace("['session.get', 'run.get'", "['fixture.connected', 'session.get', 'run.get'");
    assert.notEqual(changed, bytes);
    await writeFile(wire, changed);
    assert.throws(() => checkControlV1(directory), /generated_control_v1_is_stale/u);
    await writeFile(path.join(directory, 'src/control/v1.ts'), renderControlV1(directory));
    checkControlV1(directory);
    // Only an ordinary temporary schema module is imported. No installed
    // client, peer, grant, StateOwner or native proof can be issued here.
    const generated = await import(pathToFileURL(path.join(directory, 'src/control/v1.ts')).href);
    const actual = await import(pathToFileURL(wire).href);
    assert.equal(generated.CONTROL_V1_DECLARED_METHOD_METADATA, actual.CONTROL_METHODS_V1);
    assert.equal(generated.CONTROL_V1_CONNECTED_METHOD_METADATA, actual.INSTALLED_CONTROL_FEATURES);
    assert(generated.CONTROL_V1_DECLARED_METHOD_METADATA.includes('fixture.declared'));
    assert(generated.CONTROL_V1_CONNECTED_METHOD_METADATA.includes('fixture.connected'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
