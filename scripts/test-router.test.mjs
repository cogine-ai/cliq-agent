import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

test('test routing retains every source test and preserves child failures', async () => {
  const repo = fileURLToPath(new URL('../', import.meta.url)), runner = fileURLToPath(new URL('./test.mjs', import.meta.url));
  const inventory = spawnSync(process.execPath, [runner, '--list'], { cwd: repo, encoding: 'utf8' });
  assert.equal(inventory.status, 0, inventory.stderr);
  const plan = JSON.parse(inventory.stdout), files = plan.flatMap(group => group.files);
  const tracked = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', 'src'],
    { cwd: repo, encoding: 'utf8' });
  assert.equal(tracked.status, 0, tracked.stderr);
  const expected = [...new Set(tracked.stdout.split('\0').filter(filename => /\.test\.tsx?$/u.test(filename) &&
    existsSync(path.join(repo, filename))))].sort();
  assert.deepEqual([...files].sort(), expected);
  assert.equal(new Set(files).size, files.length);
  assert.deepEqual(plan.map(group => group.concurrency), [2, 1]);
  const timed = ['src/state/control-list-capacity.test.ts', 'src/state/session-continuity.test.ts'];
  assert.deepEqual(plan[1].files, timed);

  const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-test-router-'));
  try {
    await mkdir(path.join(fixture, 'src/state'), { recursive: true });
    await writeFile(path.join(fixture, 'package.json'), '{"type":"module"}\n');
    // These inert children only import modules; they never modify dependencies.
    await symlink(path.join(repo, 'node_modules'), path.join(fixture, 'node_modules'), 'junction');
    for (const filename of timed) await writeFile(path.join(fixture, filename),
      "import test from 'node:test';test('timed fixture',()=>console.log('CLIQ_TIMED_TEST_FIXTURE'));\n");
    const ordinary = path.join(fixture, 'src/example.test.ts');
    const environment = { ...process.env }; delete environment.NODE_TEST_CONTEXT;
    const run = () => spawnSync(process.execPath, [runner], { cwd: fixture, env: environment, encoding: 'utf8', timeout: 20_000 });
    await writeFile(ordinary, "import test from 'node:test';test('inert failure',()=>{throw new Error('expected fixture failure')});\n");
    const failed = run();
    assert.equal(failed.status, 1, failed.stderr);
    assert.equal(failed.stdout.split('CLIQ_TIMED_TEST_FIXTURE').length - 1, 2);
    await writeFile(ordinary, "import test from 'node:test';test('ordinary fixture',()=>{});\n");
    const passed = run();
    assert.equal(passed.status, 0, passed.stderr);
    assert.equal(passed.stdout.split('CLIQ_TIMED_TEST_FIXTURE').length - 1, 2);
    await rm(ordinary);
    const timedOnly = run();
    assert.equal(timedOnly.status, 0, timedOnly.stderr);
    assert.equal(timedOnly.stdout.split('CLIQ_TIMED_TEST_FIXTURE').length - 1, 2);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
