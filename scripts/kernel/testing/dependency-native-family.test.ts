import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

/** Compile the actual production C family, without downloading a launcher,
 * changing a host or claiming namespace/installed execution qualification. */
test('dependency production worker/controller/extractor compile with their original strict Linux flags',
  { skip: process.platform !== 'linux' || process.arch !== 'x64' }, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-family-'));
    const repository = fileURLToPath(new URL('../../../', import.meta.url));
    const headers = path.resolve(path.dirname(realpathSync(process.execPath)), '../include/node');
    const run = (command: string, args: string[]) => {
      const result = spawnSync(command, args, { encoding: 'utf8', timeout: 60_000, maxBuffer: 65_536 });
      assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr);
      return result.stdout;
    };
    try {
      const cc = process.env.CLIQ_WORKER_CC ?? 'musl-gcc';
      const triple = run(cc, ['-dumpmachine']).trim(); assert.match(triple, /^[a-z0-9_-]+$/u);
      const kernel = ['-idirafter', '/usr/include', '-idirafter', path.join('/usr/include', triple)];
      for (const name of ['cliq-linux-worker-controller', 'cliq-linux-worker', 'cliq-linux-edit'])
        run(cc, ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-fno-ident', ...kernel,
          `-ffile-prefix-map=${repository}=.`, '-Wl,--build-id=none', '-s', path.join(repository, 'native/linux', `${name}.c`), '-o', path.join(root, name)]);
      const addon = path.join(root, 'worker.node'), nativeCC = process.env.CLIQ_WORKER_ADDON_CC ?? 'cc';
      run(nativeCC, ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', '-I', headers,
        path.join(repository, 'native/linux/worker-native.c'), '-o', addon]);
      const ext2 = run('pkg-config', ['--cflags', '--libs', 'ext2fs']); assert(ext2.length <= 8192);
      run(nativeCC, ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', '-pthread', '-I', headers,
        path.join(repository, 'native/linux/guest-extractor.c'), '-o', path.join(root, 'extractor.node'), ...ext2.trim().split(/\s+/u), '-lcom_err']);
      const binding = createRequire(import.meta.url)(addon) as { dependencyInterfaceVersion: number; builtinToolInterfaceVersion: number };
      assert.equal(binding.dependencyInterfaceVersion, 1); assert.equal(binding.builtinToolInterfaceVersion, 2);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
