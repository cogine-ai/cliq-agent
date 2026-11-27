import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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

// Real timer and close callbacks, with an inert native data shim. This proves
// the Node-API handle/callback lifetime only, never TLS/FD/CG/installed qualification.
test('dependency native timer, close and environment cleanup callbacks own handle scopes',
  { skip: !['darwin', 'linux'].includes(process.platform) }, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'cliq-dependency-callback-'));
    try {
      const source = await readFile(new URL('../../../native/linux/dependency-broker.h', import.meta.url), 'utf8');
      const callbacks = ['dependency_release_borrow', 'dependency_callbacks_init', 'dependency_callback_enter', 'dependency_callback_leave',
        'dependency_release_cleanup', 'dependency_maybe_finish', 'dependency_timer_closed', 'dependency_timer', 'dependency_cleanup'].map(name => {
        const declaration = new RegExp('^static (?:void|bool) ' + name + '\\([^;{]*\\) \\{', 'mu').exec(source);
        const start = declaration?.index ?? -1;
        assert(start >= 0);
        const end = source.indexOf('\nstatic ', start + 1);
        assert(end > start);
        return source.slice(start, end);
      });
      await writeFile(path.join(root, 'dependency-callbacks-under-test.h'), callbacks.join('\n'));
      const includes = spawnSync(process.execPath, [fileURLToPath(new URL('../build-state-owner-native.mjs', import.meta.url)), '--print-includes'],
        { encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 });
      assert.equal(includes.error, undefined); assert.equal(includes.signal, null); assert.equal(includes.status, 0, includes.stderr);
      const dirs = JSON.parse(includes.stdout) as string[];
      const image = path.join(root, 'callback.node');
      const built = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        ...(process.platform === 'darwin' ? ['-bundle', '-undefined', 'dynamic_lookup'] : ['-shared', '-fPIC']),
        ...dirs.flatMap(dir => ['-I', dir]), '-I', root,
        fileURLToPath(new URL('../../../native/linux/dependency-callback-scope.test.c', import.meta.url)), '-o', image],
      { encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536 });
      assert.equal(built.error, undefined); assert.equal(built.signal, null); assert.equal(built.status, 0, built.stderr);
      for (const timer of [false, true]) {
        const run = spawnSync(process.execPath, ['--expose-gc', '--input-type=module', '-e', `
          import assert from 'node:assert/strict';
          import {createHook} from 'node:async_hooks';
          import {createRequire} from 'node:module';
          import net from 'node:net';
          const addon=createRequire(import.meta.url)(process.argv[1]);
          const contexts=new Set(); let initialized=0,before=0,after=0,destroyed=0;
          createHook({
            init(id,type){if(type==='cliq dependency callbacks'){contexts.add(id);initialized++;}},
            before(id){if(contexts.has(id)){assert.equal(destroyed,0);before++;}},
            after(id){if(contexts.has(id)){assert.equal(destroyed,0);after++;}},
            destroy(id){if(contexts.has(id)){assert.equal(destroyed,0);destroyed++;}},
          }).enable();
          // An actual idle listener keeps the event loop alive, as the real
          // lifecycle's TLS server does. No request or JS polling pumps the
          // Promise continuation; this one watchdog can only fail the child.
          const listener=net.createServer(()=>{throw Error('unexpected owned test connection');});
          await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
          const start=performance.now();
          const watchdog=setTimeout(()=>{
            process.stderr.write('original native close Promise did not resume within 2000ms\\n');
            process.exit(1);
          },2000);
          const {completion,joined}=addon.exercise(process.argv[2]==='true');
          const handled=process.argv[2]==='true'
            ? assert.rejects(completion,/fixed inert callback failure/)
            : completion.then(value=>assert.equal(value.actualTimerClosed,true));
          await handled; const physical=await joined; assert.equal(physical.actualTimerClosed,true);
          global.gc(); addon.assertCallbackAlive();
          assert(physical.nativeCloseElapsedMs<2000,'the original native close callback itself exceeded 2000ms');
          assert(performance.now()-start<2000,
            'original native close continuation exceeded 2000ms; native callback='+Math.ceil(physical.nativeCloseElapsedMs)+'ms');
          clearTimeout(watchdog); await new Promise(resolve=>listener.close(resolve));
          process.once('beforeExit',()=>{
            addon.assertRetired(); assert.equal(initialized,1);
            assert(before>=1); assert.equal(after,before); assert.equal(destroyed,1);
          });
          process.stdout.write('actual native timer/close joined\\n');
        `, image, String(timer)], { encoding: 'utf8', timeout: 5000, maxBuffer: 65_536 });
        assert.equal(run.error, undefined); assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
        assert.equal(run.stdout, 'actual native timer/close joined\n');
      }
      const marker = path.join(root, 'actual-retirement');
      const teardown = spawnSync(process.execPath, ['--input-type=module', '-e', `
        import assert from 'node:assert/strict';
        import {Worker} from 'node:worker_threads';
        const worker=new Worker(new URL('data:text/javascript,'+encodeURIComponent(\`
          import {parentPort,workerData} from 'node:worker_threads';
          import {createRequire} from 'node:module';
          createRequire(workerData.image)(workerData.image).armCleanup(workerData.marker);
          parentPort.postMessage('armed');
        \`)),{workerData:{image:process.argv[1],marker:process.argv[2]}});
        await new Promise((resolve,reject)=>{worker.once('message',resolve);worker.once('error',reject);worker.once('exit',()=>reject(Error('early exit')));});
        assert.equal(await worker.terminate(),1);
        process.stdout.write('actual Worker environment retirement joined\\n');
      `, image, marker], {encoding:'utf8',timeout:5000,maxBuffer:65536});
      assert.equal(teardown.error,undefined);assert.equal(teardown.signal,null,teardown.stderr);assert.equal(teardown.status,0,teardown.stderr);
      assert.equal(teardown.stdout,'actual Worker environment retirement joined\n');
      assert.equal(await readFile(marker,'utf8'),'retire_work\nretire_joined\ntimer_closed\n');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
