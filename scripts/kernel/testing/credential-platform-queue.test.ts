import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { prepareSupervisorSeaCarrier } from './supervisor-sea-builder.js';

// The real compiled native component and real Node thread pool, not an
// installed credential authority, Secret Service availability, or Run proof.
if (process.platform === 'linux' && process.arch === 'x64')
  test('a queued credential platform request expires while the shared native workers remain blocked',
    { timeout: 180000 }, async () => {
      const fixture = await mkdtemp(path.join(os.tmpdir(), 'cliq-platform-queue-'));
      try {
        const carrier = await prepareSupervisorSeaCarrier(fixture, process.env.CLIQ_QUALIFICATION_CARRIER_ARCHIVE);
        const output = path.join(fixture, 'native');
        const recipe = fileURLToPath(new URL('../build-linux-credential-platform.mjs', import.meta.url));
        const compiled = spawnSync(process.execPath, [recipe, output, path.join(carrier.nodeRoot, 'include/node')],
          { encoding: 'utf8', timeout: 65000, maxBuffer: 65536 });
        assert.equal(compiled.error, undefined); assert.equal(compiled.signal, null);
        assert.equal(compiled.status, 0, compiled.stderr);
        const fifos = Array.from({ length: 4 }, (_, index) => path.join(fixture, `worker-${index}.fifo`));
        const created = spawnSync('mkfifo', ['--mode=600', ...fifos], { encoding: 'utf8', timeout: 5000 });
        assert.equal(created.error, undefined); assert.equal(created.signal, null);
        assert.equal(created.status, 0, created.stderr);
        const child = spawnSync(carrier.carrier, ['--no-warnings', '-e', `
          (async () => {
            const assert = require('node:assert/strict');
            const fs = require('node:fs');
            const { performance } = require('node:perf_hooks');
            assert.equal(process.versions.node, '24.21.0');
            assert.equal(process.env.UV_THREADPOOL_SIZE, '4');
            assert(process.getuid() > 0, 'this fixture requires an actual non-root Linux user');
            const loaded = { exports: {} };
            process.dlopen(loaded, ${JSON.stringify(path.join(output, 'linux-credential-platform.node'))});
            const native = loaded.exports;
            assert.equal(native.interfaceVersion, 2);
            assert.equal(native.currentUser().uid, process.getuid());
            const fifos = ${JSON.stringify(fifos)};
            let opened = 0, sentinelDone = false, ticks = 0, pending;
            const interval = setInterval(() => ticks++, 100);
            const readers = fifos.map(fifo => new Promise((resolve, reject) => {
              fs.open(fifo, fs.constants.O_RDONLY, (error, fd) => {
                if (error) reject(error); else { opened++; resolve(fd); }
              });
            }));
            for (const reader of readers) void reader.catch(() => {});
            const sentinel = new Promise((resolve, reject) => {
              fs.stat(fifos[0], (error, result) => {
                sentinelDone = true;
                if (error) reject(error); else resolve(result);
              });
            });
            void sentinel.catch(() => {});
            let deadline;
            const writers = [];
            try {
              await new Promise(resolve => setTimeout(resolve, 350));
              assert(ticks >= 2, 'main-loop timers must advance independently of the blocked worker pool');
              assert.equal(opened, 0, 'FIFO readers must still wait for real writers');
              assert.equal(sentinelDone, false, 'a real queued fs.stat must remain behind the four blocked FIFO opens');
              const secret = Buffer.alloc(65536, 0x7f); // Fixture bytes, never a real provider credential.
              const started = performance.now();
              pending = native.secretService({
                kind: 'create_compare',
                selector: { itemId: 'queue-fixture-item', ownerPrincipalId: 'queue-fixture-principal',
                  stateRootIdentityDigest: '1'.repeat(64), creatingOperationId: 'queue-fixture-operation',
                  credentialGrantId: 'queue-fixture-grant', secretGeneration: 1, credentialTargetDigest: '2'.repeat(64) },
                secret,
              }).then(value => ({ kind: 'resolved', value }), error => ({ kind: 'rejected', error }));
              secret.fill(0);
              const outcome = await Promise.race([pending, new Promise(resolve => {
                deadline = setTimeout(() => resolve({ kind: 'still_pending' }), 35000);
              })]);
              const elapsed = performance.now() - started;
              assert.equal(outcome.kind, 'rejected', 'the native queue must not extend the 30-second platform deadline');
              assert.equal(outcome.error.code, 'ERR_CLIQ_CREDENTIAL_PLATFORM');
              assert.equal(outcome.error.platformCode, 'platform_timeout');
              assert(elapsed >= 25000 && elapsed <= 35000, 'deadline rejection must occur near the actual 30-second budget');
              assert.equal(opened, 0, 'deadline must reject before releasing any real worker');
              assert.equal(sentinelDone, false, 'the worker queue must still be saturated at deadline rejection');
            } finally {
              clearTimeout(deadline); clearInterval(interval);
              // These fixture-only O_RDWR endpoints are real writers even if
              // a read-open has not entered the syscall yet. No bytes are sent.
              for (const fifo of fifos) writers.push(fs.openSync(fifo, fs.constants.O_RDWR | fs.constants.O_NONBLOCK));
              try {
                const settled = await Promise.allSettled(readers);
                await Promise.all(settled.filter(result => result.status === 'fulfilled').map(result =>
                  new Promise((resolve, reject) => fs.close(result.value, error => error ? reject(error) : resolve()))));
                await sentinel;
                if (pending) await pending;
                for (const result of settled) if (result.status === 'rejected') throw result.reason;
              } finally { for (const fd of writers) fs.closeSync(fd); }
            }
            // Admission of a subsequent real read-only operation proves that
            // queued cancellation joined its owners and released the busy gate.
            // This does not require a user manager to be available or ready.
            assert.equal(native.currentUser().uid, process.getuid());
            let next;
            assert.doesNotThrow(() => {
              next = native.userManager({ kind: 'inspect', unit: 'cliq-queue-fixture-not-installed.service' });
            });
            assert.equal(typeof next.then, 'function');
            await next.catch(() => {});
          })().catch(error => { console.error(error); process.exitCode = 1; });
        `], { encoding: 'utf8', timeout: 75000, killSignal: 'SIGKILL', maxBuffer: 65536,
          env: { PATH: process.env.PATH, UV_THREADPOOL_SIZE: '4' }, cwd: fixture });
        // spawnSync bounds and reaps only the fixture process. On the expected
        // RED it has already released and joined all of its blocked work.
        assert.equal(child.error, undefined); assert.equal(child.signal, null);
        assert.equal(child.status, 0, child.stderr);
      } finally { await rm(fixture, { recursive: true, force: true }); }
    });
