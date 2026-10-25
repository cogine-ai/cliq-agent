// Actual Linux process observations only. No installed, Run or death proof.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { readFileSync, readlinkSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../systemd-user-probe.mjs', import.meta.url), 'utf8');
function actualFunction(name, next, context) {
  const start = source.indexOf(`function ${name}(`), end = source.indexOf(`\nfunction ${next}(`, start);
  assert(start >= 0 && end > start && source.indexOf(`function ${name}(`, start + 1) === -1);
  // Execute the exact test-owned probe functions against real /proc. Importing
  // its privileged main or injecting synthetic filesystem facts is unnecessary.
  return vm.runInNewContext(`${source.slice(start, end)}\n${name}`, context);
}
function actualStat(pid) {
  const text = readFileSync(`/proc/${pid}/stat`, 'utf8');
  const fields = text.slice(text.lastIndexOf(') ') + 2).trim().split(/\s+/u);
  assert(fields.length >= 20);
  return { pid, state: fields[0], startTimeTicks: fields[19] };
}

for (const mode of ['dumpable', 'private']) {
  test(`the real ${mode} original lifetime remains present until its parent reaps it`,
    { skip: process.platform !== 'linux' ? 'requires real Linux /proc and WNOWAIT/reap; component only' : false, timeout: 10_000 }, async t => {
      const bootId = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
      const processFact = actualFunction('processFact', 'cgroupPath', { assert, readFileSync, readlinkSync, statSync, bootId });
      const sameLifetime = actualFunction('sameLifetime', 'baseline', {});
      // The live-denial negative case requires the ordinary unprivileged
      // observer. Do not silently pass it under ptrace-capable root.
      const effective = /^CapEff:\s+([a-f0-9]+)$/mu.exec(readFileSync('/proc/self/status', 'utf8'));
      assert(effective && (BigInt(`0x${effective[1]}`) & (1n << 19n)) === 0n, 'fixture must not have CAP_SYS_PTRACE');
      const directory = await mkdtemp(path.join(os.tmpdir(), 'cliq-systemd-process-'));
      let child, lines, exited, closed, joined = false;
      try {
        const executable = process.env.CLIQ_SYSTEMD_PROCESS_FIXTURE ?? path.join(directory, 'lifetime');
        if (!process.env.CLIQ_SYSTEMD_PROCESS_FIXTURE) {
          const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            new URL('./systemd-process-lifetime-probe.c', import.meta.url).pathname, '-o', executable],
          { encoding: 'utf8', timeout: 5000, maxBuffer: 8192 });
          assert.equal(compiled.error, undefined); assert.equal(compiled.signal, null); assert.equal(compiled.status, 0, compiled.stderr);
        }
        child = spawn(executable, [mode], { stdio: ['pipe', 'pipe', 'pipe'] });
        exited = once(child, 'exit');
        closed = once(child, 'close');
        let diagnostic = ''; child.stderr.on('data', chunk => { diagnostic += chunk; assert(diagnostic.length <= 1024); });
        child.stdin.on('error', () => {}); // The real exit/status below still determines success.
        const output = createInterface({ input: child.stdout }); lines = output[Symbol.asyncIterator]();
        const first = await lines.next(), live = /^LIVE ([1-9][0-9]*)$/u.exec(first.value);
        assert(!first.done && live, diagnostic);
        const pid = Number(live[1]), original = actualStat(pid); let liveNamespaceError;
        assert.notEqual(original.state, 'Z');
        if (mode === 'private') {
          assert.throws(() => readlinkSync(`/proc/${pid}/ns/cgroup`), { code: 'EACCES' });
          assert.throws(() => processFact(pid), error => {
            assert.equal(error.code, 'EACCES'); liveNamespaceError = error; return true;
          });
          assert.equal(actualStat(pid).startTimeTicks, original.startTimeTicks);
          assert.notEqual(actualStat(pid).state, 'Z', 'live EACCES is never an exited fact');
        } else {
          const fact = processFact(pid);
          assert.equal(fact.present, true); assert.equal(fact.startTimeTicks, original.startTimeTicks);
          assert.match(fact.cgroupNamespace, /^cgroup:\[[0-9]+\]$/u);
        }
        child.stdin.write('e'); assert.deepEqual(await lines.next(), { value: 'ZOMBIE', done: false });
        const before = actualStat(pid), beforeUid = statSync(`/proc/${pid}`).uid;
        assert.equal(before.state, 'Z'); assert.equal(before.startTimeTicks, original.startTimeTicks);
        assert.throws(() => readlinkSync(`/proc/${pid}/ns/cgroup`), { code: mode === 'private' ? 'EACCES' : 'ENOENT' });
        const fact = processFact(pid), after = actualStat(pid);
        assert.equal(after.state, 'Z'); assert.equal(after.startTimeTicks, before.startTimeTicks);
        assert.equal(fact.present, true); assert.equal(fact.state, 'Z'); assert.equal(fact.pid, pid);
        assert.equal(fact.startTimeTicks, original.startTimeTicks); assert.equal(fact.bootId, bootId);
        assert.equal(fact.uid, beforeUid); assert.equal(fact.uid, statSync(`/proc/${pid}`).uid);
        assert.equal(fact.cgroupNamespace, null);
        assert.equal(sameLifetime(fact, { ...original, bootId }), true, 'an unreaped zombie still blocks original retirement');
        if (liveNamespaceError) {
          const observed = JSON.parse(liveNamespaceError.message.split('; procNamespaceObservation=')[1]);
          assert.deepEqual(Object.keys(observed).sort(), ['first', 'originalStartTimeTicks', 'pid', 'second']);
          assert.equal(observed.pid, pid); assert.equal(observed.originalStartTimeTicks, original.startTimeTicks);
          for (const sample of [observed.first, observed.second]) {
            assert.deepEqual(Object.keys(sample).sort(), ['startTimeTicks', 'state', 'uid']);
            assert.notEqual(sample.state, 'Z'); assert.equal(sample.startTimeTicks, original.startTimeTicks);
            assert.equal(typeof sample.uid, 'number');
          }
        }
        child.stdin.end('r'); assert.deepEqual(await lines.next(), { value: 'REAPED', done: false });
        assert.deepEqual(await exited, [0, null], diagnostic); assert.deepEqual(await closed, [0, null]); joined = true;
        assert.equal(diagnostic, '');
        assert.equal(processFact(pid).present, false); assert.equal(sameLifetime(processFact(pid), { ...original, bootId }), false);
        t.diagnostic(JSON.stringify({ componentOnly: true, installedQualified: false, mode,
          originalPidAndStartPreserved: true, zombieStillPresent: true, parentActuallyReaped: true, driverJoined: true }));
      } finally {
        // EOF makes the owning parent kill/reap its own child on any failure.
        // Await that actual driver before deleting its test-owned executable.
        if (child && !joined) { child.stdin.end(); await exited; await closed; }
        await lines?.return(); await rm(directory, { recursive: true });
      }
    });
}
