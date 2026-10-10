import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, rm, symlink } from 'node:fs/promises';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

const retirement = 'ERR_CLIQ_RESOURCE_RETIREMENT';

async function faultFixture(t: TestContext) {
  const container = await mkdtemp(path.join(process.cwd(), '.cliq-current-process-fault-'));
  t.after(() => rm(container, { recursive: true, force: true }));
  const binary = path.join(container, 'fault.node');
  const includes = JSON.parse(execFileSync(process.execPath, [
    fileURLToPath(new URL('../../scripts/kernel/build-state-owner-native.mjs', import.meta.url)), '--print-includes'
  ], { encoding: 'utf8' })) as string[];
  const compiled = spawnSync('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
    ...(process.platform === 'linux' ? ['-shared', '-fPIC'] : ['-bundle', '-undefined', 'dynamic_lookup']),
    ...includes.flatMap(include => ['-I', include]),
    fileURLToPath(new URL('./testing/current-process-fault-native.c', import.meta.url)), '-o', binary], { encoding: 'utf8' });
  assert.equal(compiled.status, 0, compiled.stderr);
  return { binary, container };
}

type Observation = {
  faulted: number; retiredFdReused: boolean; sentinelIntact: boolean;
  granted?: boolean; code?: string; firstCode?: string; nextCode?: string; assertCode?: string;
  nextCaptureGranted: boolean; nextCaptureCode?: string;
};

function childAt(binary: string, container: string, body: string, args: string[] = [], executable = process.execPath) {
  // Each disposable process retires its own uncertain descriptors on death.
  // The native public binding is unchanged except for the syscall fault setter.
  const result = spawnSync(executable, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { Module } from 'node:module';
    import { openSync, fstatSync, readSync, renameSync, writeFileSync } from 'node:fs';
    import { constants } from 'node:os';
    const [binary, sentinel, ...args] = process.argv.slice(1);
    const module = new Module(binary); process.dlopen(module, binary);
    const binding = module.exports;
    const bytes = Buffer.from('unrelated descriptor must remain open');
    writeFileSync(sentinel, bytes, { mode: 0o600 });
    let faulted = 0, retiredFd = -1, reusedFd = -1;
    function setFault(point, ordinal = 1) {
      binding.setFault(point, ordinal, fd => {
        faulted++; retiredFd = fd;
        // Reuse the actual just-closed FD before the native caller receives EIO.
        for (let count = 0; count < 256; count++) {
          const candidate = openSync(sentinel, 'r');
          assert.ok(candidate <= fd, 'the target descriptor was unexpectedly occupied');
          if (candidate === fd) { reusedFd = candidate; break; }
        }
        assert.equal(reusedFd, fd, 'failed to occupy the actual retired descriptor');
        return constants.errno.EIO;
      });
    }
    function observed(extra) {
      let nextCapture, nextCaptureCode;
      try { nextCapture = binding.captureCurrentProcess(); } catch (error) { nextCaptureCode = error.code; }
      const nextCaptureGranted = nextCapture !== undefined;
      try { nextCapture?.close(); } catch { /* Do not mistake close failure for capture refusal. */ }
      let sentinelIntact = false;
      try {
        const read = Buffer.alloc(bytes.length);
        sentinelIntact = fstatSync(reusedFd).isFile() &&
          readSync(reusedFd, read, 0, read.length, 0) === bytes.length && read.equals(bytes);
      } catch {}
      console.log(JSON.stringify({ faulted, retiredFdReused: retiredFd === reusedFd, sentinelIntact, nextCaptureGranted, nextCaptureCode, ...extra }));
      process.exit(0);
    }
    const baseline = binding.captureCurrentProcess();
    assert.equal(baseline.pid, process.pid);
    assert.equal(baseline.uid, process.geteuid());
    assert.equal(fstatSync(baseline.imageFd).size, baseline.imageByteCount);
    baseline.assertHeld(); baseline.close(); baseline.close();
    ${body}
  `, binary, path.join(container, 'sentinel'), ...args], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim()) as Observation;
}

function assertRetired(observed: Observation) {
  assert.equal(observed.faulted, 1, 'the real close must complete and report the injected EIO');
  assert.equal(observed.retiredFdReused, true, 'the sentinel must reuse the just-closed descriptor');
  assert.equal(observed.sentinelIntact, true, 'cleanup must not close or replace an unrelated reused descriptor');
  assert.equal(observed.nextCaptureGranted, false, 'a new capture must refuse before returning another handle');
  assert.equal(observed.nextCaptureCode, retirement, 'a new capture cannot erase unjoined process-image resources');
}

test('current process capture cannot grant an observation after temporary descriptor retirement reports EIO', async t => {
  const { binary, container } = await faultFixture(t);
  const points = ['after_directory_close', 'after_image_close'];
  // Linux also retires the procfs start-token stream and credentials stream.
  const cases = points.map<[string, number]>(point => [point, 1]);
  if (process.platform === 'linux') cases.push(['after_fclose', 1], ['after_fclose', 2]);
  for (const [point, ordinal] of cases) await t.test(`${point} #${ordinal}`, () => {
    const observed = childAt(binary, container, `
      setFault(args[0], Number(args[1]));
      let observation, code;
      try { observation = binding.captureCurrentProcess(); } catch (error) { code = error.code; }
      const granted = observation !== undefined;
      observation?.close();
      observed({ granted, code });
    `, [point, String(ordinal)]);
    assertRetired(observed);
    assert.equal(observed.granted, false);
    assert.equal(observed.code, retirement);
  });
});

test('current process self assertion retains temporary retirement failure instead of granting or reporting image mismatch', async t => {
  const { binary, container } = await faultFixture(t);
  const cases: [string, number][] = [['after_directory_close', 1], ['after_image_close', 1]];
  if (process.platform === 'linux') cases.push(['after_fclose', 1], ['after_fclose', 2], ['after_fclose', 3]);
  for (const [point, ordinal] of cases) await t.test(`${point} #${ordinal}`, () => {
    const observed = childAt(binary, container, `
      const observation = binding.captureCurrentProcess();
      setFault(args[0], Number(args[1]));
      let granted = false, code, assertCode, firstCode, nextCode;
      try { observation.assertHeld(); granted = true; } catch (error) { code = error.code; }
      try { observation.assertHeld(); } catch (error) { assertCode = error.code; }
      try { observation.close(); } catch (error) { firstCode = error.code; }
      try { observation.close(); } catch (error) { nextCode = error.code; }
      observed({ granted, code, assertCode, firstCode, nextCode });
    `, [point, String(ordinal)]);
    assertRetired(observed);
    assert.equal(observed.granted, false);
    assert.equal(observed.code, retirement);
    assert.equal(observed.assertCode, retirement);
    assert.equal(observed.firstCode, retirement);
    assert.equal(observed.nextCode, retirement);
  });
});

test('explicit process image close is consumed before EIO and repeated close cannot retire a reused FD', async t => {
  const { binary, container } = await faultFixture(t);
  const observed = childAt(binary, container, `
    const observation = binding.captureCurrentProcess();
    setFault('after_image_close');
    let firstCode, nextCode, assertCode;
    try { observation.close(); } catch (error) { firstCode = error.code; }
    try { observation.close(); } catch (error) { nextCode = error.code; }
    try { observation.assertHeld(); } catch (error) { assertCode = error.code; }
    assert.equal(retiredFd, observation.imageFd);
    observed({ firstCode, nextCode, assertCode });
  `);
  assertRetired(observed);
  assert.equal(observed.firstCode, retirement);
  assert.equal(observed.nextCode, retirement);
  assert.equal(observed.assertCode, retirement);
});

test('capture image mismatch cannot hide uncertain cleanup or retry closing its reused descriptor', async t => {
  const { binary, container } = await faultFixture(t);
  const executable = path.join(container, 'bin', 'node');
  await mkdir(path.dirname(executable), { mode: 0o700 });
  await symlink(path.resolve(process.execPath, '../../lib'), path.join(container, 'lib'), 'dir');
  await copyFile(process.execPath, executable);
  await chmod(executable, 0o500);
  const observed = childAt(binary, container, `
    // Mutate this disposable image only after native capture opened it and
    // checked its named counterpart. Revalidation must refuse that stale cut;
    // its owned original image still needs closing on the failure path.
    binding.setFault('after_image_close', 1, () => {
      renameSync(process.execPath, process.execPath + '.running');
      writeFileSync(process.execPath, 'not the running executable image\\n', { mode: 0o500 });
      setFault('after_image_close');
      return 0;
    });
    let observation, code;
    try { observation = binding.captureCurrentProcess(); } catch (error) { code = error.code; }
    const granted = observation !== undefined;
    try { observation?.close(); } catch { /* Capture must refuse before returning a handle. */ }
    observed({ granted, code });
  `, [], executable);
  assertRetired(observed);
  assert.equal(observed.granted, false);
  assert.equal(observed.code, retirement);
});
