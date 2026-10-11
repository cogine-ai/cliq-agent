// One disposable Linux qualification, not an installed signed Supervisor I1,
// a production launcher, or durable worker-birth/death evidence. Invoke this
// fixed file through sudo from the runner UID, with the existing CLIQ_I1_*
// resources. Private inherited IPC selects only these three fixed roles.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { chmod, copyFile, lstat, mkdtemp, open, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

const role = process.argv[2] ?? 'job';
assert.ok(['job', 'helper', 'child'].includes(role) && process.argv.length <= 3, 'fixed qualification role required');
assert.equal(process.platform, 'linux', 'actual Linux is required; never skipped');
const DIRECTORY = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
const NAMESPACES = ['user', 'pid', 'mnt', 'cgroup', 'ipc', 'uts', 'net'];
const LIMIT = 32 * 1024;
const descriptor = handle => `/proc/self/fd/${handle.fd}`;
const identity = stat => Object.fromEntries(['dev', 'ino', 'uid', 'gid', 'mode'].map(key => [key, String(stat[key])]));
const errorText = error => String(error?.stack ?? error).slice(0, 4096);

async function bounded(operation, milliseconds = 30_000) {
  let timer;
  try {
    return await Promise.race([operation, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('controller birth qualification timed out')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

function mailbox(endpoint, cancel = () => {}, observe = () => {}) {
  const queue = [];
  let waiting, failure;
  const fail = error => {
    failure ??= error; cancel(error);
    if (waiting) { waiting.reject(failure); waiting = undefined; }
  };
  endpoint.on('message', value => {
    try {
      assert.ok(value && typeof value === 'object' && typeof value.type === 'string');
      assert.ok(Buffer.byteLength(JSON.stringify(value)) <= LIMIT, 'bounded private IPC required');
      observe(value);
      if (value.type === 'abort') { fail(new Error('job cancelled the birth qualification')); return; }
      if (failure) return;
      if (waiting) { waiting.resolve(value); waiting = undefined; }
      else { assert.ok(queue.length < 8, 'unexpected IPC backlog'); queue.push(value); }
    } catch (error) { fail(error); }
  });
  endpoint.on('error', fail);
  endpoint.on('disconnect', () => fail(new Error('private qualification IPC disconnected')));
  return {
    get failure() { return failure; },
    async next(type) {
      // A final message may precede the peer's real exit/disconnect in the
      // same turn. Consume it, then independently require the actual join.
      if (!queue.length && failure) throw failure;
      const value = queue.length ? queue.shift() : await bounded(new Promise((resolve, reject) => { waiting = { resolve, reject }; }));
      assert.equal(value.type, type, `expected ${type}, not ${value.type}`); return value;
    },
    send(value) {
      assert.ok(endpoint.connected && Buffer.byteLength(JSON.stringify(value)) <= LIMIT);
      return bounded(new Promise((resolve, reject) => endpoint.send(value, error => error ? reject(error) : resolve())));
    }
  };
}

async function readBounded(filename, limit = LIMIT) {
  const handle = await open(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const bytes = Buffer.alloc(limit + 1); let used = 0;
    for (;;) {
      const read = await handle.read(bytes, used, bytes.length - used, null);
      used += read.bytesRead;
      assert.ok(used <= limit, `unbounded kernel observation: ${filename}`);
      if (read.bytesRead === 0) return bytes.subarray(0, used).toString('utf8');
    }
  } finally { await handle.close(); }
}

async function processFact(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0 && pid <= 0x7fffffff);
  const stat = await readBounded(`/proc/${pid}/stat`), end = stat.lastIndexOf(')');
  assert.ok(end > 0);
  const fields = stat.slice(end + 2).trim().split(/\s+/u);
  assert.match(fields[19], /^[0-9]{1,32}$/u);
  const status = await readBounded(`/proc/${pid}/status`);
  const number = name => {
    const match = status.match(new RegExp(`^${name}:\\s+([0-9]+)$`, 'mu'));
    assert.ok(match, `missing ${name}`); return Number(match[1]);
  };
  const ids = name => {
    const match = status.match(new RegExp(`^${name}:\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)$`, 'mu'));
    assert.ok(match, `missing ${name}`); return match.slice(1).map(Number);
  };
  const membership = (await readBounded(`/proc/${pid}/cgroup`)).trim();
  assert.match(membership, /^0::\/[^\n]*$/u, 'single unified cgroup hierarchy required');
  const relative = membership.slice(3); assert.equal(path.posix.normalize(relative), relative);
  return { pid, token: `linux-proc-start-ticks:${fields[19]}`, state: fields[0], ppid: number('PPid'), tracerPid: number('TracerPid'),
    uid: ids('Uid'), gid: ids('Gid'), cgroup: `/sys/fs/cgroup${relative === '/' ? '' : relative}` };
}

async function namespaces(pid) {
  const result = {};
  for (const name of NAMESPACES) {
    const handle = await open(`/proc/${pid}/ns/${name}`, fs.constants.O_RDONLY);
    try { const stat = await handle.stat({ bigint: true }); result[name] = { dev: String(stat.dev), ino: String(stat.ino) }; }
    finally { await handle.close(); }
  }
  return result;
}

async function imageFact(filename) {
  // /proc/PID/exe is an intentional kernel magic link, not a caller path.
  const handle = await open(filename, fs.constants.O_RDONLY);
  try {
    const before = await handle.stat({ bigint: true });
    assert.ok(before.isFile() && before.size > 0n && before.size <= 512n * 1024n ** 2n, 'bounded actual executable required');
    const digest = createHash('sha256'), buffer = Buffer.alloc(64 * 1024); let position = 0;
    while (position < Number(before.size)) {
      const read = await handle.read(buffer, 0, Math.min(buffer.length, Number(before.size) - position), position);
      assert.ok(read.bytesRead > 0, 'actual executable truncated');
      digest.update(buffer.subarray(0, read.bytesRead)); position += read.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    for (const key of ['dev', 'ino', 'uid', 'gid', 'mode', 'size', 'mtimeNs', 'ctimeNs']) assert.equal(after[key], before[key]);
    return { ...identity(before), size: String(before.size), digest: digest.digest('hex') };
  } finally { await handle.close(); }
}

async function holdDirectory(filename) {
  assert.ok(path.isAbsolute(filename) && path.normalize(filename) === filename);
  let handle = await open('/', DIRECTORY);
  try {
    for (const component of filename.split('/').slice(1)) {
      assert.ok(component && component !== '.' && component !== '..');
      const next = await open(`${descriptor(handle)}/${component}`, DIRECTORY);
      try { await handle.close(); } catch (error) { await next.close(); throw error; }
      handle = next;
    }
    return handle;
  } catch (error) { await handle.close(); throw error; }
}

async function directoryFact(handle, filename, expected) {
  const held = await handle.stat({ bigint: true }), named = await lstat(filename, { bigint: true });
  assert.ok(held.isDirectory() && named.isDirectory() && !named.isSymbolicLink());
  assert.deepEqual(identity(named), identity(held));
  if (expected) assert.deepEqual(identity(held), expected);
  assert.equal(fs.statfsSync(descriptor(handle)).type, 0x63677270, 'actual held cgroup2 required');
  return identity(held);
}

async function pids(handle) {
  const value = (await readBounded(`${descriptor(handle)}/cgroup.procs`)).trim();
  if (!value) return [];
  assert.match(value, /^[0-9]+(?:\s+[0-9]+)*$/u);
  return value.split(/\s+/u).map(Number).sort((a, b) => a - b);
}

async function domain(handle, leaf = false) {
  assert.equal((await readBounded(`${descriptor(handle)}/cgroup.type`)).trim(), 'domain');
  if (leaf) assert.equal((await readBounded(`${descriptor(handle)}/cgroup.subtree_control`)).trim(), '');
}

async function populated(handle, expected) {
  const value = await readBounded(`${descriptor(handle)}/cgroup.events`);
  assert.match(value, new RegExp(`(?:^|\\n)populated ${expected ? 1 : 0}\\n`, 'u'));
}

async function absent(filename) { await assert.rejects(lstat(filename), { code: 'ENOENT' }); }
function sameProcess(actual, expected, tracer = 0) {
  assert.equal(actual.pid, expected.pid); assert.equal(actual.token, expected.token);
  assert.equal(actual.ppid, expected.ppid);
  assert.equal(actual.cgroup, expected.cgroup); assert.deepEqual(actual.uid, expected.uid); assert.deepEqual(actual.gid, expected.gid);
  assert.equal(actual.tracerPid, tracer);
}

async function helper() {
  assert.equal(process.getuid(), 0); assert.equal(process.geteuid(), 0); assert.ok(process.send);
  let cancelled, tracer, released = true, primary, observation;
  const ipc = mailbox(process, error => { cancelled ??= error; });
  const held = [];
  try {
    const input = await ipc.next('arm'), expected = input.expected;
    const self = await processFact(process.pid);
    assert.ok(self.cgroup !== expected.rootPath && !self.cgroup.startsWith(`${expected.rootPath}/`), 'helper must remain outside disposable cgroup');
    const stage = path.dirname(fileURLToPath(import.meta.url));
    for (const filename of [fileURLToPath(import.meta.url), path.join(stage, 'linux-fork-tracer.node')]) {
      const stat = await lstat(filename); assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0 && stat.nlink === 1 && (stat.mode & 0o222) === 0);
    }
    tracer = createRequire(import.meta.url)(path.join(stage, 'linux-fork-tracer.node'));
    for (const method of ['arm', 'pollFork', 'release']) assert.equal(typeof tracer[method], 'function');
    const root = await holdDirectory(expected.rootPath); held.push(root);
    await directoryFact(root, expected.rootPath, expected.root); await domain(root);
    sameProcess(await processFact(expected.source.pid), expected.source);
    assert.deepEqual((await namespaces(process.pid)).user, expected.namespaces.user, 'tracer must share the target user namespace');
    assert.deepEqual(await namespaces(expected.source.pid), expected.namespaces);
    assert.deepEqual(await imageFact(`/proc/${expected.source.pid}/exe`), expected.nodeImage);
    tracer.arm(expected.source.pid); released = false;
    sameProcess(await processFact(expected.source.pid), expected.source, process.pid);
    await ipc.send({ type: 'armed' });
    const deadline = performance.now() + 30_000;
    let pid;
    for (;;) {
      if (cancelled) throw cancelled;
      pid = tracer.pollFork();
      if (pid !== null) break;
      assert.ok(performance.now() < deadline, 'first controller fork not captured; never retried or skipped');
      await delay(5);
    }
    const source = await processFact(expected.source.pid), child = await processFact(pid);
    sameProcess(source, expected.source, process.pid);
    assert.equal(source.state, 't'); assert.equal(child.state, 't'); assert.equal(child.tracerPid, process.pid);
    assert.equal(child.ppid, source.pid); assert.deepEqual(child.uid, source.uid); assert.deepEqual(child.gid, source.gid);
    const parentPath = path.join(expected.rootPath, 'controllers');
    assert.equal(path.dirname(child.cgroup), parentPath);
    assert.match(path.basename(child.cgroup), /^controller-[a-f0-9]{32}$/u);
    const parent = await holdDirectory(parentPath); held.push(parent);
    const leaf = await holdDirectory(child.cgroup); held.push(leaf);
    const rootFact = await directoryFact(root, expected.rootPath, expected.root);
    const parentFact = await directoryFact(parent, parentPath), leafFact = await directoryFact(leaf, child.cgroup);
    for (const value of [rootFact, parentFact, leafFact]) {
      assert.equal(value.uid, String(source.uid[0])); assert.equal(value.gid, String(source.gid[0]));
      assert.equal(BigInt(value.mode) & 0o7777n, 0o700n);
    }
    await domain(root); await domain(parent); await domain(leaf, true);
    assert.deepEqual(await pids(root), []); assert.deepEqual(await pids(parent), []); assert.deepEqual(await pids(leaf), [pid]);
    await populated(leaf, true);
    const childNamespaces = await namespaces(pid);
    assert.deepEqual(childNamespaces, expected.namespaces); assert.deepEqual(await namespaces(source.pid), expected.namespaces);
    const preExec = await imageFact(`/proc/${pid}/exe`); assert.deepEqual(preExec, expected.nodeImage);
    sameProcess(await processFact(source.pid), expected.source, process.pid);
    const last = await processFact(pid); sameProcess(last, child, process.pid); assert.equal(last.state, 't');
    observation = { source, child, root: rootFact, parent: parentFact, leaf: leafFact, namespaces: childNamespaces, preExec };
  } catch (error) { primary = error; }
  finally {
    if (!released && tracer) {
      try {
        const deadline = performance.now() + 10_000;
        while (!tracer.release()) { assert.ok(performance.now() < deadline, 'explicit tracer release timed out'); await delay(5); }
        released = true;
        if (observation) {
          const source = await processFact(observation.source.pid), child = await processFact(observation.child.pid);
          sameProcess(source, observation.source); sameProcess(child, observation.child);
        }
      } catch (error) { primary = new AggregateError([...(primary ? [primary] : []), error], 'attachment closure remains uncertain'); }
    }
    for (const handle of held.reverse()) {
      try { await handle.close(); } catch (error) { primary = new AggregateError([...(primary ? [primary] : []), error], 'held descriptor retirement failed'); }
    }
    await ipc.send({ type: 'finished', released, ...(primary ? { error: errorText(primary) } : { observation }) });
    process.exitCode = primary ? 1 : 0; process.disconnect();
  }
}

async function child() {
  assert.notEqual(process.getuid(), 0); assert.equal(process.getuid(), process.geteuid()); assert.ok(process.send);
  const abort = new AbortController(), ipc = mailbox(process, error => abort.abort(error));
  let fixture, launcher, controller, primary;
  try {
    const input = await ipc.next('prepare');
    const { createLinuxWorkerCampaignFixture } = await import(pathToFileURL(path.join(input.repository, 'src/sandbox/testing/worker-campaign-fixture.ts')).href);
    const { openLinuxWorkerLauncher } = await import(pathToFileURL(path.join(input.repository, 'src/sandbox/linux-worker.ts')).href);
    fixture = await createLinuxWorkerCampaignFixture({ ...input.options, label: 'first-controller-anchor-birth' });
    launcher = await openLinuxWorkerLauncher({ ...input.options, runtimeAuthority: fixture.runtimeAuthority });
    const entry = fixture.runtimeAuthority.bundle.entries.find(value => value.entryId === 'linux_worker_controller');
    assert.ok(entry && entry.executable && entry.role === 'platform_helper');
    await ipc.send({ type: 'ready', controllerDigest: entry.digest, controllerBytes: entry.byteCount });
    await ipc.next('start');
    // All imports, fixture setup and unrelated child actions preceded arm.
    // The next native main-thread fork is synchronous, before the first await.
    controller = await bounded(launcher.startController({ signal: abort.signal }));
    const { observation } = await ipc.next('result');
    assert.equal(controller.pid, observation.child.pid); assert.equal(controller.processStartToken, observation.child.token);
    const actual = await processFact(controller.pid); sameProcess(actual, observation.child);
    assert.equal(actual.ppid, process.pid); assert.notEqual(actual.state, 't');
    assert.deepEqual(await namespaces(controller.pid), observation.namespaces);
    const executable = await imageFact(`/proc/${controller.pid}/exe`);
    assert.equal(executable.digest, entry.digest); assert.equal(Number(executable.size), entry.byteCount);
    sameProcess(await processFact(controller.pid), observation.child);
    const held = [];
    try {
      const root = await holdDirectory(input.options.cgroupParent); held.push(root);
      const parent = await holdDirectory(path.dirname(actual.cgroup)); held.push(parent);
      const leaf = await holdDirectory(actual.cgroup); held.push(leaf);
      await directoryFact(root, input.options.cgroupParent, observation.root);
      await directoryFact(parent, path.dirname(actual.cgroup), observation.parent); await directoryFact(leaf, actual.cgroup, observation.leaf);
      assert.deepEqual(await pids(leaf), [controller.pid]);
      await bounded(controller.close(), 15_000); controller = undefined;
      await absent(`/proc/${actual.pid}`); await absent(actual.cgroup);
      assert.deepEqual(identity(await leaf.stat({ bigint: true })), observation.leaf);
      await directoryFact(root, input.options.cgroupParent, observation.root);
      await directoryFact(parent, path.dirname(actual.cgroup), observation.parent);
    } finally {
      const failures = [];
      for (const handle of held.reverse()) { try { await handle.close(); } catch (error) { failures.push(error); } }
      if (failures.length) throw new AggregateError(failures, 'controller observation descriptors did not retire');
    }
    await launcher.close(); launcher = undefined;
    await fixture.dispose(); fixture = undefined;
    await ipc.send({ type: 'qualified', controllerPid: actual.pid, controllerStartToken: actual.token, executableDigest: executable.digest });
  } catch (error) { primary = error; }
  finally {
    const failures = [];
    for (const resource of [controller, launcher]) { try { await bounded(resource?.close(), 15_000); } catch (error) { failures.push(error); } }
    if (fixture) {
      try { await bounded(fixture.store.close()); } catch (error) { failures.push(error); }
      // Failed/uncertain qualification is retained for controlled job teardown.
      console.error(`retaining first-controller-birth fixture: ${fixture.stateRoot}`);
    }
    if (primary || failures.length) throw new AggregateError([...(primary ? [primary] : []), ...failures], 'non-root controller qualification failed');
    process.disconnect();
  }
}

function ownChild(child) {
  let status;
  const joined = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { status = { code, signal }; resolve(status); });
  });
  // Cleanup can join after a primary failure without an unhandled rejection.
  joined.catch(() => {});
  return { child, joined, get status() { return status; }, token: undefined };
}

async function job() {
  assert.equal(process.getuid(), 0); assert.equal(process.geteuid(), 0);
  const uid = Number(process.env.SUDO_UID), gid = Number(process.env.SUDO_GID);
  assert.ok(Number.isSafeInteger(uid) && uid > 0 && Number.isSafeInteger(gid) && gid >= 0, 'invoke sudo from the runner UID');
  const resource = name => {
    const value = process.env[name]; assert.ok(value && path.isAbsolute(value) && path.normalize(value) === value, `missing ${name}`); return value;
  };
  const options = { installationRoot: resource('CLIQ_I1_INSTALLATION'), cgroupParent: resource('CLIQ_I1_CGROUP_PARENT'), stateVolume: resource('CLIQ_I1_STATE_VOLUME') };
  assert.ok(options.cgroupParent.startsWith('/sys/fs/cgroup/'));
  const source = await processFact(process.pid);
  assert.ok(source.cgroup !== options.cgroupParent && !source.cgroup.startsWith(`${options.cgroupParent}/`));
  const repository = fileURLToPath(new URL('../..', import.meta.url));
  let root, rootFact, stage, stageFact, launch, childIpc, trace, traceIpc, traceReceipt, released = true, primary, qualification;
  try {
    root = await holdDirectory(options.cgroupParent); rootFact = await directoryFact(root, options.cgroupParent);
    assert.equal(rootFact.uid, String(uid)); assert.equal(rootFact.gid, String(gid)); assert.equal(BigInt(rootFact.mode) & 0o7777n, 0o700n);
    await domain(root); assert.deepEqual(await pids(root), []); await populated(root, false);
    stage = await mkdtemp('/var/tmp/cliq-first-controller-birth-'); stageFact = identity(await lstat(stage, { bigint: true }));
    const script = path.join(stage, 'qualify-controller-anchor-birth.mjs'), node = path.join(stage, 'node');
    await copyFile(fileURLToPath(import.meta.url), script, fs.constants.COPYFILE_EXCL);
    await copyFile(process.execPath, node, fs.constants.COPYFILE_EXCL);
    await chmod(script, 0o555); await chmod(node, 0o555);
    const includes = spawnSync(process.execPath, [path.join(repository, 'scripts/kernel/build-state-owner-native.mjs'), '--print-includes'], { encoding: 'utf8', timeout: 30_000 });
    if (includes.error) throw includes.error; assert.equal(includes.status, 0, includes.stderr);
    const paths = JSON.parse(includes.stdout); assert.ok(Array.isArray(paths) && paths.length && paths.every(value => typeof value === 'string' && path.isAbsolute(value)));
    const module = path.join(stage, 'linux-fork-tracer.node');
    const compile = spawnSync('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
      ...paths.flatMap(value => ['-I', value]), path.join(repository, 'scripts/kernel/linux-fork-tracer.c'), '-o', module], { encoding: 'utf8', timeout: 30_000 });
    if (compile.error) throw compile.error; assert.equal(compile.status, 0, compile.stderr);
    // Native self-image attestation read-opens every ancestor directory; mere
    // traversal permission is insufficient. Only root can modify this stage.
    await chmod(module, 0o500); await chmod(stage, 0o755);
    const nodeImage = await imageFact(node), controllerImage = await imageFact(path.join(options.installationRoot, 'cliq-linux-worker-controller'));
    const env = { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio = ['ignore', 'inherit', 'inherit', 'ipc'];
    trace = ownChild(spawn(node, [script, 'helper'], { env, stdio }));
    traceIpc = mailbox(trace.child, () => {}, value => {
      if (value.type === 'finished') {
        assert.equal(traceReceipt, undefined, 'helper may finish only once'); assert.equal(typeof value.released, 'boolean');
        traceReceipt = value;
      }
    });
    trace.token = (await processFact(trace.child.pid)).token;
    const loader = fileURLToPath(import.meta.resolve('tsx'));
    // The root shim only places its own exclusive child, then execs setpriv.
    // Its PID/start lifetime is unchanged by both execs; no controller wrapper.
    launch = ownChild(spawn('/bin/bash', ['-c', 'set -e; printf "%s\\n" "$$" > "$1/supervisor/cgroup.procs"; shift; exec /usr/bin/setpriv --reuid="$1" --regid="$2" --clear-groups -- "$3" --import "$4" "$5" child',
      'cliq-first-controller-birth', options.cgroupParent, String(uid), String(gid), node, loader, script],
      { env: { ...env, HOME: '/nonexistent', TSX_DISABLE_CACHE: '1' }, stdio, cwd: repository }));
    childIpc = mailbox(launch.child); launch.token = (await processFact(launch.child.pid)).token;
    await childIpc.send({ type: 'prepare', repository, options });
    const ready = await childIpc.next('ready');
    assert.equal(ready.controllerDigest, controllerImage.digest); assert.equal(ready.controllerBytes, Number(controllerImage.size));
    const actual = await processFact(launch.child.pid);
    assert.equal(actual.token, launch.token); assert.equal(actual.ppid, process.pid); assert.equal(actual.tracerPid, 0);
    assert.deepEqual(actual.uid, [uid, uid, uid, uid]); assert.deepEqual(actual.gid, [gid, gid, gid, gid]);
    assert.equal(actual.cgroup, path.join(options.cgroupParent, 'supervisor'));
    assert.deepEqual(await imageFact(`/proc/${actual.pid}/exe`), nodeImage);
    await directoryFact(root, options.cgroupParent, rootFact);
    const expected = { source: actual, rootPath: options.cgroupParent, root: rootFact, namespaces: await namespaces(actual.pid), nodeImage };
    released = false;
    await traceIpc.send({ type: 'arm', expected }); await traceIpc.next('armed');
    sameProcess(await processFact(actual.pid), actual, trace.child.pid);
    await childIpc.send({ type: 'start' });
    const result = await traceIpc.next('finished'); released = result.released;
    const traceStatus = await bounded(trace.joined); assert.equal(traceStatus.code, 0, result.error); assert.equal(traceStatus.signal, null);
    assert.equal(released, true, result.error); assert.ok(result.observation); const observation = result.observation;
    await absent(`/proc/${trace.child.pid}`);
    await childIpc.send({ type: 'result', observation });
    const qualified = await childIpc.next('qualified'), launchStatus = await bounded(launch.joined);
    assert.equal(launchStatus.code, 0); assert.equal(launchStatus.signal, null);
    await absent(`/proc/${launch.child.pid}`);
    assert.equal(qualified.controllerPid, observation.child.pid); assert.equal(qualified.controllerStartToken, observation.child.token);
    assert.equal(qualified.executableDigest, controllerImage.digest);
    await directoryFact(root, options.cgroupParent, rootFact); await populated(root, false);
    qualification = { scenario: 'actual-first-controller-anchor-birth', supervisorPid: actual.pid, supervisorStartToken: actual.token,
      controllerPid: qualified.controllerPid, controllerStartToken: qualified.controllerStartToken, controllerCgroup: observation.child.cgroup,
      root: observation.root, controllerLeaf: observation.leaf, preExecNodeDigest: observation.preExec.digest, controllerDigest: qualified.executableDigest,
      note: 'external root tracer witnessed the real first clone3 child before user-space setup; detached and joined helper before same-lifetime HELLO and actual controller image SHA; non-root producer and controller-only retirement; offline CI test-root prefix, not installed signed Supervisor I1 or worker death evidence' };
  } catch (error) { primary = error; }
  finally {
    const failures = [];
    if (primary) {
      if (trace && !trace.status) {
        try {
          if (trace.child.connected) await traceIpc.send({ type: 'abort' });
          await bounded(trace.joined, 15_000);
        }
        catch (error) { failures.push(error); }
      }
      if (traceReceipt) {
        released = traceReceipt.released;
        if (traceReceipt.error) failures.push(new Error(traceReceipt.error));
      }
      if (released && (!trace || trace.status) && launch && !launch.status) {
        try {
          if (launch.child.connected) await childIpc.send({ type: 'abort' });
          await bounded(launch.joined, 15_000);
        } catch (error) { failures.push(error); }
      }
      if (launch?.child.pid && launch.token) {
        // Only an abnormal, already failed qualification may use job teardown.
        // An implicit tracer detach is never promoted to positive observation.
        try {
          await directoryFact(root, options.cgroupParent, rootFact);
          const kill = await open(`${descriptor(root)}/cgroup.kill`, fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW);
          try { await kill.writeFile('1\n'); } finally { await kill.close(); }
        } catch (error) { failures.push(error); }
      }
      for (const owned of [trace, launch]) {
        if (!owned || owned.status) continue;
        try {
          const actual = await processFact(owned.child.pid);
          assert.equal(actual.token, owned.token, 'refusing to kill a different process lifetime');
          assert.ok(owned.child.kill('SIGKILL'));
        } catch (error) { failures.push(error); }
        try { await bounded(owned.joined, 15_000); } catch (error) { failures.push(error); }
      }
      console.error(`failed first-controller-birth qualification; fixture and root-owned staging retained (${stage ?? 'not created'}); ` +
        `helper=${trace?.child.pid ?? 'none'} Supervisor=${launch?.child.pid ?? 'none'} released=${released}; no positive evidence`);
    }
    try { await root?.close(); } catch (error) { failures.push(error); }
    if (!primary && failures.length === 0 && stage) {
      try {
        const stat = await lstat(stage, { bigint: true }); assert.ok(stat.isDirectory() && !stat.isSymbolicLink());
        const current = identity(stat);
        for (const key of ['dev', 'ino', 'uid', 'gid']) assert.equal(current[key], stageFact[key]);
        assert.equal(current.uid, '0'); await rm(stage, { recursive: true, force: false });
      } catch (error) { failures.push(error); }
    }
    if (primary || failures.length) throw new AggregateError([...(primary ? [primary] : []), ...failures], 'controller first-birth qualification or cleanup failed');
  }
  console.log(JSON.stringify(qualification));
}

await ({ job, helper, child })[role]();
