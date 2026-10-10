#!/usr/bin/env node
// OS lifecycle diagnostics only. These observations are not kernel authority,
// an installed Supervisor qualification, or containment-death evidence.
import assert from 'node:assert/strict';
import { fork, spawn, spawnSync } from 'node:child_process';
import { constants, closeSync, existsSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readlinkSync, readdirSync, renameSync, statSync,
  statfsSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const self = fileURLToPath(import.meta.url);
const controllers = ['cpu', 'memory', 'pids'];
const limits = { 'cpu.max': '25000 100000', 'memory.max': '134217728', 'pids.max': '64' };
const cgroupMount = '/sys/fs/cgroup';
const bootId = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const errorText = (error) => String(error?.stack ?? error).slice(0, 8192);

function publish(file, value, mode = 0o600) {
  const temporary = `${file}.tmp-${process.pid}`;
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode);
  try {
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  assert(!existsSync(file), `refusing to replace diagnostic file: ${file}`);
  renameSync(temporary, file);
  const directory = openSync(join(file, '..'), constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

function command(executable, args, allowFailure = false) {
  const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 10_000,
    maxBuffer: 128 * 1024, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' } });
  if (result.error || (!allowFailure && result.status !== 0)) {
    throw new Error(`${executable} ${args.join(' ')}: ${result.error ?? result.stderr?.trim() ?? result.status}`);
  }
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function properties(output) {
  const result = {};
  for (const line of output.trim().split('\n')) {
    const separator = line.indexOf('=');
    if (separator < 0) continue;
    const name = line.slice(0, separator);
    assert(!(name in result), `duplicate systemd property: ${name}`);
    result[name] = line.slice(separator + 1);
  }
  return result;
}

function processFact(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return { present: false };
  try {
    const text = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const fields = text.slice(text.lastIndexOf(') ') + 2).trim().split(/\s+/);
    assert(fields.length >= 20, 'incomplete /proc process stat');
    const memberships = readFileSync(`/proc/${pid}/cgroup`, 'utf8').trim().split('\n');
    const unified = memberships.filter((line) => line.startsWith('0::'));
    assert.equal(unified.length, 1, 'one unified cgroup membership is required');
    let cgroupNamespace = null;
    try { cgroupNamespace = readlinkSync(`/proc/${pid}/ns/cgroup`); }
    catch (error) {
      // A zombie can retain its PID/start while nsproxy is already gone. A
      // missing namespace link must never relabel that process as absent.
      if (error.code !== 'ENOENT' && error.code !== 'ESRCH') throw error;
    }
    return { present: true, pid, uid: statSync(`/proc/${pid}`).uid,
      state: fields[0], startTimeTicks: fields[19], bootId,
      cgroupPath: unified[0].slice(3), cgroupNamespace };
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ESRCH') return { present: false, pid };
    throw error;
  }
}

function cgroupPath(relative) {
  assert(relative.startsWith('/') && !relative.split('/').includes('..'), 'invalid kernel cgroup path');
  return `${cgroupMount}${relative}`;
}

function directoryFact(path) {
  try {
    const stat = lstatSync(path, { bigint: true });
    assert(stat.isDirectory() && !stat.isSymbolicLink(), 'cgroup path is not a real directory');
    assert.equal(Number(statfsSync(path).type), 0x63677270, 'cgroup v2 filesystem required');
    return { present: true, path, dev: String(stat.dev), ino: String(stat.ino) };
  } catch (error) {
    if (error.code === 'ENOENT') return { present: false, path };
    throw error;
  }
}

function hold(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  const stat = fstatSync(fd, { bigint: true });
  return { fd, original: { present: true, path, dev: String(stat.dev), ino: String(stat.ino) } };
}

function heldFact(held) {
  const stat = fstatSync(held.fd, { bigint: true });
  const fdPath = readlinkSync(`/proc/self/fd/${held.fd}`);
  return { dev: String(stat.dev), ino: String(stat.ino), fdPath,
    deleted: fdPath.endsWith(' (deleted)') };
}

function sameDirectory(current, original) {
  return current.present && current.dev === original.dev && current.ino === original.ino;
}

function diagnostic(file, uid) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(fd);
    assert(metadata.isFile() && metadata.uid === uid && metadata.nlink === 1 && metadata.size <= 128 * 1024,
      'unexpected diagnostic readiness file');
    return JSON.parse(readFileSync(fd, 'utf8'));
  } finally { closeSync(fd); }
}

function enableControllers(root) {
  assert.equal(readFileSync(join(root, 'cgroup.type'), 'utf8').trim(), 'domain');
  assert.equal(readFileSync(join(root, 'cgroup.procs'), 'utf8').trim(), '', 'delegation root must be empty');
  const available = readFileSync(join(root, 'cgroup.controllers'), 'utf8').trim().split(/\s+/);
  for (const controller of controllers) assert(available.includes(controller), `${controller} not delegated`);
  writeFileSync(join(root, 'cgroup.subtree_control'), '+cpu +memory +pids\n');
  const enabled = readFileSync(join(root, 'cgroup.subtree_control'), 'utf8').trim().split(/\s+/);
  for (const controller of controllers) assert(enabled.includes(controller), `${controller} enable failed`);
  return { available, enabled };
}

function setLimits(path) {
  for (const [name, value] of Object.entries(limits)) {
    writeFileSync(join(path, name), `${value}\n`);
    assert.equal(readFileSync(join(path, name), 'utf8').trim(), value, `${name} readback failed`);
  }
}

function childReady(child, kind) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error(`${kind} readiness timed out`)), 10_000);
    const onError = (error) => finish(error);
    const onExit = (code, signal) => finish(new Error(`${kind} exited before readiness: ${code}/${signal}`));
    const onMessage = (message) => message?.kind === kind ? finish(undefined, message)
      : finish(new Error(`invalid ${kind} readiness`));
    function finish(error, message) {
      clearTimeout(timer);
      child.off('error', onError); child.off('exit', onExit); child.off('message', onMessage);
      if (error) reject(error); else resolve(message);
    }
    child.once('error', onError); child.once('exit', onExit); child.once('message', onMessage);
  });
}

function exitChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return child.exitCode === 0 && child.signalCode === null ? Promise.resolve()
      : Promise.reject(new Error(`unexpected dummy child exit: ${child.exitCode}/${child.signalCode}`));
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('dummy child exit timed out')), 10_000);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      if (code !== 0 || signal) reject(new Error(`unexpected dummy child exit: ${code}/${signal}`)); else resolve();
    });
    if (child.connected) child.send({ kind: 'exit' });
  });
}

function sameLifetime(actual, recorded) {
  return actual.present && actual.pid === recorded.pid && actual.startTimeTicks === recorded.startTimeTicks && actual.bootId === recorded.bootId;
}

function baseline(uid) {
  const unit = properties(command('/usr/bin/systemctl', ['show', `user@${uid}.service`,
    '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,InvocationID', '--no-pager']).stdout);
  for (const name of ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'InvocationID']) {
    assert(Object.hasOwn(unit, name), `runner unit baseline lacks ${name}`);
  }
  assert(/^\d+$/.test(unit.MainPID), 'runner manager PID is not a confirmed integer');
  // A successful enumeration can confirm no registered user. A failed lookup
  // or unavailable bus cannot be relabeled as the same "unknown" twice.
  const users = command('/usr/bin/loginctl', ['list-users', '--no-legend', '--no-pager']).stdout;
  const registered = users.trim().split('\n').filter(Boolean).some((line) => {
    const match = line.match(/^\s*(\d+)\s+\S/);
    assert(match, 'invalid loginctl user enumeration');
    return Number(match[1]) === uid;
  });
  const user = registered ? { registered: true, ...properties(command('/usr/bin/loginctl', ['show-user', String(uid),
    '--property=Linger', '--property=State', '--property=RuntimePath']).stdout) } : { registered: false };
  if (registered) for (const name of ['Linger', 'State', 'RuntimePath']) {
    assert(Object.hasOwn(user, name), `runner user baseline lacks ${name}`);
  }
  const pid = Number(unit.MainPID ?? 0);
  return { uid, unit, user, manager: processFact(pid),
    cgroup: unit.ControlGroup ? directoryFact(cgroupPath(unit.ControlGroup)) : { present: false } };
}

async function worker(path) {
  assert.equal(Number(statfsSync(path).type), 0x63677270, 'worker requires cgroup v2');
  writeFileSync(join(path, 'cgroup.procs'), `${process.pid}\n`);
  const fact = processFact(process.pid);
  assert.equal(cgroupPath(fact.cgroupPath), path, 'dummy worker did not enter its own leaf');
  process.send?.({ kind: 'worker_ready', fact });
  process.on('message', (message) => { if (message?.kind === 'exit') process.exit(0); });
  // Keep the dummy alive after parent IPC disconnect; only the OS lifecycle
  // or the scoped cleanup should kill a live-worker scenario.
  setInterval(() => {}, 1000);
}

async function grandchild(path) {
  const fact = processFact(process.pid);
  assert.equal(cgroupPath(fact.cgroupPath), path, 'grandchild was not born in the anchored worker leaf');
  process.on('message', (message) => { if (message?.kind === 'exit') process.exit(0); });
  process.on('disconnect', () => process.exit(0));
  process.send({ kind: 'grandchild_ready', fact });
  setInterval(() => {}, 1000);
}

async function anchoredWorker(path, controllerPath, mode) {
  assert(mode === 'empty' || mode === 'live');
  const birth = processFact(process.pid);
  assert.equal(cgroupPath(birth.cgroupPath), controllerPath, 'worker was not born inside the anchor');
  writeFileSync(join(path, 'cgroup.procs'), `${process.pid}\n`);
  const fact = processFact(process.pid);
  assert.equal(cgroupPath(fact.cgroupPath), path, 'anchored worker leaf migration failed');
  const child = fork(self, ['grandchild', path], { execArgv: [], stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    try { await exitChild(child); process.exit(0); } catch (error) { console.error(errorText(error)); process.exit(1); }
  };
  // For the stronger live A/B contrast, both descendants survive controller
  // EOF. Only the successor's exact nonroot cgroup.kill retires that old run.
  if (mode === 'empty') process.on('disconnect', stop);
  process.on('message', (message) => { if (message?.kind === 'exit') void stop(); });
  const ready = await childReady(child, 'grandchild_ready');
  assert.equal(ready.fact.pid, child.pid);
  process.send({ kind: 'anchored_worker_ready', birth, fact, grandchild: ready.fact });
  setInterval(() => {}, 1000);
}

async function controller(workerPath, mode) {
  assert(mode === 'empty' || mode === 'live', 'unknown anchored worker mode');
  const birth = processFact(process.pid);
  const controllerPath = join(workerPath, '..', 'controller');
  assert.equal(cgroupPath(birth.cgroupPath), controllerPath, 'controller was not atomically born in its anchor leaf');
  assert.equal(Number(statfsSync(workerPath).type), 0x63677270);
  const child = fork(self, ['anchored-worker', workerPath, controllerPath, mode], {
    execArgv: [], stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    try { await exitChild(child); process.exit(0); } catch (error) { console.error(errorText(error)); process.exit(1); }
  };
  // Only the actual inherited private IPC EOF ends this dummy's production.
  // No pid/path disappearance is promoted to native death authority.
  process.on('disconnect', () => {
    if (mode === 'live') process.exit(0);
    else void stop();
  });
  const ready = await childReady(child, 'anchored_worker_ready');
  assert.equal(ready.fact.pid, child.pid);
  if (mode === 'empty') {
    await exitChild(child);
    assert(!processFact(ready.fact.pid).present && !processFact(ready.grandchild.pid).present,
      'empty anchored descendants were not reaped');
  }
  process.send({ kind: 'controller_ready', controller: birth, workerBirth: ready.birth,
    worker: ready.fact, grandchild: ready.grandchild });
  setInterval(() => {}, 1000);
}

async function anchor(output, unit) {
  const invocationId = process.env.INVOCATION_ID;
  assert(/^[a-f0-9]{32}$/.test(invocationId ?? ''), 'actual anchor invocation required');
  const initial = processFact(process.pid);
  assert.equal(basename(initial.cgroupPath), unit, 'anchor must start in its actual unit root');
  const root = cgroupPath(initial.cgroupPath);
  const keeper = join(root, 'keeper');
  mkdirSync(keeper, { mode: 0o700 });
  writeFileSync(join(keeper, 'cgroup.procs'), `${process.pid}\n`);
  assert.equal(cgroupPath(processFact(process.pid).cgroupPath), keeper, 'anchor keeper migration failed');
  const delegation = enableControllers(root);
  publish(join(output, 'anchor.json'), { diagnosticOnly: true, uid: process.getuid(), unit,
    invocationId, main: processFact(process.pid), root: directoryFact(root), ...delegation });
  // After this initialization the anchor only stays alive. The Supervisor,
  // not the keeper, creates and retires all case-private worker subtrees.
  setInterval(() => {}, 1000);
}

async function retireAnchorRuns(parent, output, unit) {
  assert(process.getuid() > 0, 'retirement must exercise the actual nonroot UID');
  const retired = [];
  for (const entry of readdirSync(parent, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    assert(/^run-[a-f0-9]{32}$/.test(entry.name), 'unexpected private worker subtree');
    const prior = diagnostic(join(output, `${entry.name.slice(4)}.json`), process.getuid());
    assert.equal(prior.layout, 'B'); assert.equal(prior.unit, unit);
    const path = join(parent, entry.name);
    assert.equal(prior.workerRoot.path, path);
    const held = hold(path);
    try {
      assert(sameDirectory(held.original, prior.workerRoot), 'old run cgroup identity changed');
      const lifetimes = [prior.controller, prior.worker, prior.grandchild];
      const eofDeadline = Date.now() + 10_000;
      while (sameLifetime(processFact(prior.controller.pid), prior.controller) && Date.now() < eofDeadline) await sleep(50);
      const beforeProcesses = lifetimes.map((lifetime) => ({ recorded: lifetime, actual: processFact(lifetime.pid) }));
      assert(!sameLifetime(beforeProcesses[0].actual, prior.controller), 'old controller did not exit/reap after private IPC EOF');
      if (prior.mode === 'live') for (const { recorded, actual } of beforeProcesses.slice(1)) {
        assert(sameLifetime(actual, recorded) && actual.state !== 'Z', 'live anchored descendant did not survive controller EOF');
      }
      for (const lifetime of lifetimes) {
        const actual = processFact(lifetime.pid);
        if (sameLifetime(actual, lifetime)) {
          assert.equal(actual.uid, process.getuid());
          assert(cgroupPath(actual.cgroupPath).startsWith(`${path}/`), 'recorded descendant escaped its old run');
        }
      }
      // Resolve through the retained exact inode, not an inferred replacement.
      // The writer is the successor Supervisor UID; never root/chmod fallback.
      writeFileSync(`/proc/self/fd/${held.fd}/cgroup.kill`, '1\n');
      const deadline = Date.now() + 10_000;
      let events, processes;
      do {
        events = properties(readFileSync(`/proc/self/fd/${held.fd}/cgroup.events`, 'utf8').replaceAll(' ', '='));
        processes = lifetimes.map((lifetime) => ({ recorded: lifetime, actual: processFact(lifetime.pid) }));
        if (events.populated === '0' && processes.every(({ recorded, actual }) => !sameLifetime(actual, recorded))) break;
        await sleep(50);
      } while (Date.now() < deadline);
      assert.equal(events.populated, '0', 'old anchored subtree remains populated');
      assert(processes.every(({ recorded, actual }) => !sameLifetime(actual, recorded)), 'old anchored PID/start lifetime or zombie remains');
      assert(sameDirectory(directoryFact(path), held.original), 'retirement changed the retained old cgroup identity');
      retired.push({ diagnosticOnly: true, writerUid: process.getuid(), path,
        original: held.original, heldFd: heldFact(held), beforeProcesses, events, processes,
        controllerEofLifetimeAbsent: true, cgroupKillWritten: true });
    } finally { closeSync(held.fd); }
  }
  return retired;
}

async function main(mode, output, unit, layout = 'A', anchorFile, birthHelper) {
  assert(mode === 'empty' || mode === 'live', 'unknown dummy worker mode');
  assert(layout === 'A' || layout === 'B', 'unknown lifecycle layout');
  const invocationId = process.env.INVOCATION_ID;
  assert(/^[a-f0-9]{32}$/.test(invocationId ?? ''), 'actual systemd INVOCATION_ID required');
  const initial = processFact(process.pid);
  assert.equal(basename(initial.cgroupPath), unit, 'MainPID must start in the actual unit root');
  const root = cgroupPath(initial.cgroupPath);
  assert.equal(readFileSync(join(root, 'cgroup.type'), 'utf8').trim(), 'domain');
  const available = readFileSync(join(root, 'cgroup.controllers'), 'utf8').trim().split(/\s+/);
  for (const controller of controllers) assert(available.includes(controller), `${controller} not delegated`);
  const supervisor = join(root, `supervisor-${invocationId}`);
  mkdirSync(supervisor, { mode: 0o700 });
  writeFileSync(join(supervisor, 'cgroup.procs'), `${process.pid}\n`);
  assert.equal(cgroupPath(processFact(process.pid).cgroupPath), supervisor, 'MainPID leaf migration failed');
  const { enabled } = enableControllers(root);
  if (layout === 'B') {
    assert(process.getuid() > 0, 'anchor birth must exercise the actual nonroot UID');
    const anchorFact = diagnostic(anchorFile, process.getuid());
    const actualAnchor = processFact(anchorFact.main.pid);
    assert(sameLifetime(actualAnchor, anchorFact.main) && actualAnchor.uid === process.getuid(), 'anchor lifetime changed');
    assert.equal(cgroupPath(actualAnchor.cgroupPath), join(anchorFact.root.path, 'keeper'));
    assert(sameDirectory(directoryFact(anchorFact.root.path), anchorFact.root), 'anchor root identity changed');
    const workerParent = join(anchorFact.root.path, `workers-${unit}`);
    if (!existsSync(workerParent)) mkdirSync(workerParent, { mode: 0o700 });
    enableControllers(workerParent);
    const retirements = await retireAnchorRuns(workerParent, output, unit);
    const workerRoot = join(workerParent, `run-${invocationId}`);
    mkdirSync(workerRoot, { mode: 0o700 });
    enableControllers(workerRoot);
    setLimits(workerRoot);
    const controllerLeaf = join(workerRoot, 'controller');
    const workerLeaf = join(workerRoot, 'worker');
    mkdirSync(controllerLeaf, { mode: 0o700 }); mkdirSync(workerLeaf, { mode: 0o700 });
    const helper = spawn(birthHelper, [controllerLeaf, process.execPath, self, 'controller', workerLeaf, mode], {
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    const ready = await childReady(helper, 'controller_ready');
    assert.equal(cgroupPath(ready.controller.cgroupPath), controllerLeaf, 'controller birth membership mismatch');
    const actualController = processFact(ready.controller.pid);
    assert(sameLifetime(actualController, ready.controller) && actualController.uid === process.getuid(), 'controller lifetime mismatch');
    assert.equal(cgroupPath(actualController.cgroupPath), controllerLeaf);
    const launcher = processFact(helper.pid);
    assert(launcher.present && launcher.uid === process.getuid(), 'native birth launcher missing');
    assert.equal(cgroupPath(launcher.cgroupPath), supervisor);
    const sourceParts = launcher.cgroupPath.split('/').filter(Boolean);
    const destinationParts = actualController.cgroupPath.split('/').filter(Boolean);
    let commonLength = 0;
    while (commonLength < sourceParts.length && sourceParts[commonLength] === destinationParts[commonLength]) commonLength++;
    const commonPath = cgroupPath(`/${sourceParts.slice(0, commonLength).join('/')}`);
    const commonProcsPath = join(commonPath, 'cgroup.procs');
    const commonProcs = lstatSync(commonProcsPath);
    assert(commonProcs.isFile() && !commonProcs.isSymbolicLink(), 'unexpected common ancestor cgroup.procs');
    const birthAccess = { observedByUid: process.getuid(),
      source: { pid: launcher.pid, path: launcher.cgroupPath, namespace: launcher.cgroupNamespace },
      destination: { pid: actualController.pid, path: actualController.cgroupPath, namespace: actualController.cgroupNamespace },
      commonAncestor: { directory: directoryFact(commonPath), cgroupProcs: {
        path: commonProcsPath, uid: commonProcs.uid, gid: commonProcs.gid, mode: commonProcs.mode & 0o7777 } },
      interpretation: 'nonroot observation only; actual clone3 success, not mode inference, validates birth access' };
    publish(join(output, `${invocationId}.json`), { diagnosticOnly: true, layout, invocationId, unit, mode,
      uid: process.getuid(), main: processFact(process.pid), supervisorRoot: directoryFact(root),
      root: directoryFact(anchorFact.root.path), workerParent: directoryFact(workerParent),
      workerRoot: directoryFact(workerRoot), controllerLeaf, workerLeaf, anchor: anchorFact,
      launcher, controller: ready.controller, workerBirth: ready.workerBirth, worker: ready.worker,
      grandchild: ready.grandchild, retirements, birthAccess, available, enabled, limits,
      birth: 'nonroot clone3 CLONE_INTO_CGROUP; no migration fallback',
      topology: 'OS dummy controller inside run for cleanup; not production controller/death topology' });
    setInterval(() => {}, 1000);
    return;
  }
  const workerRoot = join(root, `worker-${invocationId}`);
  mkdirSync(workerRoot, { mode: 0o700 });
  setLimits(workerRoot);
  const child = fork(self, ['worker', workerRoot], { execArgv: [], stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  const childFact = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('dummy worker readiness timed out')), 10_000);
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('exit', (code, signal) => { clearTimeout(timer); reject(new Error(`worker exited before readiness: ${code}/${signal}`)); });
    child.once('message', (message) => {
      clearTimeout(timer);
      if (message?.kind !== 'worker_ready' || message.fact?.pid !== child.pid) reject(new Error('invalid worker readiness'));
      else resolve(message.fact);
    });
  });
  assert.equal(cgroupPath(childFact.cgroupPath), workerRoot);
  if (mode === 'empty') {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('dummy worker exit timed out')), 10_000);
      child.once('exit', (code, signal) => {
        clearTimeout(timer);
        if (code !== 0 || signal) reject(new Error(`unexpected empty-worker exit: ${code}/${signal}`));
        else resolve();
      });
      child.send({ kind: 'exit' });
    });
    assert(!processFact(childFact.pid).present, 'empty worker was not reaped');
  }
  publish(join(output, `${invocationId}.json`), { diagnosticOnly: true, layout, invocationId, unit, mode,
    uid: process.getuid(), main: processFact(process.pid), worker: childFact,
    workerNow: processFact(childFact.pid), root: directoryFact(root),
    workerRoot: directoryFact(workerRoot), available, enabled, limits });
  setInterval(() => {}, 1000);
}

async function campaign(config) {
  assert.equal(process.getuid(), 0, 'root orchestration required');
  assert(config.uid !== config.runnerUid && config.uid > 0, 'fresh UID must differ from runner/root');
  const userCommand = (args, allowFailure = false) => command('/usr/sbin/runuser', ['--user', config.username, '--', '/usr/bin/env', '-i',
    `HOME=${config.home}`, 'PATH=/usr/bin:/bin', 'LC_ALL=C',
    `XDG_RUNTIME_DIR=/run/user/${config.uid}`,
    `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${config.uid}/bus`, '/usr/bin/systemctl', '--user', ...args], allowFailure);
  const systemd = (...args) => userCommand(args);
  const show = (unit) => properties(systemd('show', unit, '--no-pager',
    '--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,InvocationID,NRestarts,Result,ExecMainCode,ExecMainStatus,Delegate,FragmentPath,Type,KillMode,Restart').stdout);
  const manager = properties(command('/usr/bin/systemctl', ['show', `user@${config.uid}.service`,
    '--property=ActiveState,MainPID,ControlGroup,Delegate,DropInPaths', '--no-pager']).stdout);
  assert.equal(manager.ActiveState, 'active', 'actual user manager is not active');
  assert.equal(processFact(Number(manager.MainPID)).uid, config.uid, 'user manager UID mismatch');
  assert.equal(manager.Delegate, 'yes', 'user manager is not delegated');
  assert(manager.DropInPaths.split(' ').includes(config.dropin), 'UID-specific delegation drop-in not loaded');
  const report = { schemaVersion: 2, diagnosticOnly: true,
    scope: 'systemd-user dummy OS lifecycle; not installed Supervisor or death authority',
    bootId, nodeVersion: process.version, cgroupNamespace: readlinkSync('/proc/self/ns/cgroup'), manager,
    kernelRelease: command('/usr/bin/uname', ['-r']).stdout.trim(),
    systemdVersion: command('/usr/bin/systemctl', ['--version']).stdout.split('\n')[0], cases: [] };
  let anchorSnapshot;
  const checkAnchor = () => {
    assert(anchorSnapshot, 'anchor has not been initialized');
    const shown = show(config.anchor.unit);
    const actual = processFact(Number(shown.MainPID));
    assert.equal(shown.ActiveState, 'active', 'persistent anchor stopped');
    assert.equal(shown.InvocationID, anchorSnapshot.invocationId, 'anchor invocation changed');
    assert.equal(shown.FragmentPath, config.anchor.unitFile);
    assert.equal(shown.Delegate, 'yes'); assert.equal(shown.Type, 'exec');
    assert.equal(shown.KillMode, 'control-group'); assert.equal(shown.Restart, 'no');
    assert(sameLifetime(actual, anchorSnapshot.main) && actual.uid === config.uid, 'anchor MainPID lifetime changed');
    assert.equal(cgroupPath(actual.cgroupPath), join(anchorSnapshot.root.path, 'keeper'));
    assert.equal(cgroupPath(shown.ControlGroup), anchorSnapshot.root.path);
    assert(shown.ControlGroup.startsWith(`${manager.ControlGroup}/`), 'anchor outside actual disposable manager');
    const root = directoryFact(anchorSnapshot.root.path);
    assert(sameDirectory(root, anchorSnapshot.root), 'anchor root identity changed');
    return { unit: shown, main: actual, root };
  };
  const startAnchor = async () => {
    report.anchor = {};
    systemd('start', config.anchor.unit);
    const deadline = Date.now() + 15_000;
    do {
      if (existsSync(config.anchor.readyFile)) {
        anchorSnapshot = diagnostic(config.anchor.readyFile, config.uid);
        assert.equal(anchorSnapshot.unit, config.anchor.unit); assert.equal(anchorSnapshot.uid, config.uid);
        report.anchor.before = checkAnchor();
        return;
      }
      const shown = show(config.anchor.unit);
      assert(shown.ActiveState !== 'failed', `anchor initialization failed: ${JSON.stringify(shown)}`);
      await sleep(50);
    } while (Date.now() < deadline);
    throw new Error('anchor initialization timed out');
  };
  const ready = (scenario, shown) => {
    if (!/^[a-f0-9]{32}$/.test(shown.InvocationID ?? '')) return undefined;
    const path = join(scenario.directory, `${shown.InvocationID}.json`);
    if (!existsSync(path)) return undefined;
    const data = diagnostic(path, config.uid);
    assert.equal(data.invocationId, shown.InvocationID);
    assert.equal(data.uid, config.uid);
    assert.equal(data.main.pid, Number(shown.MainPID));
    assert.equal(data.unit, scenario.unit);
    assert.equal(data.mode, scenario.mode);
    assert.equal(data.layout, scenario.layout);
    assert.equal(shown.Delegate, 'yes', 'user unit is not delegated');
    assert.equal(shown.Type, 'exec', 'unexpected service execution type');
    assert.equal(shown.KillMode, 'control-group', 'unexpected service descendant lifecycle');
    assert.equal(shown.Restart, scenario.restart === 'automatic' ? 'on-failure' : 'no', 'unexpected restart policy');
    assert.equal(shown.FragmentPath, scenario.unitFile, 'unexpected user unit definition');
    assert(shown.ControlGroup.startsWith(`${manager.ControlGroup}/`) && basename(shown.ControlGroup) === scenario.unit,
      'unit cgroup is outside the disposable user manager');
    const root = cgroupPath(shown.ControlGroup);
    const actualMain = processFact(Number(shown.MainPID));
    assert.equal(actualMain.uid, config.uid);
    assert.equal(actualMain.startTimeTicks, data.main.startTimeTicks);
    assert.equal(cgroupPath(actualMain.cgroupPath), join(root, `supervisor-${shown.InvocationID}`));
    if (scenario.layout === 'A') {
      assert.equal(data.root.path, root);
      assert.equal(data.workerRoot.path, join(root, `worker-${shown.InvocationID}`));
    } else {
      checkAnchor();
      assert.equal(data.supervisorRoot.path, root);
      assert(sameDirectory(directoryFact(root), data.supervisorRoot), 'Supervisor root drift at readiness');
      assert.equal(data.root.path, anchorSnapshot.root.path);
      assert.equal(data.anchor.invocationId, anchorSnapshot.invocationId);
      assert.equal(data.workerParent.path, join(data.root.path, `workers-${scenario.unit}`));
      assert.equal(data.workerRoot.path, join(data.workerParent.path, `run-${shown.InvocationID}`));
      assert(sameDirectory(directoryFact(data.workerParent.path), data.workerParent), 'worker parent drift at readiness');
      assert.equal(data.controllerLeaf, join(data.workerRoot.path, 'controller'));
      assert.equal(data.workerLeaf, join(data.workerRoot.path, 'worker'));
      const actualController = processFact(data.controller.pid);
      assert(sameLifetime(actualController, data.controller) && actualController.uid === config.uid, 'anchored controller missing');
      assert.equal(cgroupPath(actualController.cgroupPath), data.controllerLeaf);
      assert.equal(cgroupPath(data.controller.cgroupPath), data.controllerLeaf);
      assert.equal(cgroupPath(data.workerBirth.cgroupPath), data.controllerLeaf);
      assert.equal(data.workerBirth.pid, data.worker.pid);
      assert.equal(data.workerBirth.startTimeTicks, data.worker.startTimeTicks);
      assert.equal(cgroupPath(data.grandchild.cgroupPath), data.workerLeaf);
      const actualGrandchild = processFact(data.grandchild.pid);
      if (scenario.mode === 'live') {
        assert(sameLifetime(actualGrandchild, data.grandchild) && actualGrandchild.uid === config.uid && actualGrandchild.state !== 'Z',
          'live anchored grandchild missing');
        assert.equal(cgroupPath(actualGrandchild.cgroupPath), data.workerLeaf);
      } else assert(!actualGrandchild.present, 'empty anchored grandchild remains');
      for (const retirement of data.retirements) {
        assert.equal(retirement.writerUid, config.uid, 'retirement was not nonroot');
        assert.equal(retirement.cgroupKillWritten, true);
        assert(retirement.path.startsWith(`${data.workerParent.path}/run-`), 'retirement outside private worker parent');
      }
    }
    assert(sameDirectory(directoryFact(data.root.path), data.root), 'root identity drift at readiness');
    assert(sameDirectory(directoryFact(data.workerRoot.path), data.workerRoot), 'worker cgroup drift at readiness');
    const actualWorker = processFact(data.worker.pid);
    if (scenario.mode === 'live') {
      assert(actualWorker.present && actualWorker.uid === config.uid && actualWorker.state !== 'Z', 'live worker missing');
      assert.equal(actualWorker.startTimeTicks, data.worker.startTimeTicks);
      assert.equal(cgroupPath(actualWorker.cgroupPath), scenario.layout === 'A' ? data.workerRoot.path : data.workerLeaf);
    } else assert(!actualWorker.present, 'empty worker is still present');
    assert.deepEqual(data.limits, limits, 'unexpected diagnostic limits');
    const enabled = readFileSync(join(data.root.path, 'cgroup.subtree_control'), 'utf8').trim().split(/\s+/);
    for (const controller of controllers) assert(enabled.includes(controller), 'controller enable missing');
    for (const [name, expected] of Object.entries(limits)) {
      assert.equal(readFileSync(join(data.workerRoot.path, name), 'utf8').trim(), expected);
    }
    return data;
  };
  const waitReady = async (scenario, initial, precedingInvocationId) => {
    const deadline = Date.now() + 15_000;
    let last;
    do {
      last = show(scenario.unit);
      const data = Number(last.MainPID) > 0 && last.InvocationID !== precedingInvocationId ? ready(scenario, last) : undefined;
      if (data) return { outcome: 'started', unit: last, data };
      if (last.ActiveState === 'failed' && Number(last.MainPID) === 0 &&
        (!precedingInvocationId || last.InvocationID !== precedingInvocationId || last.Result === 'start-limit-hit')) {
        if (initial) throw new Error(`initial dummy start failed: ${JSON.stringify(last)}`);
        return { outcome: 'failed', unit: last };
      }
      await sleep(50);
    } while (Date.now() < deadline);
    if (initial) throw new Error(`initial dummy readiness timed out: ${JSON.stringify(last)}`);
    return { outcome: 'timeout', unit: last };
  };
  systemd('daemon-reload');
  try {
    for (const scenario of config.scenarios) {
      if (scenario.layout === 'B' && !anchorSnapshot) await startAnchor();
      const item = { layout: scenario.layout, mode: scenario.mode, restart: scenario.restart, unit: scenario.unit };
      report.cases.push(item);
      let rootHeld, workerHeld, workerParentHeld, supervisorHeld;
      try {
        systemd('start', scenario.unit);
        const first = await waitReady(scenario, true);
        item.before = first;
        rootHeld = hold(first.data.root.path);
        workerHeld = hold(first.data.workerRoot.path);
        if (scenario.layout === 'B') {
          workerParentHeld = hold(first.data.workerParent.path);
          supervisorHeld = hold(first.data.supervisorRoot.path);
          assert(sameDirectory(workerParentHeld.original, first.data.workerParent), 'worker parent changed before descriptor observation');
          assert(sameDirectory(supervisorHeld.original, first.data.supervisorRoot), 'Supervisor root changed before descriptor observation');
        }
        assert(sameDirectory(rootHeld.original, first.data.root), 'root changed before descriptor observation');
        assert(sameDirectory(workerHeld.original, first.data.workerRoot), 'worker root changed before descriptor observation');
        const observe = () => {
          const root = directoryFact(first.data.root.path);
          const workerRoot = directoryFact(first.data.workerRoot.path);
          const oldWorker = processFact(first.data.worker.pid);
          const workerParent = workerParentHeld ? directoryFact(first.data.workerParent.path) : undefined;
          return { root, workerRoot, rootHeldFd: heldFact(rootHeld), workerHeldFd: heldFact(workerHeld),
            oldMain: processFact(first.data.main.pid), oldWorker,
            workerParent, workerParentHeldFd: workerParentHeld ? heldFact(workerParentHeld) : undefined,
            supervisorRoot: supervisorHeld ? directoryFact(first.data.supervisorRoot.path) : root,
            supervisorHeldFd: supervisorHeld ? heldFact(supervisorHeld) : heldFact(rootHeld),
            anchor: scenario.layout === 'B' ? checkAnchor() : undefined,
            oldController: first.data.controller ? processFact(first.data.controller.pid) : undefined,
            oldGrandchild: first.data.grandchild ? processFact(first.data.grandchild.pid) : undefined,
            oldLauncher: first.data.launcher ? processFact(first.data.launcher.pid) : undefined,
            originalWorkerLifetimePresent: sameLifetime(oldWorker, first.data.worker),
            retainedExactCgroupPrerequisite: sameDirectory(root, rootHeld.original) && sameDirectory(workerRoot, workerHeld.original) &&
              (!workerParentHeld || sameDirectory(workerParent, workerParentHeld.original))
              ? 'present; not a death proof' : 'not_met; current native retained-inode recovery cannot open these exact paths' };
        };
        // Ask the actual manager to kill its MainPID, never a path/PID from dummy output.
        systemd('kill', '--kill-who=main', '--signal=SIGKILL', scenario.unit);
        item.transitions = [];
        const deadline = Date.now() + 15_000;
        let lastKey;
        let stopped = false;
        let replacement;
        do {
          const shown = show(scenario.unit);
          const facts = observe();
          const key = JSON.stringify({ shown, facts });
          if (key !== lastKey) item.transitions.push({ elapsedMs: 15_000 - Math.max(0, deadline - Date.now()), unit: shown, facts });
          lastKey = key;
          if (scenario.restart === 'manual') {
            if (Number(shown.MainPID) === 0 && ['inactive', 'failed'].includes(shown.ActiveState)) { stopped = true; break; }
          } else {
            if (shown.InvocationID !== first.unit.InvocationID && Number(shown.MainPID) > 0) {
              replacement = await waitReady(scenario, false);
              break;
            }
            if (shown.ActiveState === 'failed' && Number(shown.MainPID) === 0 &&
              (shown.InvocationID !== first.unit.InvocationID || shown.Result === 'start-limit-hit')) {
              replacement = { outcome: 'failed', unit: shown };
              break;
            }
          }
          await sleep(50);
        } while (Date.now() < deadline);
        if (scenario.restart === 'manual') {
          item.stopObserved = stopped;
          item.afterStop = observe();
          if (stopped) {
            // No old directory is recreated by the orchestrator or dummy.
            const result = userCommand(['start', scenario.unit], true);
            item.startCommand = result;
            // A failed CLI call is not evidence of a service failure, and the
            // killed predecessor's failed state is not a new restart outcome.
            replacement = await waitReady(scenario, false, first.unit.InvocationID);
          }
        }
        item.restartResult = replacement ?? { outcome: 'timeout', unit: show(scenario.unit) };
        item.afterRestart = observe();
        if (item.restartResult.outcome === 'timeout') {
          throw new Error('incomplete lifecycle diagnostic: restart outcome timed out; this is not a negative retained-inode fact');
        }
        if (replacement?.outcome === 'started') {
          assert.notEqual(replacement.unit.InvocationID, first.unit.InvocationID, 'restart reused invocation identity');
          assert(replacement.data.main.startTimeTicks !== first.data.main.startTimeTicks ||
            replacement.data.main.pid !== first.data.main.pid, 'restart reused MainPID lifetime');
        }
        if (scenario.layout === 'B') {
          assert.equal(replacement?.outcome, 'started', 'B restart did not obtain a verified diagnostic readiness');
          checkAnchor();
          assert(sameDirectory(directoryFact(first.data.root.path), rootHeld.original), 'B anchor root was replaced');
          assert(sameDirectory(directoryFact(first.data.workerParent.path), workerParentHeld.original), 'B worker parent was replaced');
          assert(sameDirectory(directoryFact(first.data.workerRoot.path), workerHeld.original), 'B old run cgroup was replaced');
          assert(!heldFact(rootHeld).deleted && !heldFact(workerParentHeld).deleted && !heldFact(workerHeld).deleted,
            'B retained cgroup descriptor was deleted');
          const retirement = replacement.data.retirements.find((value) => value.path === first.data.workerRoot.path);
          assert(retirement && sameDirectory(retirement.original, workerHeld.original) && retirement.writerUid === config.uid,
            'successor did not nonroot-retire this exact old run');
          for (const lifetime of [first.data.controller, first.data.worker, first.data.grandchild]) {
            assert(!sameLifetime(processFact(lifetime.pid), lifetime), 'old B descendant PID/start lifetime or zombie remains');
          }
          item.anchorInvariantVerified = true;
          item.oldRunRetiredByNonrootSuccessor = true;
        }
      } catch (error) {
        item.error = errorText(error);
        try {
          // Diagnostics for this exact disposable UID/unit only. Journal
          // text never participates in readiness or containment authority.
          item.journal = command('/usr/bin/journalctl', ['--no-pager', '--output=short-monotonic', '--lines=40',
            `_UID=${config.uid}`, `_SYSTEMD_USER_UNIT=${scenario.unit}`], true);
        } catch (journalError) { item.journalError = errorText(journalError); }
        throw error;
      } finally {
        if (rootHeld) closeSync(rootHeld.fd);
        if (workerHeld) closeSync(workerHeld.fd);
        if (workerParentHeld) closeSync(workerParentHeld.fd);
        if (supervisorHeld) closeSync(supervisorHeld.fd);
        systemd('stop', scenario.unit);
      }
    }
  } catch (error) {
    report.error = errorText(error);
    throw error;
  } finally {
    if (anchorSnapshot) {
      report.anchor ??= {};
      let finalError;
      try { report.anchor.after = checkAnchor(); }
      catch (error) { report.anchor.error = errorText(error); report.error ??= errorText(error); finalError = error; }
      try { systemd('stop', config.anchor.unit); }
      catch (error) { report.anchor.stopError = errorText(error); report.error ??= errorText(error); finalError ??= error; }
      publish(config.reportFile, report, 0o644);
      if (finalError) throw finalError;
    } else publish(config.reportFile, report, 0o644);
  }
}

try {
  const [role, ...args] = process.argv.slice(2);
  if (role === 'worker') await worker(args[0]);
  else if (role === 'grandchild') await grandchild(args[0]);
  else if (role === 'anchored-worker') await anchoredWorker(...args);
  else if (role === 'controller') await controller(...args);
  else if (role === 'anchor') await anchor(...args);
  else if (role === 'main') await main(...args);
  else if (role === 'baseline') publish(args[1], baseline(Number(args[0])), 0o644);
  else if (role === 'compare-baseline') assert.deepEqual(JSON.parse(readFileSync(args[0], 'utf8')), JSON.parse(readFileSync(args[1], 'utf8')),
    'runner user-manager/linger baseline changed; do not repair unrelated runner state');
  else if (role === 'campaign') await campaign(JSON.parse(readFileSync(args[0], 'utf8')));
  else throw new Error('unknown OS diagnostic role');
} catch (error) {
  console.error(errorText(error));
  // A failed dummy may have a forked child/IPC handle; leave no accidental
  // long-lived MainPID. The manager and scoped cleanup own its descendants.
  process.exit(1);
}
