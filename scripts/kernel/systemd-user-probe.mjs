#!/usr/bin/env node
// OS lifecycle diagnostics only. These observations are not kernel authority,
// an installed Supervisor qualification, or containment-death evidence.
import assert from 'node:assert/strict';
import { fork, spawnSync } from 'node:child_process';
import { constants, closeSync, existsSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readlinkSync, renameSync, statSync,
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
    return { present: true, pid, uid: statSync(`/proc/${pid}`).uid,
      state: fields[0], startTimeTicks: fields[19], bootId,
      cgroupPath: unified[0].slice(3) };
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

async function main(mode, output, unit) {
  assert(mode === 'empty' || mode === 'live', 'unknown dummy worker mode');
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
  assert.equal(readFileSync(join(root, 'cgroup.procs'), 'utf8').trim(), '', 'delegation root must be empty');
  writeFileSync(join(root, 'cgroup.subtree_control'), '+cpu +memory +pids\n');
  const enabled = readFileSync(join(root, 'cgroup.subtree_control'), 'utf8').trim().split(/\s+/);
  for (const controller of controllers) assert(enabled.includes(controller), `${controller} enable failed`);
  const workerRoot = join(root, `worker-${invocationId}`);
  mkdirSync(workerRoot, { mode: 0o700 });
  for (const [name, value] of Object.entries(limits)) {
    writeFileSync(join(workerRoot, name), `${value}\n`);
    assert.equal(readFileSync(join(workerRoot, name), 'utf8').trim(), value, `${name} readback failed`);
  }
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
  publish(join(output, `${invocationId}.json`), { diagnosticOnly: true, invocationId, unit, mode,
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
  const report = { schemaVersion: 1, diagnosticOnly: true,
    scope: 'systemd-user dummy OS lifecycle; not installed Supervisor or death authority',
    bootId, nodeVersion: process.version, cgroupNamespace: readlinkSync('/proc/self/ns/cgroup'), manager,
    kernelRelease: command('/usr/bin/uname', ['-r']).stdout.trim(),
    systemdVersion: command('/usr/bin/systemctl', ['--version']).stdout.split('\n')[0], cases: [] };
  const ready = (scenario, shown) => {
    if (!/^[a-f0-9]{32}$/.test(shown.InvocationID ?? '')) return undefined;
    const path = join(scenario.directory, `${shown.InvocationID}.json`);
    if (!existsSync(path)) return undefined;
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    let data;
    try {
      const metadata = fstatSync(fd);
      assert(metadata.isFile() && metadata.uid === config.uid && metadata.nlink === 1 && metadata.size <= 32 * 1024,
        'unexpected diagnostic readiness file');
      data = JSON.parse(readFileSync(fd, 'utf8'));
    } finally { closeSync(fd); }
    assert.equal(data.invocationId, shown.InvocationID);
    assert.equal(data.uid, config.uid);
    assert.equal(data.main.pid, Number(shown.MainPID));
    assert.equal(data.unit, scenario.unit);
    assert.equal(data.mode, scenario.mode);
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
    assert.equal(data.root.path, root);
    assert.equal(data.workerRoot.path, join(root, `worker-${shown.InvocationID}`));
    assert(sameDirectory(directoryFact(root), data.root), 'root identity drift at readiness');
    assert(sameDirectory(directoryFact(data.workerRoot.path), data.workerRoot), 'worker cgroup drift at readiness');
    const actualWorker = processFact(data.worker.pid);
    if (scenario.mode === 'live') {
      assert(actualWorker.present && actualWorker.uid === config.uid && actualWorker.state !== 'Z', 'live worker missing');
      assert.equal(actualWorker.startTimeTicks, data.worker.startTimeTicks);
      assert.equal(cgroupPath(actualWorker.cgroupPath), data.workerRoot.path);
    } else assert(!actualWorker.present, 'empty worker is still present');
    assert.deepEqual(data.limits, limits, 'unexpected diagnostic limits');
    const enabled = readFileSync(join(root, 'cgroup.subtree_control'), 'utf8').trim().split(/\s+/);
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
      const item = { mode: scenario.mode, restart: scenario.restart, unit: scenario.unit };
      report.cases.push(item);
      let rootHeld, workerHeld;
      try {
        systemd('start', scenario.unit);
        const first = await waitReady(scenario, true);
        item.before = first;
        rootHeld = hold(first.data.root.path);
        workerHeld = hold(first.data.workerRoot.path);
        assert(sameDirectory(rootHeld.original, first.data.root), 'root changed before descriptor observation');
        assert(sameDirectory(workerHeld.original, first.data.workerRoot), 'worker root changed before descriptor observation');
        const observe = () => {
          const root = directoryFact(first.data.root.path);
          const workerRoot = directoryFact(first.data.workerRoot.path);
          const oldWorker = processFact(first.data.worker.pid);
          return { root, workerRoot, rootHeldFd: heldFact(rootHeld), workerHeldFd: heldFact(workerHeld),
            oldMain: processFact(first.data.main.pid), oldWorker,
            originalWorkerLifetimePresent: oldWorker.present && oldWorker.startTimeTicks === first.data.worker.startTimeTicks,
            retainedExactCgroupPrerequisite: sameDirectory(root, rootHeld.original) && sameDirectory(workerRoot, workerHeld.original)
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
        systemd('stop', scenario.unit);
      }
    }
  } catch (error) {
    report.error = errorText(error);
    throw error;
  } finally { publish(config.reportFile, report, 0o644); }
}

try {
  const [role, ...args] = process.argv.slice(2);
  if (role === 'worker') await worker(args[0]);
  else if (role === 'main') await main(...args);
  else if (role === 'baseline') publish(args[1], baseline(Number(args[0])), 0o644);
  else if (role === 'compare-baseline') assert.deepEqual(JSON.parse(readFileSync(args[0], 'utf8')), JSON.parse(readFileSync(args[1], 'utf8')),
    'runner user-manager/linger baseline changed; do not repair unrelated runner state');
  else if (role === 'campaign') await campaign(JSON.parse(readFileSync(args[0], 'utf8')));
  else throw new Error('expected main, worker, baseline, compare-baseline, or campaign role');
} catch (error) {
  console.error(errorText(error));
  // A failed dummy may have a forked child/IPC handle; leave no accidental
  // long-lived MainPID. The manager and scoped cleanup own its descendants.
  process.exit(1);
}
