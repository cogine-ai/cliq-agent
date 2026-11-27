import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

/** Private owner shared by the two production native build recipes. A lane
 * remains occupied through original child close, pipe drain and process-group
 * disappearance. Meson keeps --jobs 1, so it never adds a second compiler lane.
 * This is build-process custody, not an installed resource/death authority. */
// Build-only wall time includes queueing and process-group retirement.
export const WORKER_BUILD_TIMEOUT_MS = 8 * 60_000;

export function createWorkerBuildScope(signal) {
  const cancellation = new AbortController(), queued = [], active = new Set(), waiters = [];
  const deadline = performance.now() + WORKER_BUILD_TIMEOUT_MS;
  let refused, revoked = false, disposed = false;
  const retirementErrors = [];
  const groupExists = pid => {
    try { process.kill(-pid, 0); return true; }
    catch (error) { if (error.code === 'ESRCH') return false; throw error; }
  };
  const kill = entry => {
    // A launcher may already have exited while its children still hold pipes.
    if (!entry.child.pid) return;
    try { process.kill(-entry.child.pid, 'SIGKILL'); }
    catch (error) { if (error.code !== 'ESRCH') retirementErrors.push(error); }
  };
  const idle = () => { if (!active.size && !queued.length) for (const resolve of waiters.splice(0)) resolve(); };
  function abort(error = new Error('Production native build was cancelled')) {
    if (!revoked) { revoked = true; refused = error; }
    if (!cancellation.signal.aborted) cancellation.abort(refused);
    for (const entry of queued.splice(0)) entry.reject(refused);
    for (const entry of active) kill(entry);
    idle();
  }
  function assertActive() {
    if (!revoked && performance.now() >= deadline) abort(new Error(`Production native build exceeded ${WORKER_BUILD_TIMEOUT_MS}ms`));
    if (revoked) throw refused;
    if (disposed) throw new Error('Production native build is already joined');
  }
  async function closed(entry, code, childSignal) {
    clearTimeout(entry.timer);
    let error = entry.error;
    if (!error && (code !== 0 || childSignal)) {
      error = Object.assign(new Error(`Native build command failed: ${path.basename(entry.binary)}`),
        { code, signal: childSignal, stdout: entry.stdout.join(''), stderr: entry.stderr.join('') });
      abort(error);
    }
    if (error) Object.assign(error, { stdout: entry.stdout.join(''), stderr: entry.stderr.join('') });
    try {
      if (entry.child.pid && groupExists(entry.child.pid)) {
        if (!revoked) abort(new Error('Native build command left an unjoined process group'));
        kill(entry);
        while (groupExists(entry.child.pid)) {
          if (performance.now() >= deadline) throw new Error('Native build process group did not retire before its original deadline');
          await new Promise(resolve => setTimeout(resolve, 10));
        }
      }
    } catch (failure) { retirementErrors.push(failure); abort(failure); }
    active.delete(entry);
    if (error || revoked) entry.reject(revoked ? refused : error);
    else entry.resolve({ stdout: entry.stdout.join(''), stderr: entry.stderr.join('') });
    pump(); idle();
  }
  function pump() {
    while (!revoked && !disposed && active.size < 2 && queued.length) {
      const entry = queued.shift();
      try {
        assertActive();
        entry.child = spawn(entry.binary, entry.args, { cwd: entry.cwd, env: entry.env,
          detached: true, stdio: entry.inherit ? 'inherit' : ['ignore', 'pipe', 'pipe'] });
      } catch (error) { entry.reject(error); abort(error); break; }
      active.add(entry);
      entry.timer = setTimeout(() => abort(new Error(`Native build command timed out: ${path.basename(entry.binary)}`)),
        Math.max(1, Math.min(entry.timeout, deadline - performance.now())));
      for (const name of ['stdout', 'stderr']) {
        const stream = entry.child[name];
        if (!stream) continue;
        stream.setEncoding('utf8');
        stream.on('data', part => {
          entry[`${name}Bytes`] += Buffer.byteLength(part);
          if (entry[`${name}Bytes`] > 1024 * 1024) abort(new Error('Native build command output exceeded its original 1MiB bound'));
          else entry[name].push(part);
        });
        stream.on('error', error => { entry.error ??= error; abort(error); });
      }
      entry.child.once('error', error => { entry.error ??= error; abort(error); });
      entry.child.once('exit', (code, childSignal) => {
        if (code !== 0 || childSignal) {
          const error = Object.assign(new Error(`Native build command failed: ${path.basename(entry.binary)}`),
            { code, signal: childSignal, stdout: entry.stdout.join(''), stderr: entry.stderr.join('') });
          entry.error ??= error; abort(error);
        }
      });
      entry.child.once('close', (code, childSignal) => { void closed(entry, code, childSignal); });
    }
  }
  const externalAbort = () => abort(signal.reason);
  const terminated = () => abort(new Error('Production native build received SIGTERM'));
  const interrupted = () => abort(new Error('Production native build received SIGINT'));
  process.on('SIGTERM', terminated); process.on('SIGINT', interrupted);
  signal?.addEventListener('abort', externalAbort, { once: true });
  const timer = setTimeout(() => abort(new Error(`Production native build exceeded ${WORKER_BUILD_TIMEOUT_MS}ms`)), WORKER_BUILD_TIMEOUT_MS);
  if (signal?.aborted) externalAbort();
  return Object.freeze({
    signal: cancellation.signal, abort, assertActive,
    run(binary, args, { cwd, env, inherit = false, timeout = WORKER_BUILD_TIMEOUT_MS } = {}) {
      try { assertActive(); } catch (error) { return Promise.reject(error); }
      return new Promise((resolve, reject) => {
        queued.push({ binary, args, cwd, env, inherit, timeout, resolve, reject,
          stdout: [], stderr: [], stdoutBytes: 0, stderrBytes: 0 });
        pump();
      });
    },
    async join() {
      if (active.size || queued.length) await new Promise(resolve => waiters.push(resolve));
      if (retirementErrors.length) throw new AggregateError(
        revoked && !retirementErrors.includes(refused) ? [refused, ...retirementErrors] : retirementErrors,
        'Native build process groups did not join');
    },
    retired() { return !active.size && !queued.length && !retirementErrors.length; },
    dispose() {
      if (active.size || queued.length) throw new Error('Cannot release an unjoined native build owner');
      disposed = true; clearTimeout(timer);
      process.removeListener('SIGTERM', terminated); process.removeListener('SIGINT', interrupted);
      signal?.removeEventListener('abort', externalAbort);
    },
  });
}
export const BUBBLEWRAP_SOURCE = Object.freeze({
  version: '0.12.0',
  url: 'https://github.com/containers/bubblewrap/releases/download/v0.12.0/bubblewrap-0.12.0.tar.xz',
  sha256: '9760d007363e3abba7c747489910f9f82d9fca53ba3bd3282e396fa3c97a3314',
  byteCount: 126452,
});
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export function assertBubblewrapSource(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== BUBBLEWRAP_SOURCE.byteCount ||
      digest(bytes) !== BUBBLEWRAP_SOURCE.sha256) throw new Error('The fixed official bubblewrap source does not match its complete archive hash');
}
async function command(scope, binary, args, cwd) {
  return scope.run(binary, args, { cwd,
    env: { ...process.env, CC: 'cc', LC_ALL: 'C', LANG: 'C', PYTHONDONTWRITEBYTECODE: '1' } });
}

/** Actual argument parsing only. No namespace is created by --help, and this
 * cannot establish that a tmpfs mount, process boundary or Run is qualified. */
export async function assertBubblewrapRecipeSyntax(binary, buildScope) {
  const scope = buildScope ?? createWorkerBuildScope();
  try {
    const before = await lstat(binary);
    if (!before.isFile() || before.nlink !== 1 || ![0, process.getuid()].includes(before.uid) ||
        (before.mode & 0o6022) !== 0 || (before.mode & 0o111) === 0) throw new Error('The bubblewrap build is not a protected non-setuid executable');
    const bytes = await readFile(binary);
    const result = await command(scope, binary, ['--size', '4096', '--tmpfs', '/', '--help']);
    if (result.stderr.length !== 0 || !result.stdout.includes('--size BYTES')) throw new Error('The fixed bubblewrap recipe syntax is unsupported');
    const after = await lstat(binary);
    for (const field of ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(after[field], before[field]);
    assert((await readFile(binary)).equals(bytes));
    return { sha256: digest(bytes), byteCount: bytes.byteLength };
  } catch (error) { scope.abort(error); throw error; }
  finally { if (!buildScope) { try { await scope.join(); scope.assertActive(); } finally { scope.dispose(); } } }
}

/** Developer/package build only. The official archive is fixed and fully
 * verified before extraction or execution. There is no host-PATH fallback.
 * The original RuntimeBundle publisher signs the actual resulting image. */
export async function buildBubblewrap(outputDirectory, stagingParent, offlineSourceBytes, buildScope) {
  if (process.platform !== 'linux' || !path.isAbsolute(outputDirectory) || !path.isAbsolute(stagingParent))
    throw new Error('The fixed bubblewrap build requires Linux and absolute owned build directories');
  const scope = buildScope ?? createWorkerBuildScope();
  let work;
  try {
    scope.assertActive();
    work = await mkdtemp(path.join(stagingParent, 'bubblewrap-'));
    // Offline component builds may supply only these same fully pinned bytes;
    // they cannot select another URL, source, version, flags or executable.
    let archive;
    if (offlineSourceBytes !== undefined) { assertBubblewrapSource(offlineSourceBytes); archive = Buffer.from(offlineSourceBytes); }
    else {
      const response = await fetch(BUBBLEWRAP_SOURCE.url, { signal: AbortSignal.any([scope.signal, AbortSignal.timeout(30000)]) });
      if (!response.ok || !response.body) {
        await response.body?.cancel();
        throw new Error('The fixed official bubblewrap source could not be downloaded');
      }
      const parts = [], reader = response.body.getReader(); let size = 0, failed = false;
      try {
        for (;;) {
          const { value: part, done } = await reader.read();
          if (done) break;
          size += part.byteLength;
          if (size > BUBBLEWRAP_SOURCE.byteCount) throw new Error('The bubblewrap source exceeds its fixed archive length');
          parts.push(Buffer.from(part));
        }
      } catch (error) { failed = true; throw error; }
      finally {
        // Revocation is not the join: the enclosing build task also awaits
        // the issued fetch/read, cancellation and reader.closed settlement.
        // It cannot finish while an owned body reader is still outstanding.
        try {
          if (failed) await Promise.allSettled([reader.cancel(), reader.closed]);
          else await reader.closed;
        } finally { reader.releaseLock(); }
      }
      archive = Buffer.concat(parts); assertBubblewrapSource(archive);
    }
    const archivePath = path.join(work, 'source.tar.xz'), source = path.join(work, 'source'), build = path.join(work, 'build');
    await writeFile(archivePath, archive, { flag: 'wx', mode: 0o600 }); await mkdir(source, { mode: 0o700 });
    // Only the complete pinned upstream archive is accepted. Its two license
    // aliases point to COPYING within this fresh, private extraction tree.
    await command(scope, 'tar', ['--extract', '--xz', '--file', archivePath, '--directory', source, '--strip-components=1',
      '--no-same-owner', '--no-same-permissions', '--keep-old-files'], work);
    const options = ['--buildtype=release', '--wrap-mode=nodownload', '-Dman=disabled', '-Dtests=false',
      '-Dbash_completion=disabled', '-Dzsh_completion=disabled', '-Dselinux=enabled', '-Dassume_kernel=5.6.0'];
    await command(scope, 'meson', ['setup', build, source, ...options], work);
    await command(scope, 'meson', ['compile', '-C', build, '--jobs', '1'], work);
    const built = path.join(build, 'bwrap');
    const image = await assertBubblewrapRecipeSyntax(built, scope);
    const destination = path.join(outputDirectory, 'cliq-linux-bubblewrap');
    await copyFile(built, destination, constants.COPYFILE_EXCL); await chmod(destination, 0o500);
    assert.deepEqual(await assertBubblewrapRecipeSyntax(destination, scope), image);
    const compiler = await command(scope, 'cc', ['--version'], work), meson = await command(scope, 'meson', ['--version'], work);
    const libcap = await command(scope, 'pkg-config', ['--modversion', 'libcap'], work);
    const selinux = await command(scope, 'pkg-config', ['--modversion', 'libselinux'], work);
    const provenance = { format: 'cliq-bubblewrap-build-provenance-v1', source: BUBBLEWRAP_SOURCE,
      build: { options, jobs: 1, compilerVersion: compiler.stdout, mesonVersion: meson.stdout.trim(), libcapVersion: libcap.stdout.trim(), selinuxVersion: selinux.stdout.trim(),
        environmentFlags: { CFLAGS: process.env.CFLAGS ?? '', CPPFLAGS: process.env.CPPFLAGS ?? '', LDFLAGS: process.env.LDFLAGS ?? '',
          CPATH: process.env.CPATH ?? '', LIBRARY_PATH: process.env.LIBRARY_PATH ?? '' } },
      image, syntaxProbeExecuted: true, namespaceAndTmpfsQualificationClaimed: false, hostFallbackUsed: false, setuidSupported: false };
    await writeFile(path.join(outputDirectory, 'cliq-linux-bubblewrap.provenance.json'), JSON.stringify(provenance, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return provenance;
  } catch (error) { scope.abort(error); throw error; }
  finally {
    if (!buildScope) {
      try { await scope.join(); scope.assertActive(); }
      finally {
        scope.dispose();
        if (work && scope.retired()) await rm(work, { recursive: true, force: true });
      }
    } else if (work && scope.retired()) await rm(work, { recursive: true, force: true });
  }
}
