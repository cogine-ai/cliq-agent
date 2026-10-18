import path from 'node:path';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, mkdir, open, type FileHandle } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalJsonBytes } from '../kernel/canonical.js';
import { normalizeAbsolutePath } from '../kernel/identity.js';
import { immutableSnapshot } from '../model/immutable.js';
import { decodeCredentialPlatformUser, decodeUserManagerObservation, type CredentialPlatformUser,
  type InstalledUnitObservation, type NativeCredentialPlatformBinding, type UserManagerObservation } from './credential-platform.js';
import { KernelStorageError, ResourceRetirementError } from './errors.js';
import { assertInstalledManagerObservationAvailable, loadInstalledCredentialPlatform, loadInstalledManagerObserver, withHeldInstalledRuntime,
  type HeldInstalledRuntime, type InstalledManagerObserver } from './installed-runtime.js';
import { stateRootIdentityFromDescriptor } from './native-owner.js';

// The initial ELF must not consume these loading inputs before the signed
// bootstrap can perform its own closed-environment descriptor exec.
const loaderVariables = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG', 'LD_DEBUG_OUTPUT',
  'LD_PROFILE', 'LD_PROFILE_OUTPUT', 'LD_ORIGIN_PATH', 'LD_TRACE_LOADED_OBJECTS', 'LD_TRACE_PRELINKING',
  'LD_WARN', 'LD_VERBOSE', 'LD_BIND_NOW', 'LD_BIND_NOT', 'LD_DYNAMIC_WEAK', 'LD_HWCAP_MASK',
  'LD_SHOW_AUXV', 'LD_USE_LOAD_BIAS', 'LD_ASSUME_KERNEL', 'GCONV_PATH', 'LOCPATH', 'GLIBC_TUNABLES',
  'NODE_COMPILE_CACHE', 'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_ICU_DATA',
  'NODE_REDIRECT_WARNINGS', 'NODE_REPL_EXTERNAL_MODULE', 'NODE_V8_COVERAGE', 'OPENSSL_CONF',
  'OPENSSL_CONF_INCLUDE', 'OPENSSL_MODULES', 'OPENSSL_ENGINES', 'SSL_CERT_DIR', 'SSL_CERT_FILE'] as const;
const fixedEnvironment = ['PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C'] as const;
type Profile = Readonly<{ role: 'keeper' | 'supervisor'; unit: string; text: string; executable: string;
  args: readonly string[]; flags: readonly string[] }>;
type Profiles = Readonly<{ keeper: Profile; supervisor: Profile }>;
let retirementFailure: ResourceRetirementError | undefined;

function refuse(message: string, cause?: unknown): never {
  throw new KernelStorageError('RECOVERY_REQUIRED', message, cause === undefined ? undefined : { cause });
}
function healthy(): void { if (retirementFailure) throw retirementFailure; }
function equalStrings(actual: readonly string[], expected: readonly string[]): boolean {
  const sorted = [...expected].sort();
  return actual.length === expected.length && [...actual].sort().every((entry, index) => entry === sorted[index]);
}
function commandWord(value: string): string {
  const escaped = value.replace(/%/gu, '%%').replace(/["\x00-\x1f\x7f]/gu, character =>
    character === '"' ? '\\"' : `\\x${character.charCodeAt(0).toString(16).padStart(2, '0')}`);
  return /^[A-Za-z0-9_./:+-]+$/u.test(escaped) ? escaped : `"${escaped}"`;
}

/** Pure profile bytes only, never an installation/proof/native factory. Unit
 * names retain the full StateRoot identity digest, not a truncated pathname. */
export function installedServiceProfiles(stateRoot: string, rootIdentityDigest: string): Profiles {
  if (normalizeAbsolutePath(stateRoot) !== stateRoot || !/^[0-9a-f]{64}$/u.test(rootIdentityDigest))
    throw new TypeError('installed service profile requires a canonical root and complete identity digest');
  // ExecStart validates the decoded executable with systemd's string_is_safe;
  // unit quoting or C-escaping cannot make these filesystem bytes acceptable.
  if (/[\x00-\x1f\x7f"']/u.test(stateRoot))
    throw new TypeError('installed service root contains characters forbidden in a systemd executable path');
  const executable = path.join(stateRoot, 'runtime/bootstrap');
  const keeper = `cliq-${rootIdentityDigest}-keeper.service`, supervisor = `cliq-${rootIdentityDigest}-supervisor.service`;
  // ':' suppresses environment expansion for literal dollar-bearing paths.
  // It is a fixed parser flag, never a shell or caller-selected command.
  const flags = executable.includes('$') ? ['no-env-expand'] : [];
  const word = commandWord(`${flags.length ? ':' : ''}${executable}`);
  const make = (role: Profile['role'], unit: string): Profile => Object.freeze({ role, unit, executable,
    args: Object.freeze([executable, `--bootstrap-${role}`]), flags: Object.freeze([...flags]), text:
      `[Unit]\nDescription=Cliq installed ${role}\nStartLimitIntervalSec=30s\nStartLimitBurst=${role === 'keeper' ? 2 : 4}\n` +
      (role === 'supervisor' ? `Requires=${keeper}\nAfter=${keeper}\n` : '') +
      `[Service]\nType=exec\nWorkingDirectory=/\nExecStart=${word} --bootstrap-${role}\n` +
      `UnsetEnvironment=${loaderVariables.join(' ')}\nEnvironment=${fixedEnvironment.join(' ')}\n` +
      `UMask=0077\nSlice=app.slice\nDelegate=cpu memory pids\nKillMode=control-group\nRestart=${role === 'keeper' ? 'no' : 'on-failure'}\n` +
      'RestartSec=2s\nTimeoutStartSec=30s\nTimeoutStopSec=2s\n' });
  return Object.freeze({ keeper: make('keeper', keeper), supervisor: make('supervisor', supervisor) });
}

type Directory = { handle: FileHandle; info: BigIntStats; parent?: Directory; name: string };
type HeldProfile = { handle: FileHandle; info: BigIntStats; parent: Directory; profile: Profile };
const directoryFields = ['dev', 'ino', 'uid', 'gid', 'mode'] as const;
const fileFields = [...directoryFields, 'size', 'nlink', 'mtimeNs', 'ctimeNs'] as const;
function matches(left: BigIntStats, right: BigIntStats, fields: readonly (keyof BigIntStats)[]): boolean {
  return fields.every(key => left[key] === right[key]);
}
function child(parent: Directory, name: string): string { return `/proc/self/fd/${parent.handle.fd}/${name}`; }

/** All paths are reached through retained no-follow ancestor descriptors. A
 * failed close is consumed once and poisons this owner, never retried by fd. */
class ProfileScope {
  private readonly handles = new Set<FileHandle>();
  private readonly directories: Directory[] = [];
  private readonly files: HeldProfile[] = [];
  constructor(private readonly uid: number) {}
  private own(handle: FileHandle): FileHandle { this.handles.add(handle); return handle; }
  private checkDirectory(info: BigIntStats, userOwned: boolean): void {
    if (!info.isDirectory() || (userOwned ? info.uid !== BigInt(this.uid) : info.uid !== 0n && info.uid !== BigInt(this.uid)) ||
        (userOwned && (info.mode & 0o022n) !== 0n)) refuse('installed service profile directory is not a safe same-user directory');
  }
  private async assertDirectory(directory: Directory): Promise<void> {
    const held = await directory.handle.stat({ bigint: true });
    const named = await lstat(directory.parent ? child(directory.parent, directory.name) : '/', { bigint: true });
    if (!matches(directory.info, held, directoryFields) || !matches(held, named, directoryFields))
      refuse('installed service profile directory identity changed');
  }
  async assertHeld(): Promise<void> {
    healthy();
    for (const directory of this.directories) await this.assertDirectory(directory);
    for (const file of this.files) {
      const held = await file.handle.stat({ bigint: true }), named = await lstat(child(file.parent, file.profile.unit), { bigint: true });
      if (!matches(file.info, held, fileFields) || !matches(held, named, fileFields)) refuse('installed service profile identity changed');
    }
  }
  async profilesDirectory(home: string, create: boolean): Promise<Directory> {
    const root = this.own(await open('/', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    let parent: Directory = { handle: root, info: await root.stat({ bigint: true }), name: '/' };
    this.checkDirectory(parent.info, false); this.directories.push(parent);
    const components = normalizeAbsolutePath(home).split('/').slice(1);
    for (let index = 0; index < components.length; index++) parent = await this.directory(parent, components[index]!, false, index === components.length - 1);
    for (const name of ['.config', 'systemd', 'user']) parent = await this.directory(parent, name, create, true);
    await this.assertHeld(); return parent;
  }
  private async directory(parent: Directory, name: string, create: boolean, userOwned: boolean): Promise<Directory> {
    await this.assertDirectory(parent);
    if (create) {
      try { await mkdir(child(parent, name), { mode: 0o700 }); await parent.handle.sync(); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    }
    const named = await lstat(child(parent, name), { bigint: true }); this.checkDirectory(named, userOwned);
    const handle = this.own(await open(child(parent, name), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW));
    const info = await handle.stat({ bigint: true }); this.checkDirectory(info, userOwned);
    if (!matches(named, info, directoryFields)) refuse('installed service directory changed while opening');
    const result = { handle, info, parent, name }; this.directories.push(result);
    await this.assertDirectory(parent); return result;
  }
  async read(parent: Directory, profile: Profile): Promise<boolean> {
    await this.assertHeld();
    let handle: FileHandle;
    try { handle = this.own(await open(child(parent, profile.unit), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
    const info = await handle.stat({ bigint: true }), expected = Buffer.from(profile.text);
    if (!info.isFile() || info.uid !== BigInt(this.uid) || info.nlink !== 1n || (info.mode & 0o7777n) !== 0o600n || info.size !== BigInt(expected.length))
      refuse('installed service profile is incompatible; restore the fixed profile explicitly');
    const bytes = await handle.readFile();
    if (!bytes.equals(expected)) refuse('installed service profile was edited; it will not be overwritten');
    this.files.push({ handle, info, parent, profile }); await this.assertHeld(); return true;
  }
  async create(parent: Directory, profile: Profile): Promise<void> {
    await this.assertHeld();
    let handle: FileHandle;
    try { handle = this.own(await open(child(parent, profile.unit), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST' && await this.read(parent, profile)) return;
      throw error;
    }
    await handle.writeFile(profile.text); await handle.sync();
    const info = await handle.stat({ bigint: true });
    if (!info.isFile() || info.uid !== BigInt(this.uid) || info.nlink !== 1n || (info.mode & 0o7777n) !== 0o600n || info.size !== BigInt(Buffer.byteLength(profile.text)))
      refuse('new installed service profile does not retain its fixed identity');
    this.files.push({ handle, info, parent, profile }); await parent.handle.sync(); await this.assertHeld();
  }
  async close(): Promise<void> {
    const handles = [...this.handles].reverse(); this.handles.clear();
    const results = await Promise.allSettled(handles.map(handle => handle.close()));
    const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
    if (failures.length) {
      retirementFailure ??= new ResourceRetirementError('installed service profile descriptors did not retire', failures.map(result => result.reason));
      throw retirementFailure;
    }
  }
}

function checkedManager(value: unknown, kind: UserManagerObservation['kind'], user: CredentialPlatformUser): UserManagerObservation {
  const observation = decodeUserManagerObservation(value);
  if (observation.kind !== kind || observation.uid !== user.uid || observation.gid !== user.gid || observation.home !== user.home)
    refuse('installed user manager identity differs from the current same-user installation');
  return observation;
}
function checkEffectiveUnit(observation: UserManagerObservation, profile: Profile, profiles: Profiles, directory: string): InstalledUnitObservation {
  const unit = observation.unit;
  if (!unit || unit.Id !== profile.unit || !equalStrings(unit.Names, [profile.unit]) || unit.Following || unit.LoadState !== 'loaded' ||
      unit.FragmentPath !== path.join(directory, profile.unit) || unit.SourcePath || unit.DropInPaths.length || unit.NeedDaemonReload || unit.Transient ||
      unit.Type !== 'exec' || unit.ExecStart.length !== 1 || unit.ExecStart[0]!.path !== profile.executable ||
      !canonicalJsonBytes(unit.ExecStart[0]!.argv).equals(canonicalJsonBytes(profile.args)) || !equalStrings(unit.ExecStart[0]!.flags, profile.flags) ||
      !unit.Delegate || !equalStrings(unit.DelegateControllers, ['cpu', 'memory', 'pids']) || unit.KillMode !== 'control-group' ||
      unit.KillSignal !== 15 || !unit.SendSIGKILL || unit.Restart !== (profile.role === 'keeper' ? 'no' : 'on-failure') ||
      unit.RestartUSec !== '2000000' || unit.TimeoutStartUSec !== '30000000' || unit.TimeoutStopUSec !== '2000000' || unit.UMask !== 0o077 ||
      !equalStrings(unit.Environment, fixedEnvironment) || !equalStrings(unit.UnsetEnvironment, loaderVariables) ||
      unit.EnvironmentFiles.length || unit.PassEnvironment.length || unit.User || unit.Group || unit.DynamicUser || unit.PAMName ||
      unit.WorkingDirectory !== '/' || unit.RootDirectory || unit.RootImage ||
      [unit.ExecCondition, unit.ExecStartPre, unit.ExecStartPost, unit.ExecReload, unit.ExecStop, unit.ExecStopPost,
        unit.Requisite, unit.Wants, unit.BindsTo, unit.PartOf, unit.OnFailure, unit.OnSuccess].some(values => values.length))
    refuse('installed service effective configuration drifted; explicit installation remediation is required');
  // Only systemd's ordinary initialization/shutdown dependencies may accompany
  // the fixed Supervisor→keeper edge. The explicit '/' working directory adds
  // ordering after the perpetual root mount, not permission to start a mount.
  // Loading Supervisor also mirrors its After=keeper as keeper.Before=Supervisor.
  const required = ['app.slice', ...(profile.role === 'supervisor' ? [profiles.keeper.unit] : [])];
  const before = ['shutdown.target', ...(profile.role === 'keeper' ? [profiles.supervisor.unit] : [])];
  if (!required.every(name => unit.Requires.includes(name) && unit.After.includes(name)) ||
      unit.Requires.some(name => ![...required, 'sysinit.target', 'basic.target'].includes(name)) ||
      unit.After.some(name => ![...required, '-.mount', 'sysinit.target', 'basic.target', 'systemd-journald.socket'].includes(name)) ||
      unit.Before.some(name => !before.includes(name)) || unit.Conflicts.some(name => name !== 'shutdown.target'))
    refuse('installed service dependencies differ from the fixed profiles');
  return unit;
}

async function withProfiles<T, P extends NativeCredentialPlatformBinding | InstalledManagerObserver>(selected: HeldInstalledRuntime,
  create: boolean, platform: P,
  operation: (input: { platform: P; user: CredentialPlatformUser; profiles: Profiles;
    scope: ProfileScope; directory: Directory; directoryPath: string; stateRoot: string }) => Promise<T>): Promise<T> {
  // Both fixed loaders look up the genuine selection before observing caller
  // properties. The ordinary client supplies no mutating platform capability.
  healthy();
  assertInstalledManagerObservationAvailable(selected);
  return withHeldInstalledRuntime(selected, async installed => {
    // A cached native capability still observes the user anew, only after this
    // borrow's full-byte entry revalidation. Metadata is never its substitute.
    const user = decodeCredentialPlatformUser(platform.currentUser());
    if (process.platform !== 'linux' || user.uid !== process.geteuid!() || user.gid !== process.getegid!() || normalizeAbsolutePath(user.home) !== user.home)
      refuse('installed service setup requires the actual same-user Linux passwd home');
    if (installed.stateRoot.ownerUid !== user.uid) refuse('installed service root owner differs from the actual user');
    const root = stateRootIdentityFromDescriptor(installed.stateRoot.canonicalPath, installed.stateRoot);
    const profiles = installedServiceProfiles(root.canonicalAbsolutePath, root.identityDigest), scope = new ProfileScope(user.uid);
    try {
      const directory = await scope.profilesDirectory(user.home, create);
      // Each read owns descriptors. Do not fail-fast into close while a sibling
      // could still open/register one; these two bounded reads need no fanout.
      const present = [await scope.read(directory, profiles.keeper), await scope.read(directory, profiles.supervisor)];
      if (!create && present.some(value => !value)) refuse('installed service profiles are missing; run explicit install_services setup');
      if (create) {
        if (!present[0]) await scope.create(directory, profiles.keeper);
        if (!present[1]) await scope.create(directory, profiles.supervisor);
      }
      await installed.revalidate();
      const result = await operation({ platform, user, profiles, scope, directory,
        directoryPath: path.join(user.home, '.config/systemd/user'), stateRoot: root.canonicalAbsolutePath });
      await scope.assertHeld(); await installed.revalidate(); return result;
    } catch (error) {
      if (error instanceof KernelStorageError) throw error;
      refuse('installed profiles or user manager are unavailable; explicit installation remediation is required');
    } finally { await scope.close(); }
  });
}

/** Explicit same-user setup only: create missing fixed bytes, fsync, reload.
 * It never overwrites edited profiles, enables units or starts the manager. */
export async function installServices(selected: HeldInstalledRuntime): Promise<Readonly<{ keeperUnit: string; supervisorUnit: string }>> {
  return withProfiles(selected, true, await loadInstalledCredentialPlatform(selected), async ({ platform, user, profiles, scope, directoryPath }) => {
    checkedManager(await platform.userManager({ kind: 'reload' }), 'reload', user); await scope.assertHeld();
    for (const profile of [profiles.keeper, profiles.supervisor])
      checkEffectiveUnit(checkedManager(await platform.userManager({ kind: 'inspect', unit: profile.unit }), 'inspect', user), profile, profiles, directoryPath);
    return Object.freeze({ keeperUnit: profiles.keeper.unit, supervisorUnit: profiles.supervisor.unit });
  });
}

export type InstalledCredentialSupervisorObservation = Readonly<{ stateRoot: string; uid: number; gid: number;
  supervisor: InstalledUnitObservation; keeper: InstalledUnitObservation; manager: UserManagerObservation['manager']; bus: UserManagerObservation['bus'] }>;

async function keeperReadyHint(stateRoot: string, uid: number): Promise<boolean> {
  const filename = path.join(stateRoot, 'runtime/keeper.ready');
  let handle: FileHandle;
  try { handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
  try {
    const info = await handle.stat({ bigint: true }), named = await lstat(filename, { bigint: true });
    if (!info.isFile() || info.uid !== BigInt(uid) || (info.mode & 0o7777n) !== 0o600n || info.nlink !== 1n || info.size !== 40n ||
        !matches(info, named, fileFields)) refuse('installed keeper scheduling locator has an invalid physical identity');
    return true;
  } finally {
    try { await handle.close(); }
    catch (error) { retirementFailure ??= new ResourceRetirementError('installed keeper scheduling descriptor did not retire', error); throw retirementFailure; }
  }
}

/** Fixed internal friend: callers cannot choose a unit, manager, PID or profile.
 * Ordinary clients observe only; explicit credential ensure may start already
 * compatible profiles, never install or reload them. */
async function observeSupervisor(selected: HeldInstalledRuntime, platform: NativeCredentialPlatformBinding | InstalledManagerObserver,
  credentialPlatform?: NativeCredentialPlatformBinding): Promise<InstalledCredentialSupervisorObservation> {
  return withProfiles(selected, false, platform, async ({ platform, user, profiles, scope, directoryPath, stateRoot }) => {
    const inspect = async (profile: Profile) => {
      const result = 'inspect' in platform ? await platform.inspect(profile.unit)
        : await platform.userManager({ kind: 'inspect', unit: profile.unit });
      const observation = checkedManager(result, 'inspect', user);
      return { observation, unit: checkEffectiveUnit(observation, profile, profiles, directoryPath) };
    };
    let keeper = await inspect(profiles.keeper), supervisor = await inspect(profiles.supervisor);
    if (credentialPlatform && supervisor.unit.ActiveState !== 'active' && supervisor.unit.ActiveState !== 'activating') {
      if (keeper.unit.ActiveState === 'failed') refuse('installed keeper failed; explicit containment recovery is required');
      if (keeper.unit.ActiveState !== 'active' && keeper.unit.ActiveState !== 'activating') {
        checkedManager(await credentialPlatform.userManager({ kind: 'start', unit: profiles.keeper.unit }), 'start', user);
        keeper = await inspect(profiles.keeper);
      }
      // Type=exec orders only initial ELF startup, not keeper publication.
      // This is a bounded scheduling hint; native Supervisor.acquireAnchor
      // still verifies the sole original descriptor/process/root proof.
      const deadline = performance.now() + 30000;
      for (;;) {
        if (keeper.unit.ActiveState === 'active' && keeper.unit.SubState === 'running' && keeper.unit.MainPID > 0 &&
            keeper.unit.MainPID === keeper.unit.ExecMainPID && /^[0-9a-f]{32}$/u.test(keeper.unit.InvocationID) &&
            await keeperReadyHint(stateRoot, user.uid)) break;
        if (performance.now() >= deadline || keeper.unit.ActiveState === 'failed') refuse('installed keeper did not publish its bounded startup locator');
        await delay(20); keeper = await inspect(profiles.keeper);
      }
      await scope.assertHeld();
      // This fixed native inspect also revalidates the genuine held selection
      // after the named-file hint and immediately before starting Supervisor.
      const readyKeeper = keeper.unit; keeper = await inspect(profiles.keeper);
      if (keeper.unit.ActiveState !== 'active' || keeper.unit.SubState !== 'running' || keeper.unit.MainPID !== readyKeeper.MainPID ||
          keeper.unit.ExecMainPID !== readyKeeper.ExecMainPID || keeper.unit.InvocationID !== readyKeeper.InvocationID ||
          keeper.unit.ControlGroup !== readyKeeper.ControlGroup)
        refuse('installed keeper invocation changed after its startup scheduling hint');
      checkedManager(await credentialPlatform.userManager({ kind: 'start', unit: profiles.supervisor.unit }), 'start', user);
      keeper = await inspect(profiles.keeper); supervisor = await inspect(profiles.supervisor);
    }
    if (!canonicalJsonBytes(keeper.observation.bus).equals(canonicalJsonBytes(supervisor.observation.bus)) ||
        !canonicalJsonBytes(keeper.observation.manager).equals(canonicalJsonBytes(supervisor.observation.manager)))
      refuse('user manager changed across installed service observations');
    return immutableSnapshot({ stateRoot, uid: user.uid, gid: user.gid, supervisor: supervisor.unit, keeper: keeper.unit,
      manager: supervisor.observation.manager, bus: supervisor.observation.bus });
  });
}

/** One connection reuses only its original loaded platform. Each observation
 * opens, reads in full and joins a new ProfileScope; no profile inode, manager
 * observation, user identity or full-byte validation result is cached. */
export async function loadInstalledSupervisorObserver(selected: HeldInstalledRuntime, purpose: 'control' | 'credential') {
  if (purpose !== 'control' && purpose !== 'credential') throw new TypeError('invalid installed service observation purpose');
  const credentialPlatform = purpose === 'credential' ? await loadInstalledCredentialPlatform(selected) : undefined;
  let managerObserver = purpose === 'control' ? await loadInstalledManagerObserver(selected) : undefined;
  const observer = Object.freeze({
    observe(this: unknown, startIfNeeded = false): Promise<InstalledCredentialSupervisorObservation> {
      if (this !== observer || typeof startIfNeeded !== 'boolean' || startIfNeeded && !credentialPlatform)
        return Promise.reject(new TypeError('installed observation requires its original fixed-purpose connection'));
      // These synchronous original gates precede enqueue. The real manager
      // operation below uses its existing direct native job registry, never
      // another load/borrow that would wait on this cut's own selection tail.
      assertInstalledManagerObservationAvailable(selected);
      if (startIfNeeded && credentialPlatform) return observeSupervisor(selected, credentialPlatform, credentialPlatform);
      // A readonly cut retains the original readonly facade's per-call Busy
      // checks; a previously loaded credential capability is not its substitute.
      if (managerObserver) return observeSupervisor(selected, managerObserver);
      return loadInstalledManagerObserver(selected).then(platform => {
        managerObserver = platform;
        return observeSupervisor(selected, platform);
      });
    },
  });
  return observer;
}

export async function observeInstalledCredentialSupervisor(selected: HeldInstalledRuntime, startIfNeeded = false): Promise<InstalledCredentialSupervisorObservation> {
  const observer = await loadInstalledSupervisorObserver(selected, startIfNeeded ? 'credential' : 'control');
  return observer.observe(!!startIfNeeded);
}
