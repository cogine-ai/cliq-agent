#!/usr/bin/env bash
# Disposable actual-systemd-user lifecycle diagnostics. --installed instead
# qualifies the real signed keeper/Supervisor owner chain, not full I1 or
# containment-death authority. --secrets observes credential-platform and SQLite
# path prerequisites without qualifying production credential authority.
# --credentials exercises one actual installed enrollment/read journey, not I1.
# Invoke with sudo, an absolute existing Node path
# and an optional new output directory. Do not run on a host
# without an independently disposable test UID and actual systemd user manager.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

probe_campaign_kind=diagnostic
case ${1:-} in
  --installed) probe_campaign_kind=installed; shift ;;
  --installed-retirement-refusal) probe_campaign_kind=retirement; shift ;;
  --secrets) probe_campaign_kind=secrets; shift ;;
  --credentials) probe_campaign_kind=credentials; shift ;;
  --run-journey) probe_campaign_kind=run-journey; shift ;;
esac
readonly probe_campaign_kind
if [[ $(id -u) != 0 || $# -lt 1 || $# -gt 2 ]]; then
  printf 'usage: sudo bash %s [--installed|--installed-retirement-refusal|--secrets|--credentials|--run-journey] ABSOLUTE_NODE_PATH [NEW_OUTPUT_DIRECTORY]\n' "$0" >&2
  exit 2
fi
readonly probe_node=$1
[[ "$probe_node" = /* && -f "$probe_node" && -x "$probe_node" && ! -L "$probe_node" ]] || {
  printf 'Node must be an absolute existing non-symlink executable\n' >&2; exit 2;
}
[[ "$probe_node" =~ ^/[a-zA-Z0-9_./+-]+$ ]] || {
  printf 'Node path must not contain systemd command-line metacharacters\n' >&2; exit 2;
}
[[ ${SUDO_UID:-} =~ ^[0-9]+$ && ${SUDO_UID:-0} -gt 0 ]] || {
  printf 'invoke through sudo from the runner user so its baseline can be preserved\n' >&2; exit 2;
}
readonly probe_runner_uid=$SUDO_UID
readonly probe_source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly probe_source="$probe_source_dir/systemd-user-probe.mjs"
[[ -f "$probe_source" && ! -L "$probe_source" ]] || exit 2
readonly probe_birth_source="$probe_source_dir/cliq-anchor-birth-probe.c"
[[ -f "$probe_birth_source" && ! -L "$probe_birth_source" ]] || exit 2
readonly probe_installed_driver="$probe_source_dir/qualify-installed-keeper.ts"
[[ ( "$probe_campaign_kind" != installed && "$probe_campaign_kind" != retirement ) || ( -f "$probe_installed_driver" && ! -L "$probe_installed_driver" ) ]] || exit 2
readonly probe_secret_driver="$probe_source_dir/qualify-secret-service.ts"
readonly probe_secret_source="$probe_source_dir/cliq-secret-service-probe.c"
readonly probe_sqlite_driver="$probe_source_dir/qualify-sqlite-paths.ts"
readonly probe_credential_driver="$probe_source_dir/testing/credential-installed-journey.ts"
readonly probe_credential_source="$probe_source_dir/testing/credential-journey-observer.c"
readonly probe_credential_store_source="$probe_source_dir/testing/credential-store-fixture.c"
readonly probe_run_driver="$probe_source_dir/qualify-installed-run-journey.ts"
if [[ "$probe_campaign_kind" = installed || "$probe_campaign_kind" = retirement || "$probe_campaign_kind" = secrets || "$probe_campaign_kind" = credentials || "$probe_campaign_kind" = run-journey ]]; then
  probe_typescript_driver=$probe_installed_driver
  if [[ "$probe_campaign_kind" = secrets ]]; then
    probe_typescript_driver=$probe_secret_driver
    [[ -f "$probe_secret_driver" && ! -L "$probe_secret_driver" && -f "$probe_secret_source" && ! -L "$probe_secret_source" ]] || exit 2
    [[ -f "$probe_sqlite_driver" && ! -L "$probe_sqlite_driver" ]] || exit 2
  fi
  if [[ "$probe_campaign_kind" = credentials ]]; then
    probe_typescript_driver=$probe_credential_driver
    [[ -f "$probe_credential_driver" && ! -L "$probe_credential_driver" && -f "$probe_credential_source" && ! -L "$probe_credential_source" ]] || exit 2
    [[ -f "$probe_credential_store_source" && ! -L "$probe_credential_store_source" ]] || exit 2
  fi
  if [[ "$probe_campaign_kind" = run-journey ]]; then
    probe_typescript_driver=$probe_run_driver
    [[ -f "$probe_run_driver" && ! -L "$probe_run_driver" && -f "$probe_credential_source" && ! -L "$probe_credential_source" ]] || exit 2
  fi
  probe_installed_loader=$("$probe_node" --input-type=module -e \
    'import { createRequire } from "node:module"; process.stdout.write(createRequire(process.argv[1]).resolve("tsx"));' \
    "$probe_typescript_driver")
  [[ "$probe_installed_loader" = /* && -f "$probe_installed_loader" ]] || exit 2
  readonly probe_installed_loader
fi
[[ $(stat -f -c '%t' /sys/fs/cgroup) = 63677270 ]] || {
  printf 'actual unified cgroup v2 is required\n' >&2; exit 2;
}
[[ $(cat /proc/1/comm) = systemd ]] || {
  printf 'actual systemd PID 1 is required; no child-manager fallback\n' >&2; exit 2;
}

if [[ $# = 2 ]]; then
  [[ "$2" = /* && ! -e "$2" && ! -L "$2" ]] || {
    printf 'output directory must be absolute and not already exist\n' >&2; exit 2;
  }
  mkdir -m 0755 -- "$2"
  readonly probe_output=$2
else
  readonly probe_output=$(mktemp -d /var/tmp/cliq-systemd-probe-output.XXXXXX)
  chmod 0755 "$probe_output"
fi
readonly probe_fixture=$(mktemp -d /var/tmp/cliq-systemd-probe.XXXXXX)
# Native actual-image inspection read-opens every ancestor. This root-owned
# stage is readable, never writable, by the disposable UID; private trees below
# it retain 0700. Do not make the package or StateRoot public to bypass checks.
chmod 0755 "$probe_fixture"
readonly probe_fixture_identity=$(stat -c '%d:%i:%u' "$probe_fixture")
readonly probe_suffix=${probe_fixture##*.}
readonly probe_username="cliq-probe-${probe_suffix,,}"
readonly probe_home="$probe_fixture/home"
readonly probe_skel="$probe_fixture/empty-skel"
readonly probe_mail="$probe_fixture/mail"
readonly probe_script="$probe_fixture/systemd-user-probe.mjs"
readonly probe_birth_helper="$probe_fixture/cliq-anchor-birth-probe"
readonly probe_secret_helper="$probe_fixture/cliq-secret-service-probe"
readonly probe_anchor_unit="cliq-probe-$probe_suffix-anchor.service"
readonly probe_anchor_directory="$probe_home/probe/anchor"
readonly probe_installed_keeper_unit="cliq-probe-$probe_suffix-installed-keeper.service"
readonly probe_installed_supervisor_unit="cliq-probe-$probe_suffix-installed-supervisor.service"
readonly probe_installed_state="$probe_home/probe/installed-state"
readonly probe_ledger="$probe_fixture/ownership-ledger.json"
readonly probe_volume_image="$probe_fixture/run-home.ext4"
readonly probe_volume_original="$probe_fixture/run-home-original.json"
readonly probe_volume_mounted="$probe_fixture/run-home-mounted.json"
readonly probe_before="$probe_output/runner-baseline-before.json"
readonly probe_after="$probe_output/runner-baseline-after.json"
probe_created=0
probe_group_created=0
probe_ledger_digest=''
probe_uid=''
probe_gid=''
probe_dropin=''
probe_dropin_directory=''
probe_dropin_created=0
probe_dropin_digest=''
probe_manager_cgroup=''
probe_cleanup_errors=0
probe_units=()

probe_fail_cleanup() {
  printf 'cleanup: %s\n' "$*" >&2
  probe_cleanup_errors=$((probe_cleanup_errors + 1))
}

probe_user_systemctl() {
  runuser --user "$probe_username" -- env -i \
    HOME="$probe_home" PATH=/usr/bin:/bin LC_ALL=C \
    XDG_RUNTIME_DIR="/run/user/$probe_uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$probe_uid/bus" \
    /usr/bin/systemctl --user "$@"
}

probe_remove_group() {
  local actual_group
  actual_group=$(getent group "$probe_username")
  if [[ -n "$actual_group" ]]; then
    if [[ $(printf '%s' "$actual_group" | cut -d: -f3) = "$probe_gid" && \
      -z $(printf '%s' "$actual_group" | cut -d: -f4) && \
      -z $(getent passwd | awk -F: -v gid="$probe_gid" '$4 == gid { print $1 }') ]]; then
      groupdel "$probe_username" || probe_fail_cleanup 'disposable group removal failed'
    else
      probe_fail_cleanup 'disposable group identity/membership changed; refusing removal'
    fi
  fi
}

probe_ledger_valid() {
  [[ -n "$probe_ledger_digest" && -f "$probe_ledger" && ! -L "$probe_ledger" && \
    "$(stat -c '%u:%a:%h' "$probe_ledger")" = '0:444:1' && \
    "$(sha256sum "$probe_ledger" | cut -d' ' -f1)" = "$probe_ledger_digest" ]]
}

# Only the new installed-Run fixture needs this actual hard filesystem bound.
# Keep the original home hidden, not changed; the production installer still
# creates .cliq/kernel-v1 itself. All privileged retirement decisions below use
# root-frozen physical identities, never a path returned by the test account.
probe_run_volume() {
  "$probe_node" --input-type=module - "$1" "$probe_fixture" "$probe_fixture_identity" \
    "$probe_home" "$probe_volume_image" "$probe_volume_original" "$probe_volume_mounted" \
    "$probe_uid" "$probe_gid" "$probe_output/run-filesystem.json" <<'NODE'
import assert from 'node:assert/strict';
import { constants, closeSync, existsSync, fchmodSync, fsyncSync, ftruncateSync, lstatSync,
  openSync, readFileSync, readdirSync, statfsSync, writeFileSync } from 'node:fs';
const [action, fixture, fixtureIdentity, home, image, originalFile, mountedFile, uidText, gidText, reportFile] = process.argv.slice(2);
assert.equal(process.geteuid(), 0);
assert.match(fixture, /^\/var\/tmp\/cliq-systemd-probe\.[A-Za-z0-9]+$/u);
assert.equal(home, `${fixture}/home`); assert.equal(image, `${fixture}/run-home.ext4`);
assert.equal(originalFile, `${fixture}/run-home-original.json`); assert.equal(mountedFile, `${fixture}/run-home-mounted.json`);
const uid = Number(uidText), gid = Number(gidText), ceiling = 1024 ** 3;
assert(Number.isSafeInteger(uid) && uid > 0 && uid === gid);
function identity(file, kind) {
  const value = lstatSync(file, { bigint: true });
  assert(!value.isSymbolicLink() && (kind === 'directory' ? value.isDirectory() : value.isFile()));
  return { device: String(value.dev), inode: String(value.ino), uid: Number(value.uid), gid: Number(value.gid),
    mode: Number(value.mode & 0o7777n), ...(kind === 'file' ? { size: String(value.size), links: Number(value.nlink) } : {}) };
}
const root = identity(fixture, 'directory');
assert.equal(`${root.device}:${root.inode}:${root.uid}`, fixtureIdentity); assert.equal(root.mode, 0o755);
function frozen(file) {
  const value = identity(file, 'file');
  assert.equal(value.uid, 0); assert.equal(value.gid, 0); assert.equal(value.mode, 0o444); assert.equal(value.links, 1);
  assert(BigInt(value.size) <= 65536n);
  return JSON.parse(readFileSync(file, 'utf8'));
}
function writeFrozen(file, value) {
  const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, `${JSON.stringify(value)}\n`); fchmodSync(fd, 0o444); fsyncSync(fd); } finally { closeSync(fd); }
}
function filesystem() {
  const value = statfsSync(home, { bigint: true }), capacity = value.blocks * value.bsize;
  assert(value.blocks > 0n && value.bsize > 0n && capacity <= BigInt(Number.MAX_SAFE_INTEGER));
  return { filesystemType: Number(value.type), totalBytes: Number(capacity) };
}
function mounts() {
  const bytes = readFileSync('/proc/self/mountinfo'); assert(bytes.length <= 8 * 1024 ** 2);
  return bytes.toString('utf8').trim().split('\n').map(line => {
    const fields = line.split(' '), separator = fields.indexOf('-'); assert(separator >= 6);
    return { id: fields[0], device: fields[2], root: fields[3], target: fields[4], options: fields[5],
      type: fields[separator + 1], source: fields[separator + 2] };
  }).filter(value => value.target === home || value.target.startsWith(`${home}/`));
}
function imageIdentity() {
  const value = identity(image, 'file');
  assert.equal(value.uid, 0); assert.equal(value.gid, 0); assert.equal(value.mode, 0o600);
  assert.equal(value.links, 1); assert.equal(value.size, String(ceiling)); return value;
}
function noImageAssociation() {
  const names = readdirSync('/sys/block'); assert(names.length <= 4096);
  for (const name of names.filter(value => /^loop[0-9]+$/u.test(value))) {
    let backing;
    try { backing = readFileSync(`/sys/block/${name}/loop/backing_file`, 'utf8'); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    assert(backing.length <= 4096); assert.notEqual(backing.trim(), image);
  }
}
function loop(mount, homeDevice) {
  assert.match(mount.source, /^\/dev\/loop[0-9]+$/u); assert.match(mount.device, /^7:[0-9]+$/u);
  const device = lstatSync(mount.source, { bigint: true }); assert(device.isBlockDevice() && !device.isSymbolicLink());
  assert.equal(String(device.rdev), homeDevice);
  const major = ((device.rdev >> 8n) & 0xfffn) | ((device.rdev >> 32n) & 0xfffff000n);
  const minor = (device.rdev & 0xffn) | ((device.rdev >> 12n) & 0xffffff00n);
  assert.equal(`${major}:${minor}`, mount.device);
  const base = `/sys/dev/block/${mount.device}/loop`;
  const read = name => { const value = readFileSync(`${base}/${name}`, 'utf8'); assert(value.length <= 4096); return value.trim(); };
  const value = { source: mount.source, device: mount.device, inode: String(device.ino), rdev: String(device.rdev),
    uid: Number(device.uid), gid: Number(device.gid), mode: Number(device.mode & 0o7777n),
    backingFile: read('backing_file'), offset: read('offset'), sizeLimit: read('sizelimit'), autoclear: read('autoclear') };
  assert.equal(value.uid, 0); assert.equal(value.backingFile, image); assert.equal(value.offset, '0');
  assert.equal(value.sizeLimit, '0'); assert.equal(value.autoclear, '1'); return value;
}
function mounted(original, partial = false) {
  assert.deepEqual(imageIdentity(), original.image);
  const inventory = mounts(); assert.equal(inventory.length, 1);
  const mount = inventory[0]; assert.equal(mount.target, home); assert.equal(mount.root, '/'); assert.equal(mount.type, 'ext4');
  assert.match(mount.id, /^[1-9][0-9]*$/u);
  const options = mount.options.split(',');
  for (const option of ['rw', 'nodev', 'nosuid']) assert(options.includes(option));
  assert(!options.includes('noexec'));
  const actual = identity(home, 'directory');
  assert.notEqual(actual.device, original.home.device);
  if (partial) {
    assert([0, uid].includes(actual.uid) && [0, gid].includes(actual.gid) && [0o700, 0o755].includes(actual.mode));
  } else { assert.equal(actual.uid, uid); assert.equal(actual.gid, gid); assert.equal(actual.mode, 0o700); }
  const observed = filesystem(); assert.equal(observed.filesystemType, 0xef53); assert(observed.totalBytes <= ceiling);
  return { mount, home: actual, image: original.image, loop: loop(mount, actual.device), filesystem: observed };
}
if (action === 'initialize') {
  assert.equal(mounts().length, 0);
  const before = identity(home, 'directory'); assert.equal(before.uid, uid); assert.equal(before.gid, gid); assert.equal(before.mode, 0o700);
  const beforeFilesystem = filesystem();
  const fd = openSync(image, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { ftruncateSync(fd, ceiling); fsyncSync(fd); } finally { closeSync(fd); }
  writeFrozen(originalFile, { home: before, image: imageIdentity(), beforeFilesystem });
} else if (action === 'capture' || action === 'retire-cut') {
  const original = frozen(originalFile), inventory = mounts();
  if (action === 'retire-cut' && inventory.length === 0) {
    assert(!existsSync(mountedFile)); assert.deepEqual(identity(home, 'directory'), original.home);
    assert.deepEqual(imageIdentity(), original.image); noImageAssociation();
    process.stdout.write('unmounted\n');
  } else {
    const value = mounted(original, action === 'retire-cut' && !existsSync(mountedFile));
    if (existsSync(mountedFile)) assert.deepEqual(value, frozen(mountedFile));
    else writeFrozen(mountedFile, value);
    if (action === 'capture') writeFrozen(reportFile, { diagnosticOnly: true, dedicatedBoundedExt4: true,
      before: original.beforeFilesystem, mounted: value.filesystem, hardCapacityCeilingBytes: ceiling,
      nativeGenerationQuotaVerified: false, nativeWorkerVerified: false });
    else process.stdout.write('mounted\n');
  }
} else if (action === 'unmounted') {
  const original = frozen(originalFile), retained = existsSync(mountedFile) ? frozen(mountedFile) : undefined;
  assert.equal(mounts().length, 0); assert.deepEqual(identity(home, 'directory'), original.home);
  assert.deepEqual(imageIdentity(), original.image); noImageAssociation();
  if (retained) {
    // Autoclear must have consumed the original loop association. Never detach
    // an observed/reused numeric loop device and never use lazy/force unmount.
    assert(!existsSync(`/sys/dev/block/${retained.loop.device}/loop/backing_file`));
  }
} else assert.fail('unsupported fixed volume operation');
NODE
}

probe_retire_run_volume() {
  [[ "$probe_campaign_kind" = run-journey ]] || return 0
  if ! probe_ledger_valid; then probe_fail_cleanup 'ownership ledger changed; refusing bounded volume retirement'; return 1; fi
  # initialize may not have completed. No mount operation precedes this frozen
  # record; if its absence is inconsistent with a mount, retain everything.
  if [[ ! -e "$probe_volume_original" && ! -L "$probe_volume_original" ]]; then
    if mountpoint -q "$probe_home"; then probe_fail_cleanup 'unregistered fixture home mount retained'; return 1; fi
    return 0
  fi
  local disposition
  if ! disposition=$(probe_run_volume retire-cut); then probe_fail_cleanup 'bounded fixture volume identity changed; refusing unmount'; return 1; fi
  if [[ "$disposition" = mounted ]]; then
    if ! probe_ledger_valid; then probe_fail_cleanup 'ownership ledger changed before bounded volume unmount'; return 1; fi
    if ! umount -- "$probe_home"; then probe_fail_cleanup 'bounded fixture volume did not unmount; retaining account and fixture'; return 1; fi
  elif [[ "$disposition" != unmounted ]]; then probe_fail_cleanup 'unknown bounded volume retirement cut'; return 1
  fi
  # A normal unmount autoclears this exact loop association. A short bounded
  # read-only wait accommodates kernel retirement without detaching a device.
  local attempt
  for attempt in {1..100}; do
    if probe_run_volume unmounted >/dev/null 2>&1; then return 0; fi
    sleep 0.05
  done
  probe_fail_cleanup 'bounded fixture mount/loop retirement was not proven'; return 1
}

probe_cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n "$probe_ledger_digest" ]]; then
    if probe_ledger_valid; then
      # External account commands may have committed before a signal prevents
      # their shell completion flag. Flags are hints, never cleanup authority.
      # Exact live identities below still have to match the frozen ledger.
      [[ -z $(getent passwd "$probe_username") ]] || probe_created=1
      [[ -z $(getent group "$probe_username") ]] || probe_group_created=1
    else
      probe_fail_cleanup 'ownership ledger changed; retaining all registered resources'
    fi
  fi
  if [[ "$probe_created" = 1 ]]; then
    local actual_account
    actual_account=$(getent passwd "$probe_username")
    if [[ "$(printf '%s' "$actual_account" | cut -d: -f3)" != "$probe_uid" || \
      "$(printf '%s' "$actual_account" | cut -d: -f4)" != "$probe_gid" || \
      "$(printf '%s' "$actual_account" | cut -d: -f6)" != "$probe_home" || \
      "$probe_uid" = 0 || "$probe_uid" = "$probe_runner_uid" ]]; then
      probe_fail_cleanup 'account identity changed; refusing to signal or delete it'
    elif ! probe_ledger_valid; then
      probe_fail_cleanup 'immutable ownership ledger changed; refusing cleanup'
    else
      local probe_current_manager_cgroup
      if ! probe_current_manager_cgroup=$(systemctl show "user@$probe_uid.service" --property=ControlGroup --value); then
        probe_fail_cleanup 'cannot inspect disposable manager cgroup before stop'
      fi
      if [[ -n "$probe_current_manager_cgroup" && \
        ( "$probe_current_manager_cgroup" != /* || "${probe_current_manager_cgroup##*/}" != "user@$probe_uid.service" ) ]]; then
        probe_fail_cleanup 'unexpected disposable manager cgroup path'
      fi
      if [[ -S "/run/user/$probe_uid/bus" ]]; then
        for probe_unit in "${probe_units[@]}"; do
          probe_user_systemctl stop "$probe_unit" >/dev/null 2>&1 || true
        done
      fi
      # Only this newly created UID may be terminated. Never touch runner UID,
      # user.slice, existing linger, or any pre-existing manager/service.
      loginctl disable-linger "$probe_username" >/dev/null 2>&1 || probe_fail_cleanup 'disable-linger failed'
      loginctl terminate-user "$probe_uid" >/dev/null 2>&1 || true
      systemctl stop "user@$probe_uid.service" "user-runtime-dir@$probe_uid.service" "user-$probe_uid.slice" >/dev/null 2>&1 || \
        probe_fail_cleanup 'disposable manager stop failed'
      local probe_remaining_units probe_remaining_unit probe_remaining_load probe_remaining_active probe_remaining_rest
      if probe_remaining_units=$(systemctl list-units --all --no-legend --plain \
        "user@$probe_uid.service" "user-runtime-dir@$probe_uid.service" "user-$probe_uid.slice"); then
        while read -r probe_remaining_unit probe_remaining_load probe_remaining_active probe_remaining_rest; do
          [[ -n "$probe_remaining_unit" ]] || continue
          [[ "$probe_remaining_active" = inactive || "$probe_remaining_active" = failed ]] || \
            probe_fail_cleanup "disposable unit remains $probe_remaining_active: $probe_remaining_unit"
        done <<< "$probe_remaining_units"
      else
        probe_fail_cleanup 'cannot inspect disposable units after stop'
      fi
      local probe_process_status=0
      for probe_attempt in {1..100}; do
        pgrep -u "$probe_uid" >/dev/null
        probe_process_status=$?
        [[ "$probe_process_status" = 0 ]] || break
        sleep 0.05
      done
      if [[ "$probe_process_status" = 0 ]]; then
        probe_fail_cleanup 'disposable UID still owns processes; retaining account and fixture'
      elif [[ "$probe_process_status" != 1 ]]; then
        probe_fail_cleanup 'cannot inspect disposable UID processes; refusing resource removal'
      else
        [[ ! -e "/run/user/$probe_uid" && ! -L "/run/user/$probe_uid" ]] || \
          probe_fail_cleanup 'disposable runtime directory remains after manager stop'
        if [[ -n "$probe_manager_cgroup" && -e "/sys/fs/cgroup$probe_manager_cgroup" ]]; then
          probe_fail_cleanup 'disposable manager cgroup remains after stop'
        fi
        if [[ -n "$probe_current_manager_cgroup" && -e "/sys/fs/cgroup$probe_current_manager_cgroup" ]]; then
          probe_fail_cleanup 'observed disposable manager cgroup remains after stop'
        fi
        [[ ! -e "/sys/fs/cgroup/user.slice/user-$probe_uid.slice" ]] || \
          probe_fail_cleanup 'disposable user-slice cgroup remains after stop'
        [[ ! -e "/var/lib/systemd/linger/$probe_username" && ! -L "/var/lib/systemd/linger/$probe_username" ]] || \
          probe_fail_cleanup 'disposable linger registration remains'
        if [[ -e "$probe_dropin_directory" || -L "$probe_dropin_directory" ]]; then
          if [[ "$probe_dropin_created" != 1 || ! -d "$probe_dropin_directory" || \
            -L "$probe_dropin_directory" || $(stat -c '%u' "$probe_dropin_directory") != 0 ]]; then
            # mkdir may have committed immediately before its completion flag.
            # Do not infer ownership: leave the path and fail cleanup visibly.
            probe_fail_cleanup 'unconfirmed drop-in directory retained; refusing deletion'
          else
            if [[ -f "$probe_dropin" && ! -L "$probe_dropin" && \
              $(stat -c '%u:%a:%h' "$probe_dropin") = '0:444:1' && \
              $(sha256sum "$probe_dropin" | cut -d' ' -f1) = "$probe_dropin_digest" ]]; then
              rm -- "$probe_dropin" || probe_fail_cleanup 'drop-in unlink failed'
            elif [[ -e "$probe_dropin" || -L "$probe_dropin" ]]; then
              probe_fail_cleanup 'drop-in identity changed/unconfirmed; refusing unlink'
            fi
            rmdir -- "$probe_dropin_directory" || probe_fail_cleanup 'drop-in directory is not empty'
          fi
        fi
        if [[ "$probe_dropin_created" = 1 ]]; then
          # Invalidate the removed per-UID override in the system manager's
          # unit cache. This reloads definitions, never restarts runner units;
          # the runner's exact process/manager/linger baseline is checked below.
          systemctl daemon-reload || probe_fail_cleanup 'removed drop-in cache invalidation failed'
        fi
        if [[ "$probe_cleanup_errors" = 0 ]]; then
          if probe_retire_run_volume; then
            userdel "$probe_username" || probe_fail_cleanup 'disposable account removal failed'
            probe_remove_group
          fi
        fi
      fi
    fi
  elif [[ "$probe_group_created" = 1 ]]; then
    if probe_ledger_valid; then
      probe_remove_group
    else
      probe_fail_cleanup 'ledger changed after group creation; refusing group cleanup'
    fi
  fi
  if [[ -f "$probe_before" ]]; then
    "$probe_node" "$probe_source" baseline "$probe_runner_uid" "$probe_after" || probe_fail_cleanup 'runner after-baseline capture failed'
    "$probe_node" "$probe_source" compare-baseline "$probe_before" "$probe_after" || probe_fail_cleanup 'runner baseline changed'
  fi
  # Only a root-created, ledger-scoped disposable tree is removed. -P/-xdev
  # prevent following a new user's symlinks or crossing into another mount.
  if [[ "$probe_cleanup_errors" = 0 && ! -L "$probe_fixture" && \
    "$(stat -c '%d:%i:%u' "$probe_fixture")" = "$probe_fixture_identity" ]]; then
    find -P "$probe_fixture" -xdev -depth -mindepth 1 -delete || probe_fail_cleanup 'fixture contents removal failed'
    rmdir -- "$probe_fixture" || probe_fail_cleanup 'fixture directory removal failed'
  else
    probe_fail_cleanup "fixture retained for inspection: $probe_fixture"
  fi
  printf '{"diagnosticOnly":true,"cleanupErrors":%s,"campaignExitStatus":%s}\n' \
    "$probe_cleanup_errors" "$original_status" > "$probe_output/cleanup.json"
  printf 'Systemd qualification output (%s): %s\n' "$probe_campaign_kind" "$probe_output"
  if [[ "$original_status" = 0 && "$probe_cleanup_errors" != 0 ]]; then original_status=1; fi
  exit "$original_status"
}
trap probe_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$probe_node" "$probe_source" baseline "$probe_runner_uid" "$probe_before"
if getent passwd "$probe_username" >/dev/null || getent group "$probe_username" >/dev/null || \
  [[ -e "/var/lib/systemd/linger/$probe_username" || -L "/var/lib/systemd/linger/$probe_username" ]]; then
  printf 'disposable account name collision; never adopt an existing UID\n' >&2
  exit 1
fi
# Select an unused numeric lifetime, not merely a new account name. Never
# adopt an orphan process, runtime directory, loaded manager or old drop-in.
for probe_candidate in {20000..20999}; do
  [[ "$probe_candidate" != "$probe_runner_uid" ]] || continue
  getent passwd "$probe_candidate" >/dev/null && continue
  getent group "$probe_candidate" >/dev/null && continue
  [[ ! -e "/run/user/$probe_candidate" && ! -L "/run/user/$probe_candidate" ]] || continue
  [[ ! -e "/run/systemd/system/user@$probe_candidate.service.d" && \
    ! -L "/run/systemd/system/user@$probe_candidate.service.d" ]] || continue
  [[ ! -e "/sys/fs/cgroup/user.slice/user-$probe_candidate.slice" ]] || continue
  if pgrep -u "$probe_candidate" >/dev/null; then continue; else
    [[ $? = 1 ]] || { printf 'failed to inspect candidate UID processes\n' >&2; exit 1; }
  fi
  probe_loaded_units=$(systemctl list-units --all --no-legend --plain \
    "user@$probe_candidate.service" "user-runtime-dir@$probe_candidate.service" "user-$probe_candidate.slice")
  [[ -z "$probe_loaded_units" ]] || continue
  probe_uid=$probe_candidate
  probe_gid=$probe_candidate
  break
done
[[ -n "$probe_uid" ]] || { printf 'no fresh disposable UID available\n' >&2; exit 1; }
readonly probe_uid probe_gid
[[ "$probe_uid" != 0 && "$probe_uid" != "$probe_runner_uid" ]] || exit 1
readonly probe_dropin_directory="/run/systemd/system/user@$probe_uid.service.d"
readonly probe_dropin="$probe_dropin_directory/50-cliq-probe.conf"
[[ ! -e "$probe_dropin_directory" && ! -L "$probe_dropin_directory" ]] || {
  printf 'UID-specific drop-in directory already exists; refusing to modify it\n' >&2; exit 1;
}

# Root-owned write-once ledger/config. It cannot be replaced through the new
# user's home; cleanup uses its frozen hash and the in-process exact identities.
"$probe_node" --input-type=module - "$probe_ledger" "$probe_fixture" "$probe_fixture_identity" \
  "$probe_username" "$probe_uid" "$probe_gid" "$probe_runner_uid" "$probe_home" "$probe_dropin" "$probe_output" "$probe_birth_helper" "$probe_campaign_kind" <<'NODE'
import { writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
const [file, fixture, fixtureIdentity, username, uidText, gidText, runnerText, home, dropin, output, birthHelper, mode] = process.argv.slice(2);
const uid = Number(uidText), gid = Number(gidText), runnerUid = Number(runnerText);
const suffix = fixture.slice(fixture.lastIndexOf('.') + 1);
const scenarios = ['A', 'B'].flatMap(layout => ['empty', 'live'].flatMap(mode => ['manual', 'automatic'].map(restart => {
  const prefix = layout === 'B' ? 'anchor-' : '';
  const unit = `cliq-probe-${suffix}-${prefix}${mode}-${restart}.service`;
  return { layout, mode, restart, unit, unitFile: `${home}/.config/systemd/user/${unit}`, directory: `${home}/probe/${prefix}${mode}-${restart}` };
})));
const anchorUnit = `cliq-probe-${suffix}-anchor.service`;
const anchor = { unit: anchorUnit, unitFile: `${home}/.config/systemd/user/${anchorUnit}`,
  directory: `${home}/probe/anchor`, readyFile: `${home}/probe/anchor/anchor.json` };
const installed = mode === 'installed' || mode === 'retirement' ? {
  buildFixture: `${fixture}/installed-package-build`, packageRoot: `${fixture}/installed-package-build/package`,
  preloadLibrary: `${fixture}/installed-package-build/installed-loader-preload.so`,
  preloadMarker: `${home}/probe/installed-loader-preload.marker`,
  installerEntry: `${fixture}/installed-package-build/installed-runtime-installer.mjs`,
  stateRoot: `${home}/probe/installed-state`, releaseKeysFile: `${fixture}/installed-release-keys.json`,
  keeperUnit: `cliq-probe-${suffix}-installed-keeper.service`,
  supervisorUnit: `cliq-probe-${suffix}-installed-supervisor.service`,
  keeperUnitFile: `${home}/.config/systemd/user/cliq-probe-${suffix}-installed-keeper.service`,
  supervisorUnitFile: `${home}/.config/systemd/user/cliq-probe-${suffix}-installed-supervisor.service`,
  reportFile: `${output}/report.json`,
} : undefined;
const secretService = mode === 'secrets' ? {
  helper: `${fixture}/cliq-secret-service-probe`,
  controlDirectory: `${home}/probe/secret-service-control`,
  generation: randomBytes(32).toString('hex'),
  reportFile: `${output}/secret-service.json`,
} : undefined;
const sqlitePaths = mode === 'secrets' ? {
  buildFixture: `${fixture}/sqlite-path-build`, caseRoot: `${home}/probe/sqlite-path-cases`,
  reportFile: `${output}/sqlite-paths.json`,
} : undefined;
const credentials = mode === 'credentials' ? {
  buildFixture: `${fixture}/credential-package-build`, packageRoot: `${fixture}/credential-package-build/package`,
  installerEntry: `${fixture}/credential-package-build/installed-runtime-installer.mjs`,
  stateRoot: `${home}/probe/credential-state`, releaseKeysFile: `${fixture}/credential-release-keys.json`,
  controlDirectory: `${home}/probe/credential-secret-service-control`,
  observer: `${fixture}/cliq-credential-journey-observer`, storeFixture: `${fixture}/cliq-credential-store-fixture`,
  reportFile: `${output}/credential-journey.json`,
} : undefined;
const runJourney = mode === 'run-journey' ? {
  buildFixture: `${fixture}/run-package-build`, packageRoot: `${fixture}/run-package-build/package`,
  installerEntry: `${fixture}/run-package-build/installed-runtime-installer.mjs`,
  stateRoot: `${home}/.cliq/kernel-v1`, releaseKeysFile: `${fixture}/run-release-keys.json`,
  controlDirectory: `${home}/probe/run-secret-service-control`,
  observer: `${fixture}/cliq-credential-journey-observer`, workspace: `${home}/probe/run-workspace`,
  reportFile: `${output}/installed-run-journey.json`,
} : undefined;
writeFileSync(file, JSON.stringify({ diagnosticOnly: true, fixture, fixtureIdentity, username,
  uid, gid, runnerUid, home, dropin, birthHelper, anchor, scenarios, installed, secretService, sqlitePaths, credentials, runJourney,
  reportFile: `${output}/systemd-user-probe.json` }, null, 2) + '\n',
  { flag: 'wx', mode: 0o444 });
NODE
probe_ledger_digest=$(sha256sum "$probe_ledger" | cut -d' ' -f1)
readonly probe_ledger_digest
groupadd --gid "$probe_gid" "$probe_username"
probe_group_created=1
mkdir -m 0755 -- "$probe_skel"
# CREATE_MAIL_SPOOL is a useradd default, not a -K login.defs option. Keep
# any enabled spool inside the already ledger-scoped disposable fixture.
mkdir -m 0700 -- "$probe_mail"
useradd --create-home --no-user-group --no-log-init -K HOME_MODE=0700 -K "MAIL_DIR=$probe_mail" --uid "$probe_uid" --gid "$probe_gid" \
  --skel "$probe_skel" --home-dir "$probe_home" --shell /usr/sbin/nologin "$probe_username"
probe_created=1
[[ $(id -u "$probe_username") = "$probe_uid" && $(id -g "$probe_username") = "$probe_gid" ]] || exit 1
if [[ "$probe_campaign_kind" = run-journey ]]; then
  # This is the same actual bounded-ext4 quota shape as the existing worker
  # campaign. Its HOME must remain executable: signed bootstrap and Supervisor
  # images are installed here; the private worker namespace remains unchanged.
  probe_run_volume initialize
  mkfs.ext4 -q -F "$probe_volume_image"
  mount -t ext4 -o loop,nodev,nosuid "$probe_volume_image" "$probe_home"
  chown "$probe_uid:$probe_gid" "$probe_home"
  chmod 0700 "$probe_home"
  probe_run_volume capture
fi
install -o root -g root -m 0444 -- "$probe_source" "$probe_script"
if [[ "$probe_campaign_kind" = diagnostic ]]; then
cc -std=c11 -O2 -Wall -Wextra -Werror "$probe_birth_source" -o "$probe_birth_helper"
chmod 0555 "$probe_birth_helper"
fi
if [[ "$probe_campaign_kind" = secrets ]]; then
  [[ -x /usr/bin/gnome-keyring-daemon && -x /usr/bin/busctl && -x /usr/bin/strace ]] || {
    printf 'actual GNOME Keyring daemon, user-bus inspection and SQLite tracer are required\n' >&2; exit 1;
  }
  unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR
  read -r -a probe_gio_flags <<< "$(pkg-config --cflags --libs gio-2.0)"
  cc -std=c11 -O2 -Wall -Wextra -Werror "$probe_secret_source" -o "$probe_secret_helper" "${probe_gio_flags[@]}"
  chmod 0555 "$probe_secret_helper"
fi
if [[ "$probe_campaign_kind" = credentials ]]; then
  [[ -x /usr/bin/gnome-keyring-daemon && -x /usr/bin/busctl ]] || {
    printf 'actual GNOME Keyring daemon and user-bus inspection are required\n' >&2; exit 1;
  }
  unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR
  read -r -a probe_gio_flags <<< "$(pkg-config --cflags --libs gio-2.0)"
  cc -std=c11 -O2 -Wall -Wextra -Werror "$probe_credential_source" -o "$probe_fixture/cliq-credential-journey-observer" "${probe_gio_flags[@]}"
  chmod 0555 "$probe_fixture/cliq-credential-journey-observer"
  cc -std=c11 -O2 -Wall -Wextra -Werror "$probe_credential_store_source" -o "$probe_fixture/cliq-credential-store-fixture" "${probe_gio_flags[@]}"
  chmod 0555 "$probe_fixture/cliq-credential-store-fixture"
fi
if [[ "$probe_campaign_kind" = run-journey ]]; then
  [[ -x /usr/bin/gnome-keyring-daemon && -x /usr/bin/busctl && -x /usr/bin/openssl ]] || {
    printf 'actual Secret Service, user-bus inspection and TLS build tools are required\n' >&2; exit 1;
  }
  unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR
  read -r -a probe_gio_flags <<< "$(pkg-config --cflags --libs gio-2.0)"
  cc -std=c11 -O2 -Wall -Wextra -Werror "$probe_credential_source" -o "$probe_fixture/cliq-credential-journey-observer" "${probe_gio_flags[@]}"
  chmod 0555 "$probe_fixture/cliq-credential-journey-observer"
fi
mkdir -m 0755 -- "$probe_home/.config" "$probe_home/.config/systemd" "$probe_home/.config/systemd/user"
if [[ "$probe_campaign_kind" = credentials || "$probe_campaign_kind" = run-journey ]]; then
  # The signed same-user setup, not this root harness, writes its fixed profiles.
  # These three exact directories have just been created inside the frozen home.
  chown "$probe_uid:$probe_gid" "$probe_home/.config" "$probe_home/.config/systemd" "$probe_home/.config/systemd/user"
fi
mkdir -m 0700 -- "$probe_home/probe"
chown "$probe_uid:$probe_gid" "$probe_home/probe"
if [[ "$probe_campaign_kind" = diagnostic ]]; then
for probe_layout in A B; do
  if [[ "$probe_layout" = B ]]; then probe_prefix=anchor-; else probe_prefix=''; fi
  for probe_mode in empty live; do
    for probe_restart in manual automatic; do
    probe_unit="cliq-probe-$probe_suffix-$probe_prefix$probe_mode-$probe_restart.service"
    probe_units+=("$probe_unit")
    probe_directory="$probe_home/probe/$probe_prefix$probe_mode-$probe_restart"
    mkdir -m 0700 -- "$probe_directory"
    chown "$probe_uid:$probe_gid" "$probe_directory"
    if [[ "$probe_restart" = automatic ]]; then probe_restart_setting=on-failure; else probe_restart_setting=no; fi
    {
      printf '[Unit]\nStartLimitIntervalSec=30s\nStartLimitBurst=2\n'
      if [[ "$probe_layout" = B ]]; then
        printf 'Requires=%s\nAfter=%s\n' "$probe_anchor_unit" "$probe_anchor_unit"
      fi
      printf '[Service]\nType=exec\nExecStart=%s %s main %s %s %s %s' \
        "$probe_node" "$probe_script" "$probe_mode" "$probe_directory" "$probe_unit" "$probe_layout"
      if [[ "$probe_layout" = B ]]; then printf ' %s %s' "$probe_anchor_directory/anchor.json" "$probe_birth_helper"; fi
      printf '\nDelegate=cpu memory pids\nKillMode=control-group\nRestart=%s\nRestartSec=2s\nTimeoutStopSec=2s\nEnvironment=NODE_OPTIONS=\n' "$probe_restart_setting"
    } > "$probe_home/.config/systemd/user/$probe_unit"
    chmod 0444 "$probe_home/.config/systemd/user/$probe_unit"
    done
  done
done
probe_units+=("$probe_anchor_unit")
mkdir -m 0700 -- "$probe_anchor_directory"
chown "$probe_uid:$probe_gid" "$probe_anchor_directory"
printf '[Service]\nType=exec\nExecStart=%s %s anchor %s %s\nDelegate=cpu memory pids\nKillMode=control-group\nRestart=no\nTimeoutStopSec=2s\nEnvironment=NODE_OPTIONS=\n' \
  "$probe_node" "$probe_script" "$probe_anchor_directory" "$probe_anchor_unit" > "$probe_home/.config/systemd/user/$probe_anchor_unit"
chmod 0444 "$probe_home/.config/systemd/user/$probe_anchor_unit"
elif [[ "$probe_campaign_kind" = installed || "$probe_campaign_kind" = retirement ]]; then
  # Registered in the immutable ledger before the account or either unit was
  # created. Only the Supervisor retries; its keeper must remain the same source.
  probe_units+=("$probe_installed_keeper_unit" "$probe_installed_supervisor_unit")
  for probe_installed_role in keeper supervisor; do
    if [[ "$probe_installed_role" = keeper ]]; then
      probe_unit=$probe_installed_keeper_unit
      probe_installed_restart=no
      probe_installed_burst=2
    else
      probe_unit=$probe_installed_supervisor_unit
      probe_installed_restart=on-failure
      probe_installed_burst=4
    fi
    {
      printf '[Unit]\nStartLimitIntervalSec=30s\nStartLimitBurst=%s\n' "$probe_installed_burst"
      if [[ "$probe_installed_role" = supervisor ]]; then
        printf 'Requires=%s\nAfter=%s\n' "$probe_installed_keeper_unit" "$probe_installed_keeper_unit"
      fi
      printf '[Service]\nType=exec\nExecStart=%s/runtime/bootstrap --bootstrap-%s\n' \
        "$probe_installed_state" "$probe_installed_role"
      # Remove known loading inputs for the fixed glibc/Node/OpenSSL carrier
      # before ELF startup. Unit text is not hostile-manager qualification;
      # actual injection with positive controls remains required.
      # An env -i executable wrapper would itself start with those routes open.
      printf 'UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT LD_PROFILE LD_PROFILE_OUTPUT LD_ORIGIN_PATH LD_TRACE_LOADED_OBJECTS LD_TRACE_PRELINKING LD_WARN LD_VERBOSE LD_BIND_NOW LD_BIND_NOT LD_DYNAMIC_WEAK LD_HWCAP_MASK LD_SHOW_AUXV LD_USE_LOAD_BIAS LD_ASSUME_KERNEL GCONV_PATH LOCPATH GLIBC_TUNABLES NODE_COMPILE_CACHE NODE_OPTIONS NODE_PATH NODE_EXTRA_CA_CERTS NODE_ICU_DATA NODE_REDIRECT_WARNINGS NODE_REPL_EXTERNAL_MODULE NODE_V8_COVERAGE OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES SSL_CERT_DIR SSL_CERT_FILE\n'
      printf 'Environment=PATH=/usr/bin:/bin LANG=C LC_ALL=C\nDelegate=cpu memory pids\nKillMode=control-group\nRestart=%s\nRestartSec=2s\nTimeoutStopSec=2s\n' "$probe_installed_restart"
    } > "$probe_home/.config/systemd/user/$probe_unit"
    chmod 0444 "$probe_home/.config/systemd/user/$probe_unit"
  done
fi
readonly probe_units
mkdir -m 0755 -- "$probe_dropin_directory"
probe_dropin_created=1
printf '[Service]\nDelegate=\nDelegate=cpu memory pids\n' > "$probe_dropin"
chmod 0444 "$probe_dropin"
probe_dropin_digest=$(sha256sum "$probe_dropin" | cut -d' ' -f1)
readonly probe_dropin_digest
# The fresh instance has never been loaded; its new instance-specific drop-in
# is read at first startup, without reloading unrelated system-manager units.
loginctl enable-linger "$probe_username"
systemctl start "user@$probe_uid.service"
probe_manager_cgroup=$(systemctl show "user@$probe_uid.service" --property=ControlGroup --value)
readonly probe_manager_cgroup
[[ "$probe_manager_cgroup" = /* && "$probe_manager_cgroup" != / && \
  "${probe_manager_cgroup##*/}" = "user@$probe_uid.service" ]] || {
  printf 'unexpected disposable user manager cgroup path\n' >&2; exit 1;
}
for probe_attempt in {1..100}; do
  [[ -S "/run/user/$probe_uid/bus" ]] && break
  sleep 0.05
done
[[ -S "/run/user/$probe_uid/bus" ]] || {
  printf 'actual user bus unavailable; no dbus-run-session/child fallback\n' >&2; exit 1;
}
if [[ "$probe_campaign_kind" = diagnostic ]]; then
  "$probe_node" "$probe_script" campaign "$probe_ledger"
elif [[ "$probe_campaign_kind" = installed ]]; then
  "$probe_node" --import "$probe_installed_loader" "$probe_installed_driver" --campaign "$probe_ledger"
elif [[ "$probe_campaign_kind" = retirement ]]; then
  "$probe_node" --import "$probe_installed_loader" "$probe_installed_driver" --retirement-refusal "$probe_ledger"
elif [[ "$probe_campaign_kind" = credentials ]]; then
  # No returned production unit name becomes privileged cleanup authority.
  # The immutable ledger's exact fresh UID/manager owns the complete retirement.
  "$probe_node" --import "$probe_installed_loader" "$probe_credential_driver" --campaign "$probe_ledger"
elif [[ "$probe_campaign_kind" = run-journey ]]; then
  # Fixed driver, exact fresh UID and the same frozen ledger/baseline/cleanup.
  # No arbitrary driver, production pause flag or manager-policy override.
  "$probe_node" --import "$probe_installed_loader" "$probe_run_driver" --campaign "$probe_ledger"
else
  "$probe_node" --import "$probe_installed_loader" "$probe_secret_driver" --campaign "$probe_ledger"
  "$probe_node" --import "$probe_installed_loader" "$probe_sqlite_driver" --campaign "$probe_ledger"
fi
