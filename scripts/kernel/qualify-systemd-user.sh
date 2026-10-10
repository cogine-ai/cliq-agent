#!/usr/bin/env bash
# Disposable actual-systemd-user lifecycle diagnostics, NOT installed Supervisor
# qualification or containment-death authority. Invoke with sudo, an absolute
# existing Node path and an optional new output directory. Do not run on a host
# without an independently disposable test UID and actual systemd user manager.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

if [[ $(id -u) != 0 || $# -lt 1 || $# -gt 2 ]]; then
  printf 'usage: sudo bash %s ABSOLUTE_NODE_PATH [NEW_OUTPUT_DIRECTORY]\n' "$0" >&2
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
chmod 0711 "$probe_fixture"
readonly probe_fixture_identity=$(stat -c '%d:%i:%u' "$probe_fixture")
readonly probe_suffix=${probe_fixture##*.}
readonly probe_username="cliq-probe-${probe_suffix,,}"
readonly probe_home="$probe_fixture/home"
readonly probe_script="$probe_fixture/systemd-user-probe.mjs"
readonly probe_ledger="$probe_fixture/ownership-ledger.json"
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
          userdel "$probe_username" || probe_fail_cleanup 'disposable account removal failed'
          probe_remove_group
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
  printf 'OS lifecycle diagnostic output: %s\n' "$probe_output"
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
  "$probe_username" "$probe_uid" "$probe_gid" "$probe_runner_uid" "$probe_home" "$probe_dropin" "$probe_output" <<'NODE'
import { writeFileSync } from 'node:fs';
const [file, fixture, fixtureIdentity, username, uidText, gidText, runnerText, home, dropin, output] = process.argv.slice(2);
const uid = Number(uidText), gid = Number(gidText), runnerUid = Number(runnerText);
const suffix = fixture.slice(fixture.lastIndexOf('.') + 1);
const scenarios = ['empty', 'live'].flatMap(mode => ['manual', 'automatic'].map(restart => {
  const unit = `cliq-probe-${suffix}-${mode}-${restart}.service`;
  return { mode, restart, unit, unitFile: `${home}/.config/systemd/user/${unit}`, directory: `${home}/probe/${mode}-${restart}` };
}));
writeFileSync(file, JSON.stringify({ diagnosticOnly: true, fixture, fixtureIdentity, username,
  uid, gid, runnerUid, home, dropin, scenarios, reportFile: `${output}/systemd-user-probe.json` }, null, 2) + '\n',
  { flag: 'wx', mode: 0o444 });
NODE
probe_ledger_digest=$(sha256sum "$probe_ledger" | cut -d' ' -f1)
readonly probe_ledger_digest
groupadd --gid "$probe_gid" "$probe_username"
probe_group_created=1
useradd --create-home --no-user-group --uid "$probe_uid" --gid "$probe_gid" \
  --home-dir "$probe_home" --shell /usr/sbin/nologin "$probe_username"
probe_created=1
[[ $(id -u "$probe_username") = "$probe_uid" && $(id -g "$probe_username") = "$probe_gid" ]] || exit 1
install -o root -g root -m 0444 -- "$probe_source" "$probe_script"
mkdir -m 0755 -- "$probe_home/.config" "$probe_home/.config/systemd" "$probe_home/.config/systemd/user"
mkdir -m 0700 -- "$probe_home/probe"
chown "$probe_uid:$probe_gid" "$probe_home/probe"
for probe_mode in empty live; do
  for probe_restart in manual automatic; do
    probe_unit="cliq-probe-$probe_suffix-$probe_mode-$probe_restart.service"
    probe_units+=("$probe_unit")
    probe_directory="$probe_home/probe/$probe_mode-$probe_restart"
    mkdir -m 0700 -- "$probe_directory"
    chown "$probe_uid:$probe_gid" "$probe_directory"
    if [[ "$probe_restart" = automatic ]]; then probe_restart_setting=on-failure; else probe_restart_setting=no; fi
    printf '[Unit]\nStartLimitIntervalSec=30s\nStartLimitBurst=2\n[Service]\nType=exec\nExecStart=%s %s main %s %s %s\nDelegate=cpu memory pids\nKillMode=control-group\nRestart=%s\nRestartSec=2s\nTimeoutStopSec=2s\nEnvironment=NODE_OPTIONS=\n' \
      "$probe_node" "$probe_script" "$probe_mode" "$probe_directory" "$probe_unit" "$probe_restart_setting" \
      > "$probe_home/.config/systemd/user/$probe_unit"
    chmod 0444 "$probe_home/.config/systemd/user/$probe_unit"
  done
done
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
"$probe_node" "$probe_script" campaign "$probe_ledger"
