#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: verify-detached-daemon.sh PID EXPECTED_EXECUTABLE_SHA256" >&2
  exit 64
fi

daemon_pid=$1
expected_digest=$2
proc_root=${CLIQ_PROC_ROOT:-/proc}

case "$daemon_pid" in
  ''|*[!0-9]*) exit 1 ;;
esac
case "$expected_digest" in
  *[!0-9a-f]*|'') exit 1 ;;
esac
if [ "${#expected_digest}" -ne 64 ]; then
  exit 1
fi

status_file="$proc_root/$daemon_pid/status"
executable_file="$proc_root/$daemon_pid/exe"
if [ ! -r "$status_file" ] || [ ! -e "$executable_file" ]; then
  exit 1
fi

parent_pid=''
while IFS=: read -r field value; do
  if [ "$field" = "PPid" ]; then
    set -- $value
    parent_pid=${1:-}
    break
  fi
done < "$status_file"
if [ "$parent_pid" != "1" ]; then
  exit 1
fi

if [ -n "${CLIQ_BUSYBOX:-}" ]; then
  hash_output=$("$CLIQ_BUSYBOX" sha256sum "$executable_file")
else
  sha256sum_program=${CLIQ_SHA256SUM:-sha256sum}
  hash_output=$("$sha256sum_program" "$executable_file")
fi
set -- $hash_output
observed_digest=${1:-}
if [ "$observed_digest" != "$expected_digest" ]; then
  exit 1
fi
