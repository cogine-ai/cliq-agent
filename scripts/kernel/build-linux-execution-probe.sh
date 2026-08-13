#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: build-linux-execution-probe.sh OUTPUT_DIRECTORY" >&2
  exit 64
fi
if [ "$(uname -s)" != "Linux" ]; then
  echo "the Linux execution probe must be built on Linux" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
output_root=$1
case "$output_root" in
  /*) ;;
  *) echo "output directory must be an absolute path" >&2; exit 64 ;;
esac
if [ -e "$output_root" ]; then
  echo "refusing to replace existing output directory: $output_root" >&2
  exit 1
fi

compiler=${CC:-musl-gcc}
bubblewrap=$(command -v bwrap || true)
if [ -z "$bubblewrap" ]; then
  echo "bubblewrap is required" >&2
  exit 1
fi
bubblewrap=$(readlink -f "$bubblewrap")

mkdir -p "$output_root/bin"
"$compiler" -std=c11 -O2 -Wall -Wextra -Werror -static -fno-ident \
  -ffile-prefix-map="$repo_root"=. -Wl,--build-id=none -s \
  "$repo_root/native/linux/cliq-linux-probe.c" -o "$output_root/bin/cliq-linux-probe"
chmod 0555 "$output_root/bin/cliq-linux-probe"
"$output_root/bin/cliq-linux-probe" --self-test

launcher_sha256=$(sha256sum "$output_root/bin/cliq-linux-probe" | awk '{print $1}')
bubblewrap_sha256=$(sha256sum "$bubblewrap" | awk '{print $1}')
manifest_digest=$(node "$repo_root/scripts/kernel/write-linux-execution-probe-manifest.mjs" \
  "$output_root/execution-probe-manifest.json" \
  "$launcher_sha256" "$bubblewrap" "$bubblewrap_sha256")

echo "INSTALLATION_ROOT=$output_root"
echo "MANIFEST_DIGEST=$manifest_digest"
