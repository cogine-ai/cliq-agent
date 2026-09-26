#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: build-macos-execution-probe.sh OUTPUT_DIRECTORY" >&2
  exit 64
fi
if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  echo "the macOS execution probe currently requires Apple silicon macOS" >&2
  exit 1
fi
if [ -z "${CLIQ_CODESIGN_IDENTITY:-}" ]; then
  echo "CLIQ_CODESIGN_IDENTITY must name a Developer ID Application identity" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
output_root=$1
case "$output_root" in
  /*) ;;
  *) echo "output directory must be an absolute path" >&2; exit 64 ;;
esac

asset_cache=${CLIQ_M0_ASSET_CACHE:-/private/tmp/cliq-m0-asset-cache}
build_root=$(mktemp -d /private/tmp/cliq-macos-probe-build.XXXXXX)
cleanup() {
  rm -rf -- "$build_root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p -- "$asset_cache" "$output_root"
vmlinuz="$asset_cache/alpine-3.22.5-aarch64-vmlinuz-virt"
upstream_initramfs="$asset_cache/alpine-3.22.5-aarch64-initramfs-virt"
base_url=https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/netboot-3.22.5

download() {
  destination=$1
  url=$2
  if [ ! -f "$destination" ]; then
    curl --ipv4 --retry 3 --retry-all-errors --fail --location --silent --show-error \
      -o "$destination.partial" "$url"
    mv -- "$destination.partial" "$destination"
  fi
}

verify_sha256() {
  filename=$1
  expected=$2
  observed=$(shasum -a 256 "$filename" | awk '{print $1}')
  if [ "$observed" != "$expected" ]; then
    echo "SHA-256 mismatch for $filename" >&2
    exit 1
  fi
}

download "$vmlinuz" "$base_url/vmlinuz-virt"
download "$upstream_initramfs" "$base_url/initramfs-virt"
verify_sha256 "$vmlinuz" f270bfa4324e37f0a28662909b0450c802c8279143f353cbc7fe250cdfb733a8
verify_sha256 "$upstream_initramfs" 508de7f561b94aac0b569611574502e4528eb21230318badac9626b7f1791bf4

# Alpine's arm64 vmlinuz is a self-extracting EFI image. The pinned zimg
# header places its gzip-compressed raw Linux Image at byte 52152. macOS dd
# with bs=1 copies the whole image one byte at a time; tail uses byte offsets.
tail -c +52153 "$vmlinuz" > "$build_root/kernel-payload.gz"
gzip -dc "$build_root/kernel-payload.gz" > "$build_root/Image" || true
verify_sha256 "$build_root/Image" 377d3480f52e7407bf635ea8a3322b7eb0b3c59eb051e977fb465bef706757b1

mkdir -p -- "$build_root/initramfs-root"
(
  cd "$build_root/initramfs-root"
  gzip -dc "$upstream_initramfs" | cpio -idm --quiet
  cp -- "$repo_root/native/macos/CliqKernelProbe/guest/init" init
  cp -- "$repo_root/native/macos/CliqKernelProbe/guest/verify-detached-daemon.sh" \
    cliq-verify-detached-daemon
  chmod 0755 init cliq-verify-detached-daemon
  find . -print | LC_ALL=C sort | cpio -o -H newc --quiet | gzip -9n > "$build_root/cliq-initramfs-virt"
)

worker_sha256=$(shasum -a 256 "$build_root/initramfs-root/bin/busybox" | awk '{print $1}')
kernel_sha256=$(shasum -a 256 "$build_root/Image" | awk '{print $1}')
initramfs_sha256=$(shasum -a 256 "$build_root/cliq-initramfs-virt" | awk '{print $1}')

app="$output_root/CliqKernelProbe.app"
if [ -e "$app" ]; then
  echo "refusing to replace existing bundle: $app" >&2
  exit 1
fi
mkdir -p -- "$app/Contents/MacOS" "$app/Contents/Resources"
cp -- "$repo_root/native/macos/CliqKernelProbe/Info.plist" "$app/Contents/Info.plist"
cp -- "$build_root/Image" "$app/Contents/Resources/Image"
cp -- "$build_root/cliq-initramfs-virt" "$app/Contents/Resources/cliq-initramfs-virt"
chmod 0444 "$app/Contents/Info.plist" "$app/Contents/Resources/Image" "$app/Contents/Resources/cliq-initramfs-virt"

swift_cache="$build_root/swift-module-cache"
mkdir -p -- "$swift_cache"
swiftc -module-cache-path "$swift_cache" \
  -framework Virtualization -framework CryptoKit \
  "$repo_root/native/macos/CliqKernelProbe/Sources/CliqKernelProbe/main.swift" \
  -o "$app/Contents/MacOS/cliq-kernel-probe"
chmod 0555 "$app/Contents/MacOS/cliq-kernel-probe"

manifest_digest=$(node "$repo_root/scripts/kernel/write-execution-probe-manifest.mjs" \
  "$app/Contents/Resources/execution-probe-manifest.json" \
  "$kernel_sha256" "$initramfs_sha256" "$worker_sha256")

timestamp_flag=--timestamp
if [ "${CLIQ_CODESIGN_TIMESTAMP:-1}" = "0" ]; then
  timestamp_flag=--timestamp=none
fi
codesign --force --options runtime "$timestamp_flag" \
  --entitlements "$repo_root/native/macos/CliqKernelProbe/CliqKernelProbe.entitlements" \
  --sign "$CLIQ_CODESIGN_IDENTITY" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
helper_sha256=$(shasum -a 256 "$app/Contents/MacOS/cliq-kernel-probe" | awk '{print $1}')

echo "BUNDLE_PATH=$app"
echo "MANIFEST_DIGEST=$manifest_digest"
echo "HELPER_DIGEST=$helper_sha256"
