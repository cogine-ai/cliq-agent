#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: notarize-macos-execution-probe.sh BUNDLE_PATH" >&2
  exit 64
fi
bundle=$1
profile=${CLIQ_NOTARY_KEYCHAIN_PROFILE:-coginework local}
case "$bundle" in
  /*) ;;
  *) echo "bundle path must be absolute" >&2; exit 64 ;;
esac
if [ ! -d "$bundle" ]; then
  echo "bundle does not exist: $bundle" >&2
  exit 1
fi

archive_dir=$(mktemp -d /private/tmp/cliq-notary.XXXXXX)
cleanup() {
  rm -rf -- "$archive_dir"
}
trap cleanup EXIT HUP INT TERM
archive="$archive_dir/CliqKernelProbe.zip"

ditto -c -k --keepParent "$bundle" "$archive"
xcrun notarytool submit "$archive" --keychain-profile "$profile" --wait
xcrun stapler staple "$bundle"
spctl --assess --type execute --verbose=4 "$bundle"
