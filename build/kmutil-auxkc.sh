#!/bin/sh
# SPDX-License-Identifier: MIT
# Build a Snapintosh AuxKC from kext bundles with kmutil and the 26A428 KDK.
#
# kmutil silently drops any kext whose files are not owned by root:wheel
# ("Filesystem error: Invalid ownership (501:0) should be (0:0)") and still
# exits 0 with an unrelated collection, so this stages root-owned copies and
# then checks that every requested bundle identifier is really in the output.
#
#   sudo build/kmutil-auxkc.sh OUT.kc KEXT_BUNDLE...
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo: it has to chown the staged kexts to root:wheel" >&2; exit 2; }
[ $# -ge 2 ] || { echo "usage: sudo $0 OUT.kc KEXT_BUNDLE..." >&2; exit 2; }
HERE=$(cd "$(dirname "$0")/.." && pwd)
KDK=/Library/Developer/KDKs/KDK_27.0_26A428.kdk
BOOT=$HERE/downloads/extracted/j700ap/kernelcache.release.mac17p
OUT=$1; shift
OWNER=$(stat -f %u:%g "$(dirname "$OUT")")
STAGE=$(mktemp -d /private/var/tmp/snapintosh-kexts.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
IDS=""
for k in "$@"; do
    ditto "$k" "$STAGE/$(basename "$k")"
    IDS="$IDS $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$k/Contents/Info.plist")"
done
chown -R root:wheel "$STAGE"
chmod -R go-w "$STAGE"
ARGS=""
for id in $IDS; do ARGS="$ARGS -b $id"; done
rm -f "$OUT"
# shellcheck disable=SC2086
kmutil create -z -x -n aux -a arm64e -V release -B "$BOOT" -A "$OUT" -r "$STAGE" $ARGS -M --kdk "$KDK"
chown "$OWNER" "$OUT"
missing=0
# Exact bundle list from __PRELINK_INFO, plus a fileset entry for every kext
# with code: a codeless kext (SnapintoshBootFramebuffer.kext) has no
# LC_FILESET_ENTRY, so entry_id alone would call it missing.
/usr/bin/python3 -B "$HERE/tools/auxkc-bundles.py" "$OUT" "$@" || missing=1
if strings -a "$OUT" | grep -q "Validating extension failed"; then
    echo "kmutil embedded a validation failure in $OUT:" >&2
    strings -a "$OUT" | grep -A2 "Validating extension failed" >&2
    missing=1
fi
[ $missing = 0 ] || exit 1
echo "ok: $OUT contains:$IDS"
otool -l "$OUT" | grep -A4 LC_FILESET_ENTRY | grep entry_id
shasum -a 256 "$OUT"
