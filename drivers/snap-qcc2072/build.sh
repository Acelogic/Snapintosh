#!/bin/sh
# SPDX-License-Identifier: MIT
# Build only. Linking into the guest AuxKC and hardware admission are separate.
# Failure inventory: re/build-failures.md.
set -eu
D=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${OUT:?Set OUT to a new directory for this build}"
if [ -e "$OUT" ]; then
    echo "Refusing existing output: $OUT" >&2
    exit 1
fi
SDK=$(xcrun --show-sdk-path)
KH=$SDK/System/Library/Frameworks/Kernel.framework/Headers
# The *26A428.h headers reconstruct private Apple class layouts from the KDK and
# are not distributed. Generate them from your own KDK_27.0_26A428 into include/
# (tools/gen-iomfb-header.py writes IOMobileGraphicsFamily26A428.h) before building.
for h in $(cat "$D"/src/* "$D"/include/*.h "$D"/../include/*.h 2>/dev/null | sed -n 's/^#include "\([A-Za-z0-9_]*26A428\.h\)".*/\1/p' | sort -u); do
    [ -f "$D/include/$h" ] || { echo "error: missing $D/include/$h (reconstructed from Apple's KDK 26A428, not distributed; generate it from your KDK)" >&2; exit 2; }
done
# The provider hashes its admitted firmware inputs with q1n1's SHA-256.
SHA=$(CDPATH= cd -- "$D/../../../q1n1/platform/uefi" && pwd)
[ -f "$SHA/sha256.c" ] || { echo "Missing q1n1 sha256.c beside Snapintosh" >&2; exit 1; }
# snap_wpa2 unwraps the GTK with the software AES block from Snapintosh/compat.
AES=$(CDPATH= cd -- "$D/../../compat" && pwd)
[ -f "$AES/aes.c" ] || { echo "Missing Snapintosh compat/aes.c" >&2; exit 1; }
mkdir -p "$OUT"
O=$(CDPATH= cd -- "$OUT" && pwd)
OBJ=$O/obj
K=$O/SnapintoshQCC2072.kext
mkdir -p "$OBJ" "$K/Contents/MacOS"

# Use individual quoted arguments so a checkout/SDK with spaces stays valid.
compile() {
    kind=$1
    source=$2
    object=$3
    shift 3
    xcrun "$kind" -target arm64e-apple-macos27.0 -isysroot "$SDK" \
        -mkernel -nostdinc -I"$KH" -I"$D/include" -I"$D/src" -I"$SHA" \
        -DKERNEL -DAPPLE -DNeXT -O2 -g -Wall -Wextra -Werror \
        -fno-common -MMD -MP "$@" -c "$source" -o "$object"
}

for name in SnapintoshQCC2072 SnapintoshQCC2072Interface qcc2072-provider; do
    compile clang++ "$D/src/$name.cpp" "$OBJ/$name.o" \
        -std=gnu++17 -fapple-kext -fno-exceptions -fno-rtti \
        -Wno-inconsistent-missing-override
done
for name in qcc2072-firmware qcc2072-transport qcc2072-dma qcc2072-mhi qcc2072-qmi \
            qcc2072-runtime qcc2072-qrtr qcc2072-wlfw qcc2072-ce qcc2072-htc \
            qcc2072-service qcc2072-wmi qcc2072-reo qcc2072-datapath qcc2072-dp-io qcc2072-scan qcc2072-assoc native-station native-wcl-scan native-wcl-event \
            native-rsn native-wpa2 native-wpa2-crypto qcc2072-connect kmod_info; do
    compile clang "$D/src/$name.c" "$OBJ/$name.o" -std=gnu11
done
compile clang "$SHA/sha256.c" "$OBJ/sha256.o" -std=gnu11
compile clang "$AES/aes.c" "$OBJ/aes.o" -std=gnu11 -Wno-sign-conversion
cp "$D/Info.plist" "$K/Contents/Info.plist"
xcrun clang++ -target arm64e-apple-macos27.0 -isysroot "$SDK" -mkernel \
    -nostdlib -Xlinker -kext -Xlinker -export_dynamic \
    -o "$K/Contents/MacOS/SnapintoshQCC2072" \
    "$OBJ/SnapintoshQCC2072.o" "$OBJ/SnapintoshQCC2072Interface.o" "$OBJ/qcc2072-provider.o" "$OBJ/qcc2072-firmware.o" \
    "$OBJ/qcc2072-transport.o" "$OBJ/qcc2072-dma.o" \
    "$OBJ/qcc2072-mhi.o" "$OBJ/qcc2072-qmi.o" "$OBJ/qcc2072-runtime.o" \
    "$OBJ/qcc2072-qrtr.o" "$OBJ/qcc2072-wlfw.o" "$OBJ/qcc2072-ce.o" \
    "$OBJ/qcc2072-htc.o" "$OBJ/qcc2072-service.o" "$OBJ/qcc2072-wmi.o" "$OBJ/qcc2072-reo.o" "$OBJ/qcc2072-datapath.o" "$OBJ/qcc2072-dp-io.o" "$OBJ/qcc2072-scan.o" "$OBJ/qcc2072-assoc.o" "$OBJ/sha256.o" \
    "$OBJ/native-station.o" "$OBJ/native-wcl-scan.o" "$OBJ/native-wcl-event.o" \
    "$OBJ/native-rsn.o" "$OBJ/native-wpa2.o" "$OBJ/native-wpa2-crypto.o" "$OBJ/qcc2072-connect.o" "$OBJ/aes.o" "$OBJ/kmod_info.o" \
    -L"$SDK/usr/lib" -lkmodc++ -lkmod -lcc_kext
codesign -f -s - "$K"
codesign --verify --strict "$K"
printf 'KEXT_COMPILED_NOT_RUNTIME_QUALIFIED %s\n' "$K"
