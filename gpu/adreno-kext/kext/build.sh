#!/bin/sh
# SPDX-License-Identifier: MIT
# Build AdrenoX2.kext (arm64e, MH_KEXT_BUNDLE) against the SDK Kernel.framework. No KDK needed for this
# step; kmutil (tools/mkauxkc.sh) resolves the undefined IOGPUFamily/kernel symbols against the J700 KC.
set -eu
D=$(cd "$(dirname "$0")" && pwd); O=${OUT:-$D/../out}; OBJ=$O/obj
SDK=$(xcrun --show-sdk-path)
KH=$SDK/System/Library/Frameworks/Kernel.framework/Headers
# The *26A428.h headers reconstruct private Apple class layouts from the KDK and
# are not distributed. Generate them from your own KDK_27.0_26A428 into include/
# (tools/gen-iomfb-header.py writes IOMobileGraphicsFamily26A428.h) before building.
for h in $(cat "$D"/src/* "$D"/include/*.h "$D"/../include/*.h 2>/dev/null | sed -n 's/^#include "\([A-Za-z0-9_]*26A428\.h\)".*/\1/p' | sort -u); do
    [ -f "$D/include/$h" ] || { echo "error: missing $D/include/$h (reconstructed from Apple's KDK 26A428, not distributed; generate it from your KDK)" >&2; exit 2; }
done
mkdir -p "$OBJ"
COMMON="-target arm64e-apple-macos27.0 -isysroot $SDK -mkernel -nostdinc -I$KH -I$D/include -I$D/../include -DKERNEL -DAPPLE -DNeXT -O2 -g -Wall -Werror -Wno-unused-private-field -fno-common"
CXXF="$COMMON -std=gnu++17 -fapple-kext -fno-exceptions -fno-rtti -Wno-inconsistent-missing-override"
xcrun clang++ $CXXF -c "$D/src/AdrenoX2.cpp" -o "$OBJ/AdrenoX2.o"
xcrun clang++ $CXXF -c "$D/src/AdrenoMemoryMap.cpp" -o "$OBJ/AdrenoMemoryMap.o"
xcrun clang++ $CXXF -c "$D/src/AdrenoSegmentList.cpp" -o "$OBJ/AdrenoSegmentList.o"
xcrun clang++ $CXXF -c "$D/src/AdrenoDisplay.cpp" -o "$OBJ/AdrenoDisplay.o"
xcrun clang++ $CXXF -c "$D/src/SnapintoshVirtualEthernet.cpp" -o "$OBJ/SnapintoshVirtualEthernet.o"
xcrun clang++ $CXXF -c "$D/src/AdrenoEarlyStop.cpp" -o "$OBJ/AdrenoEarlyStop.o"
xcrun clang $COMMON -c "$D/../../../compat/adreno-resource.c" -o "$OBJ/adreno-resource.o"
xcrun clang $COMMON -c "$D/../../../compat/adreno-submit.c" -o "$OBJ/adreno-submit.o"
xcrun clang $COMMON -c "$D/../../../compat/adreno-resource-list.c" -o "$OBJ/adreno-resource-list.o"
xcrun clang $COMMON -c "$D/../../../compat/adreno-fill-command.c" -o "$OBJ/adreno-fill-command.o"
xcrun clang $COMMON -c "$D/../../../compat/adreno-ib-command.c" -o "$OBJ/adreno-ib-command.o"
xcrun clang $COMMON -c "$D/src/kmod_info.c" -o "$OBJ/kmod_info.o"
K=$O/AdrenoX2.kext
rm -rf "$K"; mkdir -p "$K/Contents/MacOS"
cp "$D/Info.plist" "$K/Contents/Info.plist"
xcrun clang++ -target arm64e-apple-macos27.0 -isysroot "$SDK" -mkernel -nostdlib -Xlinker -kext \
  -Xlinker -export_dynamic -o "$K/Contents/MacOS/AdrenoX2" "$OBJ/AdrenoX2.o" "$OBJ/AdrenoMemoryMap.o" \
  "$OBJ/AdrenoSegmentList.o" "$OBJ/AdrenoDisplay.o" "$OBJ/SnapintoshVirtualEthernet.o" "$OBJ/AdrenoEarlyStop.o" "$OBJ/adreno-resource.o" "$OBJ/adreno-submit.o" "$OBJ/adreno-resource-list.o" "$OBJ/adreno-fill-command.o" "$OBJ/adreno-ib-command.o" "$OBJ/kmod_info.o" \
  -L"$SDK/usr/lib" -lkmodc++ -lkmod -lcc_kext
codesign -f -s - "$K"
echo "kext: $K"
