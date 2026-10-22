#!/bin/sh
# SPDX-License-Identifier: MIT
# Build SnapI2CHID.kext (arm64e, MH_KEXT_BUNDLE) against the SDK Kernel.framework,
# the same toolchain as gpu/adreno-kext/kext/build.sh. kmutil resolves the
# undefined IOHIDFamily/kernel symbols when the AuxKC is linked
# (tools/build-auxkc-user.py). No KDK is needed for this step. include/ holds an
# empty IOKit/hid/IOHIDPrivateKeys.h: the SDK's IOHIDDevice.h includes it but the
# SDK does not ship it, and nothing this driver uses comes from it.
set -eu
D=$(cd "$(dirname "$0")" && pwd); O=${OUT:-$D/out}; OBJ=$O/obj
SDK=$(xcrun --show-sdk-path)
KH=$SDK/System/Library/Frameworks/Kernel.framework/Headers
mkdir -p "$OBJ"
COMMON="-target arm64e-apple-macos27.0 -isysroot $SDK -mkernel -nostdinc -I$KH -I$D/src -I$D/include -DKERNEL -DAPPLE -DNeXT -O2 -g -Wall -Werror -fno-common"
CXXF="$COMMON -std=gnu++17 -fapple-kext -fno-exceptions -fno-rtti -Wno-inconsistent-missing-override"
xcrun clang++ $CXXF -c "$D/src/SnapI2CHID.cpp" -o "$OBJ/SnapI2CHID.o"
for f in geni-i2c hid-rdesc i2c-hid hid-keyboard hid-pointer hid-ptp hid-mt2; do
  xcrun clang $COMMON -std=gnu11 -c "$D/src/$f.c" -o "$OBJ/$f.o"
done
xcrun clang $COMMON -c "$D/src/kmod_info.c" -o "$OBJ/kmod_info.o"
K=$O/SnapI2CHID.kext
rm -rf "$K"; mkdir -p "$K/Contents/MacOS"
cp "$D/Info.plist" "$K/Contents/Info.plist"
xcrun clang++ -target arm64e-apple-macos27.0 -isysroot "$SDK" -mkernel -nostdlib -Xlinker -kext \
  -Xlinker -export_dynamic -o "$K/Contents/MacOS/SnapI2CHID" "$OBJ/SnapI2CHID.o" \
  "$OBJ/geni-i2c.o" "$OBJ/hid-rdesc.o" "$OBJ/i2c-hid.o" "$OBJ/hid-keyboard.o" "$OBJ/hid-pointer.o" "$OBJ/hid-ptp.o" "$OBJ/hid-mt2.o" \
  "$OBJ/kmod_info.o" \
  -L"$SDK/usr/lib" -lkmodc++ -lkmod -lcc_kext
codesign -f -s - "$K"
echo "kext: $K"
