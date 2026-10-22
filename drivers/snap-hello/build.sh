#!/bin/bash
# SPDX-License-Identifier: MIT
# Build SnapHello.kext (arm64e) with a kmod_info, as kmutil requires.
set -eu
cd "$(dirname "$0")"
SDK=$(xcrun --show-sdk-path); KH=$SDK/System/Library/Frameworks/Kernel.framework/Headers
COMMON="-target arm64e-apple-macos27.0 -isysroot $SDK -mkernel -nostdinc -I$KH -DKERNEL -DAPPLE -DNeXT -O2 -Wall -Werror -fno-common"
xcrun clang++ $COMMON -std=gnu++17 -fapple-kext -fno-exceptions -fno-rtti -c hello.cpp -o hello.o
xcrun clang $COMMON -c kmod_info.c -o kmod_info.o
xcrun clang++ -target arm64e-apple-macos27.0 -isysroot "$SDK" -mkernel -nostdlib -Xlinker -kext -Xlinker -export_dynamic \
  -o SnapHello.kext/Contents/MacOS/SnapHello hello.o kmod_info.o -L"$SDK/usr/lib" -lkmodc++ -lkmod -lcc_kext
codesign -f -s - SnapHello.kext
