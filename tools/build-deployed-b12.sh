#!/bin/bash
# SPDX-License-Identifier: MIT
# Build, from this checkout only, the three guest binaries the batch-12 desktop ran (b12v17, 2026-10-21):
#   AdrenoX2.kext     deployed AdrenoX2 73b4b8da (AuxKC 2cb7b6cc): --present-pipeline / --gpu-recover configuration
#   SnapI2CHID.kext   deployed SnapI2CHID d90e0199: -DSNAP_I2C_HID_LATENCY=1 in SnapI2CHID.o
#   AdrenoMetal.bundle deployed plug-in 758535d9 (mirror-slab set): ADRENO_LENIENT=1, -DADRENO_PIPELINE=1
# The define sets are the agents' recipes (tear-free build-objects-cm.sh / link-kext-cm.sh, gpu-recovery build-kext.sh,
# input-latency build-i2c.sh, gpu-pipeline build-plugin.sh), here with every unit compiled from source: the four units
# those recipes linked prebuilt (SnapintoshVirtualEthernet, AdrenoEarlyStop, adreno-submit, kmod_info) are compiled
# with no feature defines, which reproduces them section for section. Every feature define stays opt-in: plain
# gpu/adreno-kext/kext/build.sh, drivers/snap-i2c-hid/build.sh and gpu/adreno-kext/plugin/build.sh are unchanged.
#
#   tools/build-deployed-b12.sh OUT [REFERENCE_DIR]
# REFERENCE_DIR holds AdrenoX2.kext / SnapI2CHID.kext / AdrenoMetal.bundle to compare section by section
# (tools/macho-sections.py; build paths and DWARF are not compared).
# Environment:
#   ADRENO_COMPILER_RUNTIME  folder with libAdrenoCompiler.dylib (default build/current-assets/metal-stage-wsabort-20261020)
#   ADRENO_EMPTYFRAG_SRC     the AdrenoEmptyFragment.metal to compile (default this checkout's). The AIR records its
#                            source path, so a byte-identical plug-in needs the path the deployed build used.
set -euo pipefail
R=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:?usage: build-deployed-b12.sh OUT [REFERENCE_DIR]}; REF=${2:-}
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
SDK=$(xcrun --show-sdk-path); KH=$SDK/System/Library/Frameworks/Kernel.framework/Headers

# --- AdrenoX2 -----------------------------------------------------------------------------------------------------
D=$R/gpu/adreno-kext/kext; C=$R/compat; OBJ=$OUT/adrenox2-obj
COMMON="-target arm64e-apple-macos27.0 -isysroot $SDK -mkernel -nostdinc -I$KH -I$D/include -I$D/../include -DKERNEL -DAPPLE -DNeXT -O2 -g -Wall -Werror -Wno-unused-private-field -fno-common"
CXXF="$COMMON -std=gnu++17 -fapple-kext -fno-exceptions -fno-rtti -Wno-inconsistent-missing-override"
# per-unit sets (gpu-recovery build-kext.sh: X2F MMF DIF RSF) and the set every rebuilt unit gets (pipe-nosparse + REC)
X2F="-DADRENO_PERF_FRAMES=1 -DADRENO_RESIDENT_BUDGET_MIB=512 -DADRENO_PERF_GPU=1 -DADRENO_IB_ASYNC=1 -DADRENO_LATCH=1 -DADRENO_PRESENT_SYNC=1"
MMF="-DADRENO_RESOURCE_POOL=1 -DADRENO_POOL_ARENA=1 -DADRENO_RESIDENT_BUDGET_MIB=512 -DADRENO_PERF_GPU=1 -DADRENO_VA_RECLAIM=1"
DIF="-DADRENO_PRESENT_CACHED_READ=1 -DADRENO_PERF_FRAMES=1 -DADRENO_RESOURCE_POOL=1 -DADRENO_VSYNC60=1 -DADRENO_PERF_GPU=1 -DADRENO_BEAM=1 -DADRENO_PRESENT_CURSOR_STAGE=1 -DADRENO_PRESENT_SKIP_MAINT=1 -DADRENO_VA_RECLAIM=1 -DADRENO_LATCH=1 -DADRENO_PRESENT_SYNC=1"
RSF="-DADRENO_RESOURCE_POOL=1 -DADRENO_POOL_ARENA=1 -DADRENO_VA_RECLAIM=1"
ALL="-DADRENO_PERF_GPU=1 -DADRENO_VA_WIDE=1 -DADRENO_PIPELINE=1 -DADRENO_GPU_RECOVER=1"
rm -rf "$OBJ"; mkdir -p "$OBJ"
xcrun clang++ $CXXF $X2F $ALL -c "$D/src/AdrenoX2.cpp" -o "$OBJ/AdrenoX2.o"
xcrun clang++ $CXXF $MMF $ALL -c "$D/src/AdrenoMemoryMap.cpp" -o "$OBJ/AdrenoMemoryMap.o"
xcrun clang++ $CXXF $DIF $ALL -c "$D/src/AdrenoDisplay.cpp" -o "$OBJ/AdrenoDisplay.o"
xcrun clang++ $CXXF $ALL -c "$D/src/AdrenoSegmentList.cpp" -o "$OBJ/AdrenoSegmentList.o"
xcrun clang $COMMON $RSF $ALL -c "$C/adreno-resource.c" -o "$OBJ/adreno-resource.o"
for u in adreno-resource-list adreno-fill-command adreno-ib-command; do
  xcrun clang $COMMON $ALL -c "$C/$u.c" -o "$OBJ/$u.o"
done
xcrun clang++ $CXXF -c "$D/src/SnapintoshVirtualEthernet.cpp" -o "$OBJ/SnapintoshVirtualEthernet.o"
xcrun clang++ $CXXF -c "$D/src/AdrenoEarlyStop.cpp" -o "$OBJ/AdrenoEarlyStop.o"
xcrun clang $COMMON -c "$C/adreno-submit.c" -o "$OBJ/adreno-submit.o"
xcrun clang $COMMON -c "$D/src/kmod_info.c" -o "$OBJ/kmod_info.o"
K=$OUT/AdrenoX2.kext; rm -rf "$K"; mkdir -p "$K/Contents/MacOS"; cp "$D/Info.plist" "$K/Contents/Info.plist"
xcrun clang++ -target arm64e-apple-macos27.0 -isysroot "$SDK" -mkernel -nostdlib -Xlinker -kext -Xlinker -export_dynamic \
  -o "$K/Contents/MacOS/AdrenoX2" "$OBJ/AdrenoX2.o" "$OBJ/AdrenoMemoryMap.o" "$OBJ/AdrenoSegmentList.o" \
  "$OBJ/AdrenoDisplay.o" "$OBJ/SnapintoshVirtualEthernet.o" "$OBJ/AdrenoEarlyStop.o" "$OBJ/adreno-resource.o" \
  "$OBJ/adreno-submit.o" "$OBJ/adreno-resource-list.o" "$OBJ/adreno-fill-command.o" "$OBJ/adreno-ib-command.o" \
  "$OBJ/kmod_info.o" -L"$SDK/usr/lib" -lkmodc++ -lkmod -lcc_kext
codesign -f -s - "$K" 2>/dev/null

# --- SnapI2CHID ---------------------------------------------------------------------------------------------------
I=$R/drivers/snap-i2c-hid; IOBJ=$OUT/snapi2chid-obj; rm -rf "$IOBJ"; mkdir -p "$IOBJ"
ICOMMON="-target arm64e-apple-macos27.0 -isysroot $SDK -mkernel -nostdinc -I$KH -I$I/src -I$I/include -DKERNEL -DAPPLE -DNeXT -O2 -g -Wall -Werror -fno-common"
ICXXF="$ICOMMON -std=gnu++17 -fapple-kext -fno-exceptions -fno-rtti -Wno-inconsistent-missing-override"
xcrun clang++ $ICXXF -DSNAP_I2C_HID_LATENCY=1 -c "$I/src/SnapI2CHID.cpp" -o "$IOBJ/SnapI2CHID.o"
for f in geni-i2c hid-rdesc i2c-hid hid-keyboard hid-pointer hid-ptp hid-mt2; do
  xcrun clang $ICOMMON -std=gnu11 -c "$I/src/$f.c" -o "$IOBJ/$f.o"
done
xcrun clang $ICOMMON -c "$I/src/kmod_info.c" -o "$IOBJ/kmod_info.o"
H=$OUT/SnapI2CHID.kext; rm -rf "$H"; mkdir -p "$H/Contents/MacOS"; cp "$I/Info.plist" "$H/Contents/Info.plist"
xcrun clang++ -target arm64e-apple-macos27.0 -isysroot "$SDK" -mkernel -nostdlib -Xlinker -kext -Xlinker -export_dynamic \
  -o "$H/Contents/MacOS/SnapI2CHID" "$IOBJ/SnapI2CHID.o" "$IOBJ/geni-i2c.o" "$IOBJ/hid-rdesc.o" "$IOBJ/i2c-hid.o" \
  "$IOBJ/hid-keyboard.o" "$IOBJ/hid-pointer.o" "$IOBJ/hid-ptp.o" "$IOBJ/hid-mt2.o" "$IOBJ/kmod_info.o" \
  -L"$SDK/usr/lib" -lkmodc++ -lkmod -lcc_kext
codesign -f -s - "$H" 2>/dev/null

# --- AdrenoMetal (plugin/build.sh with the deployed flags; build.sh itself is not modified) ------------------------
P=$R/gpu/adreno-kext/plugin; POUT=$OUT/plugin; mkdir -p "$POUT"
EMPTY=${ADRENO_EMPTYFRAG_SRC:-$P/AdrenoMetal/AdrenoEmptyFragment.metal}
cmp -s "$EMPTY" "$P/AdrenoMetal/AdrenoEmptyFragment.metal"
sed -e "s|^D=\$(cd \"\$(dirname \"\$0\")\" \&\& pwd);|D=$P;|" \
    -e "s|\"\$S/AdrenoEmptyFragment.metal\"|\"$EMPTY\"|" \
    -e "s|^CFL=\"-arch arm64e|CFL=\"-DADRENO_PIPELINE=1 -arch arm64e|" "$P/build.sh" > "$POUT/build-wrapped.sh"
grep -q -- '-DADRENO_PIPELINE=1 -arch arm64e' "$POUT/build-wrapped.sh"
OUT=$POUT ADRENO_LENIENT=1 ADRENO_COMPILER_RUNTIME=${ADRENO_COMPILER_RUNTIME:-$R/build/current-assets/metal-stage-wsabort-20261020} \
  sh "$POUT/build-wrapped.sh" > "$POUT/build.log"
rm -rf "$OUT/AdrenoMetal.bundle"; mv "$POUT/AdrenoMetal.bundle" "$OUT/AdrenoMetal.bundle"
grep '^CDHash=' "$POUT/build.log" || true

shasum -a 256 "$K/Contents/MacOS/AdrenoX2" "$H/Contents/MacOS/SnapI2CHID" "$OUT/AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal"
if [ -n "$REF" ]; then
  st=0
  for b in AdrenoX2.kext/Contents/MacOS/AdrenoX2 SnapI2CHID.kext/Contents/MacOS/SnapI2CHID \
           AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal; do
    [ -e "$REF/$b" ] || { echo "== $b: not in $REF"; continue; }
    echo "== $b against $REF"
    python3 "$R/tools/macho-sections.py" "$REF/$b" "$OUT/$b" | tee "$OUT/compare.txt" | tail -1
    tail -1 "$OUT/compare.txt" | grep -q '^\([0-9]*\) of \1 sections identical' || st=1
  done
  exit $st
fi
