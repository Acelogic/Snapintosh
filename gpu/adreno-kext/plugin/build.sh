#!/bin/sh
# SPDX-License-Identifier: MIT
# Build AdrenoMetal.bundle (arm64e, like every IOGPU-family plug-in; WindowServer is arm64e) and the host harness.
# Output: out/AdrenoMetal.bundle, out/regtest. Ad-hoc signed; print the CDHash that must go into the guest trust cache.
set -eu
D=$(cd "$(dirname "$0")" && pwd); S=$D/AdrenoMetal; O=${OUT:-$D/out}
FP=${ADRENO_FEATURE_PROFILE_BUILD:-}
B=$O/AdrenoMetal.bundle
rm -rf "$B"; mkdir -p "$B/Contents/MacOS" "$B/Contents/Resources"
cp "$S/Info.plist" "$B/Contents/Info.plist"
CFL="-arch arm64e -mmacosx-version-min=27.0 -fobjc-arc -fobjc-arc-exceptions -O2 -Wall -Wno-objc-method-access -Wno-incomplete-implementation -Wno-protocol -Wno-objc-protocol-method-implementation -Wno-objc-protocol-property-synthesis -Wno-deprecated-declarations"
[ -n "$FP" ] && CFL="$CFL -DADRENO_FEATURE_PROFILE=${FP}ull"
# ADRENO_LENIENT=1: drop (and log once) a render pass or draw the IB builder refuses instead of failing the command
# buffer (AdrenoRenderEncoder.m). The strict default keeps every refusal an exception (the tests pin them).
[ -n "${ADRENO_LENIENT:-}" ] && CFL="$CFL -DADRENO_LENIENT=1"
# Per-user compile records in the Metal client's cache folder (AdrenoShader.m): on unless ADRENO_SHADER_CACHE_PERSIST=0.
case "${ADRENO_SHADER_CACHE_PERSIST:-1}" in 0|1) CFL="$CFL -DADRENO_SHADER_CACHE_PERSIST=${ADRENO_SHADER_CACHE_PERSIST:-1}";; *) exit 64;; esac
# Optional precompiled shader pack (shader_cache_pack.py), linked read-only into the plug-in itself so an
# install replaces the same files as before and creates none (docs/SHADER-COMPILE-PATH-20260928.md).
PACK=${ADRENO_SHADER_CACHE_PACK:-}
LDPACK=""
if [ -n "$PACK" ]; then
  test -f "$PACK"
  LDPACK="-Wl,-sectcreate,__ADRENO,__shadercache,$PACK -Wl,-segprot,__ADRENO,r,r"
fi
# The fragment stage of pipelines without a fragment function, as AIR in its own read-only section (AdrenoCompilerInput.m).
xcrun -sdk macosx metal -c "$S/AdrenoEmptyFragment.metal" -o "$O/AdrenoEmptyFragment.air"
LDPACK="$LDPACK -Wl,-sectcreate,__ADRENO,__emptyfrag,$O/AdrenoEmptyFragment.air"
xcrun clang $CFL -bundle -o "$B/Contents/MacOS/AdrenoMetal" \
  "$S/AdrenoMTLDevice.m" "$S/AdrenoResources.m" "$S/AdrenoCommandBuffer.m" "$S/AdrenoRenderEncoder.m" "$S/AdrenoBlitEncoder.m" "$S/AdrenoComputeEncoder.m" "$S/AdrenoResourceUsage.m" "$S/AdrenoFillCommands.m" "$S/AdrenoCompilerInput.m" "$S/AdrenoShader.m" "$S/AdrenoPipeline.m" "$S/AdrenoDrawCommands.m" "$S/AdrenoEarlyStop.m" \
  $LDPACK -framework Foundation -framework Metal -framework IOKit -framework IOSurface "$S/IOGPU.tbd"
if [ -n "${ADRENO_COMPILER_RUNTIME:-}" ]; then
  test -f "$ADRENO_COMPILER_RUNTIME/libAdrenoCompiler.dylib"
  mkdir -p "$B/Contents/Frameworks"
  cp "$ADRENO_COMPILER_RUNTIME/"*.dylib "$B/Contents/Frameworks/"
  for lib in "$B/Contents/Frameworks/"*.dylib; do codesign --verify --strict "$lib"; done
fi
codesign -f -s - "$B" 2>/dev/null
xcrun clang -arch arm64e -fobjc-arc -O1 -o "$O/regtest" "$D/harness/regtest.m" \
  -framework Foundation -framework Metal -framework IOKit -framework IOSurface
codesign -f -s - "$O/regtest" 2>/dev/null
echo "bundle: $B"
codesign -dvvv "$B" 2>&1 | grep -E '^CDHash=|^CandidateCDHashFull sha256=|^Format='
