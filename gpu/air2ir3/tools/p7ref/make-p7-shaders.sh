#!/bin/zsh
# SPDX-License-Identifier: MIT
# Regenerate tools/a16gpu-p7/p7-shaders.json from the Stage 6 compiler tree (host only, M3 Max).
#   AIR2IR3_TREE=<stage6 tree with build/air2ir3, build/mesa, third_party/mesa, corpus/SkyLight>
#   OUT=<scratch dir> tools/a16gpu-p7/make-p7-shaders.sh
# 1. air2ir3 compiles SkyLight SimpleVertex and SimpleTextureFragment (colour attachment 0 = MTLPixelFormat
#    80, BGRA8Unorm) into ir3_store_variant blobs + sidecars (BINDING-ABI v2);
# 2. export_p7_shaders (built here against the same Mesa) reloads them with ir3_retrieve_variant and writes
#    the JSON the A16 tool uploads from. The tool pins the JSON's sha256 (a16gpu_p6p7.P7_SHADERS_SHA256).
set -e
HERE=${0:a:h}
T=${AIR2IR3_TREE:?set AIR2IR3_TREE to the Stage 6 tree}
OUT=${OUT:-$HERE/../../build/a16gpu-p7}
mkdir -p $OUT
M=$T/third_party/mesa
B=$T/build/mesa
INC=(-I$M/src/freedreno/common -I$B/src/freedreno/ir3 -I$M/src/freedreno/ir3 -I$B/src/freedreno -I$M/src/freedreno
     -I$M/src/freedreno/registers -I$B/src/freedreno/registers -I$B/src/freedreno/registers/adreno
     -I$B/src/freedreno/common -I$M/src/freedreno/common -I$B/include -I$M/include -I$B/src -I$M/src
     -I$B/src/compiler/nir -I$M/src/compiler/nir -I$B/src/compiler -I$M/src/compiler -I$B/src/util -I$M/src/util)
DEFS=(-DHAVE_PTHREAD -DHAVE___BUILTIN_CLZ -DHAVE___BUILTIN_CLZLL -DHAVE___BUILTIN_CTZ -DHAVE___BUILTIN_FFS
      -DHAVE___BUILTIN_FFSLL -DHAVE___BUILTIN_POPCOUNT -DHAVE___BUILTIN_POPCOUNTLL -DHAVE___BUILTIN_UNREACHABLE
      -DHAVE___BUILTIN_EXPECT -DHAVE_FUNC_ATTRIBUTE_PACKED -DHAVE_FUNC_ATTRIBUTE_UNUSED -DHAVE_STRUCT_TIMESPEC -DMESA_DEBUG=0)
LIBS=($B/src/freedreno/ir3/libfreedreno_ir3.a $B/src/freedreno/isa/libir3encode.a $B/src/freedreno/isa/libir3decode.a
      $B/src/compiler/isaspec/libisaspec.a $B/src/freedreno/common/libfreedreno_common.a $B/src/compiler/nir/libnir.a
      $B/src/compiler/libcompiler.a $B/src/util/libmesa_util.a $B/src/util/libmesa_util_simd.a
      $B/src/c11/impl/libmesa_util_c11.a $B/src/util/blake3/libblake3.a)
clang++ -std=c++17 -O1 -g -Wno-deprecated-declarations -Wno-c99-designator $INC $DEFS $HERE/export_p7_shaders.cpp \
  $LIBS -L/opt/homebrew/opt/zstd/lib -lzstd -lz -o $OUT/export_p7_shaders
$T/build/air2ir3 $T/corpus/SkyLight/SimpleVertex.bc --stage vertex --json $OUT/vs.json --variant $OUT/vs.ir3v --quiet
$T/build/air2ir3 $T/corpus/SkyLight/SimpleTextureFragment.bc --stage fragment --rt-format 0=80 \
  --json $OUT/fs.json --variant $OUT/fs.ir3v --quiet
$OUT/export_p7_shaders $OUT/vs.ir3v $OUT/fs.ir3v $OUT/vs.json $OUT/fs.json > $OUT/p7-shaders.json
python3 -c "import json,sys; json.load(open('$OUT/p7-shaders.json'))"
shasum -a 256 $OUT/p7-shaders.json
echo "compiler: $($T/build/air2ir3 --compiler-id)"
