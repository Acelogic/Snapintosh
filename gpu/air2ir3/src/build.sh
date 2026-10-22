#!/bin/zsh
# SPDX-License-Identifier: MIT
# Builds air2ir3 (and the llvmpipe/GLSL test tools when asked) against Homebrew LLVM 22 and the
# private Mesa build in ../build/mesa (see README.md "Rebuild").
#   ./build.sh            -> build/air2ir3
#   ./build.sh all        -> also build/nirexec (llvmpipe runner) and build/nirdiff (SPIR-V NIR differential)
#   ./build.sh tools      -> only nirexec + nirdiff
#   ./build.sh v0         -> build/air2ir3-v0 (the unmodified prototype, for before/after runs)
#   ./build.sh swift      -> the Metal-side tools from source: build/mtlgold (tools/mtlgold.swift),
#                            build/mtlrefl (vtools/mtlrefl.swift, used by vtools/reflcmp.py and
#                            diffscenes.py) and build/pipelinekey (tools/pipelinekey.swift).  No
#                            Mesa/LLVM needed; `all` builds them too.
# Every mode also builds build/libair2ir3.a (the compiler library, air2ir3_api.h) and
# build/api_test (the C API test / online-compile timing, tests/api_test.c).
set -e
HERE=${0:a:h}
ROOT=${HERE:h}
M=$ROOT/third_party/mesa
B=$ROOT/build/mesa
OUT=$ROOT/build
LLVM=/opt/homebrew/opt/llvm
INC=(-I$HERE -I$B/src/freedreno/ir3 -I$M/src/freedreno/ir3 -I$B/src/freedreno -I$M/src/freedreno
     -I$M/src/freedreno/registers -I$B/src/freedreno/registers -I$B/src/freedreno/registers/adreno
     -I$B/src/freedreno/common -I$M/src/freedreno/common -I$B/include -I$M/include -I$B/src -I$M/src
     -I$B/src/freedreno/isa -I$M/src/freedreno/isa -I$B/src/compiler/nir -I$M/src/compiler/nir
     -I$B/src/compiler -I$M/src/compiler -I$B/src/util -I$M/src/util -I$M/src/util/format
     -I$M/src/gallium/include -I$M/src/gallium/auxiliary -I$B/src/gallium/auxiliary -I$M/src/gallium/drivers
     -I$M/src/gallium/winsys -I$M/src/mesa -I$B/src/mesa -I$M/src/compiler/glsl -I$B/src/compiler/glsl -I$M/src/mapi -I$B/src/mapi)
DEFS=(-D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -DHAVE_PTHREAD -DUSE_GCC_ATOMIC_BUILTINS
      -DHAVE___BUILTIN_CLZ -DHAVE___BUILTIN_CLZLL -DHAVE___BUILTIN_CTZ -DHAVE___BUILTIN_FFS -DHAVE___BUILTIN_FFSLL
      -DHAVE___BUILTIN_POPCOUNT -DHAVE___BUILTIN_POPCOUNTLL -DHAVE___BUILTIN_UNREACHABLE -DHAVE___BUILTIN_EXPECT
      -DHAVE_FUNC_ATTRIBUTE_PACKED -DHAVE_FUNC_ATTRIBUTE_UNUSED -DHAVE_FUNC_ATTRIBUTE_NORETURN -DHAVE_STRUCT_TIMESPEC -DMESA_DEBUG=0)
IR3LIBS=($B/src/freedreno/ir3/libfreedreno_ir3.a $B/src/freedreno/isa/libir3encode.a $B/src/freedreno/isa/libir3decode.a
      $B/src/compiler/isaspec/libisaspec.a $B/src/freedreno/common/libfreedreno_common.a)
BASELIBS=($B/src/compiler/nir/libnir.a $B/src/compiler/libcompiler.a $B/src/util/libmesa_util.a $B/src/util/libmesa_util_simd.a
      $B/src/c11/impl/libmesa_util_c11.a $B/src/util/blake3/libblake3.a)
LLVMFLAGS=($(${LLVM}/bin/llvm-config --cxxflags | sed 's/-std=c++[0-9]*//; s/-fno-exceptions//'))
LLVMLIBS=($(${LLVM}/bin/llvm-config --ldflags --libs core bitreader bitwriter passes irreader analysis transformutils ipo scalaropts instcombine --system-libs))
CXXF=(-std=c++17 -O1 -g -fno-rtti -Wno-deprecated-declarations -Wno-c99-designator -Wno-unused-parameter)
swift_tools() {
  mkdir -p $OUT
  swiftc -O $ROOT/tools/mtlgold.swift -o $OUT/mtlgold
  swiftc -O $ROOT/vtools/mtlrefl.swift -o $OUT/mtlrefl
  swiftc -O $ROOT/tools/pipelinekey.swift -o $OUT/pipelinekey
  echo built $OUT/mtlgold $OUT/mtlrefl $OUT/pipelinekey
}
if [[ "$1" == swift ]]; then swift_tools; exit 0; fi
[[ -f $B/build.ninja ]] || { echo "build/mesa is not configured: run tools/mesa-setup.sh and tools/mesa-ninja.sh first"; exit 1; }
CID=$(python3 $ROOT/tools/compiler_id.py)
IDDEF=(-DAIR2IR3_COMPILER_ID=\"$CID\")
mkdir -p $OUT $ROOT/scratch $ROOT/results
if [[ "$1" == v0 ]]; then
  clang++ $CXXF $LLVMFLAGS $INC $DEFS -c $HERE/air2ir3.v0-prototype.cpp -o $OUT/air2ir3-v0.o
  clang++ -o $OUT/air2ir3-v0 $OUT/air2ir3-v0.o $IR3LIBS $BASELIBS $LLVMLIBS -L/opt/homebrew/opt/zstd/lib -lzstd -lz
  echo built $OUT/air2ir3-v0; exit 0
fi
clang -std=c11 -O1 -g $INC $DEFS -c $HERE/a8xx_sampler.c -o $OUT/a8xx_sampler.o
# the library object (no CLI) is shared by libair2ir3.a, api_test, nirexec and nirdiff
clang++ $CXXF $LLVMFLAGS $INC $DEFS $IDDEF -DAIR2IR3_NO_MAIN -c $HERE/air2ir3.cpp -o $OUT/air2ir3_lib.o
rm -f $OUT/libair2ir3.a; /opt/homebrew/opt/llvm/bin/llvm-ar rcs $OUT/libair2ir3.a $OUT/air2ir3_lib.o $OUT/a8xx_sampler.o
clang -std=c11 -O1 -g -I$HERE -c $ROOT/tests/api_test.c -o $OUT/api_test.o
clang++ -o $OUT/api_test $OUT/api_test.o $OUT/libair2ir3.a $IR3LIBS $BASELIBS $LLVMLIBS -L/opt/homebrew/opt/zstd/lib -lzstd -lz
echo built $OUT/libair2ir3.a $OUT/api_test "($CID)"
if [[ "$1" != tools ]]; then
  clang++ $CXXF $LLVMFLAGS $INC $DEFS $IDDEF -c $HERE/air2ir3.cpp -o $OUT/air2ir3.o
  clang++ -o $OUT/air2ir3.new $OUT/air2ir3.o $OUT/a8xx_sampler.o $IR3LIBS $BASELIBS $LLVMLIBS -L/opt/homebrew/opt/zstd/lib -lzstd -lz
  mv -f $OUT/air2ir3.new $OUT/air2ir3
  echo built $OUT/air2ir3
fi

if [[ "$1" == all || "$1" == tools ]]; then
  # llvmpipe NIR runner: executes the AIR-derived NIR (vertex + fragment) with gallium llvmpipe.
  LPLIBS=($B/src/gallium/drivers/llvmpipe/libllvmpipe.a $B/src/gallium/auxiliary/libgallium.a
          $B/src/gallium/winsys/sw/null/libws_null.a)
  ALLLLVM=($(${LLVM}/bin/llvm-config --ldflags --libs all --system-libs))
  clang++ $CXXF $LLVMFLAGS $INC $DEFS -c $HERE/nirexec.cpp -o $OUT/nirexec.o
  clang++ $CXXF $LLVMFLAGS $INC -I$M/src/compiler/spirv -I$B/src/compiler/spirv $DEFS -c $HERE/spvnir.cpp -o $OUT/spvnir.o
  clang++ -o $OUT/nirexec $OUT/nirexec.o $OUT/spvnir.o $OUT/air2ir3_lib.o $OUT/a8xx_sampler.o $B/src/compiler/spirv/libvtn.a -L/opt/homebrew/opt/spirv-tools/lib -lSPIRV-Tools $LPLIBS $IR3LIBS $BASELIBS $ALLLLVM \
     -L/opt/homebrew/opt/zstd/lib -lzstd -lz
  echo built $OUT/nirexec
  # Mesa's own SPIR-V front end (spirv_to_nir, as used by Turnip/lavapipe) for the NIR differential
  # and for running the reference GLSL on llvmpipe (nirexec --spv-vs/--spv-fs).
  clang++ $CXXF $LLVMFLAGS $INC $DEFS -c $HERE/nirdiff.cpp -o $OUT/nirdiff.o
  clang++ -o $OUT/nirdiff $OUT/nirdiff.o $OUT/spvnir.o $OUT/air2ir3_lib.o $OUT/a8xx_sampler.o $B/src/compiler/spirv/libvtn.a -L/opt/homebrew/opt/spirv-tools/lib -lSPIRV-Tools \
     $IR3LIBS $BASELIBS $ALLLLVM -L/opt/homebrew/opt/zstd/lib -lzstd -lz
  echo built $OUT/nirdiff
fi
if [[ "$1" == all ]]; then swift_tools; fi
