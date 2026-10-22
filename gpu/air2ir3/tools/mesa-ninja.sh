#!/bin/zsh
# SPDX-License-Identifier: MIT
# Build the Mesa libraries (and generated headers) that src/build.sh links, and nothing else.
# A bare `ninja` in build/mesa also builds drivers/tools whose bison grammars need bison >= 3
# (macOS ships bison 2.3), so it is deliberately not used.  Extra arguments are passed to ninja.
set -e
export PATH=/opt/homebrew/opt/llvm/bin:$PATH
cd ${0:a:h:h}/build/mesa
TARGETS=(src/freedreno/ir3/libfreedreno_ir3.a src/freedreno/isa/libir3encode.a src/freedreno/isa/libir3decode.a
  src/compiler/isaspec/libisaspec.a src/freedreno/common/libfreedreno_common.a src/compiler/nir/libnir.a
  src/compiler/libcompiler.a src/util/libmesa_util.a src/util/libmesa_util_simd.a src/c11/impl/libmesa_util_c11.a
  src/util/blake3/libblake3.a src/gallium/drivers/llvmpipe/libllvmpipe.a src/gallium/auxiliary/libgallium.a
  src/gallium/winsys/sw/null/libws_null.a src/compiler/spirv/libvtn.a
  src/freedreno/registers/adreno/a8xx_descriptors.xml.h src/freedreno/registers/adreno/a8xx_enums.xml.h
  src/freedreno/registers/adreno/a6xx_enums.xml.h src/freedreno/registers/adreno/adreno_common.xml.h)
exec ninja "$@" $TARGETS
