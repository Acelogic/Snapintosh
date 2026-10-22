/* SPDX-License-Identifier: MIT */
// The fragment stage of render pipelines that have no fragment function (RenderBox's path_edges writes stencil only;
// docs/USERSPACE-GRAPHICS-20261019.md). build.sh links its AIR into __ADRENO,__emptyfrag; AdrenoCompilerInput reads it.
#include <metal_stdlib>
using namespace metal;
fragment void adreno_empty_fragment() {}
