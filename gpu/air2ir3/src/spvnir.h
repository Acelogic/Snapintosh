/* SPDX-License-Identifier: MIT */
// spvnir.h - Mesa's own SPIR-V front end (spirv_to_nir, the path Turnip/lavapipe use), lowered to
// the same NIR "shape" the AIR front end emits, so the two can be diffed and executed side by side.
//
// Binding convention for the reference GLSL (tests/nirdiff/*.glsl, compiled with glslc):
//   set 0, binding n : texture2D           -> texture_index n   (Metal texture(n))
//   set 1, binding n : sampler             -> sampler_index n   (Metal sampler(n) or the S# the AIR
//                                                                 front end chose for a constexpr sampler)
//   set 2, binding n : std140 uniform block -> load_ubo(n, off)  (Metal buffer(n), constant space)
//   in/out locations : the AIR slots (VS attribute n, varying slot = sorted-name slot, RT n)
#pragma once
#include <string>
#include "nir.h"

// Returns nullptr and sets *err on failure.
nir_shader *spv_frontend(const char *path, mesa_shader_stage stage, const nir_shader_compiler_options *nopts,
                         std::string *err);
