/* SPDX-License-Identifier: MIT */
// Binding index given by a function-constant expression (__metal_implicit_attr_int_expr_N).
#include <metal_stdlib>
using namespace metal;
constant int tex_base [[function_constant(0)]];
constant int buf_base [[function_constant(1)]];
fragment float4 attr_expr(texture2d<float> t [[texture(tex_base + 1)]],
                          constant float4 &tint [[buffer(buf_base * 2)]],
                          sampler s [[sampler(0)]], float4 p [[position]]) {
  return t.sample(s, p.xy / 256.0) * tint;
}
