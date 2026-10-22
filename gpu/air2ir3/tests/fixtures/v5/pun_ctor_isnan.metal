/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
constant bool B [[function_constant(1)]];
constant float F [[function_constant(4)]];
constant bool Q2 = (B || (isnan(F)));
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0)]], constant float4 &b2 [[buffer(2), function_constant(Q2)]]) {
  float4 r = 0; r.x += b0.x; if (Q2) r.x += b2.x; return r;
}
