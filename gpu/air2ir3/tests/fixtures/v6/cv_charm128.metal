/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
constant float F [[function_constant(4)]];
constant half H [[function_constant(10)]];
constant bool Q0 = (char(F) == char(-128));
constant bool Q1 = (char(H) == char(-128));
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]]) {
  float4 r = 0;
  if (Q0) r.x += b0.x; if (Q1) r.x += b1.x;
  return r;
}
