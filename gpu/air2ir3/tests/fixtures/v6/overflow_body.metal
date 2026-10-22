/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// verify6: finite inputs whose static-initialiser arithmetic overflows (half(N) + 0 for N = 70000).
// Metal: Q0 true, b0 present and read.  Ours: presence true, body output undefined (fast-math poison).
constant bool B [[function_constant(1)]];
constant int N [[function_constant(3)]];
constant bool Q0 = ((half(B) + half(N)) >= 255.5h);
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1)]]) {
  float4 r = b1;
  if (Q0) r.x += b0.x;
  return r;
}
