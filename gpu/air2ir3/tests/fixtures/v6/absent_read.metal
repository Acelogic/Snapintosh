/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// verify6: an int -> half conversion that overflows (finite input) inside a static-initialiser predicate.
// Metal: isfinite(half(N)) is false for N = 70000, so b0 is absent and not read.  The sidecar agrees
// (b0 absent); the body must not read b0 either.
constant int N [[function_constant(3)]];
constant bool Q0 = isfinite(half(N));
constant bool Q1 = !isinf(half(N));
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]],
                  constant float4 &b2 [[buffer(2)]]) {
  float4 r = b2;
  if (Q0) r.x += b0.x;
  if (Q1) r.y += b1.x;
  return r;
}
