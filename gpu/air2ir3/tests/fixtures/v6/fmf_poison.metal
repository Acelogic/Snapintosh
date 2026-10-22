/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// fix round 6 (fc6 shadow 3, shader 27): a static initialiser whose fast-math arithmetic overflows.  F = FLT_MAX,
// K = -128: float(K) * F is -inf, which then enters `fsub fast` (ninf): poison.  Metal made Q0 false (absent);
// in overflow_body the same class (inf entering `fadd fast`) came out true.  Refused; finite cases == Metal.
constant float F [[function_constant(4)]];
constant ushort U [[function_constant(5)]];
constant char K [[function_constant(8)]];
constant uchar M0 = uchar(signbit((float((float(F) * float(K))) - float(as_type<uchar2>(U).x))));
constant bool Q0 = bool(M0);
constant bool Q1 = (F * float(K)) < 0.0;
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]],
                  constant float4 &b2 [[buffer(2)]]) {
  float4 r = b2;
  if (Q0) r.x += b0.x;
  if (Q1) r.y += b1.x;
  return r;
}
