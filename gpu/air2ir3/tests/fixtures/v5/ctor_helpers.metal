/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// fix round 5 (verify5 minor 1): AIR calls in the static initialiser that read only SET constants no
// longer force a refusal when another constant is unset.  Constants as tests/fcv5.py (fcv5metal types).
constant bool A [[function_constant(0)]];
constant int N [[function_constant(3)]];
constant float F [[function_constant(4)]];
constant half H [[function_constant(10)]];
constant bool Q0 = (int(F) == 2);
constant bool Q1 = (popcount(N) == 3);
constant bool Q2 = (clamp(N, 2, 9) == 5);
constant bool Q3 = (floor(H) == 1.0h);
constant bool Q4 = A;
constant bool Q5 = (abs(N) == 7);
constant bool Q6 = (clz(N) >= 0);
constant bool Q7 = (float(N) > 99.5);
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]],
                  constant float4 &b2 [[buffer(2), function_constant(Q2)]], constant float4 &b3 [[buffer(3), function_constant(Q3)]],
                  constant float4 &b4 [[buffer(4), function_constant(Q4)]], constant float4 &b5 [[buffer(5), function_constant(Q5)]],
                  constant float4 &b6 [[buffer(6), function_constant(Q6)]], constant float4 &b7 [[buffer(7), function_constant(Q7)]]) {
  float4 r = 0;
  if (Q0) r.x += b0.x; if (Q1) r.x += b1.x; if (Q2) r.x += b2.x; if (Q3) r.x += b3.x;
  if (Q4) r.x += b4.x; if (Q5) r.x += b5.x; if (Q6) r.x += b6.x; if (Q7) r.x += b7.x;
  return r;
}
