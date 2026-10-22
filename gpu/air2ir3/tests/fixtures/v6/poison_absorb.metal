/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// verify6: a poison-capable conversion whose result is absorbed ((x || true), (x && false), x * 0)
// with F unset / NaN / out of range.  Metal's answer vs ours (present set; refusal acceptable).
constant bool A [[function_constant(0)]];
constant float F [[function_constant(4)]];
constant bool Q0 = (int(F) == 2) || true;
constant bool Q1 = (int(F) == 2) && false;
constant bool Q2 = ((int(F) * 0) == 0);
constant bool Q3 = (uint(F) == 7u) || A;
constant bool Q4 = A || (uint(F) == 7u);
constant bool Q5 = ((int(F) & 0) == 0);
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]],
  constant float4 &b2 [[buffer(2), function_constant(Q2)]], constant float4 &b3 [[buffer(3), function_constant(Q3)]],
  constant float4 &b4 [[buffer(4), function_constant(Q4)]], constant float4 &b5 [[buffer(5), function_constant(Q5)]]) {
  float4 r = 0;
  if (Q0) r.x += b0.x; if (Q1) r.x += b1.x; if (Q2) r.x += b2.x; if (Q3) r.x += b3.x; if (Q4) r.x += b4.x; if (Q5) r.x += b5.x;
  return r;
}
