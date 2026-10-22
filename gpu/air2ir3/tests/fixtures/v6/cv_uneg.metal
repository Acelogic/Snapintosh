/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// verify6: in-range float -> integer conversions whose SOURCE lies just outside the destination range
// (truncation brings it in): Metal folds uint(-0.5) = 0, char(-128.5) = -128, short(-32768.5) = -32768.
constant float F [[function_constant(4)]];
constant half H [[function_constant(10)]];
constant bool Q0 = (uint(F) == 0u);
constant bool Q1 = (ushort(F) == ushort(0));
constant bool Q2 = (uchar(F) == uchar(0));
constant bool Q3 = (uint(H) == 0u);
constant bool Q4 = (ushort(H) == ushort(0));
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]],
  constant float4 &b2 [[buffer(2), function_constant(Q2)]], constant float4 &b3 [[buffer(3), function_constant(Q3)]],
  constant float4 &b4 [[buffer(4), function_constant(Q4)]], constant float4 &b5 [[buffer(5)]]) {
  float4 r = 0;
  if (Q0) r.x += b0.x; if (Q1) r.x += b1.x; if (Q2) r.x += b2.x; if (Q3) r.x += b3.x; if (Q4) r.x += b4.x;
  r.y = float(uint(F)) + b5.y * 0.0;          // body use: the same conversion, read as a value
  return r;
}
