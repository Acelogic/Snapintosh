/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
constant float F [[function_constant(4)]];
constant half H [[function_constant(10)]];
constant bool Q0 = F;
constant bool Q1 = (int(F) == 0);
constant bool Q2 = (int(F) == 2147483647);
constant bool Q3 = (int(F) == -2147483647 - 1);
constant bool Q4 = (uint(F) == 0u);
constant bool Q5 = (uint(F) == 4294967295u);
constant bool Q6 = (short(H) == 32767);
constant bool Q7 = (short(H) == 0);
constant bool Q8 = (int(F) == -7);
constant bool Q9 = (uchar(F) == 255);
constant bool Q10 = (uint(F) == 7u);
constant bool Q11 = H;
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]],
 constant float4 &b2 [[buffer(2), function_constant(Q2)]], constant float4 &b3 [[buffer(3), function_constant(Q3)]],
 constant float4 &b4 [[buffer(4), function_constant(Q4)]], constant float4 &b5 [[buffer(5), function_constant(Q5)]],
 constant float4 &b6 [[buffer(6), function_constant(Q6)]], constant float4 &b7 [[buffer(7), function_constant(Q7)]],
 constant float4 &b8 [[buffer(8), function_constant(Q8)]], constant float4 &b9 [[buffer(9), function_constant(Q9)]],
 constant float4 &b10 [[buffer(10), function_constant(Q10)]], constant float4 &b11 [[buffer(11), function_constant(Q11)]]) {
  return float4(1);
}
