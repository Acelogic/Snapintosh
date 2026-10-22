/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// verify6: a poison-capable conversion (NaN / out-of-range float -> integer) whose result another SET
// constant makes irrelevant in C terms: (x || A) with A = true, (x && B) with B = false, A ? true : x ...
// Metal evaluates select(poison, ...) as poison -> the predicate is false; fix5 must refuse (item 2).
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant float F [[function_constant(4)]];
constant half H [[function_constant(10)]];
constant bool Q0 = (uint(F) == 7u) || A;
constant bool Q1 = (int(F) == 2) || A;
constant bool Q2 = (uint(F) == 7u) && B;
constant bool Q3 = A ? true : (int(F) == 2);
constant bool Q4 = (int(F) == 2) ? true : A;
constant bool Q5 = (short(H) == 3) || A;
constant bool Q6 = !((uint(F) == 7u) && B);
constant bool Q7 = (uchar(F) != 3) || A;
constant bool Q8 = select(A, true, int(F) == 2);
constant bool Q9 = (int(F) > 0) | A;
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]],
  constant float4 &b2 [[buffer(2), function_constant(Q2)]], constant float4 &b3 [[buffer(3), function_constant(Q3)]],
  constant float4 &b4 [[buffer(4), function_constant(Q4)]], constant float4 &b5 [[buffer(5), function_constant(Q5)]],
  constant float4 &b6 [[buffer(6), function_constant(Q6)]], constant float4 &b7 [[buffer(7), function_constant(Q7)]],
  constant float4 &b8 [[buffer(8), function_constant(Q8)]], constant float4 &b9 [[buffer(9), function_constant(Q9)]]) {
  float4 r = 0;
  if (Q0) r.x += b0.x; if (Q1) r.x += b1.x; if (Q2) r.x += b2.x; if (Q3) r.x += b3.x; if (Q4) r.x += b4.x;
  if (Q5) r.x += b5.x; if (Q6) r.x += b6.x; if (Q7) r.x += b7.x; if (Q8) r.x += b8.x; if (Q9) r.x += b9.x;
  return r;
}
