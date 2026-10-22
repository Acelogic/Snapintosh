/* SPDX-License-Identifier: MIT */
// fix2 (verify2 item 5): more predicate shapes over unset constants, compared with Metal on all
// 135 set/unset combinations (tests/regress.py unset_fc_semantics).
#include <metal_stdlib>
using namespace metal;
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant bool C [[function_constant(2)]];
constant int  N [[function_constant(3)]];
constant bool Q0 = N < 2;
constant bool Q1 = N != 2;
constant bool Q2 = (N & 2) != 0;
constant bool Q3 = A == B;
constant bool Q4 = !(A || C);
constant bool Q5 = is_function_constant_defined(B) ? B : !C;
constant bool Q6 = (A && B) || C;
constant bool Q7 = A ? (B || C) : (N >= 1);
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]],
                  constant float4 &b1 [[buffer(1), function_constant(Q1)]],
                  constant float4 &b2 [[buffer(2), function_constant(Q2)]],
                  constant float4 &b3 [[buffer(3), function_constant(Q3)]],
                  constant float4 &b4 [[buffer(4), function_constant(Q4)]],
                  constant float4 &b5 [[buffer(5), function_constant(Q5)]],
                  constant float4 &b6 [[buffer(6), function_constant(Q6)]],
                  constant float4 &b7 [[buffer(7), function_constant(Q7)]]) {
  float4 r = 0;
  if (Q0) r += b0; if (Q1) r += b1; if (Q2) r += b2; if (Q3) r += b3; if (Q4) r += b4; if (Q5) r += b5; if (Q6) r += b6; if (Q7) r += b7;
  return r;
}
