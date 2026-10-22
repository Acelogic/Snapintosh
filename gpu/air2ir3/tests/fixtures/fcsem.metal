/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant bool C [[function_constant(2)]];
constant int  N [[function_constant(3)]];
constant bool P_and = A && B;
constant bool P_or = A || B;
constant bool P_not = !A;
constant bool P_eq = N == 1;
constant bool P_ternary = A ? B : C;
constant bool P_defA = is_function_constant_defined(A) && A;
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(P_and)]],
                  constant float4 &b1 [[buffer(1), function_constant(P_or)]],
                  constant float4 &b2 [[buffer(2), function_constant(P_not)]],
                  constant float4 &b3 [[buffer(3), function_constant(P_eq)]],
                  constant float4 &b4 [[buffer(4), function_constant(P_ternary)]],
                  constant float4 &b5 [[buffer(5), function_constant(A)]],
                  constant float4 &b6 [[buffer(6), function_constant(P_defA)]]) {
  float4 r = 0;
  if (P_and) r += b0; if (P_or) r += b1; if (P_not) r += b2; if (P_eq) r += b3; if (P_ternary) r += b4; if (A) r += b5; if (P_defA) r += b6;
  return r;
}
