/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant bool C [[function_constant(2)]];
constant int  N [[function_constant(3)]];
constant bool P0 = A != B;
constant bool P1 = !(A && B);
constant bool P2 = N > 0;
constant bool P3 = (A || B) && C;
constant bool P4 = N == 0 || A;
constant bool P5 = is_function_constant_defined(N) ? (N == 2) : B;
constant bool P6 = !A && !B;
constant bool P7 = (N & 1) != 0;
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(P0)]],
                  constant float4 &b1 [[buffer(1), function_constant(P1)]],
                  constant float4 &b2 [[buffer(2), function_constant(P2)]],
                  constant float4 &b3 [[buffer(3), function_constant(P3)]],
                  constant float4 &b4 [[buffer(4), function_constant(P4)]],
                  constant float4 &b5 [[buffer(5), function_constant(P5)]],
                  constant float4 &b6 [[buffer(6), function_constant(P6)]],
                  constant float4 &b7 [[buffer(7), function_constant(P7)]]) {
  float4 r = 0;
  if (P0) r += b0; if (P1) r += b1; if (P2) r += b2; if (P3) r += b3; if (P4) r += b4; if (P5) r += b5; if (P6) r += b6; if (P7) r += b7;
  return r;
}
