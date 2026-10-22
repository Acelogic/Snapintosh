/* SPDX-License-Identifier: MIT */
// verify3: unset-constant shapes where the other arm is NOT a constant (LLVM: select undef, X, Y
// picks Y only when Y is a Constant), plus more presence predicates.
#include <metal_stdlib>
using namespace metal;
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant bool C [[function_constant(2)]];
constant int  N [[function_constant(3)]];
constant bool Q0 = !A;
constant bool Q1 = A != B;
constant bool Q2 = (N * 2) > 3;
constant bool Q3 = A ? true : C;
fragment float4 f(constant float4 &b0 [[buffer(0), function_constant(Q0)]],
                  constant float4 &b1 [[buffer(1), function_constant(Q1)]],
                  constant float4 &b2 [[buffer(2), function_constant(Q2)]],
                  constant float4 &b3 [[buffer(3), function_constant(Q3)]],
                  constant float4 &b4 [[buffer(4)]],
                  constant float4 &b5 [[buffer(5)]],
                  constant float4 &b6 [[buffer(6)]],
                  constant float4 &b7 [[buffer(7)]]) {
  float4 r = 0;
  if (Q0) r += b0; if (Q1) r += b1; if (Q2) r += b2; if (Q3) r += b3;
  r += A ? b4 : b5;
  if (!B) r += b6;
  r += C ? float4(0) : b7;
  return r;
}
