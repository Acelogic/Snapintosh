/* SPDX-License-Identifier: MIT */
// verify3: branches / switch on unset constants with non-constant arms.
#include <metal_stdlib>
using namespace metal;
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant bool C [[function_constant(2)]];
constant int  N [[function_constant(3)]];
fragment float4 f(constant float4 &b0 [[buffer(0)]], constant float4 &b1 [[buffer(1)]],
                  constant float4 &b2 [[buffer(2)]], constant float4 &b3 [[buffer(3)]],
                  constant float4 &b4 [[buffer(4)]], constant float4 &b5 [[buffer(5)]],
                  constant float4 &b6 [[buffer(6)]], constant float4 &b7 [[buffer(7)]]) {
  float4 r = 0;
  if (A) r += b0; else r += b1;
  switch (N) { case 1: r += b2; break; case 2: r += b3; break; default: r += b4; break; }
  r += select(b5, b6, B);
  r += (C && A) ? b7 : float4(0);
  return r;
}
