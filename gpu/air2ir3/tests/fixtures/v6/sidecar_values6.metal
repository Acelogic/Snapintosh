/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// fix round 6 (cache format 5): every function-constant type the sidecar must hold exactly
constant uint W [[function_constant(9)]];
constant int N [[function_constant(3)]];
constant float F [[function_constant(4)]];
constant half H [[function_constant(10)]];
constant char K [[function_constant(8)]];
constant ushort U [[function_constant(5)]];
constant bool A [[function_constant(0)]];
constant float2 V [[function_constant(12)]];
fragment float4 f(constant float4 &b0 [[buffer(0)]]) {
  return b0 * float(W) + float(N) + F + float(H) + float(K) + float(U) + float(A) + V.xyxy;
}
