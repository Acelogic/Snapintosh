/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
constant uint W [[function_constant(9)]];
constant int N [[function_constant(3)]];
constant float F [[function_constant(4)]];
fragment float4 f(constant float4 &b0 [[buffer(0)]]) { return b0 * float(W) + float(N) + F; }
