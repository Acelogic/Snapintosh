/* SPDX-License-Identifier: MIT */
// verify4 work/fc/min/m4.metal (verify4 item 1): one int constant N unset, the bools set; ABI v4 folded the N test
// from sample values and read other buffers than Metal.  ABI v5 refuses every N-unset case (tests/regress.py unset_fc_proof).
#include <metal_stdlib>
using namespace metal;
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant bool C [[function_constant(2)]];
constant int N [[function_constant(3)]];
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0)]], constant float4 &b1 [[buffer(1)]], constant float4 &b2 [[buffer(2)]], constant float4 &b5 [[buffer(5)]]) {
  float4 r = 0;
  r.x += (uint(N) == 4u) ? 0.0 : b5.x;
  r.x += b0.x;
  return r;
}
