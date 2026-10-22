/* SPDX-License-Identifier: MIT */
// verify4 work/fc/pmin/p1.metal (verify4 item 2): a presence predicate with only A unset (B = C = 0, N = 2).  ABI v5
// accepts it only as a direct copy of A (absent) or when it is the same for every A (tests/regress.py presence_predicates).
#include <metal_stdlib>
using namespace metal;
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant bool C [[function_constant(2)]];
constant int N [[function_constant(3)]];
constant bool Q0 = (A ? (A != ((N & 1) != 0)) : false);
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0)]], constant float4 &b10 [[buffer(10), function_constant(Q0)]]) {
  float4 r = 0; r.x += b0.x;
  return r;
}
