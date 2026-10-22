/* SPDX-License-Identifier: MIT */
// fix3 (verify3 item 1): an unset constant whose value cannot matter is accepted (ABI v4 refuses only
// variants in which an unset constant decides something).  With B = false, `B && A` is false for
// every A; with C = true, `A || C` is true for every A.  With B or C unset (or the deciding one set
// the other way), A decides and the variant is refused.
#include <metal_stdlib>
using namespace metal;
constant bool A [[function_constant(0)]];
constant bool B [[function_constant(1)]];
constant bool C [[function_constant(2)]];
constant int  N [[function_constant(3)]];
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0)]], constant float4 &b1 [[buffer(1)]], constant float4 &b2 [[buffer(2)]]) {
  float4 r = 0;
  if (B && A) { for (int i = 0; i < int(b0.w); i++) r.x += b0.x; }
  r.x += select(b1, b2, A || C).x;
  return r;
}
