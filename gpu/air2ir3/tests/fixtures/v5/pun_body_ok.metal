/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// verify5: a float / half function constant that the front end loads as an integer (isnan, isinf,
// signbit, as_type) is specialised by value conversion instead of by bit pattern.
constant float F [[function_constant(4)]];
constant half H [[function_constant(10)]];
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0)]], constant float4 &b1 [[buffer(1)]], constant float4 &b2 [[buffer(2)]], constant float4 &b3 [[buffer(3)]]) {
  float4 r = 0;
  if (isnan(F)) r.x += b0.x;
  if (signbit(F)) r.x += b1.x;
  r.y = float(as_type<uint>(F) >> 16);
  r.z = float(as_type<ushort>(H));
  if (isinf(H)) r.x += b2.x;
  r.w = float(isfinite(F));
  return r;
}
