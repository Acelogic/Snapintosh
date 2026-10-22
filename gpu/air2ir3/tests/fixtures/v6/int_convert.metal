/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// fix round 6: integer -> integer vector conversions (air.convert.u.v4i32.s.v4i16 ...) extend by the
// SOURCE signedness, as C does: uint4(short4(-1)) is 0xffffffff, int4(ushort4(65535)) is 65535.
// Runtime values (from buffer(0).x = 1.0), so the conversions reach NIR; fix round 5 zero-extended a
// signed source to an unsigned type and sign-extended an unsigned source to a signed one.
constant bool A [[function_constant(0)]];
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0)]]) {
  short4 s = short4(-b0.xxxx);              // -1
  ushort4 u = ushort4(b0.xxxx * 65535.0);   // 65535
  char4 c = char4(-b0.xxxx * 2.0);          // -2
  uint4 a = uint4(s); int4 b = int4(u); uint4 d = uint4(c);
  float4 r = float4(float(a.x >> 16), float(b.y), float(d.z >> 8), float(a.w & 0xffffu));
  return A ? r : -r;
}
