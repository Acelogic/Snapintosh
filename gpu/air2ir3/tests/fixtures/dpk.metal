/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
struct P { float4 a; };
kernel void dpk(constant P& p0 [[buffer(0)]], constant P& p1 [[buffer(1)]], texture2d<float, access::write> o [[texture(0)]],
                uint2 g [[thread_position_in_grid]], uint2 n [[threadgroups_per_grid]]) {
  o.write(p0.a + float4(n.x), g);
}
kernel void dpk2(constant P& p0 [[buffer(0)]], constant P& p5 [[buffer(5)]], texture2d<float, access::write> o [[texture(0)]],
                uint2 g [[thread_position_in_grid]], uint2 n [[threadgroups_per_grid]]) {
  o.write(p5.a + float4(n.x), g);
}
