/* SPDX-License-Identifier: MIT */
// Framebuffer fetch of colours 0 and 2: must use FS bindless set 4, slots 55 and 57 (32+32-1-8+rt).
#include <metal_stdlib>
using namespace metal;
struct Out { half4 c0 [[color(0)]]; half4 c2 [[color(2)]]; };
fragment Out fbfetch_slots(half4 d0 [[color(0)]], half4 d2 [[color(2)]]) {
  Out o; o.c0 = d0 * 0.5h + d2 * 0.5h; o.c2 = d2.bgra; return o;
}
