/* SPDX-License-Identifier: MIT */
// Derivatives of 16-bit values (A16 v101/v102, docs/USERSPACE-GRAPHICS-20261019.md): air2ir3 must take them at 32 bits.
// On the X2-90, dsx / dsy on half registers return derivatives tens of times too large, which erased the shape mask of
// CoreAnimation's Liquid Glass background (glass_background_*_lph: fwidth(half)).
#include <metal_stdlib>
using namespace metal;
struct V { float4 position [[position]]; float2 uv; };
fragment half4 deriv16_frag(V in [[stage_in]]) {
    half hx = half(in.uv.x), hy = half(in.uv.y);
    return half4(dfdx(hx), dfdy(hy), fwidth(hx), dfdx(in.uv.x) > 0 ? 1.0h : 0.0h);
}
