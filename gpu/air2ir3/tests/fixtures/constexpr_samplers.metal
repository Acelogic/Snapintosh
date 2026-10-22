/* SPDX-License-Identifier: MIT */
// API sampler(0) and sampler(1) plus two constexpr samplers: constexpr samplers take S#15 and S#14
// (the prototype put them at S#16+, outside the 16 hardware sampler slots of the non-bindless path).
#include <metal_stdlib>
using namespace metal;
fragment float4 cs_frag(texture2d<float> t0 [[texture(0)]], texture2d<float> t1 [[texture(1)]],
                        sampler a [[sampler(0)]], sampler b [[sampler(1)]], float4 p [[position]]) {
  constexpr sampler px(coord::pixel, address::clamp_to_zero, filter::linear);
  constexpr sampler rp(address::repeat, filter::nearest, mip_filter::linear, max_anisotropy(4));
  float2 uv = p.xy / 512.0;
  return t0.sample(a, uv) + t1.sample(b, uv) + t0.sample(px, p.xy) + t1.sample(rp, uv * 3);
}
