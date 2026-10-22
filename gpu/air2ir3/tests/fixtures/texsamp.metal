/* SPDX-License-Identifier: MIT */
// fix2 item 9: T# and S# are independent Metal indices; num_samp (NTEX/NSAMP) must cover both, and
// need_pixlod (PIXLODENABLE) follows implicit-derivative sampling only.
#include <metal_stdlib>
using namespace metal;
struct V { float4 p [[position]]; float2 uv; };
fragment float4 split(V in [[stage_in]], texture2d<float> t [[texture(2)]], sampler s [[sampler(5)]]) {
  return t.sample(s, in.uv);
}
fragment float4 readonly_tex(V in [[stage_in]], texture2d<float> t [[texture(1)]]) {
  return t.read(uint2(in.p.xy));
}
fragment float4 explicit_lod(V in [[stage_in]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]]) {
  return t.sample(s, in.uv, level(0.0));
}
