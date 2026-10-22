/* SPDX-License-Identifier: MIT */
// verify4 work/desc/desc.metal (verify4 item 4): descriptor-count probes; d_read is a read()-only function whose isam
// names s#0 (ABI v5: NSAMP >= 1 + every s#, tests/regress.py nsamp_every_tex).
#include <metal_stdlib>
using namespace metal;
constant bool FC [[function_constant(0)]];
constexpr sampler cs(filter::linear, address::repeat);
constexpr sampler cs2(filter::nearest, address::clamp_to_edge);
fragment float4 d_unused_api(texture2d<float> t [[texture(0)]], sampler s0 [[sampler(0)]]) { return t.sample(cs, float2(0.5)); }
fragment float4 d_gated_api(texture2d<float> t [[texture(0)]], sampler s0 [[sampler(0), function_constant(FC)]]) { return FC ? t.sample(s0, float2(0.3)) : t.sample(cs, float2(0.5)); }
fragment float4 d_mixed(texture2d<float> t [[texture(0)]], sampler s1 [[sampler(1)]]) { return t.sample(cs, float2(0.5)) + t.sample(s1, float2(0.2)) + t.sample(cs2, float2(0.7)); }
fragment float4 d_hi(texture2d<float> t [[texture(14)]], sampler s [[sampler(3)]]) { return t.sample(s, float2(0.5)); }
fragment float4 d_read(texture2d<float> t [[texture(5)]]) { return t.read(uint2(1, 1)); }
fragment float4 d_arr(array<texture2d<float>, 3> t [[texture(2)]], sampler s [[sampler(0)]], constant uint &k [[buffer(0)]]) { return t[k].sample(s, float2(0.5)); }
fragment float4 d_gather(texture2d<float> t [[texture(3)]], sampler s [[sampler(2)]]) { return t.gather(s, float2(0.5)); }
fragment float4 d_fb_and_tex(float4 c [[color(0)]], texture2d<float> t [[texture(1)]]) { return c + t.sample(cs, float2(0.5)); }
fragment float4 d_15(texture2d<float> t [[texture(0)]], sampler s0 [[sampler(0)]], sampler s1 [[sampler(1)]], sampler s2 [[sampler(2)]], sampler s3 [[sampler(3)]], sampler s4 [[sampler(4)]], sampler s5 [[sampler(5)]], sampler s6 [[sampler(6)]], sampler s7 [[sampler(7)]], sampler s8 [[sampler(8)]], sampler s9 [[sampler(9)]], sampler s10 [[sampler(10)]], sampler s11 [[sampler(11)]], sampler s12 [[sampler(12)]], sampler s13 [[sampler(13)]], sampler s14 [[sampler(14)]], sampler s15 [[sampler(15)]]) {
  return t.sample(s0, 0.1) + t.sample(s15, 0.2) + t.sample(cs, 0.3); }
struct VO { float4 p [[position]]; };
vertex VO d_vs(uint i [[vertex_id]], texture2d<float> t [[texture(7)]], sampler s [[sampler(1)]]) { VO o; o.p = t.sample(s, float2(0.5), level(0)); return o; }
