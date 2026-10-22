// SPDX-License-Identifier: MIT
// Single-feature A16 probes for `a16gpu.py render --probes` (docs/A16-ADRENO-STAGE6-RENDER.md, "A16 run 1:
// diagnosis and probes"). Each fragment function isolates one piece of state that run 1 found wrong or had
// not proven, so one short A16 session confirms each fix on its own. Built by make-probes.sh into
// probes.air (what air2ir3 compiles) and probes.metallib (what render_metal_golden.swift draws); both
// sha-pinned in tools/a16gpu_render_scenes.py.
#include <metal_stdlib>
using namespace metal;

struct VIn { float2 pos [[attribute(0)]]; float2 uv [[attribute(1)]]; };
struct VOut { float4 position [[position]]; float2 uv; };

// pixel-space quad -> NDC with the scenes' orthographic matrix (as SkyLight's SimpleVertex)
vertex VOut probe_vs(VIn in [[stage_in]], constant float4x4 &mvp [[buffer(1)]]) {
  VOut o;
  o.position = mvp * float4(in.pos, 0.0, 1.0);
  o.uv = in.uv;
  return o;
}

#define B(n) constant float4 &b##n [[buffer(n)]]
#define S(n) r = band == n - BASE ? b##n : r;

// UBO index sweep, low half: 16 vertical bands of 6 pixels, band k = constant buffer(k) = UBO k. Every buffer is
// read and the band selects a value (no pointer selection), so each UBO is loaded by the preamble.
fragment float4 probe_ubo_lo(VOut in [[stage_in]], B(0), B(1), B(2), B(3), B(4), B(5), B(6), B(7), B(8), B(9), B(10),
                             B(11), B(12), B(13), B(14), B(15)) {
#define BASE 0
  int band = clamp(int(in.position.x) / 6, 0, 15);
  float4 r = b15;
  S(0) S(1) S(2) S(3) S(4) S(5) S(6) S(7) S(8) S(9) S(10) S(11) S(12) S(13) S(14)
  return r;
#undef BASE
}

// UBO index sweep, high half: 15 bands, band k = constant buffer(16 + k) = UBO 16 + k (pixels 90..95 repeat the
// last band). Compiled with air2ir3 --test-ubo-slots 32 (probe only: ABI v6 refuses UBO indices above 15).
fragment float4 probe_ubo_hi(VOut in [[stage_in]], B(16), B(17), B(18), B(19), B(20), B(21), B(22), B(23), B(24),
                             B(25), B(26), B(27), B(28), B(29), B(30)) {
#define BASE 16
  int band = clamp(int(in.position.x) / 6, 0, 14);
  float4 r = b30;
  S(16) S(17) S(18) S(19) S(20) S(21) S(22) S(23) S(24) S(25) S(26) S(27) S(28) S(29)
  return r;
#undef BASE
}

// Output components that are compile-time constants: ir3 writes them with alias.rt (SP_PS_OUTPUT_CONST_*).
fragment float4 probe_alias_rgb(VOut in [[stage_in]]) { return float4(0.2, 0.4, 0.6, in.uv.x); }   // x,y,z aliased
fragment float4 probe_alias_zw(VOut in [[stage_in]]) { return float4(in.uv.x, in.uv.y, 0.4, 1.0); } // z,w aliased

// Framebuffer fetch alone: the attachment read back with R and B swapped (a copy would look like "unchanged").
fragment float4 probe_fetch(VOut in [[stage_in]], float4 d [[color(0)]]) { return d.zyxw; }

// An A8Unorm texture: the sample is (0, 0, 0, a); the output moves a to red and shows the zero channels.
fragment float4 probe_a8(VOut in [[stage_in]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]]) {
  float4 c = t.sample(s, in.uv);
  return float4(c.a, c.r + 0.2, c.b + 0.4, 1.0 - c.g);
}
