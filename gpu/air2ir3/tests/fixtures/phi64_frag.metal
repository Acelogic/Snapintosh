/* SPDX-License-Identifier: MIT */
// Regression: 64-bit loop-carried values become `phi i64` (prototype: "bit size mismatch comp 0 for phi i64").
#include <metal_stdlib>
using namespace metal;
struct U { uint n; uint pad; ulong seed; };
fragment float4 phi64_frag(constant U &u [[buffer(0)]], float4 pos [[position]]) {
  ulong acc = u.seed + (ulong)pos.x;
  for (uint i = 0; i < u.n; i++) acc = acc * 6364136223846793005ul + (ulong)i;
  return float4(float(acc & 0xff) / 255.0, float((acc >> 8) & 0xff) / 255.0, float((acc >> 56) & 0xff) / 255.0, 1);
}
