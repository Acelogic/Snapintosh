/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// fix round 6 (A16 render run 2, probe_ubo_lo / probe_ubo_hi): air.clamp.s / air.clamp.u were compiled as
// the float clamp (max.f / min.f on the integer's bits); 1..15 are fp32 denormals, which Adreno flushes.
constant bool A [[function_constant(0)]];
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(constant float4 &b0 [[buffer(0)]], constant float4 &b3 [[buffer(3)]]) {
  int k = int(b3.x);                                   // 8 at run time
  uint m = uint(b0.x) + 40u;                           // 41
  float4 r = float4(float(clamp(k, 0, 15)), float(clamp(k - 20, -3, 15)), float(clamp(m, 2u, 30u)), float(clamp(k, 9, 15)));
  return A ? r : -r;
}
