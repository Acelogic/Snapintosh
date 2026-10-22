/* SPDX-License-Identifier: MIT */
// Regression: 64-bit loop-carried values become `phi i64` (prototype: "bit size mismatch comp 0 for phi i64").
#include <metal_stdlib>
using namespace metal;
struct U { uint n; uint pad; ulong seed; };
kernel void phi64_kernel(device ulong *out [[buffer(0)]], constant uint &n [[buffer(1)]], uint tid [[thread_position_in_grid]]) {
  ulong acc = tid;
  for (uint i = 0; i < n; i++) acc += out[i] ^ (acc << 1);
  out[tid] = acc;
}
