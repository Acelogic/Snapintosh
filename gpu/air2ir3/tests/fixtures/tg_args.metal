/* SPDX-License-Identifier: MIT */
// threadgroup(n) buffer arguments (setThreadgroupMemoryLength:atIndex:) next to static threadgroup
// memory.  Regression test "threadgroup_args" (BINDING-ABI.md 3.8).
#include <metal_stdlib>
using namespace metal;
kernel void k(device float4 *out [[buffer(0)]], threadgroup float4 *a [[threadgroup(0)]], threadgroup float *b [[threadgroup(2)]],
              uint lid [[thread_index_in_threadgroup]], uint gid [[thread_position_in_grid]], uint tsz [[threads_per_threadgroup]]) {
  threadgroup float stat[16];
  a[lid] = float4(gid); b[lid] = float(lid); stat[lid & 15] = 2.0;
  threadgroup_barrier(mem_flags::mem_threadgroup);
  out[gid] = a[(lid + 1) % tsz] * b[(lid + 3) % tsz] + stat[(lid + 5) & 15];
}
