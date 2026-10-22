/* SPDX-License-Identifier: MIT */
// ABI v6 (q1n1 A16 render run 1): a8xx honours UBO 0..15 only.  Regression test "ubo_slots_16".
#include <metal_stdlib>
using namespace metal;
// constant buffer(2) and a device buffer: the driver table lands at UBO 3
fragment float4 table_low(constant float4 &k [[buffer(2)]], device const float4 *d [[buffer(9)]]) { return k + d[0]; }
// constant buffer(16): above the table a8xx honours (refused; accepted only with --test-ubo-slots)
fragment float4 const_hi(constant float4 &k [[buffer(16)]]) { return k; }
// constant buffer(15) and a device buffer: the table would be UBO 16 (refused)
fragment float4 table_no_room(constant float4 &k [[buffer(15)]], device const float4 *d [[buffer(0)]]) { return k + d[0]; }
