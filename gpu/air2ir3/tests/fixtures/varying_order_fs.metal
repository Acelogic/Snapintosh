/* SPDX-License-Identifier: MIT */
// Fragment half of varying_order_vs.metal: consumes a subset of the outputs, in another order.
#include <metal_stdlib>
using namespace metal;
struct FIn { float2 aa [[user(aa)]]; float2 zz [[user(zz)]]; };
fragment float4 vary_fs(FIn i [[stage_in]]) { return float4(i.aa, i.zz); }
