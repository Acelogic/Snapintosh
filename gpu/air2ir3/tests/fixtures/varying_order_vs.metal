/* SPDX-License-Identifier: MIT */
// Vertex outputs and fragment inputs declared in different orders (see varying_order_fs.metal):
// slots must be assigned by sorted name in both stages (BINDING-ABI.md section 4); the prototype
// used declaration order.
#include <metal_stdlib>
using namespace metal;
struct VOut { float4 pos [[position]]; float2 zz [[user(zz)]]; float3 mm [[user(mm)]]; float2 aa [[user(aa)]]; };
vertex VOut vary_vs(uint vid [[vertex_id]], constant float4 *pos [[buffer(0)]]) {
  VOut o; o.pos = pos[vid]; o.zz = pos[vid].xy; o.mm = pos[vid].xyz * 2; o.aa = pos[vid].zw; return o;
}
