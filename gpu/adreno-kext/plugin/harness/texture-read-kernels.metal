/* SPDX-License-Identifier: MIT */
// Kernels for tools/test-adreno-ca-apl.py: every texture2d read() form Metal's compiler service hands the plug-in as
// AIR 2.2 `air.read_texture_2d.*(texture, coord, lod, access)` (docs/WINDOWSERVER-APL-ABORT-20261020.md), and a
// multisample size query (one operand, no lod), which must be refused, not read out of bounds.
#include <metal_stdlib>
using namespace metal;
kernel void read_sample(texture2d<half> t [[texture(0)]], device half4 *o [[buffer(0)]], uint2 p [[thread_position_in_grid]]) { o[p.x] = t.read(p); }
kernel void read_sample_lod(texture2d<half> t [[texture(0)]], device half4 *o [[buffer(0)]], uint2 p [[thread_position_in_grid]]) { o[p.x] = t.read(p, 3); }
kernel void read_read(texture2d<float, access::read> t [[texture(0)]], device float4 *o [[buffer(0)]], uint2 p [[thread_position_in_grid]]) { o[p.x] = t.read(p); }
kernel void read_read_lod(texture2d<float, access::read> t [[texture(0)]], device float4 *o [[buffer(0)]], uint2 p [[thread_position_in_grid]]) { o[p.x] = t.read(p, 5); }
kernel void read_ushort(texture2d<float, access::read> t [[texture(0)]], device float4 *o [[buffer(0)]], ushort2 p [[thread_position_in_grid]]) { o[p.x] = t.read(p); }
kernel void read_uint(texture2d<uint, access::read> t [[texture(0)]], device uint4 *o [[buffer(0)]], uint2 p [[thread_position_in_grid]]) { o[p.x] = t.read(p); }
kernel void read_int(texture2d<int, access::read> t [[texture(0)]], device int4 *o [[buffer(0)]], uint2 p [[thread_position_in_grid]]) { o[p.x] = t.read(p); }
kernel void ms_size(texture2d_ms<float, access::read> t [[texture(0)]], device uint *o [[buffer(0)]], uint2 p [[thread_position_in_grid]]) { o[p.x] = t.get_width() + t.get_height(); }
