/* SPDX-License-Identifier: MIT */
// fix3 (verify3 item 4): which fragment functions must run per sample on a multisampled pipeline.
#include <metal_stdlib>
using namespace metal;
struct VS { float4 p [[position]]; float2 uv [[sample_perspective]]; };
struct VC { float4 p [[position]]; float2 uv; };
fragment float4 ms_sample_id(uint s [[sample_id]]) { return float4(float(s), 0, 0, 1); }
fragment float4 ms_sample_interp(VS v [[stage_in]]) { return float4(v.uv, 0, 1); }
fragment float4 ms_fbfetch(float4 c [[color(0)]]) { return c * 0.5; }
fragment float4 ms_plain(VC v [[stage_in]]) { return float4(v.uv, 0, 1); }
