/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
constant uchar I [[function_constant(0)]];
constant bool G1 = (I == 1);
constant bool G0 = (I == 0);
struct O { float4 c0 [[color(0)]]; float4 c1 [[color(1), function_constant(G1)]]; };
fragment O out_c1(float4 p [[position]]) { O o; o.c0 = float4(1, 0, 0, 1); o.c1 = float4(0, 1, 0, 1); return o; }
struct O0 { float4 c0 [[color(0), function_constant(G0)]]; float4 c1 [[color(1)]]; };
fragment O0 out_c0(float4 p [[position]]) { O0 o; o.c0 = float4(1, 0, 0, 1); o.c1 = float4(0, 1, 0, 1); return o; }
struct OD { float4 c0 [[color(0), index(0)]]; float4 c0b [[color(0), index(1), function_constant(G1)]]; };
fragment OD out_dual(float4 p [[position]]) { OD o; o.c0 = float4(1, 0, 0, 1); o.c0b = float4(0.5); return o; }
fragment float4 in_fb(float4 p [[position]], float4 d1 [[color(1), function_constant(G1)]]) { return float4(1, 0, 0, 1); }
struct OT { float4 c0 [[color(0)]]; float d [[depth(any), function_constant(G1)]]; };
fragment OT out_depth(float4 p [[position]]) { OT o; o.c0 = 1; o.d = 0.5; return o; }
