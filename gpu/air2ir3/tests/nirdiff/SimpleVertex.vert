// SPDX-License-Identifier: MIT
#version 450
// SkyLight SimpleVertex: position = mvp * float4(pos, 0, 1); tex_coord = tex.  mvp = buffer(1) (constant).
layout(location = 0) in vec2 pos;
layout(location = 1) in vec2 tex;
layout(set = 2, binding = 1, std140) uniform VC { mat4 mvp; };
layout(location = 0) out vec2 tex_coord;          // generated(3texDv2_f) -> slot 0
void main() { gl_Position = mvp * vec4(pos, 0.0, 1.0); tex_coord = tex; }
