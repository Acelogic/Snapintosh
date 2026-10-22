// SPDX-License-Identifier: MIT
#version 450
// SkyLight SimpleColorVertex: attribute 0 = colour, attribute 1 = position.
layout(location = 0) in vec4 color;
layout(location = 1) in vec2 pos;
layout(set = 2, binding = 1, std140) uniform VC { mat4 mvp; };
layout(location = 0) out vec4 o_color;            // generated(5colorDv4_f) -> slot 0
void main() { gl_Position = mvp * vec4(pos, 0.0, 1.0); o_color = color; }
