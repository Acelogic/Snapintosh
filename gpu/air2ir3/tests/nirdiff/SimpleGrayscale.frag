// SPDX-License-Identifier: MIT
#version 450
// texture(1), constexpr sampler -> S#15 (BINDING-ABI.md 3.5); Rec.709 luma.
layout(location = 0) in vec2 uv;
layout(set = 0, binding = 1) uniform texture2D t;
layout(set = 1, binding = 0) uniform sampler s;   // constexpr sampler: ABI v4 lowest free S# (v3: 15)
layout(location = 0) out vec4 o;
void main() { vec4 c = texture(sampler2D(t, s), uv); o = vec4(vec3(dot(c.rgb, vec3(0.2125, 0.7154, 0.0721))), c.a); }
