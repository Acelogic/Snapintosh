// SPDX-License-Identifier: MIT
#version 450
// SkyLight ShadowCompositeFragment specialised with function constants {0:1, 1:0, 2:1, 3:1}:
// colour = sample * args[1]; colour.rgb *= args[2]  (args = buffer(0), floats at byte 4 and 8).
layout(location = 0) in vec2 uv;
layout(set = 0, binding = 0) uniform texture2D t;
layout(set = 1, binding = 0) uniform sampler s;   // constexpr sampler: ABI v4 lowest free S# (v3: 15)
layout(set = 2, binding = 0, std140) uniform FA { float a0; float a1; float a2; };
layout(location = 0) out vec4 o;
void main() { vec4 c = a1 * texture(sampler2D(t, s), uv); o = vec4(a2 * c.rgb, c.a); }
