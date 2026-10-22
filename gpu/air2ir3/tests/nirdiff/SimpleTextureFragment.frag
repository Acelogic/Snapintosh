// SPDX-License-Identifier: MIT
#version 450
// texture(0) + API sampler(0), implicit-LOD sample.
layout(location = 0) in vec2 uv;
layout(set = 0, binding = 0) uniform texture2D t;
layout(set = 1, binding = 0) uniform sampler s;
layout(location = 0) out vec4 o;
void main() { o = texture(sampler2D(t, s), uv); }
