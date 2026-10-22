// SPDX-License-Identifier: MIT
#version 450
// CoreDisplay TextureCopy: constexpr sampler (pixel coordinates, linear) -> S#15.
layout(location = 0) in vec2 uv;
layout(set = 0, binding = 0) uniform texture2D t;
layout(set = 1, binding = 0) uniform sampler s;   // constexpr sampler: ABI v4 lowest free S# (v3: 15)
layout(location = 0) out vec4 o;
void main() { o = texture(sampler2D(t, s), uv); }
