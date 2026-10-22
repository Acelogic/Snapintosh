// SPDX-License-Identifier: MIT
#version 450
// SimpleTextureTint_FragmentArgs { float4 tint; float hdr_scale; } at buffer(0).
layout(location = 0) in vec2 uv;
layout(set = 0, binding = 0) uniform texture2D t;
layout(set = 1, binding = 0) uniform sampler s;   // constexpr sampler: ABI v4 lowest free S# (v3: 15)
layout(set = 2, binding = 0, std140) uniform FA { vec4 tint; float scale; };
layout(location = 0) out vec4 o;
void main() { vec4 c = texture(sampler2D(t, s), uv) * tint; o = vec4(scale * c.rgb, c.a); }
