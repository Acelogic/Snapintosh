// SPDX-License-Identifier: MIT
#version 450
// SkyLight runtime template HorizontalBackgroundBlur.template instantiated for radius 8 (the MSL is
// build/templates/hbb_r8.metal); args { float _skipDivideByAlpha; float _inverse_hdr_scaling_factor; }.
layout(location = 0) in vec2 uv;
layout(set = 0, binding = 0) uniform texture2D t;
layout(set = 1, binding = 0) uniform sampler s;   // constexpr sampler: ABI v4 lowest free S# (v3: 15)
layout(set = 2, binding = 0, std140) uniform FA { float skip; float inv_hdr; };
layout(location = 0) out vec4 o;
#define S(off) texture(sampler2D(t, s), uv + vec2(off, 0.0))
void main() {
  vec4 color = vec4(0.0);
  color += 0.103153 * texture(sampler2D(t, s), uv);
  color += 0.191011 * S(1.47658);
  color += 0.191011 * S(-1.47658);
  color += 0.140429 * S(3.44553);
  color += 0.140429 * S(-3.44553);
  color += 0.0807155 * S(5.4149);
  color += 0.0807155 * S(-5.4149);
  color += 0.0362685 * S(7.38491);
  color += 0.0362685 * S(-7.38491);
  color.rgb *= inv_hdr;
  o = color / max(color.a + 0.000001, skip);
}
