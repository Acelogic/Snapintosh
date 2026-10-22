/* SPDX-License-Identifier: MIT */
// Regression: function-constant-gated render targets (fb-fetch inputs and outputs).
// Prototype read the colour index from the predicate slot -> colour -1 (FRAG_RESULT_SAMPLE_MASK).
#include <metal_stdlib>
using namespace metal;
constant bool use_fetch [[function_constant(0)]];
constant bool write_second [[function_constant(1)]];
struct Out {
  half4 c0 [[color(0)]];
  half4 c2 [[color(2), function_constant(write_second)]];
};
fragment Out fc_rt(half4 dst [[color(2), function_constant(use_fetch)]], float4 p [[position]]) {
  Out o;
  o.c0 = half4(0.25h);
  if (use_fetch) o.c0 += dst;
  if (write_second) o.c2 = half4(1.0h, 0.5h, 0.25h, 1.0h);
  return o;
}
