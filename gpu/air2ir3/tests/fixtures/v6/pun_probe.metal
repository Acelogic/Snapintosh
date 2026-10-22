/* SPDX-License-Identifier: MIT */
#include <metal_stdlib>
using namespace metal;
// verify6: float / half function constants read by bit pattern in the static initialiser, directly,
// through vector puns, through a shadow global stored as float and loaded as an integer (punStored),
// and the reverse (an int constant read as float bits).  No float arithmetic (no fast-math folding).
constant int N [[function_constant(3)]];
constant float F [[function_constant(4)]];
constant ushort U [[function_constant(5)]];
constant uint W [[function_constant(9)]];
constant half H [[function_constant(10)]];
constant float G = F;                       // shadow, stored as float
constant half J = H;
constant bool Q0 = signbit(F);
constant bool Q1 = isnan(F);
constant bool Q2 = isinf(F);
constant bool Q3 = (as_type<uint>(F) == 0x80000000u);
constant bool Q4 = (as_type<ushort2>(F).y == ushort(0xC0F0));
constant bool Q5 = (as_type<uchar4>(F).w >= uchar(0x80));
constant bool Q6 = signbit(H);
constant bool Q7 = isnan(H);
constant bool Q8 = (as_type<ushort>(H) == ushort(0x7C00));
constant bool Q9 = (as_type<uchar2>(H).y == uchar(0xBC));
constant bool Q10 = (as_type<uint>(G) > 0x7F800000u);
constant bool Q11 = (as_type<short>(J) < short(0));
constant bool Q12 = (as_type<half2>(F).y == -7.5h);           // bits of F read as two halves (compare: bitwise identical)
constant bool Q13 = (as_type<ushort>(as_type<half2>(W).x) == ushort(0x7E00));
constant bool Q14 = (as_type<uint>(as_type<float>(N)) == 0xFFC00000u);
constant bool Q15 = (as_type<ushort>(half(U)) == ushort(0x7C00)); // conversion, not a pun: U = 65535 -> inf
vertex float4 v(uint i [[vertex_id]]) { return float4(i == 1 ? 3.0 : -1.0, i == 2 ? 3.0 : -1.0, 0, 1); }
fragment float4 f(
  constant float4 &b0 [[buffer(0), function_constant(Q0)]], constant float4 &b1 [[buffer(1), function_constant(Q1)]],
  constant float4 &b2 [[buffer(2), function_constant(Q2)]], constant float4 &b3 [[buffer(3), function_constant(Q3)]],
  constant float4 &b4 [[buffer(4), function_constant(Q4)]], constant float4 &b5 [[buffer(5), function_constant(Q5)]],
  constant float4 &b6 [[buffer(6), function_constant(Q6)]], constant float4 &b7 [[buffer(7), function_constant(Q7)]],
  constant float4 &b8 [[buffer(8), function_constant(Q8)]], constant float4 &b9 [[buffer(9), function_constant(Q9)]],
  constant float4 &b10 [[buffer(10), function_constant(Q10)]], constant float4 &b11 [[buffer(11), function_constant(Q11)]],
  constant float4 &b12 [[buffer(12), function_constant(Q12)]], constant float4 &b13 [[buffer(13), function_constant(Q13)]],
  constant float4 &b14 [[buffer(14), function_constant(Q14)]], constant float4 &b15 [[buffer(15), function_constant(Q15)]]) {
  float4 r = 0;
  if (Q0) r.x += b0.x;  if (Q1) r.x += b1.x;  if (Q2) r.x += b2.x;  if (Q3) r.x += b3.x;
  if (Q4) r.x += b4.x;  if (Q5) r.x += b5.x;  if (Q6) r.x += b6.x;  if (Q7) r.x += b7.x;
  if (Q8) r.x += b8.x;  if (Q9) r.x += b9.x;  if (Q10) r.x += b10.x; if (Q11) r.x += b11.x;
  if (Q12) r.x += b12.x; if (Q13) r.x += b13.x; if (Q14) r.x += b14.x; if (Q15) r.x += b15.x;
  return r;
}
