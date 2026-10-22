/* SPDX-License-Identifier: MIT */
/* Scratch build stub: the ir3 text assembler needs bison >= 3 (host has 2.3).
 * ir3_parse is only used for debug shader overrides / ir3_parse_asm. */
#include "ir3_parser.h"
struct ir3 *
ir3_parse(struct ir3_shader_variant *v, struct ir3_kernel_info *k, FILE *f)
{
   (void)v; (void)k; (void)f;
   return NULL;
}
