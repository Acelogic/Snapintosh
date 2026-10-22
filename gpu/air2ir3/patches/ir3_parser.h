/* SPDX-License-Identifier: MIT */
/* Scratch build stub replacing the bison-generated header. */
#pragma once
#include <stdio.h>
#include "ir3/ir3_assembler.h"
#include "ir3/ir3_shader.h"
struct ir3 *ir3_parse(struct ir3_shader_variant *v, struct ir3_kernel_info *k, FILE *f);
