/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_MMIO_H
#define SNAP_COMPAT_MMIO_H
#include <stdint.h>

struct mmio_pair { uint64_t address; unsigned reg[2]; };
/* Decode only integer LDP Xt, Xt2, [Xn|SP, #signed-offset], without
 * writeback. An ISV=0 stage-2 translation/permission fault supplies no
 * destination registers; those must come from the fetched instruction.
 * All refusals leave the output and guest registers unchanged. */
int mmio_ldp64_decode(uint32_t instruction, uint64_t esr,
    const uint64_t regs[31], uint64_t sp, struct mmio_pair *out);
void mmio_ldp64_complete(const struct mmio_pair *pair,
    const uint64_t values[2], uint64_t regs[31]);
/* Integer STP Xt, Xt2, [Xn|SP, #signed-offset], no writeback. Sources may
 * repeat or be XZR; neither source nor base changes when the store commits. */
int mmio_stp64_decode(uint32_t instruction, uint64_t esr,
    const uint64_t regs[31], uint64_t sp, struct mmio_pair *out);

struct mmio_preload { uint64_t address; unsigned reg, base; };
/* Integer LDR Wt, [Xn|SP, #signed-imm9]! only. Decode is side-effect free;
 * commit the zero-extended result and base writeback only after a successful
 * device read. Overlapping destination/base and address wrapping refuse. */
int mmio_ldr32_pre_decode(uint32_t instruction, uint64_t esr,
    const uint64_t regs[31], uint64_t sp, struct mmio_preload *out);
void mmio_ldr32_pre_complete(const struct mmio_preload *load, uint32_t value,
    uint64_t regs[31], uint64_t *sp);
#endif
