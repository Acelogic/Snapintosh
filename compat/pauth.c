/* SPDX-License-Identifier: MIT */
#include "pauth.h"

int pauth_pacga(uint32_t instruction, uint64_t regs[31], uint64_t sp,
                pauth_generic_sign sign, void *ctx)
{
    if ((instruction & 0xffe0fc00U) != 0x9ac03000U || !regs || !sign)
        return 0;
    unsigned rd = instruction & 31, rn = (instruction >> 5) & 31;
    unsigned rm = (instruction >> 16) & 31;
    uint64_t data = rn == 31 ? 0 : regs[rn];
    uint64_t modifier = rm == 31 ? sp : regs[rm];
    uint64_t result = sign(ctx, data, modifier) & 0xffffffff00000000UL;
    if (rd != 31) regs[rd] = result;
    return 1;
}
