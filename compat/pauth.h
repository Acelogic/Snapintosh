/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Architectural PACGA only. The host supplies the cryptographic operation
 * and isolates the guest's generic key. Address PAC is a separate contract. */
typedef uint64_t (*pauth_generic_sign)(void *ctx, uint64_t data, uint64_t modifier);
int pauth_pacga(uint32_t instruction, uint64_t regs[31], uint64_t sp,
                pauth_generic_sign sign, void *ctx);
