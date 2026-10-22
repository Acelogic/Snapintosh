/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Translate a plain ERET to the nested host kernel. Other privilege regimes,
 * authenticated ERET and illegal return states require separate adapters. */
int exception_kernel_return(uint32_t instruction, uint64_t virtual_hcr,
    uint64_t pc, uint64_t guest_spsr, uint64_t *physical_spsr);
/* EL0 keeps its real privilege level under NV. The caller must additionally
 * validate the active user address space before installing this state. */
int exception_user_return(uint32_t instruction, uint64_t virtual_hcr,
    uint64_t pc, uint64_t guest_spsr, uint64_t *physical_spsr);
int exception_user_sync(uint64_t vector, uint64_t saved_spsr, uint64_t esr);
int exception_monitor_origin(uint64_t pc, uint64_t physical_spsr);
/* Narrow execution witness: the reached entry starts with MOV X0, SP.
 * A return request alone, a vector landing, or a failed instruction is not
 * evidence that this instruction completed at physical EL0. */
int exception_user_step(uint32_t instruction, uint64_t entry, uint64_t stack,
    uint64_t esr, uint64_t spsr, uint64_t pc, uint64_t x0, uint64_t sp);
/* These are delivered to XNU's handler in normal runs. It decides whether
 * to resolve the fault or panic; other exceptions remain diagnostic stops. */
int exception_kernel_page_fault(uint64_t esr);

struct exception_step { uint64_t active, saved_d; };
/* Repeated enable must not replace the original guest D bit with our temporary
 * zero. Disable when idle must not write a stale D bit into a new context. */
void exception_step_set(struct exception_step *step, int on,
                        uint64_t *spsr, uint64_t *mdscr);
int exception_step_fiq(const struct exception_step *step, int pending);
/* A synchronous guest exception can still interrupt a stepped instruction.
 * Remove monitor-only bits from its saved context before XNU reads it. */
int exception_step_suspend(struct exception_step *step, uint64_t *guest_spsr);
/* A stepped exception lands at an architectural vector slot, not at an
 * arbitrary instruction later in the same executable page. */
int exception_vector_step(uint64_t syndrome, uint64_t pc, uint64_t vbar);
