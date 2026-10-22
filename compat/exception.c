/* SPDX-License-Identifier: MIT */
#include "exception.h"

int exception_vector_step(uint64_t syndrome, uint64_t pc, uint64_t vbar)
{
    return (syndrome >> 26) == 0x32 && vbar && !(vbar & 0x7ff) &&
           pc >= vbar && pc - vbar < 0x800 && !((pc - vbar) & 0x7f);
}

void exception_step_set(struct exception_step *step, int on,
                        uint64_t *spsr, uint64_t *mdscr)
{
    const uint64_t d = 1UL << 9, ss = 1UL << 21;
    if (on) {
        if (!step->active) step->saved_d = *spsr & d;
        step->active = 1;
        *spsr = (*spsr | ss) & ~d;
        *mdscr |= 1;
    } else {
        *spsr &= ~ss;
        *mdscr &= ~1UL;
        if (step->active) *spsr = (*spsr & ~d) | step->saved_d;
        step->active = 0;
    }
}

int exception_step_fiq(const struct exception_step *step, int pending)
{
    return pending && !step->active;
}

int exception_step_suspend(struct exception_step *step, uint64_t *guest_spsr)
{
    if (!step->active) return 0;
    *guest_spsr = (*guest_spsr & ~((1UL << 9) | (1UL << 21))) | step->saved_d;
    step->active = 0;
    return 1;
}

int exception_kernel_page_fault(uint64_t esr)
{
    unsigned ec = (esr >> 26) & 63, fsc = esr & 63;
    return (ec == 0x21 || ec == 0x25) && fsc >= 4 && fsc <= 15;
}

int exception_user_return(uint32_t instruction, uint64_t virtual_hcr,
    uint64_t pc, uint64_t guest_spsr, uint64_t *physical_spsr)
{
    const uint64_t host_bits = (1UL << 34) | (1UL << 31) | (1UL << 27);
    if (!physical_spsr || instruction != 0xd69f03e0U ||
        (virtual_hcr & host_bits) != host_bits || !pc || pc >= (1UL << 47) ||
        (pc & 3) || (guest_spsr & 31) || (guest_spsr >> 32) ||
        (guest_spsr & ((1UL << 20) | (1UL << 5)))) return 0;
    *physical_spsr = guest_spsr;
    return 1;
}

int exception_user_sync(uint64_t vector, uint64_t saved_spsr, uint64_t esr)
{
    unsigned ec = (esr >> 26) & 63, fsc = esr & 63;
    return vector == 0x400 && !(saved_spsr & 31) &&
        (ec == 0x15 || ((ec == 0x20 || ec == 0x24) && fsc >= 4 && fsc <= 15));
}

int exception_monitor_origin(uint64_t pc, uint64_t physical_spsr)
{
    unsigned mode = physical_spsr & 31;
    return pc >= 0xffff800000000000UL && !(pc & 3) && (mode == 4 || mode == 5);
}

int exception_user_step(uint32_t instruction, uint64_t entry, uint64_t stack,
    uint64_t esr, uint64_t spsr, uint64_t pc, uint64_t x0, uint64_t sp)
{
    return instruction == 0x910003e0U && entry && entry < (1UL << 47) - 4 &&
        !(entry & 3) && stack && stack < (1UL << 47) &&
        (esr >> 26) == 0x32 && !(spsr & 31) && pc == entry + 4 &&
        x0 == stack && sp == stack;
}

int exception_kernel_return(uint32_t instruction, uint64_t virtual_hcr,
    uint64_t pc, uint64_t guest_spsr, uint64_t *physical_spsr)
{
    const uint64_t host_bits = (1UL << 34) | (1UL << 31) | (1UL << 27);
    unsigned mode = guest_spsr & 31;
    if (!physical_spsr || instruction != 0xd69f03e0U ||
        (virtual_hcr & host_bits) != host_bits ||
        pc < 0xffff800000000000UL || (pc & 3) ||
        (mode != 8 && mode != 9) || (guest_spsr >> 32) ||
        (guest_spsr & ((1UL << 20) | (1UL << 5))))
        return 0;
    /* NV reports EL2 in the saved mode; the kernel actually executes at
     * physical EL1. Preserve NZCV, DAIF, PAN and the stack selector. */
    *physical_spsr = (guest_spsr & ~15UL) | (mode - 4);
    return 1;
}
