/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_WATCHDOG_H
#define SNAP_COMPAT_WATCHDOG_H
#include <stdint.h>

/* Audited Apple WD1 bank: CUR +0x10, BITE +0x14, CTRL +0x1c.
 * Clock samples are in the watchdog reference domain. Counter subtraction
 * permits wrapping samples; callers must supply monotonic elapsed time.
 * Expiry latches a guest reset request. Only VM initialization clears it.
 * WD0 CTRL accepts only disable/clear for its permanently inactive channel.
 * WD0 counters/bark/IRQ/reset, WD2 and board scratch registers are separate
 * contracts. */
struct watchdog_state {
    uint64_t last;
    uint32_t current, bite, control;
    unsigned ready, reset;
};
enum watchdog_result {
    WATCHDOG_OK, WATCHDOG_BAD_STATE, WATCHDOG_UNKNOWN_REGISTER,
    WATCHDOG_BAD_WIDTH, WATCHDOG_BAD_VALUE
};
void watchdog_init(struct watchdog_state *state, uint64_t now);
/* Poll and return the next reset interval, capped by budget. A latched reset
 * returns zero; a disabled watchdog returns budget. */
uint64_t watchdog_wait(struct watchdog_state *state, uint64_t now, uint64_t budget);
enum watchdog_result watchdog_access(struct watchdog_state *state, uint64_t now,
    uint64_t offset, unsigned width, int write, uint64_t *value);
#endif
