/* SPDX-License-Identifier: MIT */
#include "watchdog.h"

void watchdog_init(struct watchdog_state *s, uint64_t now)
{
    *s = (struct watchdog_state){.last = now, .ready = 1};
}

uint64_t watchdog_wait(struct watchdog_state *s, uint64_t now, uint64_t budget)
{
    if (!s || !s->ready) return budget;
    uint64_t elapsed = now - s->last;
    /* Check before reducing the counter to 32 bits: even a late poll must
     * observe a threshold crossed before one or more counter wraps. */
    if ((s->control & 4) && (s->current >= s->bite ||
                             elapsed >= (uint64_t)s->bite - s->current))
        s->reset = 1;
    s->current += (uint32_t)elapsed;
    s->last = now;
    if (s->reset) return 0;
    if (s->control & 4) {
        uint64_t left = (uint64_t)s->bite - s->current;
        if (left < budget) return left;
    }
    return budget;
}

enum watchdog_result watchdog_access(struct watchdog_state *s, uint64_t now,
    uint64_t offset, unsigned width, int write, uint64_t *value)
{
    if (!s || !s->ready || !value) return WATCHDOG_BAD_STATE;
    if (width != 4 || (offset & 3)) return WATCHDOG_BAD_WIDTH;
    if (offset == 0x0c) {
        /* AppleARMWatchdogTimer::start disables WD0 even with wdt=-1.
         * This virtual channel has never been enabled and has no pending
         * interrupt. Admit disable and W1C status clear only. */
        if (write && (*value & ~2UL)) return WATCHDOG_BAD_VALUE;
        watchdog_wait(s, now, UINT64_MAX);
        if (!write) *value = 0;
        return WATCHDOG_OK;
    }
    if (offset != 0x10 && offset != 0x14 && offset != 0x1c)
        return WATCHDOG_UNKNOWN_REGISTER;
    /* Bit 1 is W1C IRQ status. WD1 has no implemented IRQ producer, so it
     * reads zero and clearing it is harmless. IRQ enable and unknown bits
     * fail before polling or changing any state. */
    if (write && (*value > UINT32_MAX ||
                  (offset == 0x1c && (*value & ~6UL))))
        return WATCHDOG_BAD_VALUE;
    watchdog_wait(s, now, UINT64_MAX);
    uint32_t *reg = offset == 0x10 ? &s->current :
                    offset == 0x14 ? &s->bite : &s->control;
    if (write) {
        *reg = offset == 0x1c ? (uint32_t)*value & 4 : (uint32_t)*value;
        watchdog_wait(s, now, UINT64_MAX);
    } else *value = *reg;
    return WATCHDOG_OK;
}
