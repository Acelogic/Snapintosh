/* SPDX-License-Identifier: MIT */
#include "clock.h"

enum clock_result guest_clock_user_read(struct guest_clock *clock,
    const struct clock_backend *backend, uint32_t instruction, uint64_t regs[31])
{
    if((instruction&~31U)!=0xd53cfac0U)return CLOCK_UNHANDLED;
    if(!clock || !regs)return CLOCK_BACKEND_FAILED;
    if(!(clock->cntkctl&2))return CLOCK_CONTROL_UNSUPPORTED;
    uint64_t value=0;
    enum clock_result result=guest_clock_access(clock,backend,CLOCK_CNTVCTSS,1,&value);
    if(result==CLOCK_OK && (instruction&31)!=31)regs[instruction&31]=value;
    return result;
}

int clock_rate_init(struct clock_rate *rate, uint64_t host_hz, uint64_t guest_hz)
{
    if (!rate || !host_hz || host_hz > UINT32_MAX ||
        !guest_hz || guest_hz > UINT32_MAX) return -1;
    rate->host_hz = (uint32_t)host_hz;
    rate->guest_hz = (uint32_t)guest_hz;
    return 0;
}

uint64_t clock_rate_sample(const struct clock_rate *rate, uint64_t host_count)
{
    return (host_count / rate->host_hz) * rate->guest_hz +
           ((host_count % rate->host_hz) * rate->guest_hz) / rate->host_hz;
}

uint64_t clock_rate_wait(const struct clock_rate *rate, uint64_t host_now,
                         uint64_t guest_deadline, uint64_t host_budget)
{
    uint64_t delta = guest_deadline - clock_rate_sample(rate, host_now);
    if ((int64_t)delta <= 0) return 0;
    uint64_t q = delta / rate->guest_hz;
    uint64_t part = (delta % rate->guest_hz) * rate->host_hz;
    uint64_t phase = ((host_now % rate->host_hz) * rate->guest_hz) % rate->host_hz;
    uint64_t extra;
    if (part < phase) {
        /* q is nonzero here: delta>0, and a nonzero remainder contributes
         * at least host_hz, greater than phase. */
        q--;
        extra = rate->host_hz - (phase-part) / rate->guest_hz;
    } else {
        part -= phase;
        extra = part / rate->guest_hz + (part % rate->guest_hz != 0);
    }
    if (q > host_budget / rate->host_hz) return host_budget;
    uint64_t base = q * rate->host_hz;
    return extra > host_budget-base ? host_budget : base+extra;
}

int clock_event_shift(uint64_t host_hz, uint64_t guest_hz)
{
    if (!host_hz || !guest_hz || host_hz > UINT32_MAX || guest_hz > UINT32_MAX) return 0;
    uint64_t h = host_hz, g = guest_hz;
    int k = 0;
    /* Bring h/g into [1, 2), counting the doublings (below 2^47 each). */
    while (h >= 2*g && k < 15) { g <<= 1; k++; }
    while (g > h && k > -15) { h <<= 1; k--; }
    if (h < g || h >= 2*g) return k;
    /* Round up when h/g >= sqrt(2): h^2 >= 2g^2, with both scaled below 2^31
     * so the squares fit; the dropped low bits are below one part in 2^31. */
    while (h >= (UINT64_C(1) << 31)) { h >>= 1; g >>= 1; }
    return h*h >= 2*g*g && k < 15 ? k+1 : k;
}

uint64_t clock_event_host_control(uint64_t control, uint64_t host_hz, uint64_t guest_hz)
{
    int bit = (int)((control >> 4) & 15) + clock_event_shift(host_hz, guest_hz);
    if (bit < 0) bit = 0;
    if (bit > 15) bit = 15;
    return (control & ~UINT64_C(0xf0)) | ((uint64_t)bit << 4);
}

static uint64_t event_next(uint64_t control, uint64_t now)
{
    unsigned bit = (unsigned)((control >> 4) & 15);
    uint64_t period = 1UL << (bit+1);
    uint64_t phase = control & 8 ? 0 : period/2;
    uint64_t distance = (phase-now) & (period-1);
    return now + (distance ? distance : period);
}

static void event_poll(struct guest_event *event, uint64_t now)
{
    if ((event->control & 4) && (int64_t)(now-event->next) >= 0) {
        event->pending = 1;
        event->next = event_next(event->control, now);
    }
}

void guest_event_configure(struct guest_event *event, uint64_t control, uint64_t now)
{
    event_poll(event, now);
    if ((event->control ^ control) & 0xfc)
        event->next = event_next(control, now);
    event->control = control;
}

uint64_t guest_event_wait(struct guest_event *event, uint64_t now, uint64_t budget)
{
    event_poll(event, now);
    if (event->pending) return 0;
    if (!(event->control & 4)) return budget;
    uint64_t delta = event->next-now;
    return delta < budget ? delta : budget;
}

int guest_event_consume(struct guest_event *event, uint64_t now)
{
    event_poll(event, now);
    int pending = !!event->pending;
    event->pending = 0;
    return pending;
}

uint64_t guest_timer_control(const struct guest_timer *timer, uint64_t now)
{
    uint64_t ctl = timer->ctl;
    if ((ctl & 1) && (int64_t)(timer->cval - now) <= 0) ctl |= 4;
    return ctl;
}

int guest_timer_pending(const struct guest_timer *timer, uint64_t now)
{
    return guest_timer_control(timer, now) == 5;
}

uint64_t guest_timer_wait(const struct guest_timer *timer, uint64_t now,
                          uint64_t budget)
{
    if (timer->ctl != 1 || guest_timer_pending(timer, now)) return budget;
    uint64_t delta = timer->cval - now;
    return delta < budget ? delta : budget;
}

enum clock_result guest_timer_access(struct guest_timer *timer, uint64_t reg,
                                    int read, uint64_t *value, uint64_t now)
{
    if (reg != CLOCK_CNTV_CTL && reg != CLOCK_CNTV_TVAL) return CLOCK_UNHANDLED;
    if (!timer || !value) return CLOCK_BACKEND_FAILED;
    if (read) {
        /* TVAL is architecturally UNKNOWN while disabled; choose zero. */
        *value = reg == CLOCK_CNTV_CTL ? guest_timer_control(timer, now) :
                 timer->ctl & 1 ? (uint32_t)(timer->cval - now) : 0;
        timer->reads++;
    } else {
        if (reg == CLOCK_CNTV_CTL) {
            if (*value & ~UINT64_C(7)) return CLOCK_CONTROL_UNSUPPORTED;
            timer->ctl = *value & 3; /* ISTATUS is read-only, not W1C. */
        } else {
            /* TVAL is a signed 32-bit interval, including negative deadlines.
             * Its upper 32 write bits have no architectural effect. */
            timer->cval = now + (uint64_t)(int64_t)(int32_t)(uint32_t)*value;
        }
        timer->writes++;
    }
    return CLOCK_OK;
}

enum clock_result guest_timer_idle_access(struct guest_timer *timer, uint64_t reg,
                                         int read, uint64_t *value)
{
    if (reg != CLOCK_ARCH_CNTP_CTL) return CLOCK_UNHANDLED;
    if (!timer || !value) return CLOCK_BACKEND_FAILED;
    if (read) {
        *value = timer->ctl; /* Disabled ISTATUS is UNKNOWN; choose zero. */
        timer->reads++;
    } else {
        if (*value & ~UINT64_C(7)) return CLOCK_CONTROL_UNSUPPORTED;
        if (*value & 1) return CLOCK_TIMER_UNSUPPORTED;
        timer->ctl = *value & 2;
        timer->writes++;
    }
    return CLOCK_OK;
}

enum clock_result guest_clock_access(struct guest_clock *clock,
    const struct clock_backend *backend, uint64_t reg, int read, uint64_t *value)
{
    if (reg == CLOCK_CNTV_CTL || reg == CLOCK_CNTV_TVAL)
        return CLOCK_TIMER_UNSUPPORTED;
    if (reg != CLOCK_CNTVCTSS && reg != CLOCK_CNTVCT && reg != CLOCK_CNTKCTL &&
        reg != CLOCK_ARCH_CNTVCT && reg != CLOCK_ARCH_CNTVCTSS)
        return CLOCK_UNHANDLED;
    if (!clock || !backend || !value) return CLOCK_BACKEND_FAILED;
    if (reg == CLOCK_CNTKCTL) {
        if (read) {
            *value = clock->cntkctl;
            return CLOCK_OK;
        }
        /* EL0PCTEN, EL0VCTEN, EVNTEN, EVNTDIR, EVNTI[3:0]. A larger Apple
         * event index needs a separate frequency adapter, not truncation. */
        if (*value & ~UINT64_C(0xff)) return CLOCK_CONTROL_UNSUPPORTED;
        if (!backend->control || backend->control(backend->ctx, *value))
            return CLOCK_BACKEND_FAILED;
        clock->cntkctl = *value;
        clock->writes++;
        return CLOCK_OK;
    }
    if (!read) return CLOCK_READ_ONLY;
    if (!backend->counter) return CLOCK_BACKEND_FAILED;
    uint64_t sample = backend->counter(backend->ctx);
    if (!clock->reads) clock->first = sample;
    clock->last = sample;
    clock->reads++;
    *value = sample;
    return CLOCK_OK;
}
