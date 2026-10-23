/* SPDX-License-Identifier: MIT */
/* Boot-relocation relay calls, early-stop host calls and the thermal tick.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
#if SNAP_BOOT_RELOCATE
/* vCPU 0 relocated (compat/boot-relocate.h): post the call to q1n1's CPU, the
 * only one that may run the call service, and wait at most a second. POLL's
 * latch travels through the relay's own buffer: a caller that gave up never
 * has a late answer written into its stack. */
static uint64_t boot_relay_call(struct context *c, struct boot_relocation *r, uint64_t op,
                                uint64_t a1, uint64_t a2, uint64_t a3)
{
    struct boot_relay *q = &r->relay;
    int latch = op == EARLY_STOP_HOST_POLL;
    if ((latch && (!a1 || (a2 & 7) || a2 > sizeof q->buffer)) || !boot_relay_idle(q)) {
        q->refused++;
        return BOOT_RELAY_FAILED;
    }
    volatile uint64_t *buffer = q->buffer, *caller = (volatile uint64_t *)(uintptr_t)a1;
    if (latch) for (uint64_t n = 0; n < a2 / 8; n++) buffer[n] = caller[n];
    uint64_t ticket, result, start, now;
    if (!boot_relay_post(q, op, latch ? (uintptr_t)q->buffer : a1, a2, a3, &ticket)) {
        q->refused++;
        return BOOT_RELAY_FAILED;
    }
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(start));
    while (!boot_relay_answered(q, ticket, &result)) {
        __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(now));
        if (now - start >= c->params->clock_host_hz) {
            __atomic_store_n(&q->abandoned, 1, __ATOMIC_RELEASE);
            return BOOT_RELAY_FAILED;
        }
        __asm__ volatile("yield" ::: "memory");
    }
    if (latch) for (uint64_t n = 0; n < a2 / 8; n++) caller[n] = buffer[n];
    return result;
}
#endif
#if SNAP_GUEST_NET
static struct guest_net_ops guest_net_ops_of(struct context *c);
#endif
/* Host abort (compat/early-stop.h). CPU0 is the CPU inside q1n1's P_CALL; it
 * alone calls q1n1's call service, which runs on this stack at EL2 in q1n1's
 * identity map. host_in_call keeps the report from re-entering q1n1 when a
 * fault inside it is what ended the run. */
static uint64_t early_stop_host_call(struct context *c, uint64_t op, uint64_t a1, uint64_t a2,
                                     uint64_t a3)
{
    struct early_stop_state *s = &c->early_stop;
    uint64_t (*call)(uint64_t, uint64_t, uint64_t, uint64_t) =
        (uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)c->params->early_stop.host_call;
    s->host_in_call = 1;
#if SNAP_BOOT_RELOCATE
    struct boot_relocation *relocated = boot_relocation_of(c);
    uint64_t result = relocated && !boot_relocation_on_boot_cpu(c) ?
        boot_relay_call(c, relocated, op, a1, a2, a3) : call(op, a1, a2, a3);
#else
    uint64_t result = call(op, a1, a2, a3);
#endif
    s->host_in_call = 0;
    s->host_status = result;
    return result;
}

/* At most one poll per host_poll_ms. 1 when a host stop was accepted: the
 * caller rearms the timer so its deadline (normally now) is taken at once. */
static int early_stop_host_tick(struct context *c, uint64_t physical)
{
    const struct early_stop_params *p = &c->params->early_stop;
    struct early_stop_state *s = &c->early_stop;
    if (vcpu_of(c)->slot || !early_stop_host_due(s, p, physical, c->params->clock_host_hz))
        return 0;
    if (!s->host_armed) {
        if (early_stop_host_call(c, EARLY_STOP_HOST_ARM, p->session, 0, 0)) {
            s->host_errors++;
            return 0;
        }
        s->host_armed = 1;
    }
    /* The console rides on this poll (compat/console-link.h): q1n1 serves the
     * Mac from the view while it runs, and staged input moves into the UART's
     * receive ring after it. Every poll is timed, console or not. */
    struct console_link *link = &c->console_link;
    int console = !!(p->flags & EARLY_STOP_F_CONSOLE);
    if (console) console_link_prepare(link, c->console_tail, CONSOLE_TAIL_MAX, c->console_tail_bytes);
    struct early_stop_host_request r = {0};
    uint64_t before, after;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(before));
#if SNAP_GUEST_NET
    /* The guest network rides on the same poll (compat/guest-net-link.h):
     * POLL2 carries the console view and the net view together. An older
     * q1n1 answers Q1N1_CALL_E_OP once; from then on this run polls as before
     * and the ring is never offered (poll2_unsupported). */
    struct guest_net_state *net = c->guest_net;
    int net_on = (p->flags & EARLY_STOP_F_NET) && !net->link.poll2_unsupported;
    int net_view = 0;
    uint64_t latched;
    if (net_on) {
        const struct guest_net_ops o = guest_net_ops_of(c);
        net_view = guest_net_prepare(&net->link, &o, &net->view);
        net->views = (struct guest_net_poll_views){GUEST_NET_VIEWS_MAGIC, GUEST_NET_VIEWS_VERSION,
            console ? (uintptr_t)&link->view : 0, net_view ? (uintptr_t)&net->view : 0};
        latched = early_stop_host_call(c, GUEST_NET_POLL2, (uintptr_t)&r, sizeof r, (uintptr_t)&net->views);
        if (latched == GUEST_NET_CALL_E_OP) {
            net->link.poll2_unsupported = 1;
            net_view = 0;
            latched = early_stop_host_call(c, EARLY_STOP_HOST_POLL, (uintptr_t)&r, sizeof r,
                                           console ? (uintptr_t)&link->view : 0);
        }
        if (net_view) guest_net_commit(&net->link, &o, &net->view);
    } else
        latched = early_stop_host_call(c, EARLY_STOP_HOST_POLL, (uintptr_t)&r, sizeof r,
                                       console ? (uintptr_t)&link->view : 0);
#else
    uint64_t latched = early_stop_host_call(c, EARLY_STOP_HOST_POLL, (uintptr_t)&r, sizeof r,
                                            console ? (uintptr_t)&link->view : 0);
#endif
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(after));
    console_link_account(link, after - before);
    if (console) console_link_drain(link);
    if (latched != 1) {
        if (latched) s->host_errors++;
        return 0;
    }
    uint64_t accepted = 0;
    int e = early_stop_host_admit(p, &r, &accepted);
    if (!e) e = early_stop_request(s, EARLY_STOP_SOURCE_HOST, r.reason, r.nonce, r.delay_s,
                                   accepted, physical, c->params->clock_host_hz, 0, 0, r.text);
    else early_stop_refuse(s, e);
    record(c, EV_EARLY_STOP_REQUEST, 0, (uint64_t)EARLY_STOP_SOURCE_HOST << 32 | (uint32_t)r.reason,
           r.delay_s << 32 | (uint32_t)r.nonce, (uint64_t)(int64_t)e);
    return e == EARLY_STOP_ACCEPTED;
}

/* Read only the surveyed A16 TSENS registers. A synchronous bus abort takes
 * the monitor's fault path; read_inflight/location retain the attempted read.
 * No software policy can recover an interconnect that never returns. */
static int thermal_read(void *ctx,uint64_t address,uint32_t *value)
{
    (void)ctx;
    if(!a16_thermal_address_allowed(address))return -1;
    *value=*(const volatile uint32_t *)address;
    __asm__ volatile("dsb sy" ::: "memory");return 0;
}
static uint64_t thermal_clock(void *ctx) {(void)ctx;return service_profile_clock();}
static int thermal_tick(struct context *c,uint64_t physical)
{
    if(vcpu_of(c)->slot || !c->thermal)return 0;
    const struct a16_thermal_io io={c,thermal_read,thermal_clock};
    uint64_t previous=c->thermal->reason;
    int stop=a16_thermal_poll(c->thermal,&c->early_stop,physical,c->params->clock_host_hz,&io);
    if(stop && !previous)
        record(c,EV_EARLY_STOP_REQUEST,0,(uint64_t)EARLY_STOP_SOURCE_THERMAL<<32|c->thermal->reason,
               c->thermal->location,0);
    return stop;
}
/* Preparation checkpoints: one complete sample, resampling a brief VALID clear
 * (compat/a16-thermal.c a16_thermal_admit). Nonzero refuses entry. */
static int thermal_admit(struct context *c)
{
    if(vcpu_of(c)->slot || !c->thermal)return -1;
    const struct a16_thermal_io io={c,thermal_read,thermal_clock};
    uint64_t previous=c->thermal->reason;
    int admit=a16_thermal_admit(c->thermal,&c->early_stop,c->params->clock_host_hz,&io);
    if(admit>0 && !previous)
        record(c,EV_EARLY_STOP_REQUEST,0,(uint64_t)EARLY_STOP_SOURCE_THERMAL<<32|c->thermal->reason,
               c->thermal->location,0);
    return admit;
}
/* Preparation sampling between and inside the long setup steps (docs/
 * A16-THERMAL-GUARD-20261018.md, finer checkpoints). A trip is immutable, so
 * the next thermal_admit refuses with -28. Runtime allocation keeps table_alloc. */
static void thermal_prepare_tick(struct context *c)
{
    if(c->thermal)(void)thermal_tick(c,service_profile_clock());
}
static uint64_t prepare_table_alloc(void *ctx)
{
    thermal_prepare_tick(ctx);
    return table_alloc(ctx);
}
