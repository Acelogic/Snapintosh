/* SPDX-License-Identifier: MIT */
/* Watchdog, run deadline, runtime enter/leave accounting and the EL2 timer.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */

/* A guest that never comes back leaves EL2 blocked inside the proxy call, which
 * on this machine means a power cycle -- the exact failure that makes a boot
 * attempt expensive instead of cheap. So the guest runs on a clock: the EL2
 * physical timer is armed before the ERET and routed to EL2 with HCR_EL2.IMO,
 * which EL1's own PSTATE.I cannot mask. Whatever XNU is doing, control comes
 * back and says so.
 *
 * q1n1 drives its own 1 kHz tick from this timer, so its state is saved and put
 * back rather than assumed unused. */
static void timer_arm(struct context *c,uint64_t physical,uint64_t device_due);
void xnuboot_watchdog(uint64_t seconds);
void xnuboot_watchdog(uint64_t seconds)
{
    struct context *c = context_of();
    uint64_t freq, now;
    __asm__ volatile("mrs %0, cnthp_ctl_el2" : "=r"(vcpu_of(c)->save_cnthp_ctl));
    __asm__ volatile("mrs %0, cnthp_cval_el2" : "=r"(vcpu_of(c)->save_cnthp_cval));
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (!freq) freq = 24000000;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
    vcpu_of(c)->watchdog_deadline = now + freq * seconds;
    vcpu_of(c)->watchdog_live = 1;
    /* The first guest instruction may never trap. Apply the same host-stop,
     * thermal, pending-stop and peer-poll bounds used by every later tick. */
    timer_arm(c,now,UINT64_MAX);
}

static void watchdog_off(struct context *c)
{
    if (!vcpu_of(c)->watchdog_live) return;
    vcpu_of(c)->watchdog_live = 0;
    __asm__ volatile("msr cnthp_ctl_el2, xzr; isb");
    __asm__ volatile("msr cnthp_cval_el2, %0" :: "r"(vcpu_of(c)->save_cnthp_cval));
    __asm__ volatile("msr cnthp_ctl_el2, %0" :: "r"(vcpu_of(c)->save_cnthp_ctl));
    __asm__ volatile("isb");
}

/* The deadline this CPU's timer honours: the budget, or an accepted early
 * stop before it (compat/early-stop.h). Equal to the budget when idle. */
static uint64_t run_deadline(struct context *c)
{
    return early_stop_deadline(&c->early_stop, vcpu_of(c)->watchdog_deadline);
}

static uint64_t service_profile_clock(void)
{
    uint64_t now;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(now) :: "memory");
    return now;
}

static int runtime_enter(struct context *c, const uint64_t *frame, uint64_t elr,
                         unsigned category)
{
    struct vcpu *v = vcpu_of(c);
    struct service_profile *profile = &c->service_profile[v->slot];
    if (SNAP_STEP_ALU) step_alu_enter(&c->step_alu[v->slot], category);
    /* No translation survives a sysreg access, another fault, IRQ, or CPU
     * bootstrap. Cross-CPU shadow updates are detected by shadow_tlb_syncs.
     * Only consecutive ordinary step traps in one open EXEC page can hit. */
    if (category != 0x32) step_translation_clear(&c->step_translation[v->slot]);
    if (SNAP_SERVICE_PROFILE)
        service_profile_begin(profile, service_profile_clock(), category);
#if SNAP_FAIR_TOKEN
    /* compat/service-lock.h: the token in arrival order. */
    uint32_t ticket = guest_service_queue(&c->services);
    enum guest_service_result result = guest_service_try_turn(&c->services, v->slot, ticket);
#else
    enum guest_service_result result = guest_service_try(&c->services, v->slot);
#endif
    int contended = result == SERVICE_BUSY;
    if (result == SERVICE_BUSY) {
        uint64_t now;
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
        uint64_t deadline = now + c->params->clock_host_hz; /* at most one second */
        do {
            __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
            if(guest_service_stopped(&c->services)) {result=SERVICE_STOPPED;break;}
            result=guest_service_wait_expiry(now,deadline,v->watchdog_live,v->watchdog_deadline);
            if(result!=SERVICE_BUSY) {
                if(result==SERVICE_STOPPED) {
                    guest_service_stop(&c->services,v->slot,SERVICE_STOP_NORMAL);
                    if(guest_service_stopped(&c->services)==(((uint64_t)SERVICE_STOP_NORMAL<<32)|(v->slot+1)))
                        c->service_budget_stops[v->slot]=1;
                }
                break;
            }
            __asm__ volatile("yield");
#if SNAP_FAIR_TOKEN
            result = guest_service_try_turn(&c->services, v->slot, ticket);
#else
            result = guest_service_try(&c->services, v->slot);
#endif
        } while (result == SERVICE_BUSY);
    }
#if SNAP_FINE_LOCKS
    /* The token excludes converted calls once their readers have left
     * (compat/fine-lock.h L0): none can enter while it is held, and each in
     * flight finishes one bounded critical section. Counted as wait. */
    if (result == SERVICE_OK && !guest_service_drained(&c->services)) {
        uint64_t now, deadline;
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
        deadline = now + c->params->clock_host_hz;
#if SNAP_PHASE_FAIR_GATE
        uint64_t drain_from = now;
#endif
        contended = 1;
        while (!guest_service_drained(&c->services)) {
            __asm__ volatile("yield; mrs %0, cntpct_el0" : "=r"(now));
            if ((int64_t)(now - deadline) >= 0) {
                guest_service_release(&c->services, v->slot);
                result = SERVICE_TIMEOUT;
                break;
            }
        }
#if SNAP_PHASE_FAIR_GATE
        /* compat/token-costs.h gate[5], gate[6]: drains that waited (now also
         * for converted calls queued in the previous writer's phase). */
        if (result == SERVICE_OK) {
            fine_add(&c->root_ext->gate[5], 1);
            fine_add(&c->root_ext->gate[6], now - drain_from);
        }
#endif
    }
#endif
    if (SNAP_SERVICE_PROFILE)
        service_profile_wait_done(profile, service_profile_clock(), result == SERVICE_OK,
                                  contended);
    if (result == SERVICE_OK) { v->service_acquires++; return 1; }
    /* No shared log/device writes without ownership. The private snapshot and
     * dedicated report fields preserve failure even if the event ring is full. */
    v->service_fault = result == SERVICE_STOPPED ? 0 : result;
    fill_regs(&v->async_regs, frame, 0, elr, 0);
    v->async_captured = 1;
    if (result != SERVICE_STOPPED)
        guest_service_stop(&c->services, v->slot, SERVICE_STOP_FAULT);
    watchdog_off(c);
    return 0;
}

static int runtime_leave(struct context *c, int stop)
{
    struct vcpu *v = vcpu_of(c);
    stop|=!!(c->user_view_failed || c->root_install_failures || c->kernel_view_failed);
    if (stop) guest_service_stop(&c->services, v->slot, SERVICE_STOP_NORMAL);
#if SNAP_SERVICE_SUBCLASS
    int completed = c->service_profile[v->slot].stage == 2;
#endif
    /* End before release: never charge another CPU's ownership to this one.
     * Assembly entry/exit, release itself and this instrumentation are not a
     * separately measured guest-time bucket. */
    if (SNAP_SERVICE_PROFILE)
        service_profile_end(&c->service_profile[v->slot], service_profile_clock());
#if SNAP_SERVICE_SUBCLASS
    /* Still under the lock: the sub-class buckets are shared. */
#if SNAP_OTHER_PROFILE
    unsigned sub_tag = v->slot < SERVICE_SUB_CPUS ? c->exit_profile.sub.current[v->slot] : SERVICE_SUB_OTHER;
#endif
    service_sub_charge(&c->exit_profile.sub, (unsigned)v->slot, &c->service_profile[v->slot],
                       completed);
#if SNAP_OTHER_PROFILE
    other_profile_charge(&c->root_ext->other, (unsigned)v->slot, &c->service_profile[v->slot],
                         completed, sub_tag);
#endif
#endif
    enum guest_service_result result = guest_service_release(&c->services, v->slot);
    if (result != SERVICE_OK) {
        v->service_fault = result;
        guest_service_stop(&c->services, v->slot, SERVICE_STOP_FAULT);
    }
    return stop || result != SERVICE_OK || guest_service_stopped(&c->services) != 0;
}

/* The q1n1 adapter multiplexes the guest deadline and the fixed run budget on
 * its already enabled EL2 timer PPI (26). No Apple AIC or Qualcomm peripheral
 * registers are involved. A timer expiry drives a guest level FIQ; watchdog
 * expiry still exits even when XNU has all its own interrupts masked.
 * Physical SMP also uses a 1 ms service deadline for remote IPI delivery.
 * This wakes a sleeping/busy guest without depending on its next trap or
 * borrowing an unowned SGI; only guest SR W1C consumes the queued IPI. */
static uint64_t clock_counter(void *ctx);
/* This CPU's EL2 timer at the earliest of its guest timer, the device deadline
 * (guest ticks, UINT64_MAX for none), the run budget, the IPI poll and CPU0's
 * host-stop poll. timer_sync and the lock-free CNTV_TVAL write share it. */
static void timer_arm(struct context *c, uint64_t physical, uint64_t device_due)
{
    if (!vcpu_of(c)->watchdog_live) return;
    uint64_t end = run_deadline(c);
    uint64_t budget = (int64_t)(end - physical) > 0 ? end - physical : 0;
    uint64_t delay = budget;
    if (vcpu_of(c)->timer.ctl == 1 && !vcpu_of(c)->timer_pending)
        delay = clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last,
                                vcpu_of(c)->timer.cval, budget);
    if (device_due != UINT64_MAX)
        delay = clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last,
                                device_due, delay);
#if SNAP_ANS_ASYNC
    {   /* agents/nvme-async N3, N19: the SSD command this vCPU owns is polled at its deadline. */
        uint64_t ans_due;
        if (ans_async_due_of(c, vcpu_of(c)->slot, &ans_due)) {
            uint64_t d = (int64_t)(ans_due - physical) > 0 ? ans_due - physical : 0;
            if (d < delay) delay = d;
        }
    }
#endif
    if (c->host_cpus) delay=guest_ipi_poll_delay(vcpu_of(c)->clock_rate.host_hz,delay);
    /* CPU0 polls q1n1 for a host stop no less often than asked. */
    const struct early_stop_params *stop = &c->params->early_stop;
    if (!vcpu_of(c)->slot && (stop->flags & EARLY_STOP_F_HOST)) {
        uint64_t poll = c->params->clock_host_hz / 1000 * stop->host_poll_ms;
        if (poll && poll < delay) delay = poll;
    }
    if(!vcpu_of(c)->slot && c->thermal)
        delay=a16_thermal_wait(c->thermal,physical,c->params->clock_host_hz,delay);
    uint64_t next = physical + delay;
    __asm__ volatile("msr cnthp_cval_el2, %0" :: "r"(next));
    __asm__ volatile("msr cnthp_ctl_el2, %0; isb" :: "r"(1UL));
}
static void timer_sync(struct context *c)
{
    uint64_t now, physical;
    now = clock_counter(c);
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(physical));
    uint64_t device_ticks = UINT64_MAX;
    for (unsigned i=0; i<c->params->model_count; i++) {
        device_ticks = device_model_wait(&c->params->models[i], &c->model_state[i],
                                         now, device_ticks);
    }
    device_latch_resets(c->params->models,c->model_state,
                        c->params->model_count,c->device_reset_mask);
    vcpu_of(c)->timer_pending = guest_timer_pending(&vcpu_of(c)->timer, now);
    guest_interrupt_sync(c);
    uint64_t due = device_ticks == UINT64_MAX ? UINT64_MAX : now + device_ticks;
    struct fast_timer_due *d = &c->fast_timer_due[vcpu_of(c)->slot];
    d->guest = due;
    d->physical = due == UINT64_MAX ? UINT64_MAX : physical +
        clock_rate_wait(&vcpu_of(c)->clock_rate, vcpu_of(c)->clock_raw_last, due, UINT64_MAX);
    timer_arm(c, physical, due);
}

static int device_reset_stop(struct context *c, uint64_t elr, const uint64_t *frame)
{
    if (!(c->device_reset_mask[0] | c->device_reset_mask[1])) return 0;
    record(c, EV_DEVICE_RESET, elr, c->device_reset_mask[0], c->device_reset_mask[1], 0);
    fill_regs(&vcpu_of(c)->async_regs, frame, 0, elr, 0);
    vcpu_of(c)->async_captured = 1;
    watchdog_off(c);
    return 1;
}
#if SNAP_ANS_ASYNC
/* The locked tick's ANS poll (token held; agents/nvme-async N3, N18): the owner
 * at its deadline, anyone once the command is ANS_ASYNC_BACKSTOP_US late. A
 * refusal found here stops the run as the doorbell's would (EV_ANS, kind 0xa5:
 * the tick). 1: stop. */
static int ans_async_tick(struct context *c, uint64_t elr, const uint64_t *frame)
{
    struct ans_state *s = c->root_ext->ans;
    if (!s || !ans_async_busy(s, 0)) return 0;
    struct ans_async *a = &s->async;
    uint64_t now = service_profile_clock(), due = __atomic_load_n(&a->due, __ATOMIC_RELAXED);
    int mine = __atomic_load_n(&a->owner, __ATOMIC_RELAXED) == (uint64_t)vcpu_of(c)->slot + 1 && due &&
               (int64_t)(now - due) >= 0;
    int late = due && (int64_t)(now - due - ans_async_us(c, ANS_ASYNC_BACKSTOP_US)) >= 0;
    if (!mine && !late) return 0;
    __atomic_fetch_add(&a->sched[mine ? 0 : 1], 1, __ATOMIC_RELAXED);
    struct ans_ops o = ans_ops_of(c);
    int r = ans_async_progress(s, &o, ANS_ASYNC_STEP_MAX);
    if (!r) {
        ans_async_schedule(c);
        if (ans_async_lines(c) == DEVICE_OK) return 0;
        r = ANS_E_STATE;
    }
    record(c, EV_ANS, elr, (uint64_t)r << 32 | 0xa5, s->refusal[1], s->refusal[2]);
    fill_regs(&vcpu_of(c)->async_regs, frame, 0, elr, 0);
    vcpu_of(c)->async_captured = 3;
    watchdog_off(c);
    return 1;
}
#endif

static void timer_eoi(uint64_t intid)
{
    uint64_t ctl;
    __asm__ volatile("mrs %0, icc_ctlr_el1" : "=r"(ctl));
    __asm__ volatile("dsb sy; msr icc_eoir1_el1, %0; isb" :: "r"(intid) : "memory");
    if (ctl & 2) /* EOImode: priority drop and deactivation are separate. */
        __asm__ volatile("msr icc_dir_el1, %0; isb" :: "r"(intid));
}

