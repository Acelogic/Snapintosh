/* SPDX-License-Identifier: MIT */
#include "service-lock.h"
_Static_assert(__atomic_always_lock_free(sizeof(uint64_t),0), "native 64-bit atomics required");
#define STATE_MASK ((UINT64_C(1)<<(GUEST_CPU_COUNT*3))-1)

static int valid_lifecycle(uint64_t value)
{
    if (value & ~(STATE_MASK | SERVICE_ADMISSION_CLOSED)) return 0;
    for (unsigned cpu=0; cpu<GUEST_CPU_COUNT; cpu++)
        if (((value>>(cpu*3))&7)>EXECUTOR_QUIESCED) return 0;
    return 1;
}
static unsigned state(uint64_t value, unsigned cpu) { return (value>>(cpu*3))&7; }
uint64_t guest_service_lifecycle(const struct guest_service_lock *lock)
{
    return __atomic_load_n(&lock->lifecycle,__ATOMIC_ACQUIRE);
}
static int transition(struct guest_service_lock *lock, uint64_t *before,
                      unsigned cpu, unsigned after)
{
    uint64_t value=(*before & ~(UINT64_C(7)<<(cpu*3))) | ((uint64_t)after<<(cpu*3));
    return __atomic_compare_exchange_n(&lock->lifecycle,before,value,0,
                                       __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
enum guest_service_result guest_service_boot(struct guest_service_lock *lock)
{
    if (!lock) return SERVICE_BAD_CPU;
    uint64_t before=0;
    return transition(lock,&before,0,EXECUTOR_RUNNING) ? SERVICE_OK : SERVICE_BAD_STATE;
}
enum guest_service_result guest_service_reserve(struct guest_service_lock *lock,
                                               unsigned caller, unsigned target)
{
    if (!lock || caller>=GUEST_CPU_COUNT || !target || target>=GUEST_CPU_COUNT)
        return SERVICE_BAD_CPU;
    if (guest_service_owner(lock)!=caller+1) return SERVICE_BAD_OWNER;
    uint64_t before=guest_service_lifecycle(lock);
    do {
        if (!valid_lifecycle(before)) return SERVICE_BAD_STATE;
        if (before&SERVICE_ADMISSION_CLOSED) return SERVICE_STOPPED;
        if (state(before,caller)!=EXECUTOR_RUNNING || state(before,target)!=EXECUTOR_OFF)
            return SERVICE_BAD_STATE;
    } while (!transition(lock,&before,target,EXECUTOR_RESERVED));
    return SERVICE_OK;
}
enum guest_service_result guest_service_arrive(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || !cpu || cpu>=GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    uint64_t before=guest_service_lifecycle(lock);
    do {
        if (!valid_lifecycle(before) || state(before,cpu)!=EXECUTOR_RESERVED)
            return SERVICE_BAD_STATE;
    } while (!transition(lock,&before,cpu,EXECUTOR_RUNNING));
    /* Arrival after a stop must still be accounted for, then clean up without
     * entering the guest. Returning STOPPED does not undo physical startup. */
    return guest_service_lifecycle(lock)&SERVICE_ADMISSION_CLOSED ? SERVICE_STOPPED : SERVICE_OK;
}
enum guest_service_result guest_service_quiesce(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu>=GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    if (guest_service_owner(lock)==cpu+1) return SERVICE_BAD_OWNER;
    uint64_t before=guest_service_lifecycle(lock);
    do {
        if (!valid_lifecycle(before) || !(before&SERVICE_ADMISSION_CLOSED)) return SERVICE_BAD_STATE;
        if (state(before,cpu)==EXECUTOR_QUIESCED) return SERVICE_OK;
        if (state(before,cpu)!=EXECUTOR_RUNNING) return SERVICE_BAD_STATE;
    } while (!transition(lock,&before,cpu,EXECUTOR_QUIESCED));
    return SERVICE_OK;
}
enum guest_service_result guest_service_confirm_off(struct guest_service_lock *lock,
    unsigned controller, unsigned cpu, int64_t affinity_info)
{
    if (!lock || controller || !cpu || cpu>=GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    if (affinity_info!=1) return SERVICE_BAD_STATE;
    if (guest_service_owner(lock)==cpu+1) return SERVICE_BAD_OWNER;
    uint64_t before=guest_service_lifecycle(lock);
    do {
        if (!valid_lifecycle(before) || !(before&SERVICE_ADMISSION_CLOSED) ||
            state(before,cpu)!=EXECUTOR_QUIESCED) return SERVICE_BAD_STATE;
    } while (!transition(lock,&before,cpu,EXECUTOR_OFF));
    return SERVICE_OK;
}
enum guest_service_result guest_service_cancel_launch(struct guest_service_lock *lock,
    unsigned controller, unsigned cpu, int64_t cpu_on_result, int64_t affinity_info)
{
    if (!lock || controller>=GUEST_CPU_COUNT || !cpu || cpu>=GUEST_CPU_COUNT ||
        controller==cpu) return SERVICE_BAD_CPU;
    if (controller && guest_service_owner(lock)!=controller+1) return SERVICE_BAD_OWNER;
    /* Success, ALREADY_ON, ON_PENDING and uncertain INTERNAL_FAILURE cannot
     * authorize cancellation, even if a separate observation happens to say OFF. */
    if (affinity_info!=1 || (cpu_on_result!=-1 && cpu_on_result!=-2 &&
                            cpu_on_result!=-3 && cpu_on_result!=-9)) return SERVICE_BAD_STATE;
    uint64_t before=guest_service_lifecycle(lock);
    do {
        if (!valid_lifecycle(before) || state(before,cpu)!=EXECUTOR_RESERVED ||
            (controller && state(before,controller)!=EXECUTOR_RUNNING)) return SERVICE_BAD_STATE;
    } while (!transition(lock,&before,cpu,EXECUTOR_OFF));
    return SERVICE_OK;
}
int guest_service_reusable(const struct guest_service_lock *lock)
{
    if (!lock || guest_service_owner(lock)) return 0;
#if SNAP_FINE_LOCKS
    if (guest_service_readers(lock)) return 0;
#if SNAP_PHASE_FAIR_GATE
    /* Release clears WRITER before the owner word; PHASE is history. */
    if (__atomic_load_n(&lock->readers,__ATOMIC_ACQUIRE)&SERVICE_GATE_WRITER) return 0;
#endif
#endif
    uint64_t value=guest_service_lifecycle(lock);
    if (!valid_lifecycle(value) || !(value&SERVICE_ADMISSION_CLOSED)) return 0;
    if (state(value,0)!=EXECUTOR_OFF && state(value,0)!=EXECUTOR_QUIESCED) return 0;
    for (unsigned cpu=1; cpu<GUEST_CPU_COUNT; cpu++)
        if (state(value,cpu)!=EXECUTOR_OFF) return 0;
    return 1;
}

uint64_t guest_service_owner(const struct guest_service_lock *lock)
{
    return __atomic_load_n(&lock->owner, __ATOMIC_ACQUIRE);
}
enum guest_service_result guest_service_finish(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu>=GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    int abandoned=guest_service_owner(lock)==cpu+1;
#if SNAP_FINE_LOCKS
    /* A converted call leaves the gate before its CPU's terminal path. A bit
     * still set is abandoned like a held token: dropped, a fault stop, and
     * the executor quiesces (it was running, so CPU0 is never OFF here). */
    if (guest_service_readers(lock)&(UINT64_C(1)<<cpu)) {
        guest_service_leave_shared(lock,cpu);
        guest_service_stop(lock,cpu,SERVICE_STOP_FAULT);
        if (!abandoned) {
            enum guest_service_result result=guest_service_quiesce(lock,cpu);
            return result!=SERVICE_OK ? result : SERVICE_ABORTED;
        }
    }
#endif
    guest_service_stop(lock,cpu,abandoned ? SERVICE_STOP_FAULT : SERVICE_STOP_NORMAL);
    if (abandoned) {
        enum guest_service_result result=guest_service_release(lock,cpu);
        if (result!=SERVICE_OK) return result;
    }
    uint64_t value=guest_service_lifecycle(lock);
    /* Only CPU0 can terminate before setup has admitted an executor. */
    if (!cpu && valid_lifecycle(value) && state(value,0)==EXECUTOR_OFF)
        return abandoned ? SERVICE_ABORTED : SERVICE_OK;
    enum guest_service_result result=guest_service_quiesce(lock,cpu);
    if (result!=SERVICE_OK) return result;
    return abandoned ? SERVICE_ABORTED : SERVICE_OK;
}
uint64_t guest_service_stopped(const struct guest_service_lock *lock)
{
    return __atomic_load_n(&lock->stop, __ATOMIC_ACQUIRE);
}
void guest_service_stop(struct guest_service_lock *lock, unsigned cpu, uint32_t reason)
{
    if (!lock || cpu >= GUEST_CPU_COUNT || !reason) return;
    /* Close admission in the same word as launch reservation. A racing launch
     * either remains visible in that word, or observes closure and refuses. */
    __atomic_fetch_or(&lock->lifecycle,SERVICE_ADMISSION_CLOSED,__ATOMIC_ACQ_REL);
    uint64_t expected = 0, value = ((uint64_t)reason << 32) | (cpu+1);
    __atomic_compare_exchange_n(&lock->stop, &expected, value, 0,
                                __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}
enum guest_service_result guest_service_release(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu >= GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    uint64_t expected = cpu+1;
#if SNAP_FAIR_TOKEN
#if SNAP_PHASE_FAIR_GATE
    /* compat/service-lock.h: only the owner sets and clears WRITER. Ownership
     * first (no other CPU moves the word off cpu+1), then WRITER cleared with
     * release before the owner word's release: a next writer never announces
     * over it, and a reader admitted by the clear sees this section's stores. */
    if (__atomic_load_n(&lock->owner, __ATOMIC_RELAXED) != expected) return SERVICE_BAD_OWNER;
    if (__atomic_load_n(&lock->readers, __ATOMIC_RELAXED) & SERVICE_GATE_WRITER)
        __atomic_fetch_and(&lock->readers, ~SERVICE_GATE_WRITER, __ATOMIC_RELEASE);
#endif
    /* The holder alone writes serving: pass the turn once the word is free. */
    if (!__atomic_compare_exchange_n(&lock->owner, &expected, 0, 0,
                                     __ATOMIC_RELEASE, __ATOMIC_RELAXED)) return SERVICE_BAD_OWNER;
    __atomic_store_n(&lock->serving, __atomic_load_n(&lock->serving, __ATOMIC_RELAXED) + 1,
                     __ATOMIC_RELEASE);
    return SERVICE_OK;
#endif
    return __atomic_compare_exchange_n(&lock->owner, &expected, 0, 0,
                                       __ATOMIC_RELEASE, __ATOMIC_RELAXED)
           ? SERVICE_OK : SERVICE_BAD_OWNER;
}
enum guest_service_result guest_service_try(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu >= GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    uint64_t life=guest_service_lifecycle(lock);
    if (!valid_lifecycle(life)) return SERVICE_BAD_STATE;
    if (life&SERVICE_ADMISSION_CLOSED) return SERVICE_STOPPED;
    if (state(life,cpu)!=EXECUTOR_RUNNING) return SERVICE_BAD_STATE;
#if SNAP_PHASE_FAIR_GATE
    /* Inside or announced at the gate: this CPU's drain would wait for itself. */
    if (__atomic_load_n(&lock->readers,__ATOMIC_RELAXED)&SERVICE_GATE_CPU(cpu)) return SERVICE_REENTRY;
#endif
    uint64_t expected = 0;
    if (!__atomic_compare_exchange_n(&lock->owner, &expected, cpu+1, 0,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        if (expected > GUEST_CPU_COUNT) return SERVICE_BAD_OWNER;
        return expected == cpu+1 ? SERVICE_REENTRY : SERVICE_BUSY;
    }
    /* A stop can race acquisition. Release our own token; never steal another
     * CPU's lock or clear the request. Already executing work must quiesce via
     * the adapter's coordinated stop protocol before shared RAM is reused. */
    if (guest_service_lifecycle(lock)&SERVICE_ADMISSION_CLOSED) {
        enum guest_service_result result = guest_service_release(lock, cpu);
        return result == SERVICE_OK ? SERVICE_STOPPED : result;
    }
#if SNAP_PHASE_FAIR_GATE
    /* Announce this writer: WRITER set and PHASE flipped in one RMW with the
     * reader bits, so every arrival is either before it (drained) or after
     * it (in this phase's bank). The phase comes from the word, not from the
     * ticket: a turn that ends without the token must not repeat a phase. */
    uint64_t gate=__atomic_load_n(&lock->readers,__ATOMIC_RELAXED);
    while (!__atomic_compare_exchange_n(&lock->readers,&gate,(gate|SERVICE_GATE_WRITER)^SERVICE_GATE_PHASE,1,
                                        __ATOMIC_ACQ_REL,__ATOMIC_RELAXED)) {}
#endif
    return SERVICE_OK;
}
#if SNAP_FINE_LOCKS
#if SNAP_PHASE_FAIR_GATE
/* compat/service-lock.h SNAP_PHASE_FAIR_GATE: arrival in the bank the writer
 * bits say, in one RMW; BUSY means announced. */
enum guest_service_result guest_service_enter_shared(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu >= GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    uint64_t gate=__atomic_load_n(&lock->readers,__ATOMIC_RELAXED),next;
    if (gate&SERVICE_GATE_CPU(cpu)) return SERVICE_REENTRY;
    if (!guest_service_admitted(lock,cpu)) return SERVICE_STOPPED;
    if (guest_service_owner(lock)==cpu+1) return SERVICE_REENTRY;
    do next=gate|UINT64_C(1)<<(cpu+(gate&SERVICE_GATE_WRITER ?
                                    SERVICE_GATE_BANK_SHIFT(!!(gate&SERVICE_GATE_PHASE)) : 0));
    while (!__atomic_compare_exchange_n(&lock->readers,&gate,next,1,__ATOMIC_SEQ_CST,__ATOMIC_RELAXED));
    /* A stop that closed admission before the bit was published: leave, as
     * guest_service_try releases a token a racing stop overtook. */
    if (guest_service_lifecycle(lock)&SERVICE_ADMISSION_CLOSED) {
        guest_service_leave_shared(lock,cpu);
        return SERVICE_STOPPED;
    }
    return gate&SERVICE_GATE_WRITER ? SERVICE_BUSY : SERVICE_OK;
}
enum guest_service_result guest_service_wait_shared(struct guest_service_lock *lock, unsigned cpu,
                                                    unsigned *ahead)
{
    if (!lock || cpu >= GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    uint64_t gate=__atomic_load_n(&lock->readers,__ATOMIC_ACQUIRE);
    unsigned phase;
    if (gate>>SERVICE_GATE_BANK_SHIFT(0)>>cpu&1) phase=0;
    else if (gate>>SERVICE_GATE_BANK_SHIFT(1)>>cpu&1) phase=1;
    else return gate>>cpu&1 ? SERVICE_REENTRY : SERVICE_BAD_STATE;
    /* A stop ends the wait at once, as enter_shared's admission check did on
     * every poll of the bounded wait; the arrival is withdrawn. */
    if (!guest_service_admitted(lock,cpu)) {
        guest_service_leave_shared(lock,cpu);
        return SERVICE_STOPPED;
    }
    int writer=(gate&SERVICE_GATE_WRITER)!=0;
    if (writer && (unsigned)!!(gate&SERVICE_GATE_PHASE)==phase) return SERVICE_BUSY;
    if (ahead) *ahead=(unsigned)writer;
    return SERVICE_OK;
}
void guest_service_leave_shared(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu >= GUEST_CPU_COUNT) return;
    __atomic_fetch_and(&lock->readers,~SERVICE_GATE_CPU(cpu),__ATOMIC_RELEASE);
}
#else
enum guest_service_result guest_service_enter_shared(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu >= GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    uint64_t bit=UINT64_C(1)<<cpu;
    if (__atomic_load_n(&lock->readers,__ATOMIC_RELAXED)&bit) return SERVICE_REENTRY;
    if (!guest_service_admitted(lock,cpu)) return SERVICE_STOPPED;
    uint64_t owner=guest_service_owner(lock);
    if (owner) return owner==cpu+1 ? SERVICE_REENTRY : SERVICE_BUSY;
    __atomic_fetch_or(&lock->readers,bit,__ATOMIC_SEQ_CST);
    if (__atomic_load_n(&lock->owner,__ATOMIC_SEQ_CST)) {
        guest_service_leave_shared(lock,cpu);
        return SERVICE_BUSY;
    }
    /* A stop that closed admission before the bit was published: leave, as
     * guest_service_try releases a token a racing stop overtook. */
    if (guest_service_lifecycle(lock)&SERVICE_ADMISSION_CLOSED) {
        guest_service_leave_shared(lock,cpu);
        return SERVICE_STOPPED;
    }
    return SERVICE_OK;
}
void guest_service_leave_shared(struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu >= GUEST_CPU_COUNT) return;
    __atomic_fetch_and(&lock->readers,~(UINT64_C(1)<<cpu),__ATOMIC_RELEASE);
}
#endif
#endif
#if SNAP_FAIR_TOKEN
uint32_t guest_service_queue(struct guest_service_lock *lock)
{
    return __atomic_fetch_add(&lock->next, 1, __ATOMIC_RELAXED);
}
enum guest_service_result guest_service_try_turn(struct guest_service_lock *lock,
                                                unsigned cpu, uint32_t ticket)
{
    if (!lock || cpu >= GUEST_CPU_COUNT) return SERVICE_BAD_CPU;
    if (__atomic_load_n(&lock->serving, __ATOMIC_ACQUIRE) != ticket) return SERVICE_BUSY;
    enum guest_service_result result = guest_service_try(lock, cpu);
    /* Only this turn's holder advances serving: unchanged means the turn
     * ended without a release (refused, or stopped before the owner CAS). */
    if (result != SERVICE_OK && __atomic_load_n(&lock->serving, __ATOMIC_RELAXED) == ticket)
        __atomic_store_n(&lock->serving, ticket + 1, __ATOMIC_RELEASE);
    return result;
}
#endif
