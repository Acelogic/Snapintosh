/* SPDX-License-Identifier: MIT */
#ifndef SNAP_SERVICE_LOCK_H
#define SNAP_SERVICE_LOCK_H
#include "cpu.h"
#if SNAP_FINE_LOCKS
#include "fine-lock.h"
#endif

/* CPU tokens are slot+1; zero is unlocked. Stop is a sticky request, not a
 * claim that every CPU has quiesced. Initialized to zero before publication. */
#if SNAP_FINE_LOCKS || SNAP_FAIR_TOKEN
/* readers (SNAP_FINE_LOCKS): one bit per CPU inside a converted (shared)
 * call; next/serving (SNAP_FAIR_TOKEN): the token's ticket queue. The token
 * word stays the exclusive lock; the struct keeps its 64-byte size. */
struct guest_service_lock {
    uint64_t owner, stop, lifecycle, readers;
    uint32_t next, serving;
} __attribute__((aligned(64)));
_Static_assert(sizeof(struct guest_service_lock) == 64, "one cache line");
#else
struct guest_service_lock { uint64_t owner, stop, lifecycle; } __attribute__((aligned(64)));
#endif
enum guest_service_result {
    SERVICE_OK, SERVICE_BUSY, SERVICE_STOPPED, SERVICE_REENTRY,
    SERVICE_BAD_CPU, SERVICE_BAD_OWNER, SERVICE_TIMEOUT, SERVICE_BAD_STATE,
    SERVICE_ABORTED, SERVICE_NOT_QUIESCENT
};
#define SERVICE_STOP_NORMAL 1U
#define SERVICE_STOP_FAULT  2U
#define SERVICE_ADMISSION_CLOSED (UINT64_C(1)<<63)
/* The earlier deadline determines why a busy waiter stops. A probe budget
 * expiring is a coordinated stop, not evidence of a stuck service owner. */
static inline enum guest_service_result guest_service_wait_expiry(uint64_t now,
    uint64_t service_deadline,int budget_live,uint64_t budget_deadline)
{
    if(budget_live && (int64_t)(budget_deadline-service_deadline)<=0 &&
       (int64_t)(now-budget_deadline)>=0)return SERVICE_STOPPED;
    return (int64_t)(now-service_deadline)>=0 ? SERVICE_TIMEOUT:SERVICE_BUSY;
}
enum guest_executor_state { EXECUTOR_OFF, EXECUTOR_RESERVED, EXECUTOR_RUNNING, EXECUTOR_QUIESCED };

/* Lifecycle is one atomic word: six 3-bit states plus admission-closed. */
enum guest_service_result guest_service_boot(struct guest_service_lock *lock);
enum guest_service_result guest_service_reserve(struct guest_service_lock *lock,
                                               unsigned caller, unsigned target);
enum guest_service_result guest_service_arrive(struct guest_service_lock *lock, unsigned cpu);
enum guest_service_result guest_service_quiesce(struct guest_service_lock *lock, unsigned cpu);
/* Only the primary controller may reconcile a fresh PSCI AFFINITY_INFO result.
 * Value 1 is OFF. Quiescence alone is never a physical OFF observation. */
enum guest_service_result guest_service_confirm_off(struct guest_service_lock *lock,
    unsigned controller, unsigned cpu, int64_t affinity_info);
/* A running secondary may cancel a definitely refused launch while it still
 * owns the service token. CPU0 also reconciles refused launches during cleanup.
 * Accepted/uncertain launches and arrived executors cannot be cancelled. */
enum guest_service_result guest_service_cancel_launch(struct guest_service_lock *lock,
    unsigned controller, unsigned cpu, int64_t cpu_on_result, int64_t affinity_info);
uint64_t guest_service_lifecycle(const struct guest_service_lock *lock);
int guest_service_reusable(const struct guest_service_lock *lock);
/* Called on this executor's terminal path. Closes admission, drops only its
 * own abandoned lock, and publishes quiescence. Does not imply physical OFF. */
enum guest_service_result guest_service_finish(struct guest_service_lock *lock, unsigned cpu);

enum guest_service_result guest_service_try(struct guest_service_lock *lock, unsigned cpu);
enum guest_service_result guest_service_release(struct guest_service_lock *lock, unsigned cpu);
void guest_service_stop(struct guest_service_lock *lock, unsigned cpu, uint32_t reason);
uint64_t guest_service_owner(const struct guest_service_lock *lock);
uint64_t guest_service_stopped(const struct guest_service_lock *lock);
/* Read-only form of guest_service_try's admission checks, for work that needs
 * no service token (SNAP_FAST_VCPU_TRAPS): 1 only when admission is open, the
 * lifecycle word is well formed and this CPU is a running executor, i.e. only
 * when guest_service_try could not return STOPPED, BAD_CPU or BAD_STATE. It is
 * also 0 whenever the sticky stop word is set (guest_service_stop closes
 * admission first, so this only makes a decline earlier). A stop that lands
 * after this check is seen at the CPU's next locked trap or watchdog tick,
 * exactly as for a CPU that is executing guest code. */
static inline int guest_service_admitted(const struct guest_service_lock *lock, unsigned cpu)
{
    if (!lock || cpu >= GUEST_CPU_COUNT ||
        __atomic_load_n(&lock->stop, __ATOMIC_ACQUIRE)) return 0;
    uint64_t life = __atomic_load_n(&lock->lifecycle, __ATOMIC_ACQUIRE);
    const uint64_t states = (UINT64_C(1) << (GUEST_CPU_COUNT*3)) - 1;
    if (life & ~(states | SERVICE_ADMISSION_CLOSED) || (life & SERVICE_ADMISSION_CLOSED))
        return 0;
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++)
        if (((life >> (n*3)) & 7) > EXECUTOR_QUIESCED) return 0;
    return ((life >> (cpu*3)) & 7) == EXECUTOR_RUNNING;
}
#if SNAP_FAIR_TOKEN
/* SNAP_FAIR_TOKEN (opt-in, default 0; docs/FINE-LOCKS-20261017.md): the token
 * is granted in arrival order (a ticket queue in front of the owner word), so
 * a CPU that releases and at once asks again from its own cache cannot pass a
 * waiter in another cluster (the v26 one-second SERVICE_TIMEOUT). Failure
 * modes: a waiter passed by a later arrival (FIFO is the grant order); a turn
 * that ends without the token and stalls the queue (every such turn is passed
 * on); a release that does not pass the turn (guest_service_release passes it
 * after the owner word is cleared). A waiter leaves the queue before its turn
 * only when the run stops (a timeout stops it), after which nothing takes the
 * token again.
 * A place in the token's queue; then guest_service_try_turn until it is not
 * BUSY. Its result is guest_service_try's once this ticket's turn has come:
 * OK holds the token (guest_service_release passes the turn on); any other
 * result has already passed the turn on. */
uint32_t guest_service_queue(struct guest_service_lock *lock);
enum guest_service_result guest_service_try_turn(struct guest_service_lock *lock,
                                                unsigned cpu, uint32_t ticket);
#endif
#if SNAP_FINE_LOCKS
/* The shared side of the gate (compat/fine-lock.h L0). OK: this CPU's reader
 * bit is published and no token holder exists, so no exclusive section runs
 * until guest_service_leave_shared; the caller must not wait for the token
 * before leaving. BUSY: a token holder exists (nothing published). STOPPED:
 * admission is closed or the stop word is set (nothing published).
 * Store buffering is excluded by the seq_cst pair here (bit RMW, then owner
 * load) against the token holder's owner CAS, full fence and readers load
 * (guest_service_drained): one of the two always sees the other. */
enum guest_service_result guest_service_enter_shared(struct guest_service_lock *lock, unsigned cpu);
void guest_service_leave_shared(struct guest_service_lock *lock, unsigned cpu);
#if SNAP_PHASE_FAIR_GATE
/* SNAP_PHASE_FAIR_GATE (opt-in, default 0; compat/fine-lock.h): the gate is
 * phase-fair (Brandenburg & Anderson's PF-T family). Reader and writer phases
 * alternate: a converted call arriving during a writer phase waits for that
 * writer only, and the token holder waits only for the converted calls that
 * arrived before it. The readers word keeps one bit per CPU, in one of three
 * banks chosen in the same RMW that reads the writer bits:
 *   bits 0..7 FREE (arrived with no writer present: inside), 8..15 BANK0 and
 *   16..23 BANK1 (arrived during a phase-0/phase-1 writer), bit 62 PHASE (the
 *   present or last writer's phase), bit 63 WRITER (a token holder has
 *   announced itself: guest_service_try sets it and flips PHASE in one RMW,
 *   guest_service_release clears it before the owner word).
 * A writer of phase p drains FREE and BANK(!p), never BANK(p): those arrived
 * after it. A reader in BANK(p) enters once WRITER is clear or PHASE differs
 * (the next writer then waits for it, and cannot finish while it is inside,
 * so no reader waits for two writers and the phase bit cannot ABA). All writes
 * to the word are RMWs: acquire on entry and drain, release on exit and on the
 * writer's clear. No Dekker pair remains, so drained needs no fence.
 * enter_shared: OK entered; BUSY announced in the present writer's bank (call
 * guest_service_wait_shared until it is not BUSY, or guest_service_leave_shared
 * to withdraw; a withdrawal never entered, so it is safe at any time); REENTRY
 * (the token holder, or this CPU's bit already set), STOPPED, BAD_CPU publish
 * nothing. wait_shared: OK once the phase it arrived in has ended (*ahead=1 when
 * the next writer was already present: it waits for this call); BUSY while that
 * phase lasts; STOPPED: admission closed or stop set, the arrival withdrawn;
 * BAD_STATE: not announced. guest_service_try refuses (REENTRY) a CPU whose bit
 * is set: its drain would wait for itself. */
#define SERVICE_GATE_BANK_SHIFT(phase) (8u + 8u * (unsigned)(phase))
#define SERVICE_GATE_CPU(cpu) (UINT64_C(0x010101) << (cpu))
#define SERVICE_GATE_PHASE (UINT64_C(1) << 62)
#define SERVICE_GATE_WRITER (UINT64_C(1) << 63)
_Static_assert(GUEST_CPU_COUNT <= 8, "eight CPU bits per gate bank");
enum guest_service_result guest_service_wait_shared(struct guest_service_lock *lock, unsigned cpu,
                                                    unsigned *ahead);
/* For the token holder (it owns the token and has announced itself): 1 once
 * the converted calls that arrived before it have left. */
static inline int guest_service_drained(const struct guest_service_lock *lock)
{
    uint64_t r = __atomic_load_n(&lock->readers, __ATOMIC_ACQUIRE);
    return !(r & (UINT64_C(0xff) | UINT64_C(0xff) << SERVICE_GATE_BANK_SHIFT(!(r & SERVICE_GATE_PHASE))));
}
/* One bit per CPU at the gate (inside or announced), whatever its bank. */
static inline uint64_t guest_service_readers(const struct guest_service_lock *lock)
{
    uint64_t r = __atomic_load_n(&lock->readers, __ATOMIC_ACQUIRE);
    return (r | r >> 8 | r >> 16) & 0xff;
}
#else
/* For the token holder (it owns the token): 1 once no converted call is in
 * flight. The fence orders the token acquisition before the readers load. */
static inline int guest_service_drained(const struct guest_service_lock *lock)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return !__atomic_load_n(&lock->readers, __ATOMIC_ACQUIRE);
}
static inline uint64_t guest_service_readers(const struct guest_service_lock *lock)
{
    return __atomic_load_n(&lock->readers, __ATOMIC_ACQUIRE);
}
#endif
#endif
#endif
