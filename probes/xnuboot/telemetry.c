/* SPDX-License-Identifier: MIT */
/* Event records, the guest console and map-failure notes.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
static void record(struct context *c, uint64_t kind, uint64_t pc,
                   uint64_t a, uint64_t b, uint64_t d)
{
    /* The terminal word, first and unconditionally.
     *
     * Before the repeat check and before the capacity check, because both of
     * those return early: a run whose last hundred events were repeats of one
     * sysreg trap, or whose log filled long ago, still has an answer to "what
     * was it doing when it stopped". This is the whole point of the slot -- a
     * write here that any branch below could skip would reintroduce the gap it
     * exists to close. Five words; `repeats` stays zero, because counting
     * repeats is the ring's job and this slot holds one event. */
    c->last.kind = kind;
    c->last.pc = pc;
    c->last.a = a;
    c->last.b = b;
    c->last.c = d;

    /* A spin loop reading one register fills the whole log with one fact. Repeats
     * of the last entry are counted instead of stored, so 32 slots hold 32
     * distinct things rather than 32 copies of the first. */
    if (c->events) {
        struct event *last = &c->log[c->events - 1];
        int same;
        if (kind == EV_SYSREG) {
            /* Sysreg traps collapse by which REGISTER was touched, not by
             * (pc, ISS).
             *
             * The ISS of an MSR/MRS trap carries the register's encoding, the
             * general-purpose register the value moved through, and the
             * direction. Collapsing on the whole word therefore treats "read
             * CNTFRQ into x0" and "read CNTFRQ into x1" as two different
             * facts, and the pc test splits them again per call site. They are
             * one fact -- the kernel is reading CNTFRQ -- and in the last run
             * that one fact took 36 of the 64 entries, three quarters of the
             * log before the boot had finished starting.
             *
             * SYSREG_ID keeps Op0, Op1, Op2, CRn and CRm and drops Rt (bits
             * 9:5) and the direction (bit 0). `pc` is not compared at all:
             * the same register read from two places is still the same
             * register, and the pc of the first is kept as the example. */
            same = last->kind == kind &&
                   (last->a & SYSREG_ID) == (a & SYSREG_ID);
        } else {
            same = last->kind == kind && last->pc == pc && last->a == a;
        }
        if (same) {
            last->repeats++;
            return;
        }
    }
    /* Dropped, and counted as dropped.
     *
     * This used to return silently, which made `events` cap at EVENT_MAX and
     * quietly falsified the host's overflow guard -- that guard tests
     * `events > len(log)`, which can never be true if the counter stops. A run
     * that overflowed therefore looked like a run that fitted, and the
     * classifier named a cause from a truncated tail with full confidence. */
    if (c->events >= EVENT_MAX) { c->log_dropped++; return; }
    struct event *e = &c->log[c->events++];
    e->repeats = 0;
    e->kind = kind;
    e->pc = pc;
    e->a = a;
    e->b = b;
    e->c = d;
}

/* One byte of the guest's console output, from wherever it came.
 *
 * There are two sources and one buffer. Early on the kernel asks us to print
 * for it, one character per SPTM_FN_SERIAL_PUTC; from the moment it takes its
 * serial line back it writes the same characters into a UART's transmit
 * register instead, and the dispatcher below brings them here. The host reads
 * one buffer and does not need to care which half of the boot it is reading.
 *
 * Counted when it does not fit, the way the event log counts events it drops.
 * A console that stops at exactly 1024 bytes looks the same as a kernel that
 * stopped talking, and the two are very different findings; one number tells
 * them apart. */
static void console_put(struct context *c, uint8_t byte)
{
    if (c->console_tail_bytes < CONSOLE_LOG_MAX)
        c->console_log[c->console_tail_bytes] = byte;
    c->console_tail[c->console_tail_bytes % CONSOLE_TAIL_MAX] = byte;
    c->console_tail_bytes++;
    if (c->console_len < CONSOLE_MAX)
        c->console[c->console_len++] = byte;
    else
        c->console_dropped++;
}

/* One out-of-memory mapping, folded into the span table.
 *
 * Called once per such PTE, in the order the guest asked for them. The guest
 * maps a device a page at a time -- ml_io_map walks the window handing each
 * 16K page to MAP_PAGE -- so consecutive calls walk one device's registers in
 * both address spaces at once, and folding them back into spans recovers the
 * window the kernel was working from. A span survives the log filling up,
 * which is the point: this is the shape of the device surface, and it is the
 * question the next step asks. */
static void map_range_note(struct context *c, uint64_t va, uint64_t pa,
                           uint64_t attrs)
{
    const uint64_t page = 1UL << 14;      /* the guest's granule, not ours */
    if (c->range_count) {
        struct map_range *r = &c->ranges[c->range_count - 1];
        if (r->attrs == attrs && r->va + r->pages * page == va &&
            r->pa + r->pages * page == pa) {
            r->pages++;
            return;
        }
    }
    /* Out of slots. Counted, never wrapped and never silently discarded: a
     * table that stopped growing would describe a device surface smaller than
     * the one the kernel actually asked for, and be believed. */
    if (c->range_count >= MAP_RANGES) { c->ranges_dropped++; return; }
    struct map_range *r = &c->ranges[c->range_count++];
    r->va = va;
    r->pa = pa;
    r->pages = 1;
    r->attrs = attrs;
}

/* One failed MAP_PAGE, named.
 *
 * Counted as well as logged: the log keeps 64 entries and collapses repeats, so
 * a storm of failures at different addresses would push everything before it
 * out. The count survives that and says how many there were even when the log
 * only had room for the first few. */
static void map_page_failed(struct context *c, uint64_t pc, uint64_t reason,
                            uint64_t va, uint64_t detail)
{
    c->map_failures++;
    record(c, EV_MAP_FAILED, pc, reason, va, detail);
}

