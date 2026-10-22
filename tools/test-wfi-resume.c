/* SPDX-License-Identifier: MIT */
/* SNAP_WFI_RESUME (compat/wfi-resume.h): the decision that sends a vCPU woken
 * by a monitor-only EL2 timer tick straight back into its WFI.
 *
 * Failure inventory this covers, each as a table row with its expected result:
 *   - rewinding onto anything but the exact WFI word: WFE, WFIT, NOP, YIELD,
 *     SEV(L), any other hint or data word, a word one bit away;
 *   - a WFI outside const-sealed kernel text (kext/data RAM, one word before
 *     the text, the text end itself, an empty text range) or outside guest RAM,
 *     or a WFI-valued word on the page before the PC's (its execute permission
 *     is not the PC's);
 *   - an untranslated PC-4, a misaligned translation, a misaligned or tiny PC;
 *   - EL0 (busy, not idle), AArch32, EL2/EL3 or reserved modes;
 *   - PSTATE.SS, IL or any BTYPE (ELR reached by an indirect branch), or ELR
 *     the target of the last emulated kernel ERET (returning to WFI+4);
 *   - a stopping run, a monitor single-step, open guard or user-entry probe;
 *   - a posted IPI, a pending or expired guest timer (masked or not, across
 *     counter wrap), HCR_EL2 VF/VI/VSE, this vCPU's model line, any model's
 *     pending IRQ, a due or unsynced device deadline;
 *   - no bounded next tick: watchdog off (bound 0), EL2 timer disabled or
 *     masked, due later than the poll, an unrepresentable bound;
 *   - reading guest memory while the state already declines (EL0, stop, step);
 *   - interrupt masks (DAIF), ISTATUS or other HCR bits changing the answer.
 * Then every word of the hint/barrier space and random words (only WFI may
 * resume), and a randomized differential against an independent oracle that
 * restates the rule as a conjunction plus the documented check order.
 *
 * cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
 *    -fno-sanitize-recover=all -Icompat tools/test-wfi-resume.c \
 *    -o build/test-wfi-resume && build/test-wfi-resume */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wfi-resume.h"

#define MEM_LOW UINT64_C(0x80000000)
#define MEM_WORDS 0x4000u                               /* 64 KiB of guest RAM */
#define MEM_HIGH (MEM_LOW + 4u * MEM_WORDS)
#define TEXT_BEGIN (MEM_LOW + 0x4000)
#define TEXT_END (MEM_LOW + 0x8000)
#define KVA UINT64_C(0xfffffe0007000000)                 /* VA of MEM_LOW */
#define VA(pa) (KVA + ((pa) - MEM_LOW))
#define VA_HOLE (KVA + 0xa000)                           /* one unmapped 4K page */
#define VA_OUTSIDE UINT64_C(0xfffffe0009000000)          /* maps below guest RAM */
#define VA_MISALIGNED UINT64_C(0xfffffe000a000000)       /* a broken walk: pa & 3 */

#define NOP UINT32_C(0xd503201f)
#define YIELD UINT32_C(0xd503203f)
#define WFE UINT32_C(0xd503205f)
#define WFI WFI_RESUME_WORD
#define SEV UINT32_C(0xd503209f)
#define SEVL UINT32_C(0xd50320bf)
#define WFIT UINT32_C(0xd5031020)                        /* wfit x0 (FEAT_WFxT) */
#define WFET UINT32_C(0xd5031000)                        /* wfet x0 */

static uint32_t ram[MEM_WORDS];
static unsigned pa_calls, fetch_calls;

static uint64_t fake_pa(void *ctx, uint64_t va)
{
    (void)ctx;
    pa_calls++;
    if (va >= VA_HOLE && va < VA_HOLE + 0x1000) return 0;
    if (va >= VA_OUTSIDE && va < VA_OUTSIDE + 0x1000) return 0x10000000 + (va & 0xfff);
    if (va >= VA_MISALIGNED && va < VA_MISALIGNED + 0x1000) return TEXT_BEGIN + 0x102;
    if (va >= KVA && va < KVA + 4u * MEM_WORDS + 0x1000) return MEM_LOW + (va - KVA);
    return 0;
}
static uint32_t fake_fetch(void *ctx, uint64_t pa)
{
    (void)ctx;
    fetch_calls++;
    if (pa < MEM_LOW || pa + 4 > MEM_HIGH || (pa & 3)) {
        fprintf(stderr, "FAIL: fetch outside guest RAM at %#llx\n", (unsigned long long)pa);
        exit(1);
    }
    return ram[(pa - MEM_LOW) / 4];
}
static void put(uint64_t pa, uint32_t word) { ram[(pa - MEM_LOW) / 4] = word; }

#define BOUND 24000u                                     /* 1 ms of a 24 MHz counter */
#define NOW UINT64_C(1000000000)
#define GUEST_NOW UINT64_C(5000000)
#define SITE (TEXT_BEGIN + 0x100)                        /* the idle WFI */

static struct wfi_resume_state base(void)
{
    return (struct wfi_resume_state){
        .elr = VA(SITE) + 4, .spsr = 0x3c5,              /* EL1h, DAIF masked: XNU's idle */
        .hcr = UINT64_C(0x8000000080000039),              /* RW, TGE clear, IMO/FMO/AMO, VM... */
        .timer_ctl = 1, .timer_cval = GUEST_NOW + 100000, .guest_now = GUEST_NOW,
        .physical = NOW, .device_due = UINT64_MAX,
        .el2_ctl = 1, .el2_cval = NOW + BOUND, .wake_bound = BOUND,
    };
}
static struct wfi_resume_mem mem(void)
{
    return (struct wfi_resume_mem){0, MEM_LOW, MEM_HIGH, TEXT_BEGIN, TEXT_END, fake_pa, fake_fetch};
}

enum field {
    F_NONE, F_ELR, F_SPSR, F_HCR, F_STOP, F_MONITOR, F_LAST, F_IPI, F_TPEND, F_TCTL, F_TCVAL, F_GNOW,
    F_MODEL, F_MODELS, F_PHYS, F_DEVICE, F_EL2CTL, F_EL2CVAL, F_BOUND,
    F_TEXT_BEGIN, F_TEXT_END, F_MEM_HIGH,
};
struct change { enum field f; uint64_t v; };
struct row {
    const char *name;
    struct change c[3];
    unsigned expect;
    int reads;                       /* 1: guest_pa must be called; 0: must not; -1: either */
};

static void apply(struct wfi_resume_state *s, struct wfi_resume_mem *m, struct change c)
{
    switch (c.f) {
    case F_NONE: break;
    case F_ELR: s->elr = c.v; break;
    case F_SPSR: s->spsr = c.v; break;
    case F_HCR: s->hcr = c.v; break;
    case F_STOP: s->stop = c.v; break;
    case F_MONITOR: s->monitor = c.v; break;
    case F_LAST: s->last_return = c.v; break;
    case F_IPI: s->ipi_pending = c.v; break;
    case F_TPEND: s->timer_pending = c.v; break;
    case F_TCTL: s->timer_ctl = c.v; break;
    case F_TCVAL: s->timer_cval = c.v; break;
    case F_GNOW: s->guest_now = c.v; break;
    case F_MODEL: s->model_irq_pending = c.v; break;
    case F_MODELS: s->models_pending = c.v; break;
    case F_PHYS: s->physical = c.v; break;
    case F_DEVICE: s->device_due = c.v; break;
    case F_EL2CTL: s->el2_ctl = c.v; break;
    case F_EL2CVAL: s->el2_cval = c.v; break;
    case F_BOUND: s->wake_bound = c.v; break;
    case F_TEXT_BEGIN: m->text_begin = c.v; break;
    case F_TEXT_END: m->text_end = c.v; break;
    case F_MEM_HIGH: m->mem_high = c.v; break;
    }
}

#define HCR_BASE UINT64_C(0x8000000080000039)
static const struct row rows[] = {
    /* WFI_RESUME: genuine idle WFI, nothing due, next tick within the poll. */
    {"EL1h idle WFI", {{F_NONE, 0}}, WFI_RESUME, 1},
    {"last kernel ERET went elsewhere", {{F_LAST, VA(SITE) + 8}}, WFI_RESUME, 1},
    {"EL1t idle WFI", {{F_SPSR, 0x3c4}}, WFI_RESUME, 1},
    {"interrupts unmasked (DAIF clear)", {{F_SPSR, 0x5}}, WFI_RESUME, 1},
    {"PAN/UAO/SSBS/TCO set", {{F_SPSR, 0x3c5 | (1u << 22) | (1u << 23) | (1u << 12) | (1u << 25)}},
     WFI_RESUME, 1},
    {"first word of text", {{F_ELR, VA(TEXT_BEGIN) + 4}}, WFI_RESUME, 1},
    {"text end-8 (text end-4 ends a page)", {{F_ELR, VA(TEXT_END - 8) + 4}}, WFI_RESUME, 1},
    {"WFI one word before a page end", {{F_ELR, VA(TEXT_BEGIN + 0xff8) + 4}}, WFI_RESUME, 1},
    {"ISTATUS read back set", {{F_EL2CTL, 5}}, WFI_RESUME, 1},
    {"next tick already due (refires at once)", {{F_EL2CVAL, NOW - 5}}, WFI_RESUME, 1},
    {"next tick exactly at the bound", {{F_EL2CVAL, NOW + BOUND}}, WFI_RESUME, 1},
    {"guest timer disabled, cval passed", {{F_TCTL, 0}, {F_TCVAL, GUEST_NOW - 1}}, WFI_RESUME, 1},
    {"guest timer masked, cval ahead", {{F_TCTL, 3}}, WFI_RESUME, 1},
    {"guest timer ahead across counter wrap",
     {{F_GNOW, UINT64_MAX - 10}, {F_TCVAL, 5}}, WFI_RESUME, 1},
    {"device deadline ahead", {{F_DEVICE, NOW + 1}}, WFI_RESUME, 1},
    {"other HCR bits (TWE, TVM, NV)", {{F_HCR, HCR_BASE | (1u << 14) | (1u << 26) | (UINT64_C(1) << 42)}},
     WFI_RESUME, 1},

    /* WFI_DECLINE_STATE */
    {"run stops at this exit", {{F_STOP, 1}}, WFI_DECLINE_STATE, 0},
    {"stop wins over a posted IPI", {{F_STOP, 1}, {F_IPI, 1}}, WFI_DECLINE_STATE, 0},
    {"monitor step/guard/probe", {{F_MONITOR, 1}}, WFI_DECLINE_STATE, 0},
    {"monitor wins over EL0", {{F_MONITOR, 1}, {F_SPSR, 0}}, WFI_DECLINE_STATE, 0},
    {"EL2t", {{F_SPSR, 0x3c8}}, WFI_DECLINE_STATE, 0},
    {"EL2h", {{F_SPSR, 0x3c9}}, WFI_DECLINE_STATE, 0},
    {"EL3h", {{F_SPSR, 0x3cd}}, WFI_DECLINE_STATE, 0},
    {"reserved mode 1", {{F_SPSR, 0x3c1}}, WFI_DECLINE_STATE, 0},
    {"AArch32 SVC", {{F_SPSR, 0x1d3}}, WFI_DECLINE_STATE, 0},
    {"AArch32 USR", {{F_SPSR, 0x10}}, WFI_DECLINE_STATE, 0},
    {"AArch32 mode 0x14 (low bits look like EL1t)", {{F_SPSR, 0x14}}, WFI_DECLINE_STATE, 0},
    {"PSTATE.SS", {{F_SPSR, 0x3c5 | (1u << 21)}}, WFI_DECLINE_STATE, 0},
    {"PSTATE.IL", {{F_SPSR, 0x3c5 | (1u << 20)}}, WFI_DECLINE_STATE, 0},
    {"BTYPE 1 (ELR reached by BR)", {{F_SPSR, 0x3c5 | (1u << 10)}}, WFI_DECLINE_STATE, 0},
    {"BTYPE 2 (ELR reached by BLR)", {{F_SPSR, 0x3c5 | (2u << 10)}}, WFI_DECLINE_STATE, 0},
    {"BTYPE 3", {{F_SPSR, 0x3c5 | (3u << 10)}}, WFI_DECLINE_STATE, 0},
    {"misaligned PC", {{F_ELR, VA(SITE) + 6}}, WFI_DECLINE_STATE, 0},
    {"PC 0", {{F_ELR, 0}}, WFI_DECLINE_STATE, 0},

    /* WFI_DECLINE_BUSY */
    {"EL0t: user code", {{F_SPSR, 0}}, WFI_DECLINE_BUSY, 0},
    {"EL0t with an IPI posted", {{F_SPSR, 0}, {F_IPI, 1}}, WFI_DECLINE_BUSY, 0},
    {"NOP at PC-4", {{F_ELR, VA(TEXT_BEGIN + 0x400) + 4}}, WFI_DECLINE_BUSY, 1},
    {"WFE at PC-4", {{F_ELR, VA(TEXT_BEGIN + 0x200) + 4}}, WFI_DECLINE_BUSY, 1},
    {"WFIT at PC-4", {{F_ELR, VA(TEXT_BEGIN + 0x300) + 4}}, WFI_DECLINE_BUSY, 1},
    {"WFET at PC-4", {{F_ELR, VA(TEXT_BEGIN + 0x304) + 4}}, WFI_DECLINE_BUSY, 1},
    {"YIELD at PC-4", {{F_ELR, VA(TEXT_BEGIN + 0x308) + 4}}, WFI_DECLINE_BUSY, 1},
    {"SEV at PC-4", {{F_ELR, VA(TEXT_BEGIN + 0x30c) + 4}}, WFI_DECLINE_BUSY, 1},
    {"SEVL at PC-4", {{F_ELR, VA(TEXT_BEGIN + 0x310) + 4}}, WFI_DECLINE_BUSY, 1},
    {"WFI with bit 0 flipped", {{F_ELR, VA(TEXT_BEGIN + 0x314) + 4}}, WFI_DECLINE_BUSY, 1},
    {"zero data word", {{F_ELR, VA(TEXT_BEGIN + 0x318) + 4}}, WFI_DECLINE_BUSY, 1},
    {"busy at a NOP with an IPI posted", {{F_ELR, VA(TEXT_BEGIN + 0x400) + 4}, {F_IPI, 1}},
     WFI_DECLINE_BUSY, 1},
    {"NOP outside text", {{F_ELR, VA(MEM_LOW + 0x2000) + 4}}, WFI_DECLINE_BUSY, 1},
    {"WFI is at PC, not PC-4 (not yet executed)", {{F_ELR, VA(SITE)}}, WFI_DECLINE_BUSY, 1},
    {"emulated ERET returned to WFI+4", {{F_LAST, VA(SITE) + 4}}, WFI_DECLINE_BUSY, 0},
    {"ERET return wins over an IPI", {{F_LAST, VA(SITE) + 4}, {F_IPI, 1}}, WFI_DECLINE_BUSY, 0},

    /* WFI_DECLINE_TEXT */
    {"PC-4 untranslated", {{F_ELR, VA_HOLE + 0x104}}, WFI_DECLINE_TEXT, 1},
    {"PC-4 maps outside guest RAM", {{F_ELR, VA_OUTSIDE + 0x104}}, WFI_DECLINE_TEXT, 1},
    {"misaligned translation", {{F_ELR, VA_MISALIGNED + 0x104}}, WFI_DECLINE_TEXT, 1},
    {"PC-4 maps past guest RAM", {{F_ELR, VA(MEM_HIGH) + 4}}, WFI_DECLINE_TEXT, 1},
    {"WFI in kext/data RAM", {{F_ELR, VA(MEM_LOW + 0x1000) + 4}}, WFI_DECLINE_TEXT, 1},
    {"WFI one word before text", {{F_ELR, VA(TEXT_BEGIN - 4) + 4}}, WFI_DECLINE_TEXT, 1},
    {"WFI at the text end", {{F_ELR, VA(TEXT_END) + 4}}, WFI_DECLINE_TEXT, 1},
    {"WFI in the last text word, PC on the next page", {{F_ELR, VA(TEXT_END - 4) + 4}},
     WFI_DECLINE_TEXT, 1},
    {"WFI-valued word on the page before the PC's", {{F_ELR, VA(TEXT_BEGIN + 0xffc) + 4}},
     WFI_DECLINE_TEXT, 1},
    {"no text range configured", {{F_TEXT_BEGIN, 0}, {F_TEXT_END, 0}}, WFI_DECLINE_TEXT, 1},
    {"text range of two bytes", {{F_TEXT_BEGIN, 0}, {F_TEXT_END, 2}}, WFI_DECLINE_TEXT, 1},
    {"guest RAM bound below one word", {{F_MEM_HIGH, 2}}, WFI_DECLINE_TEXT, 1},
    {"text outside wins over an IPI", {{F_ELR, VA(MEM_LOW + 0x1000) + 4}, {F_IPI, 1}},
     WFI_DECLINE_TEXT, 1},

    /* WFI_DECLINE_IPI */
    {"posted IPI", {{F_IPI, 1}}, WFI_DECLINE_IPI, 1},
    {"posted IPI with VF raised", {{F_IPI, 1}, {F_HCR, HCR_BASE | (1u << 6)}}, WFI_DECLINE_IPI, 1},
    {"posted IPI with interrupts masked", {{F_IPI, 1}, {F_SPSR, 0x3c5}}, WFI_DECLINE_IPI, 1},

    /* WFI_DECLINE_TIMER */
    {"guest timer line pending", {{F_TPEND, 1}}, WFI_DECLINE_TIMER, 1},
    {"guest deadline now", {{F_TCVAL, GUEST_NOW}}, WFI_DECLINE_TIMER, 1},
    {"guest deadline passed", {{F_TCVAL, GUEST_NOW - 1}}, WFI_DECLINE_TIMER, 1},
    {"masked guest timer, deadline passed", {{F_TCTL, 3}, {F_TCVAL, GUEST_NOW - 1}}, WFI_DECLINE_TIMER, 1},
    {"guest deadline passed across counter wrap",
     {{F_GNOW, 5}, {F_TCVAL, UINT64_MAX - 10}}, WFI_DECLINE_TIMER, 1},
    {"guest timer wins over a line", {{F_TPEND, 1}, {F_HCR, HCR_BASE | (1u << 7)}}, WFI_DECLINE_TIMER, 1},

    /* WFI_DECLINE_LINE */
    {"HCR_EL2.VF", {{F_HCR, HCR_BASE | (1u << 6)}}, WFI_DECLINE_LINE, 1},
    {"HCR_EL2.VI", {{F_HCR, HCR_BASE | (1u << 7)}}, WFI_DECLINE_LINE, 1},
    {"HCR_EL2.VSE", {{F_HCR, HCR_BASE | (1u << 8)}}, WFI_DECLINE_LINE, 1},
    {"this vCPU's model line", {{F_MODEL, 1}}, WFI_DECLINE_LINE, 1},
    {"another model IRQ pending", {{F_MODELS, 1}}, WFI_DECLINE_LINE, 1},
    {"device deadline now", {{F_DEVICE, NOW}}, WFI_DECLINE_LINE, 1},
    {"device deadline passed", {{F_DEVICE, NOW - 1}}, WFI_DECLINE_LINE, 1},
    {"device deadline not yet synced (zero)", {{F_DEVICE, 0}}, WFI_DECLINE_LINE, 1},
    {"line wins over an unbounded tick", {{F_MODELS, 1}, {F_BOUND, 0}}, WFI_DECLINE_LINE, 1},

    /* WFI_DECLINE_WAKE */
    {"watchdog off (bound 0)", {{F_BOUND, 0}}, WFI_DECLINE_WAKE, 1},
    {"EL2 timer disabled", {{F_EL2CTL, 0}}, WFI_DECLINE_WAKE, 1},
    {"EL2 timer masked", {{F_EL2CTL, 3}}, WFI_DECLINE_WAKE, 1},
    {"EL2 timer IMASK only", {{F_EL2CTL, 2}}, WFI_DECLINE_WAKE, 1},
    {"next tick one past the bound", {{F_EL2CVAL, NOW + BOUND + 1}}, WFI_DECLINE_WAKE, 1},
    {"next tick at the run budget (no poll)", {{F_EL2CVAL, NOW + UINT64_C(24000000) * 600}},
     WFI_DECLINE_WAKE, 1},
    {"unrepresentable bound", {{F_BOUND, UINT64_MAX}}, WFI_DECLINE_WAKE, 1},
};

static const char *const names[WFI_RESULTS] = {
    "RESUME", "STATE", "BUSY", "TEXT", "IPI", "TIMER", "LINE", "WAKE"};

/* The rule restated independently: resume iff every condition holds; the
 * reason is the first group (in the header's order) that fails. */
static unsigned oracle(const struct wfi_resume_state *s, const struct wfi_resume_mem *m, int *reads)
{
    unsigned mode = s->spsr & 0x1f;
    int state = s->stop || s->monitor ||
                (mode != 0 && mode != 4 && mode != 5) ||
                (mode != 0 && ((s->spsr >> 10) & 3)) ||
                (mode != 0 && ((s->spsr >> 20) & 3)) ||
                (mode != 0 && (s->elr % 4 != 0 || s->elr < 4));
    *reads = 0;
    if (state) return WFI_DECLINE_STATE;
    if (mode == 0 || s->last_return == s->elr) return WFI_DECLINE_BUSY;
    *reads = 1;
    uint64_t pa = m->guest_pa(0, s->elr - 4);
    int in_ram = pa != 0 && pa % 4 == 0 && m->mem_high >= 4 && pa >= m->mem_low && pa + 4 <= m->mem_high;
    if (!in_ram) return WFI_DECLINE_TEXT;
    uint32_t word = ram[(pa - MEM_LOW) / 4];
    if (word != 0xd503207fu) return WFI_DECLINE_BUSY;
    int in_text = m->text_end >= 4 && pa >= m->text_begin && pa + 4 <= m->text_end &&
                  (s->elr - 4) / 4096 == s->elr / 4096;
    if (!in_text) return WFI_DECLINE_TEXT;
    if (s->ipi_pending) return WFI_DECLINE_IPI;
    int64_t until = (int64_t)(s->timer_cval - s->guest_now);
    if (s->timer_pending || ((s->timer_ctl & 1) && until <= 0)) return WFI_DECLINE_TIMER;
    int64_t device = (int64_t)(s->device_due - s->physical);
    if (s->hcr & 0x40 || s->hcr & 0x80 || s->hcr & 0x100 || s->model_irq_pending ||
        s->models_pending || (s->device_due != UINT64_MAX && device <= 0))
        return WFI_DECLINE_LINE;
    int64_t next = (int64_t)(s->el2_cval - s->physical);
    int armed = (s->el2_ctl & 1) && !(s->el2_ctl & 2);
    if (s->wake_bound == 0 || s->wake_bound > (uint64_t)INT64_MAX || !armed || next > (int64_t)s->wake_bound)
        return WFI_DECLINE_WAKE;
    return WFI_RESUME;
}

static uint64_t rng = UINT64_C(0x9e3779b97f4a7c15);
static uint64_t next_random(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}
static uint64_t pick(const uint64_t *v, unsigned n) { return v[next_random() % n]; }

int main(void)
{
    unsigned failures = 0, seen[WFI_RESULTS] = {0};
    for (unsigned i = 0; i < MEM_WORDS; i++) ram[i] = NOP;
    put(TEXT_BEGIN, WFI); put(SITE, WFI); put(TEXT_END - 4, WFI); put(TEXT_END - 8, WFI);
    put(TEXT_BEGIN + 0xff8, WFI); put(TEXT_BEGIN + 0xffc, WFI);
    put(TEXT_BEGIN + 0x200, WFE); put(TEXT_BEGIN + 0x300, WFIT); put(TEXT_BEGIN + 0x304, WFET);
    put(TEXT_BEGIN + 0x308, YIELD); put(TEXT_BEGIN + 0x30c, SEV); put(TEXT_BEGIN + 0x310, SEVL);
    put(TEXT_BEGIN + 0x314, WFI ^ 1); put(TEXT_BEGIN + 0x318, 0);
    put(MEM_LOW + 0x1000, WFI); put(TEXT_BEGIN - 4, WFI); put(TEXT_END, WFI);

    /* 1. The table: every result, with the guest-memory access rule. */
    for (unsigned i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        const struct row *r = &rows[i];
        struct wfi_resume_state s = base();
        struct wfi_resume_mem m = mem();
        for (unsigned j = 0; j < 3; j++) apply(&s, &m, r->c[j]);
        struct wfi_resume_state before = s;
        pa_calls = fetch_calls = 0;
        unsigned got = wfi_resume_decide(&s, &m);
        int read = pa_calls != 0;
        if (got != r->expect || (r->reads >= 0 && read != r->reads) || memcmp(&before, &s, sizeof s) ||
            fetch_calls > 1 || pa_calls > 1) {
            printf("FAIL: %s: got %s expected %s (walks %u fetches %u)\n", r->name,
                   got < WFI_RESULTS ? names[got] : "?", names[r->expect], pa_calls, fetch_calls);
            failures++;
        }
        if (got < WFI_RESULTS) seen[got]++;
    }
    for (unsigned k = 0; k < WFI_RESULTS; k++)
        if (!seen[k]) { printf("FAIL: no table row reaches %s\n", names[k]); failures++; }

    /* 2. Only the WFI word resumes: the whole hint/barrier/system space
     * 0xd5030000..0xd503ffff at the idle site, then a million random words. */
    unsigned resumed = 0;
    for (uint32_t w = 0xd5030000u; w <= 0xd503ffffu; w++) {
        put(SITE, w);
        struct wfi_resume_state s = base();
        struct wfi_resume_mem m = mem();
        unsigned got = wfi_resume_decide(&s, &m);
        if ((got == WFI_RESUME) != (w == WFI) || (w != WFI && got != WFI_DECLINE_BUSY)) {
            printf("FAIL: word %#x -> %s\n", w, names[got]);
            failures++;
        }
        resumed += got == WFI_RESUME;
    }
    for (unsigned n = 0; n < 1000000; n++) {
        uint32_t w = (uint32_t)next_random();
        if (w == WFI) continue;
        put(SITE, w);
        struct wfi_resume_state s = base();
        struct wfi_resume_mem m = mem();
        if (wfi_resume_decide(&s, &m) != WFI_DECLINE_BUSY) {
            printf("FAIL: random word %#x was not BUSY\n", w);
            failures++;
            break;
        }
    }
    put(SITE, WFI);
    if (resumed != 1) { printf("FAIL: %u hint-space words resumed\n", resumed); failures++; }

    /* 3. Randomized differential against the oracle, over boundary values. */
    static const uint64_t elrs[] = {VA(SITE) + 4, VA(SITE), VA(SITE) + 6, VA(TEXT_BEGIN) + 4,
        VA(TEXT_END - 4) + 4, VA(TEXT_END) + 4, VA(TEXT_BEGIN - 4) + 4, VA(MEM_LOW + 0x1000) + 4,
        VA(TEXT_BEGIN + 0x200) + 4, VA(TEXT_BEGIN + 0x300) + 4, VA_HOLE + 0x104,
        VA_OUTSIDE + 0x104, VA_MISALIGNED + 0x104, VA(MEM_HIGH) + 4, 0, 2, 4, 8,
        VA(TEXT_BEGIN + 0xff8) + 4, VA(TEXT_BEGIN + 0xffc) + 4, VA(TEXT_END - 8) + 4};
    static const uint64_t spsrs[] = {0x3c5, 0x3c4, 0x5, 0x4, 0, 0x3c0, 0x3c9, 0x3c8, 0x1d3, 0x14,
        0x3c5 | (1u << 21), 0x3c5 | (1u << 20), 0x3c5 | (1u << 10), 0x3c5 | (2u << 10), 0x3c1};
    static const uint64_t bits[] = {0, 0, 0, 1};
    static const uint64_t lasts[] = {0, 0, 0, VA(SITE) + 4, VA(SITE) + 8};
    static const uint64_t hcrs[] = {HCR_BASE, HCR_BASE, HCR_BASE | 0x40, HCR_BASE | 0x80,
        HCR_BASE | 0x100, HCR_BASE | (1u << 14)};
    static const uint64_t ctls[] = {0, 1, 2, 3, 5, 7};
    static const uint64_t cvals[] = {GUEST_NOW - 1, GUEST_NOW, GUEST_NOW + 1, GUEST_NOW + 100000,
        UINT64_MAX, 0};
    static const uint64_t nows[] = {GUEST_NOW, GUEST_NOW, 5, UINT64_MAX - 10};
    static const uint64_t devices[] = {UINT64_MAX, UINT64_MAX, NOW - 1, NOW, NOW + 1, 0};
    static const uint64_t el2cvals[] = {NOW + BOUND, NOW + BOUND + 1, NOW - 1, NOW, NOW + 1,
        NOW + UINT64_C(24000000) * 600};
    static const uint64_t bounds[] = {BOUND, BOUND, BOUND, 0, UINT64_MAX, 1};
    static const uint64_t text_ends[] = {TEXT_END, TEXT_END, TEXT_END, 0, 2, TEXT_BEGIN};
    unsigned differential[WFI_RESULTS] = {0};
    for (unsigned n = 0; n < 2000000; n++) {
        struct wfi_resume_state s = {
            .elr = pick(elrs, sizeof elrs / 8), .spsr = pick(spsrs, sizeof spsrs / 8),
            .hcr = pick(hcrs, sizeof hcrs / 8), .stop = pick(bits, 4), .monitor = pick(bits, 4),
            .last_return = pick(lasts, sizeof lasts / 8),
            .ipi_pending = pick(bits, 4), .timer_pending = pick(bits, 4),
            .timer_ctl = pick(ctls, sizeof ctls / 8), .timer_cval = pick(cvals, sizeof cvals / 8),
            .guest_now = pick(nows, sizeof nows / 8), .model_irq_pending = pick(bits, 4),
            .models_pending = pick(bits, 4), .physical = NOW,
            .device_due = pick(devices, sizeof devices / 8), .el2_ctl = pick(ctls, sizeof ctls / 8),
            .el2_cval = pick(el2cvals, sizeof el2cvals / 8), .wake_bound = pick(bounds, sizeof bounds / 8)};
        struct wfi_resume_mem m = mem();
        m.text_end = pick(text_ends, sizeof text_ends / 8);
        pa_calls = 0;
        int reads;
        unsigned want = oracle(&s, &m, &reads);
        pa_calls = 0;
        unsigned got = wfi_resume_decide(&s, &m);
        if (got != want || (pa_calls != 0) != reads) {
            printf("FAIL: differential #%u: got %s oracle %s (elr %#llx spsr %#llx)\n", n,
                   names[got], names[want], (unsigned long long)s.elr, (unsigned long long)s.spsr);
            if (++failures > 20) break;
        }
        differential[got]++;
    }
    for (unsigned k = 0; k < WFI_RESULTS; k++)
        if (!differential[k]) { printf("FAIL: differential never reached %s\n", names[k]); failures++; }

    printf("%u table rows, 65536 hint-space words, 1000000 random words, 2000000 differential states:",
           (unsigned)(sizeof rows / sizeof rows[0]));
    for (unsigned k = 0; k < WFI_RESULTS; k++) printf(" %s=%u", names[k], seen[k]);
    printf("\n%s\n", failures ? "FAIL" : "PASS");
    return failures != 0;
}
