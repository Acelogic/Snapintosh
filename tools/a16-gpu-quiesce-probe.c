/* SPDX-License-Identifier: MIT */
/* Failure inventory: docs/A16-GPU-NATIVE-QUALIFICATION-20261019.md.
 * A bounded EL2 caller of the unchanged production adoption/fence/quiesce path.
 * The model replay calls the same core with the existing noncoherent CP/SMMU.
 */
#include "adreno.h"

#define GPU_PROBE_MAGIC 0x3151504736314141UL
#define GPU_PROBE_WORDS 96
#define GPU_PROBE_BYTES (GPU_PROBE_WORDS * 8)
#define GPU_PROBE_ERROR(stage) (0x47510000UL + (stage))

static uint64_t probe_now(const struct adreno_ops *o)
{
#if ADRENO_DIRECT
    uint64_t v; (void)o;
    __asm__ volatile("isb; mrs %0,cntpct_el0" : "=r"(v) :: "memory");
    return v;
#else
    return o->now(o->ctx);
#endif
}

static uint32_t probe_rd(const struct adreno_ops *o, uint64_t pa)
{
#if ADRENO_DIRECT
    (void)o; return *(volatile uint32_t *)(uintptr_t)pa;
#else
    return o->rd(o->ctx, pa);
#endif
}

static uint64_t probe_rd64(const struct adreno_ops *o, uint64_t pa)
{
#if ADRENO_DIRECT
    (void)o; return *(volatile uint64_t *)(uintptr_t)pa;
#else
    return o->rd64(o->ctx, pa);
#endif
}

static uint64_t probe_leaf(void *ctx, uint64_t va)
{
    if ((va & ~0x3fffUL) != ADRENO_WINDOW_BASE) return 0;
    return ((*(uint64_t *)ctx >> 4) & 0x3ffffffc00UL) | 1 | (0xfffUL << 40);
}

uint64_t gpu_probe_core(const struct adreno_ops *o, const struct adreno_params *params,
                        uint64_t out[GPU_PROBE_WORDS], uint64_t target, uint64_t marker)
{
    for (unsigned i = 0; i < GPU_PROBE_WORDS; i++) out[i] = 0;
    struct adreno_state s = {0};
    struct adreno_params p = *params;
    out[0] = GPU_PROBE_MAGIC; out[1] = 1; out[2] = GPU_PROBE_BYTES;
    out[3] = marker; out[4] = target; out[5] = ADRENO_WINDOW_BASE;
    out[6] = probe_now(o); out[8] = o->hz;
    uint64_t result = GPU_PROBE_ERROR(1);
    if (!target || (target & 0x3fff) || target > (1UL << 36) - 0x4000 ||
        !marker || marker > 0xffffffffUL || o->hz != 19200000 ||
        p.flags != (ADRENO_F_ENABLE | ADRENO_F_DART | ADRENO_F_RING | ADRENO_F_TZ_DONE)) goto done;
    int e = adreno_adopt(o, &p, &s, target, target + 0x4000);
    out[10] = (uint64_t)(int64_t)e; result = GPU_PROBE_ERROR(2);
    if (e) goto done;
    e = adreno_mirror(o, &p, &s, ADRENO_WINDOW_BASE, 0x4000,
                     probe_leaf, &target, target, target + 0x4000);
    out[11] = (uint64_t)(int64_t)e; result = GPU_PROBE_ERROR(3);
    if (e) goto done;
    /* Adoption's RING flag proves idle pointers. The guest request then owns
     * this one synchronous submission, just as the monitor's guest path does. */
    p.flags &= ~ADRENO_F_RING;
    uint64_t regs[4] = {ADRENO_GUEST_FENCE, ADRENO_WINDOW_BASE, marker, 0};
    e = adreno_guest_fence(o, &p, &s, regs, probe_leaf, &target, target, target + 0x4000);
    out[12] = (uint64_t)(int64_t)e; result = GPU_PROBE_ERROR(4);
    if (e) goto done;
    out[13] = probe_rd(o, target);
    if (out[13] != marker || s.fences != 1 || s.fence_error) goto done;
    adreno_quiesce(o, &p, &s);
    result = GPU_PROBE_ERROR(5);
    if (s.status != (ADRENO_S_ADOPTED | ADRENO_S_QUIESCED | ADRENO_S_TZ_DONE) ||
        s.quiesce != 41 || !(s.halt_ack & 1) || s.tlbi_timeouts || s.faults || s.serrors) goto done;
    out[14] = probe_rd(o, ADRENO_CB0 + ADRENO_CB_TTBR0) |
              (uint64_t)probe_rd(o, ADRENO_CB0 + ADRENO_CB_TTBR0 + 4) << 32;
    out[15] = probe_rd(o, ADRENO_CB0 + ADRENO_CB_TCR);
    out[16] = probe_rd(o, ADRENO_CB0 + ADRENO_CB_SCTLR);
    uint64_t root = p.cb0_ttbr0 & ADRENO_PTE_ADDR;
    for (unsigned i = 0; i < 3; i++) out[17+i] = probe_rd64(o, root + 8*(i+1));
    out[20] = probe_rd(o, ADRENO_CP_RB_RPTR); out[21] = probe_rd(o, ADRENO_CP_RB_WPTR);
    result = GPU_PROBE_ERROR(6);
    if (out[14] != p.cb0_ttbr0 || out[15] != (uint32_t)p.cb0_tcr || !(out[16] & 1) ||
        ((out[16] ^ p.cb0_sctlr) & ~ADRENO_SCTLR_FIXED) || out[17] || out[18] || out[19] ||
        out[20] != s.wptr || out[21] != s.wptr || s.tlbi != 2 || s.map_pages != 4) goto done;
    result = 0;
done:
    out[7] = probe_now(o); out[9] = result;
    const uint64_t *state = (const uint64_t *)&s;
    for (unsigned i = 0; i < ADRENO_STATE_WORDS; i++) out[32+i] = state[i];
    return result;
}

#if ADRENO_DIRECT
void *memset(void *destination, int value, __SIZE_TYPE__ count)
{
    volatile unsigned char *bytes = destination;
    for (__SIZE_TYPE__ i = 0; i < count; i++) bytes[i] = (unsigned char)value;
    return destination;
}

/* q1n1 P_CALL supplies its normal stack and vectors. Do not change interrupt,
 * exception, translation, PMU or power policy here. Strict abort handling is
 * provided by the host ControlGuard and the resident q1n1 exception path. */
__attribute__((section(".text.entry")))
uint64_t gpu_probe_entry(uint64_t out[GPU_PROBE_WORDS], const struct adreno_params *p,
                         uint64_t target, uint64_t marker)
{
    uint64_t el, mpidr, ctr, hz, before, after;
    __asm__ volatile("mrs %0,CurrentEL; mrs %1,mpidr_el1; mrs %2,ctr_el0; mrs %3,cntfrq_el0; mrs %4,isr_el1"
                     : "=r"(el), "=r"(mpidr), "=r"(ctr), "=r"(hz), "=r"(before));
    if (el != 8 || (mpidr & 0xff00ffffffUL) || ((ctr >> 16) & 15) != 4 || hz != 19200000 ||
        (before & (1UL << 8))) return GPU_PROBE_ERROR(7);
    struct adreno_ops ops = {.hz = hz};
    uint64_t result = gpu_probe_core(&ops, p, out, target, marker);
    __asm__ volatile("dsb sy; isb; mrs %0,isr_el1" : "=r"(after) :: "memory");
    out[22] = before; out[23] = after; out[24] = el; out[25] = mpidr; out[26] = ctr; out[27] = hz;
    if (after & (1UL << 8)) result = GPU_PROBE_ERROR(8);
    out[9] = result;
    for (uint64_t line = (uint64_t)out; line < (uint64_t)out + GPU_PROBE_BYTES; line += 64)
        __asm__ volatile("dc cvac,%0" :: "r"(line) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
    return result;
}
#endif
