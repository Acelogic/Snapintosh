/* SPDX-License-Identifier: MIT */
/* The wide GPU VA window (ADRENO_VA_WIDE: [1 GiB, 16 GiB), CB0 T0SZ 30; agents/gpu-va-wide FAILURE-MODES.md,
 * V-numbers below) end to end, through the monitor's own entry points, against tools/test-adreno-ring.c's model of
 * the A16's Adreno side: guest RAM behind a non-coherent CPU cache, the committed DART leaves, the CB0 walk (T0SZ
 * from the live TCR: 16 root entries) with its TLB, and the CP running ring and IB packets through CB0.
 *  - adopt (V1, V5, V8, V13): root entries 1..15 link the 15 level-2 tables of the pool (monitor memory above the
 *    guest's), every level-2 entry its level-3 table; the first and last page of every GiB are unmapped; a set root
 *    entry 15, a live T0SZ 32 and a params T0SZ 32 are refused;
 *  - across 4 GiB (V14): four DART pages at 0xffff8000..0x1_0000_8000 (root entries 3 and 4, level-3 tables 1535
 *    and 1536) mirror and walk page by page; an unmap that straddles 4 GiB is refused (one 32 MiB DART table per
 *    unmap); each half unmaps, the TLB is invalidated, and no walk is served from a stale entry; live_pages balances;
 *  - the top of the window: the last 32 KiB maps, walks and unmaps; END - 0x4000 + 0x8000 and END are refused;
 *  - the CP above 4 GiB (V4): a guest fence at 0x2_0000_0040, a FILL32 over 0x3_0000_0000, an IB whose package
 *    is at 0x3_ffff_0000 writing to 0x1_2345_0010 (CP_INDIRECT_BUFFER and CP_MEM_WRITE high words), cache
 *    maintenance across 4 GiB, adreno_ib_ring_words' high words;
 *  - a CB0 fault at FAR 0x2_0000_1000 is recorded whole (V17);
 *  - the kext side (V10, V11): the IB arena must end at or below 4 GiB; register and descriptor relocations to
 *    resources at 0x1_0000_0000 and 0x3_ffff_0000 patch both halves and validate; a lo-only data relocation to a
 *    resource above 4 GiB is refused (ADRENO_IB_E_RELOC), below it accepted;
 *  - quiesce (V7): root entries 1..15 are cleared and invalidated; nothing above 4 GiB translates afterwards.
 *
 *   clang -std=gnu11 -Icompat -Ishadow -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *     -DADRENO_VA_WIDE=1 tools/test-adreno-va-wide.c compat/adreno-ib-command.c compat/adreno-ib.c \
 *     compat/adreno-fill-command.c compat/adreno-fill.c compat/adreno-submit.c compat/adreno-resource.c \
 *     compat/adreno-resource-list.c compat/adreno.c compat/irq-forward.c shadow/stage2.c shadow/shadow.c \
 *     shadow/mmu.c -o build/test-adreno-va-wide && build/test-adreno-va-wide */
#define ADRENO_RING_NO_MAIN 1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"   /* S2 needs the draw-plan fixture: not run here */
#include "test-adreno-ring.c"
#pragma clang diagnostic pop
#include "adreno-ib-command.h"
#if !ADRENO_VA_WIDE
#error "build with -DADRENO_VA_WIDE=1"
#endif

#define FOUR_GIB 0x100000000UL
#define W_PA (GUEST_PAGE + 0x340000)            /* this file's guest pages, clear of the ring test's fixtures */

static int wide_native_unmap(void *ctx, uint64_t iova, uint64_t size)
{
    (void)ctx;
    for (uint64_t at = iova; at < iova + size; at += 0x4000) dart[(at - ADRENO_WINDOW_BASE) >> 14] = 0;
    return 0;
}
static int unmap(uint64_t va, uint64_t size)
{
    uint64_t regs[4] = {ADRENO_GUEST_UNMAP, va, size, 0};
    int e = adreno_guest_unmap(&ring_ops, &P, &S, regs, dart_leaf, wide_native_unmap, 0, MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == e && regs[1] == (e ? 0 : size));
    return e;
}
/* DC IVAC: the CPU's copy of each line is dropped (a dirty line's data with it); DRAM is what the GPU wrote. */
static unsigned invalidates;
static void m_invalidate(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    invalidates++;
    uint64_t off = ram_offset(pa, size);
    for (uint64_t line = off / 64; line <= (off + size - 1) / 64; line++) dirty[line] = cached[line] = 0;
}
static int cache_op(uint64_t va, uint64_t size, uint64_t direction)
{
    uint64_t regs[4] = {ADRENO_GUEST_CACHE, va, size, direction};
    struct adreno_ops o = ring_ops;
    o.invalidate = m_invalidate;
    int e = adreno_guest_cache(&o, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == e && regs[1] == (e ? 0 : size));
    return e;
}
static uint64_t leaf_at(uint64_t pa, int rdonly) { return pa | ADRENO_PTE_LEAF | (rdonly ? ADRENO_PTE_RDONLY : 0); }

static void test_adopt_wide(void)
{
    CHECK(ADRENO_WINDOW_END == 0x400000000UL && ADRENO_CB0_T0SZ == 30 && ADRENO_ROOT_SLOTS == 16);
    CHECK(ADRENO_L2_TABLES == 15 && ADRENO_L3_TABLES == 7680 && ADRENO_POOL_BYTES == 0x1e0f000UL);
    CHECK(POOL >= MEM_HIGH && (POOL >= ARENA + ARENA_SIZE || POOL + ADRENO_POOL_BYTES <= ARENA));
    ring_setup(22);
    CHECK(r.tcr == 0x80201eu && P.cb0_tcr == 0x80201eu);
    CHECK(dev_rd64(ROOT) == ((ROOT + 0x1000) | 3));                     /* q1n1's, untouched */
    for (unsigned g = 1; g < 16; g++) CHECK(dev_rd64(ROOT + 8 * g) == ((POOL + (g - 1) * 0x1000UL) | 3));
    for (unsigned g = 16; g < 512; g++) CHECK(dev_rd64(ROOT + 8 * g) == 0);
    const uint64_t l2[] = {0, 511, 512, 1535, 1536, 4095, 7679};
    for (unsigned i = 0; i < sizeof l2 / sizeof l2[0]; i++)
        CHECK(dev_rd64(POOL + 8 * l2[i]) == ((POOL + ADRENO_L3_OFFSET + l2[i] * 0x1000) | 3));
    for (uint64_t gib = 1; gib < 16; gib++) {
        if (gib > 1) CHECK(smmu_walk(gib << 30, 0) == 0);                /* GiB 1 holds ring_setup's fixtures */
        CHECK(smmu_walk(((gib + 1) << 30) - 0x1000, 0) == 0);
    }
    CHECK(smmu_walk(ADRENO_WINDOW_END, 0) == 0 && smmu_walk(0x10200000, 0) == (MEMPTRS | ADRENO_PTE_LEAF));
    /* Refusals (V1, V13): a root entry the mirror would claim, a live T0SZ 32, a params T0SZ 32. */
    for (unsigned n = 0; n < 3; n++) {
        q1n1_cp_fence();
        int want = ADRENO_E_ROOT;
        if (n == 0) { uint64_t e = 0x12345003; memcpy(dram + ram_offset(ROOT + 8 * 15, 8), &e, 8); }
        if (n == 1) { r.tcr = 0x802020; want = ADRENO_E_CB0; }
        if (n == 2) { r.tcr = 0x802020; P.cb0_tcr = 0x802020; want = ADRENO_E_PARAMS; }
        CHECK(adreno_adopt(&ops, &P, &S, MEM_LOW, MEM_HIGH) == want && !(S.status & ADRENO_S_ATTACHED));
        if (n == 0) CHECK(dev_rd64(ROOT + 8 * 15) == 0x12345003 && dev_rd64(ROOT + 8 * 4) == 0);
    }
}

static void test_boundary(void)
{
    ring_setup(22);
    const uint64_t below = FOUR_GIB - 0x8000, live = S.live_pages;
    for (unsigned k = 0; k < 4; k++)
        dart[(below + k * 0x4000 - ADRENO_WINDOW_BASE) >> 14] = dart_desc(W_PA + k * 0x4000, 0, 0x4000, k >= 2, 0);
    CHECK(mirror(below, 0x10000) == 0);
    CHECK(((below - ADRENO_WINDOW_BASE) >> 21) == 1535 && ((FOUR_GIB - ADRENO_WINDOW_BASE) >> 21) == 1536);
    for (unsigned k = 0; k < 16; k++) CHECK(smmu_walk(below + k * 0x1000, 1) == leaf_at(W_PA + k * 0x1000, k >= 8));
    CHECK(S.live_pages == live + 16);
    /* The CP writes through both sides (the upper half is read-only: a write there faults). */
    CHECK(fence(below + 0x7ffc, 0x534e4001) == 0 && dev_rd32(W_PA + 0x7ffc) == 0x534e4001);
    CHECK(fence(FOUR_GIB, 0x534e4002) == ADRENO_E_TARGET);              /* the fence needs a writable leaf */
    /* Cache maintenance across 4 GiB: TO_DEVICE over both sides; FROM_DEVICE refuses the read-only half. */
    CHECK(cache_op(FOUR_GIB - 0x4000, 0x8000, ADRENO_CACHE_TO_DEVICE) == 0);
    CHECK(cache_op(FOUR_GIB - 0x4000, 0x8000, ADRENO_CACHE_FROM_DEVICE) == ADRENO_E_TARGET);
    unsigned before = invalidates;
    CHECK(cache_op(FOUR_GIB - 0x8000, 0x8000, ADRENO_CACHE_FROM_DEVICE) == 0 && invalidates > before);
    /* One unmap is one 32 MiB DART table: straddling 4 GiB is refused before anything is cleared. */
    unsigned syncs = r.tlbsyncs;
    CHECK(unmap(below, 0x10000) == ADRENO_E_WINDOW && r.tlbsyncs == syncs);
    for (unsigned k = 0; k < 16; k++) CHECK(smmu_walk(below + k * 0x1000, 1) != 0);
    CHECK(unmap(below, 0x8000) == 0 && unmap(FOUR_GIB, 0x8000) == 0);
    CHECK(r.tlbsyncs == syncs + 2 && S.live_pages == live);
    for (unsigned k = 0; k < 16; k++) CHECK(smmu_walk(below + k * 0x1000, 1) == 0);   /* not from a stale TLB */
    CHECK(dart[(below - ADRENO_WINDOW_BASE) >> 14] == 0 && dart[(FOUR_GIB - ADRENO_WINDOW_BASE) >> 14] == 0);
}

static void test_top(void)
{
    ring_setup(22);
    const uint64_t top = ADRENO_WINDOW_END - 0x8000;
    map(top, W_PA + 0x10000, 0x8000, 0);
    CHECK(smmu_walk(ADRENO_WINDOW_END - 0x1000, 1) == leaf_at(W_PA + 0x17000, 0));
    CHECK(((ADRENO_WINDOW_END - 0x1000 - ADRENO_WINDOW_BASE) >> 21) == ADRENO_L3_TABLES - 1);
    CHECK(mirror(ADRENO_WINDOW_END - 0x4000, 0x8000) == ADRENO_E_WINDOW);
    CHECK(mirror(ADRENO_WINDOW_END, 0x4000) == ADRENO_E_WINDOW);
    CHECK(fence(ADRENO_WINDOW_END - 4, 0x534e5001) == 0 && dev_rd32(W_PA + 0x17ffc) == 0x534e5001);
    CHECK(fence(ADRENO_WINDOW_END, 0x534e5002) == ADRENO_E_TARGET);
    CHECK(unmap(ADRENO_WINDOW_END - 0x4000, 0x8000) == ADRENO_E_WINDOW);
    CHECK(unmap(top, 0x8000) == 0 && smmu_walk(ADRENO_WINDOW_END - 0x1000, 1) == 0);
}

static void test_cp_above(void)
{
    ring_setup(22);
    /* A guest fence: CP_MEM_WRITE's high word 2. */
    map(0x200000000UL, W_PA + 0x20000, 0x4000, 0);
    CHECK(fence(0x200000040UL, 0x534e6001) == 0 && dev_rd32(W_PA + 0x20040) == 0x534e6001);
    /* FILL32 (one page per call) over two pages at 12 GiB. */
    map(0x300000000UL, W_PA + 0x30000, 0x8000, 0);
    CHECK(fill(0x300000000UL, 0x4000, 0xa5a5a5a5) == 0 && fill(0x300004000UL, 0x4000, 0x5a5a5a5a) == 0);
    CHECK(words_not(W_PA + 0x30000, 0x4000, 0xa5a5a5a5) == 0 && words_not(W_PA + 0x34000, 0x4000, 0x5a5a5a5a) == 0);
    /* An IB fetched from 0x3_ffff_0000 that writes 0x1_2345_0010. */
    map(0x3ffff0000UL, W_PA + 0x40000, 0x4000, 1);
    map(0x123450000UL, W_PA + 0x44000, 0x4000, 0);
    const uint32_t w[4] = {pkt7(OP_MEM_WRITE, 3), 0x23450010u, 0x1u, 0x600dcafeu};
    put_package(W_PA + 0x40000, w, 4, 64);
    CHECK(ib(0x3ffff0000UL, 4, 64) == 0 && dev_rd32(W_PA + 0x44010) == 0x600dcafeu);
    CHECK(cp.violations == 0 && cp.ibs >= 1);
    /* The ring words carry the IB's high word. */
    uint32_t words[ADRENO_IB_RING_WORDS];
    unsigned n = adreno_ib_ring_words(words, FOUR_GIB, 4, P.fence_va, P.fence_va + 0x10, 7);
    CHECK(n <= ADRENO_IB_RING_WORDS && words[5] == 0 && words[6] == 1);
    adreno_ib_ring_words(words, 0x3ffffc000UL, 4, P.fence_va, P.fence_va + 0x10, 7);
    CHECK(words[5] == 0xffffc000u && words[6] == 3);
    /* A CB0 fault above 4 GiB is recorded whole. */
    r.fsr = 2; r.far_lo = 0x1000; r.far_hi = 2;
    CHECK(adreno_fault_poll(&ops, &S) == 1 && S.fault_far == 0x200001000UL);
}

static void test_quiesce_wide(void)
{
    ring_setup(22);
    map(0x200000000UL, W_PA + 0x20000, 0x4000, 0);
    CHECK(smmu_walk(0x200000000UL, 1) != 0);
    adreno_quiesce(&ring_ops, &P, &S);
    CHECK((S.status & ADRENO_S_QUIESCED) && !(S.status & ADRENO_S_ATTACHED) && (S.quiesce & 32));
    for (unsigned g = 1; g < 16; g++) CHECK(dev_rd64(ROOT + 8 * g) == 0);
    CHECK(smmu_walk(0x200000000UL, 1) == 0 && smmu_walk(0x10200000, 1) == (MEMPTRS | ADRENO_PTE_LEAF));
    /* A TLB sync that never completes: not QUIESCED (the pool stays quarantined with the guest's memory). */
    ring_setup(22);
    r.tlb_stuck = 1;
    adreno_quiesce(&ring_ops, &P, &S);
    CHECK((S.quiesce & 16) && !(S.quiesce & 32) && !(S.status & ADRENO_S_QUIESCED));
    r.tlb_stuck = 0;
    /* A CB0 someone else retargeted: the old root and its 15 mirror entries are never touched. */
    ring_setup(22);
    r.ttbr_lo = 0x8d0000000 & 0xffffffff; r.ttbr_hi = 8;
    adreno_quiesce(&ring_ops, &P, &S);
    CHECK((S.status & ADRENO_S_HIJACKED) && !(S.status & ADRENO_S_QUIESCED));
    for (unsigned g = 1; g < 16; g++) CHECK(dev_rd64(ROOT + 8 * g) == ((POOL + (g - 1) * 0x1000UL) | 3));
}

/* --- the kext side: compat/adreno-ib-command.c (V10, V11) ------------------------------------------------- */
static struct adreno_ib_tables tables;
static uint8_t arena_cpu[ADRENO_IB_ARENA_BYTES] __attribute__((aligned(64)));
static struct adreno_ib_reloc relocs[8];
static uint16_t order[8];
static uint8_t used[8];
static uint64_t targets[ADRENO_IB_TARGET_WORDS];
static uint64_t resource_va[16];
static int resolve(void *ctx, uint32_t id, unsigned access, uint64_t offset, uint64_t length, uint64_t *address)
{
    (void)ctx; (void)access; (void)length;
    if (id >= 16 || !resource_va[id]) return -1;
    *address = resource_va[id] + offset;
    return 0;
}
static uint8_t command[4096] __attribute__((aligned(8)));
static size_t build(const uint32_t *words, uint32_t n, uint32_t data_bytes, const struct adreno_ib_reloc *r, uint32_t nr)
{
    const uint64_t package = adreno_ib_package_bytes(n, data_bytes), total = adreno_ib_command_bytes(n, data_bytes, nr);
    struct adreno_ib_command c = {{ADRENO_KCMD_IB, (uint32_t)total}, ADRENO_IB_COMMAND_VERSION, 0, n, data_bytes, nr, 0,
                                  {0, 0}};
    memset(command, 0, sizeof command);
    memcpy(command, &c, sizeof c);
    memcpy(command + sizeof c, words, 4ull * n);
    memcpy(command + sizeof c + package, r, sizeof *r * nr);
    return (size_t)total;
}
static struct adreno_ib_work work;
static int stage_relocate(size_t bytes)
{
    int e = adreno_ib_stage(&work, command, bytes);
    return e ? e : adreno_ib_relocate(&work, resolve, 0);
}
static uint32_t pkg32(uint32_t at) { uint32_t v; memcpy(&v, work.package + at, 4); return v; }

static void test_kext(void)
{
    CHECK(adreno_ib_tables_init(&tables) == 0);
    /* V11: the arena (zero page + package) ends at or below 4 GiB. */
    const struct { uint64_t va; int ok; } arenas[] = {
        {ADRENO_WINDOW_BASE, 1}, {FOUR_GIB - ADRENO_IB_ARENA_BYTES, 1}, {FOUR_GIB - ADRENO_IB_ARENA_BYTES + 0x4000, 0},
        {FOUR_GIB, 0}, {0x300000000UL, 0}, {ADRENO_WINDOW_END - ADRENO_IB_ARENA_BYTES, 0}};
    for (unsigned i = 0; i < sizeof arenas / sizeof arenas[0]; i++)
        CHECK((adreno_ib_work_init(&work, &tables, arena_cpu, arenas[i].va, ADRENO_IB_ARENA_BYTES, relocs, order, used, 8,
                                   targets) == 0) == arenas[i].ok);
    CHECK(adreno_ib_work_init(&work, &tables, arena_cpu, 0x80000000UL, ADRENO_IB_ARENA_BYTES, relocs, order, used, 8,
                              targets) == 0);
    /* V10: RB_MRT_BASE (a 64-bit register, hi 32) and a UBO descriptor's BASE (hi 17) to resources above 4 GiB. */
    resource_va[1] = FOUR_GIB;
    resource_va[2] = 0x3ffff0000UL;
    resource_va[3] = 0x7fff0000UL;
    uint32_t ib[8], n = 0;
    ib[n++] = a8xx_pkt7_hdr(A8XX_E_CP_SET_MARKER, 1);
    ib[n++] = A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_DIRECT_RENDER);
    ib[n++] = a8xx_pkt7_hdr(A8XX_E_CP_CONTEXT_REG_BUNCH, 4);
    ib[n++] = A8XX_REG_RB_MRT_BASE; ib[n++] = 0; ib[n++] = A8XX_REG_RB_MRT_BASE + 1; ib[n++] = 0;
    const uint32_t data = (uint32_t)adreno_ib_data_offset(n);
    struct adreno_ib_reloc r[3] = {
        {4 * 4, 6 * 4, ADRENO_IB_RELOC_RESOURCE, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE, 6, 32, 1, 0, 0x1000},
        {data, data + 4, ADRENO_IB_RELOC_RESOURCE, ADRENO_IB_ACCESS_READ, 6, 17, 2, 0x40, 0x100},   /* data area */
        {data + 8, ADRENO_IB_RELOC_NO_HI, ADRENO_IB_RELOC_PACKAGE, ADRENO_IB_ACCESS_READ, 2, 0, 0, 0, 4}};
    CHECK(stage_relocate(build(ib, n, 64, r, 3)) == 0);
    CHECK(pkg32(16) == 0 && pkg32(24) == 1);                              /* RB_MRT_BASE lo/hi */
    CHECK(pkg32(data) == 0xffff0040u && pkg32(data + 4) == 3);            /* 17-bit BASE_HI */
    CHECK(pkg32(data + 8) == (uint32_t)work.package_gpu && !(work.package_gpu >> 32));
    CHECK(adreno_ib_validate(&work) == 0);
    /* A lo-only relocation: above 4 GiB refused (fail closed, nothing submitted), below it patched. */
    struct adreno_ib_reloc lo_only = {data, ADRENO_IB_RELOC_NO_HI, ADRENO_IB_RELOC_RESOURCE, ADRENO_IB_ACCESS_READ, 2,
                                      0, 1, 0, 4};
    CHECK(adreno_ib_work_init(&work, &tables, arena_cpu, 0x80000000UL, ADRENO_IB_ARENA_BYTES, relocs, order, used, 8,
                              targets) == 0);
    CHECK(stage_relocate(build(ib, 2, 64, &lo_only, 1)) == ADRENO_IB_E_RELOC);
    lo_only.resource_id = 3;
    CHECK(adreno_ib_work_init(&work, &tables, arena_cpu, 0x80000000UL, ADRENO_IB_ARENA_BYTES, relocs, order, used, 8,
                              targets) == 0);
    CHECK(stage_relocate(build(ib, 2, 64, &lo_only, 1)) == 0 && pkg32(adreno_ib_data_offset(2)) == 0x7fff0000u);
}

int main(void)
{
    dram = calloc(1, RAM_SIZE);
    cache = calloc(1, RAM_SIZE);
    if (!dram || !cache) return 2;
    test_adopt_wide();
    test_boundary();
    test_top();
    test_cp_above();
    test_quiesce_wide();
    test_kext();
    free(dram);
    free(cache);
    if (failures) { printf("FAILED: %u of %u wide GPU VA window checks\n", failures, checks); return 1; }
    printf("PASS: %u wide GPU VA window checks (adopt with 16 root entries, map/unmap across 4 GiB and at the top of "
           "the window, CP fence/FILL32/IB above 4 GiB, cache, fault, quiesce, kext arena and relocations)\n", checks);
    return 0;
}
