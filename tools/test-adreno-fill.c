/* SPDX-License-Identifier: MIT */
/* Whole fill transport through the existing noncoherent RAM/SMMU fixture.
 * Written before compat/adreno-fill.c. Failure inventory in the first-image doc.
 * The CP extension decodes PM4; it does not call the fill implementation to
 * determine destination, payload, count or completion. No hardware client. */
#define main adreno_existing_main
#include "test-adreno.c"
#undef main
#include "adreno-fill.h"

static unsigned cpu_destination_stores, cp_target_writes, cp_packets, cp_mode;
static struct adreno_ops fill_ops;
/* agents/gpu-x290 F1-F5 (compat/adreno-fill.h SNAP_ADRENO_FILL_BR): the fill's ring words around the data dwords --
 * 7 by default, 12 with the define, which also makes this CP run CP_THREAD_CONTROL and CP_WAIT_MEM_WRITES, record
 * the thread each CP_MEM_WRITE ran in, and report RBBM_STATUS (busy for rbbm_busy reads, or always). */
#if SNAP_ADRENO_FILL_BR
#define FILL_EXTRA ADRENO_FILL32_BR_EXTRA
static unsigned cp_thread, cp_sync_br, cp_wait_mem_writes, cp_writes_by_thread[4], rbbm_busy, rbbm_busy_forever;
#else
#define FILL_EXTRA 7u
#endif

static uint32_t cp_word(uint64_t va)
{
    uint64_t leaf = smmu_walk(va, 1);
    if (!leaf) { r.fsr = 2; return 0; }
    uint32_t value;
    memcpy(&value, dram + ram_offset((leaf & ADRENO_PTE_ADDR) | (va & 0xfff), 4), 4);
    return value;
}

static void cp_fill_run(void)
{
    if (cp_mode == 1) return;                  /* no progress */
    if (cp_mode == 2) { r.rptr = r.wptr; return; } /* stale marker must fail */
    while (r.rptr < r.wptr) {
        uint64_t ringva = 0x10100000 + 4UL * r.rptr;
        uint32_t header = cp_word(ringva), count = header & 0x3fff;
        uint32_t opcode = (header >> 16) & 0x7f;
#if SNAP_ADRENO_FILL_BR
        if (!r.fsr && (header >> 28) == 7 && (opcode == 0x17 || opcode == 0x12) && count + 1 <= r.wptr - r.rptr &&
            ((__builtin_popcount(count) + ((header >> 15) & 1)) & 1) == 1 &&
            ((__builtin_popcount(opcode) + ((header >> 23) & 1)) & 1) == 1) {
            if (opcode == 0x17) {                  /* CP_THREAD_CONTROL: one word, THREAD [1:0], SYNC_THREADS 31 */
                uint32_t word = cp_word(ringva + 4);
                if (count != 1 || r.fsr) { r.fsr = 0x80; return; }
                cp_thread = word & 3;
                if ((word & 3) == 1 && word >> 31) cp_sync_br++;
            } else {                               /* CP_WAIT_MEM_WRITES: no payload */
                if (count) { r.fsr = 0x80; return; }
                cp_wait_mem_writes++;
            }
            r.rptr += count + 1;
            continue;
        }
#endif
        if (r.fsr || (header >> 28) != 7 || opcode != 0x3d || count < 3 ||
            count + 1 > r.wptr - r.rptr ||
            ((__builtin_popcount(count) + ((header >> 15) & 1)) & 1) != 1 ||
            ((__builtin_popcount(opcode) + ((header >> 23) & 1)) & 1) != 1) {
            r.fsr = 0x80; return;
        }
        uint64_t target = (uint64_t)cp_word(ringva + 8) << 32 | cp_word(ringva + 4);
        for (uint32_t i = 0; i < count - 2; i++) {
            uint64_t va = target + 4UL * i, leaf = smmu_walk(va, 1);
            if (!leaf || (leaf & ADRENO_PTE_RDONLY)) { r.fsr = 2; return; }
            uint64_t pa = (leaf & ADRENO_PTE_ADDR) | (va & 0xfff);
            uint32_t value = cp_word(ringva + 12 + 4UL * i);
            if (r.fsr) return;
            if (pa >= GUEST_PAGE) cp_target_writes++;
            dev_wr32(pa, value);
            if (cp_mode == 3) { r.fsr = 2; return; } /* fault after first write */
        }
        cp_packets++;
#if SNAP_ADRENO_FILL_BR
        cp_writes_by_thread[cp_thread & 3]++;
#endif
        r.rptr += count + 1;
    }
}
#if SNAP_ADRENO_FILL_BR
static uint32_t fill_rd(void *ctx, uint64_t pa)
{
    if (pa == ADRENO_RBBM_STATUS) {
        if (rbbm_busy_forever) return 2;
        if (rbbm_busy) { rbbm_busy--; return 2; }
        return 1;                                  /* CP_AHB_BUSY_CX_MASTER only: idle (ADRENO_IB_RBBM_IDLE_IGNORE) */
    }
    return m_rd(ctx, pa);
}
#endif

static void fill_wr(void *ctx, uint64_t pa, uint32_t value)
{
    if (pa >= GUEST_PAGE && pa < GUEST_PAGE + GUEST_SIZE) cpu_destination_stores++;
    if (pa != ADRENO_CP_RB_WPTR) { m_wr(ctx, pa, value); return; }
    if (nlog < 4096) wlog[nlog++] = (struct regwrite){pa, value};
    if (r.drop_writes) { r.drop_writes--; r.fence_status |= 1; return; }
    r.fence_status = 0; r.wptr = value; cp_fill_run();
}

static void setup_fill(void)
{
    guest_fence_setup();
    dart[1] = dart_desc(GUEST_PAGE + 0xc000, 0, 0x4000, 0, 0);
    CHECK(mirror(ADRENO_WINDOW_BASE + 0x4000, 0x4000) == 0);
    for (uint64_t offset = 0; offset < GUEST_SIZE; offset += 4)
        dev_wr32(GUEST_PAGE + offset, 0xa55aa55a);
    /* Seed all DRAM before a cache-line fetch can retain the neighboring words. */
    for (uint64_t offset = 0; offset < GUEST_SIZE; offset += 4)
        (void)m_rd(0, GUEST_PAGE + offset);
    fill_ops = ops; fill_ops.wr = fill_wr;
    cpu_destination_stores = cp_target_writes = cp_packets = cp_mode = 0;
#if SNAP_ADRENO_FILL_BR
    fill_ops.rd = fill_rd;
    cp_thread = 3;                                 /* the ring as an IB leaves it: both threads */
    cp_sync_br = cp_wait_mem_writes = rbbm_busy = rbbm_busy_forever = 0;
    memset(cp_writes_by_thread, 0, sizeof cp_writes_by_thread);
#endif
}

static int fill(uint64_t va, uint64_t size, uint64_t value)
{
    uint64_t regs[] = {ADRENO_GUEST_FILL32, va, size, value};
    int result = adreno_guest_fill32(&fill_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
    CHECK((int64_t)regs[0] == result && regs[3] == S.wptr);
    CHECK(regs[1] == (result ? 0 : size));
    return result;
}

static void save_model_artifact(const char *name, uint64_t pa, uint64_t size)
{
    const char *directory = getenv("SNAP_FILL_ARTIFACT_DIR");
    if (!directory) return;
    char path[4096];
    int length = snprintf(path, sizeof path, "%s/%s", directory, name);
    CHECK(length > 0 && (size_t)length < sizeof path);
    if (length <= 0 || (size_t)length >= sizeof path) return;
    FILE *stream = fopen(path, "wb");
    CHECK(stream != 0);
    if (!stream) return;
    CHECK(fwrite(dram + ram_offset(pa, size), 1, size, stream) == size);
    CHECK(fclose(stream) == 0);
}

static void test_gpu_bytes(void)
{
    setup_fill();
    CHECK(fill(ADRENO_WINDOW_BASE + 0x3f00, 0x4000, 0xff00ff00) == 0);
    CHECK(cp_packets == 2 && cp_target_writes == 0x1000 && cpu_destination_stores == 0);
    CHECK(S.wptr == 22 + 0x1000 + FILL_EXTRA && r.rptr == S.wptr && S.fences == 1);
#if SNAP_ADRENO_FILL_BR
    /* F1/F3: both CP_MEM_WRITEs by BR, after SYNC_THREADS, with CP_WAIT_MEM_WRITES between; back to BOTH. */
    CHECK(cp_writes_by_thread[1] == 2 && cp_writes_by_thread[3] == 0 && cp_sync_br == 1 && cp_wait_mem_writes == 1 &&
          cp_thread == 3);
#endif
    unsigned wrong_device_bytes = 0, unexpected_cpu_changes = 0;
    for (uint64_t offset = 0; offset < GUEST_SIZE; offset += 4) {
        int changed = (offset >= 0x3f00 && offset < 0x4000) ||
                      (offset >= 0xc000 && offset < 0xff00);
        uint32_t device_value;
        memcpy(&device_value, dram + ram_offset(GUEST_PAGE + offset, 4), 4);
        wrong_device_bytes += device_value != (changed ? 0xff00ff00 : 0xa55aa55a);
        unexpected_cpu_changes += m_rd(0, GUEST_PAGE + offset) != 0xa55aa55a;
    }
    CHECK(wrong_device_bytes == 0 && unexpected_cpu_changes == 0);
    save_model_artifact("model-gpu-destination.bin", GUEST_PAGE, GUEST_SIZE);
    save_model_artifact("model-submitted-ring.bin", RING + 22 * 4, (0x1000 + FILL_EXTRA) * 4);
    m_clean(0, GUEST_PAGE, GUEST_SIZE); /* fixture caller refreshes CPU view after retirement */
    CHECK(m_rd(0, GUEST_PAGE + 0x3f00) == 0xff00ff00);
    CHECK(m_rd(0, GUEST_PAGE + 0xff00) == 0xa55aa55a);
    setup_fill();
    dart[0] = dart_desc(GUEST_PAGE, 0x200, 0x204, 0, 0);
    CHECK(fill(ADRENO_WINDOW_BASE + 0x200, 4, 0x12345678) == 0);
    CHECK(cp_target_writes == 1 && cp_packets == 2 && cpu_destination_stores == 0);
}

static void test_refusals(void)
{
    for (unsigned bad = 0; bad < 33; bad++) {
        setup_fill();
        uint64_t regs[] = {ADRENO_GUEST_FILL32, ADRENO_WINDOW_BASE + 0x3f00, 0x4000, 0xffabcdef};
        uint64_t (*get_leaf)(void *, uint64_t) = dart_leaf;
        switch (bad) {
        case 0: regs[0]++; break;
        case 1: regs[3] |= 1UL << 32; break;
        case 2: regs[2] = 0; break;
        case 3: regs[1]++; break;
        case 4: regs[2]--; break;
        case 5: regs[2] = ADRENO_FILL32_MAX_BYTES + 4; break;
        case 6: regs[1] = ADRENO_WINDOW_BASE - 4; break;
        case 7: regs[1] = ADRENO_WINDOW_END - 4; break;
        case 8: regs[1] = UINT64_MAX - 3; break;
        case 9: dart[1] = 0; break;
        case 10: dart[1] |= 4; break;
        case 11: dart[1] |= 8; break;
        case 12: dart[0] = dart_desc(GUEST_PAGE, 0x3f04, 0x4000, 0, 0); break;
        case 13: dart[1] = dart_desc(GUEST_PAGE + 0xc000, 0, 0x3efc, 0, 0); break;
        case 14: dart[1] = dart_desc(MEM_HIGH, 0, 0x4000, 0, 0); break;
        case 15: dart[1] = dart_desc(ARENA, 0, 0x4000, 0, 0); break;
        case 16: m_wr64(0, P.pool_pa + ADRENO_L3_OFFSET + 7 * 8, 0); break;
        case 17: S.status |= ADRENO_S_QUIESCED; break;
        case 18: S.status |= ADRENO_S_HIJACKED; break;
        case 19: P.flags |= ADRENO_F_RING; break;
        case 20: r.cx = 0; break;
        case 21: r.pwr = 1; break;
        case 22: r.sqe = 0; break;
        case 23: r.fsr = 2; break;
        case 24: r.ttbr_lo ^= 0x1000; break;
        case 25: r.tcr ^= 1; break;
        case 26: r.rptr--; break;
        case 27: r.rb_cntl = 11 | 2 << 8; break;   /* CP ring 4096 dwords != 8192 (ring wrap: test-adreno-ring.c) */
        case 28: fill_ops.clean = 0; break;
        case 29: get_leaf = 0; break;
        case 30: r.gfsr = 2; break;
        case 31: r.halt_ack = 1; break;
        case 32: r.sctlr &= ~1u; break;
        }
        unsigned previous_writes = nlog, previous_cleans = cleans;
        uint64_t previous_wptr = S.wptr;
        CHECK(adreno_guest_fill32(&fill_ops, &P, &S, regs, get_leaf, 0, MEM_LOW, MEM_HIGH) < 0);
        CHECK(regs[1] == 0 && nlog == previous_writes && cleans == previous_cleans);
        CHECK(S.wptr == previous_wptr && S.fences == 0 && cp_packets == 0);
        CHECK(cpu_destination_stores == 0 && r.mmio_reads_cx_off == 0);
    }
}

static void test_uncertain(void)
{
    setup_fill(); r.drop_writes = 1;
    CHECK(fill(ADRENO_WINDOW_BASE, 64, 0xabcdef12) == 0 && cp_target_writes == 16);
    for (unsigned failure = 0; failure < 5; failure++) {
        setup_fill();
        if (failure == 0) r.drop_writes = 2;
        if (failure == 1) clean_disabled = 1;
        if (failure >= 2) cp_mode = failure - 1;
        CHECK(fill(ADRENO_WINDOW_BASE, 64, 0xabcdef12) == ADRENO_FILL32_E_UNCERTAIN);
        CHECK(S.fences == 0 && cpu_destination_stores == 0);
    }
}

#if SNAP_ADRENO_FILL_BR
/* F2: completion waits for RBBM idle; a GPU that stays busy is UNCERTAIN (the destination may still change). */
static void test_idle(void)
{
    setup_fill();
    rbbm_busy = 30;
    CHECK(fill(ADRENO_WINDOW_BASE, 64, 0x0c0ffee0) == 0 && rbbm_busy == 0 && S.fences == 1);
    setup_fill();
    rbbm_busy_forever = 1;
    CHECK(fill(ADRENO_WINDOW_BASE, 64, 0x0c0ffee1) == ADRENO_FILL32_E_UNCERTAIN && S.fences == 0);
    CHECK(cpu_destination_stores == 0 && cp_target_writes == 16);
}
#endif

#ifndef ADRENO_FILL_TEST_ENTRY
#define ADRENO_FILL_TEST_ENTRY main
#endif
int ADRENO_FILL_TEST_ENTRY(void)
{
    if (adreno_existing_main()) return 1;
    checks = failures = 0;
    dram = calloc(1, RAM_SIZE); cache = calloc(1, RAM_SIZE);
    if (!dram || !cache) return 2;
    test_gpu_bytes(); test_refusals(); test_uncertain();
#if SNAP_ADRENO_FILL_BR
    test_idle();
#endif
    free(dram); free(cache);
    printf("%s: %u fill transport checks; variable PM4, GPU bytes, canaries, stale CPU cache, 33 preflight refusals and 5 uncertain completions\n",
           failures ? "FAIL" : "PASS", checks);
    return failures ? 1 : 0;
}
