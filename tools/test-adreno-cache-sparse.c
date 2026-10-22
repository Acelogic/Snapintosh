/* SPDX-License-Identifier: MIT */
/* Cache ownership per kernel command (agents/cache-maint FAILURE-MODES.md C1-C14), end to end through production code:
 * list acquire/prepare, adreno_kernel_command, the FILL32 and IB paths, the monitor's GUEST_CACHE/FILL32/IB, the CP
 * model's CP_MEMCPY, behind tools/test-adreno.c's non-coherent CPU cache (an invalidate of a dirty line fails).
 * Fixtures model the kext's call sites: FENCE through AdrenoSegmentList::submit, the map's marks and range sync.
 * Written before ADRENO_CACHE_SPARSE. Built with and without -DADRENO_CACHE_SPARSE=1: the pixels (data checks) must be
 * the same in both builds; the maintenance counts are what differ.
 *
 *   clang -std=gnu11 -Icompat -Ishadow -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror [-DADRENO_CACHE_SPARSE=1] \
 *     tools/test-adreno-cache-sparse.c compat/adreno-ib-command.c compat/adreno-ib.c compat/adreno-fill-command.c \
 *     compat/adreno-fill.c compat/adreno-submit.c compat/adreno-resource.c compat/adreno-resource-list.c compat/adreno.c \
 *     compat/irq-forward.c shadow/stage2.c shadow/shadow.c shadow/mmu.c \
 *     -Wl,-e,_sparse_main -o test-adreno-cache-sparse
 *   test-adreno-cache-sparse [--volume]    (--volume: the maintenance-volume table only)
 * The fixtures are test-adreno-ib-command.c's, included whole; its own main stays in the binary unused, and the entry
 * point is sparse_main (ld -e), so that file needs no change. */
#include "test-adreno-ib-command.c"

#ifndef ADRENO_CACHE_SPARSE
#define ADRENO_CACHE_SPARSE 0
#endif

/* ---- the kext's cache callbacks, counted ------------------------------------------------------------------- */
static struct { unsigned calls[3]; uint64_t bytes[3]; } hv;            /* GUEST_CACHE HVCs by direction */
static unsigned map_syncs[3];                                           /* whole-map syncs by direction */
static int sp_hvc(void *ctx, uint64_t address, uint64_t bytes, unsigned direction)
{
    (void)ctx;
    hv.calls[direction]++; hv.bytes[direction] += bytes;
    uint64_t regs[] = {ADRENO_GUEST_CACHE, address, bytes, direction};
    return adreno_guest_cache(&ib_ops, &P, &S, regs, dart_leaf, 0, MEM_LOW, MEM_HIGH);
}
/* AdrenoSegmentList::syncResource -> AdrenoMemoryMap::cacheSubmission. */
static int sp_sync(void *ctx, void *token, unsigned direction)
{
    (void)ctx;
    if (direction) map_syncs[direction]++;
    return adreno_resource_cache(token, direction, sp_hvc, 0);
}
#if ADRENO_CACHE_SPARSE
static struct adreno_cache_mark sp_marks[IB_FIXTURES];                 /* AdrenoMemoryMap::fCacheMark */
static struct adreno_cache_mark *sp_mark(void *ctx, void *token)
{
    (void)ctx;
    struct ib_fixture *f = ibfx_of(token);
    CHECK(f != 0);
    return f ? &sp_marks[f - ibfx] : 0;
}
/* AdrenoMemoryMap::cacheRange. */
static int sp_sync_range(void *ctx, void *token, unsigned direction, uint64_t offset, uint64_t bytes)
{
    (void)ctx;
    return adreno_resource_cache_range(token, direction, offset, bytes, sp_hvc, 0);
}
static const struct adreno_cache_ops sp_cache_ops = {sp_mark, sp_sync_range};   /* AdrenoSegmentList::kCacheOps */
#endif
static const struct adreno_resource_list_ops sp_ops = {0, ibfx_retain, ibfx_release, ibfx_prepare, ibfx_complete, sp_sync};

/* ---- speculation: the CPU may fill any line of cacheable memory at any time (Arm ARM, Normal memory), including
 * between a TO_DEVICE clean and the GPU's write. Every doorbell below first reads every fixture line into the CPU
 * cache, so a GPU write is only visible to a later CPU read through a FROM_DEVICE that ran after it. */
static void spec_all(void)
{
    for (unsigned i = 0; i < ibfx_count; i++)
        for (uint64_t o = 0; o < ibfx[i].res.length; o += 64) (void)m_rd(0, ibfx[i].pa + o);
}
static int sp_ring(void *ctx, uint64_t va, uint64_t dwords, uint64_t bytes, struct adreno_ib_reply *reply)
{
    spec_all();
    return ib_ring(ctx, va, dwords, bytes, reply);
}
static int sp_fill_transfer(void *ctx, uint64_t address, uint64_t bytes, uint32_t pattern)
{
    spec_all();
    return ib_fill_transfer(ctx, address, bytes, pattern);
}
static int sp_fence_work(void *ctx)
{
    spec_all();
    return ib_fence_work(ctx);
}

/* ---- AdrenoCommandQueue/AdrenoAcceleratorX2 call sites ----------------------------------------------------- */
struct sp_submission { struct adreno_resource_list *list; const struct adreno_fill32_request *fill; const void *command; uint64_t bytes; };
static int sp_gated_fence(void *c)
{
    struct sp_submission *s = c;
#if ADRENO_CACHE_SPARSE
    static const struct adreno_cache_scope none = {ADRENO_CACHE_SCOPE_NONE, 0, 0, 0};   /* AdrenoSegmentList::submit */
    return adreno_resource_list_submit_scope(s->list, &sp_ops, sp_fence_work, 0, &none);
#else
    return adreno_resource_list_submit(s->list, &sp_ops, sp_fence_work, 0);
#endif
}
static int sp_gated_fill(void *c) { struct sp_submission *s = c; return adreno_fill32_submit(s->list, &sp_ops, s->fill, ibfx_resolve_fill, sp_fill_transfer, 0); }
static int sp_gated_ib(void *c) { struct sp_submission *s = c; return adreno_ib_submit(&ib_work, s->list, &sp_ops, s->command, s->bytes, ibfx_resolve, sp_ring, 0); }
static int sp_k_fence(void *c) { struct sp_submission s = {c, 0, 0, 0}; return adreno_submit_gated(&ib_latch, sp_gated_fence, &s); }
static int sp_k_fill(void *c, const struct adreno_fill32_request *r) { struct sp_submission s = {c, r, 0, 0}; return adreno_submit_gated(&ib_latch, sp_gated_fill, &s); }
static int sp_k_ib(void *c, const void *command, uint64_t bytes) { struct sp_submission s = {c, 0, command, bytes}; return adreno_submit_gated(&ib_latch, sp_gated_ib, &s); }
static int sp_command(struct adreno_resource_list *list, const void *command, uint64_t bytes)
{
    const struct adreno_kernel_ops kops = {list, sp_k_fence, sp_k_fill, sp_k_ib};
    int result = adreno_kernel_command(command, bytes, &kops);
    if (result == ADRENO_SUBMIT_E_UNCERTAIN || result == ADRENO_LIST_E_VISIBILITY) adreno_resource_list_freeze(list);
    return result;
}

/* ---- kernel commands as the plug-in writes them ------------------------------------------------------------ */
static uint8_t sp_cmd[0x2000];
static int sp_fence(struct adreno_resource_list *list)
{
    const struct adreno_submit_header h = {ADRENO_KCMD_FENCE, sizeof h};
    memcpy(sp_cmd, &h, sizeof h);
    return sp_command(list, sp_cmd, sizeof h);
}
static int sp_fill(struct adreno_resource_list *list, uint32_t id, uint64_t offset, uint64_t bytes, uint32_t pattern)
{
    unsigned char c[32];
    put32(c, ADRENO_KCMD_FILL32); put32(c + 4, 32); put32(c + 8, id); put32(c + 12, pattern);
    put64(c + 16, offset); put64(c + 24, bytes);
    return sp_command(list, c, sizeof c);
}
/* One CP_MEMCPY of `bytes` from (src, soff) to (dst, doff), the copy the plug-in stages UBOs with. */
static int sp_copy(struct adreno_resource_list *list, uint32_t src, uint64_t soff, uint32_t dst, uint64_t doff, uint32_t bytes)
{
    struct ib_pkg k;
    memset(&k, 0, sizeof k);
    pk_pkt7(&k, A8XX_E_CP_MEMCPY, 5);
    const uint32_t at = k.n;
    pk_word(&k, bytes / 4); pk_word(&k, 0); pk_word(&k, 0); pk_word(&k, 0); pk_word(&k, 0);
    pk_reloc(&k, at + 1, at + 2, ADRENO_IB_RELOC_RESOURCE, ADRENO_IB_ACCESS_READ, 2, 32, src, soff, bytes);
    pk_reloc(&k, at + 3, at + 4, ADRENO_IB_RELOC_RESOURCE, ADRENO_IB_ACCESS_WRITE, 2, 32, dst, doff, bytes);
    size_t n = pk_serialize(&k, sp_cmd);
    return sp_command(list, sp_cmd, n);
}

/* ---- fixtures ---------------------------------------------------------------------------------------------- */
static struct ib_fixture *fx(uint32_t id)
{
    for (unsigned i = 0; i < ibfx_count; i++) if (ibfx[i].id == id) return &ibfx[i];
    return 0;
}
/* ibfx_add seeds the fixture's DRAM from the device side, under the CPU lines setup_fill planted: drop those clean
 * lines so the CPU's view starts coherent, as freshly initialized kernel pages are. (Unsparse, every kernel command
 * invalidated whole maps and hid that artifact.) */
static struct ib_fixture *sp_add(uint32_t id, uint64_t va, uint64_t length)
{
    struct ib_fixture *f = ibfx_add(id, va, length);
    if (f) for (uint64_t o = 0; o < f->res.length; o += 64) {
        uint64_t line = ram_offset(f->pa + o, 1) / 64;
        CHECK(!dirty[line]);
        cached[line] = 0;
    }
    return f;
}
/* A second map of fixture `of`'s pages at another GPU address (an IOSurface another process or resource maps). */
static struct ib_fixture *sp_alias(uint32_t id, uint64_t va, uint32_t of)
{
    struct ib_fixture *o = fx(of);
    if (!o || ibfx_count >= IB_FIXTURES) return 0;
    struct ib_fixture *f = &ibfx[ibfx_count++];
    *f = (struct ib_fixture){id, o->res, o->pa, 0, 0};
    f->res.address = va;
    ib_map(va, o->pa, (unsigned)(o->res.length / 0x4000), 0);
    return f;
}
static void cpu_fill(uint32_t id, uint64_t offset, uint64_t bytes, uint32_t seed)
{
    struct ib_fixture *f = fx(id);
    for (uint64_t o = 0; o < bytes; o += 4) m_wr(0, f->pa + offset + o, seed + (uint32_t)o);
}
static int cpu_equals(uint32_t id, uint64_t offset, uint64_t bytes, uint32_t seed)
{
    struct ib_fixture *f = fx(id);
    for (uint64_t o = 0; o < bytes; o += 4) if (m_rd(0, f->pa + offset + o) != seed + (uint32_t)o) return 0;
    return 1;
}
static void cpu_touch(uint32_t id, uint64_t bytes)       /* the CPU reads: its cache now holds these lines */
{
    struct ib_fixture *f = fx(id);
    for (uint64_t o = 0; o < bytes; o += 64) (void)m_rd(0, f->pa + o);
}
static void count_reset(void)
{
    memset(&hv, 0, sizeof hv); memset(map_syncs, 0, sizeof map_syncs);
}
static void sp_setup(void)
{
    ib_setup();
    count_reset();
#if ADRENO_CACHE_SPARSE
    memset(sp_marks, 0, sizeof sp_marks);
#endif
}
/* AdrenoSegmentList::initWithSharedResourceList: acquire, prepare, and (sparse) the list's cache callbacks. */
static int sp_list(struct adreno_resource_list *list, struct adreno_resource_entry *slots, const uint32_t *ids,
                   const uint16_t *usages, unsigned n)
{
    int e = ib_list_make(list, slots, ids, usages, n);
#if ADRENO_CACHE_SPARSE
    list->cache = &sp_cache_ops;
#endif
    return e;
}
static void sp_done(struct adreno_resource_list *list)
{
    CHECK(adreno_resource_list_release(list, &sp_ops) == 0);
}
#define SRC 0x21u
#define DST 0x22u
#define DST2 0x23u
#define AUX 0x24u
#define VA(n) (ADRENO_WINDOW_BASE + 0x1000000ull + 0x100000ull * (n))
#define R ADRENO_USAGE_READ
#define RW (ADRENO_USAGE_READ | ADRENO_USAGE_WRITE)
static struct adreno_resource_entry slots_a[IB_REPLAY_CAPACITY], slots_b[IB_REPLAY_CAPACITY];

/* C13/C9: a fence lets the GPU touch no list entry. Sparse: no HVC; an entry that lost its backing still refuses. */
static void test_fence_scope(void)
{
    sp_setup();
    CHECK(sp_add(SRC, VA(0), 0x4000) && sp_add(DST, VA(1), 0x4000));
    struct adreno_resource_list l;
    static const uint32_t ids[] = {SRC, DST}; static const uint16_t us[] = {R, RW};
    CHECK(sp_list(&l, slots_a, ids, us, 2) == 0);
    cpu_fill(SRC, 0, 0x4000, 0x11000000);
    count_reset();
    CHECK(sp_fence(&l) == 0);
#if ADRENO_CACHE_SPARSE
    CHECK(hv.calls[1] == 0 && hv.calls[2] == 0);
#else
    CHECK(hv.calls[1] == 2 && hv.calls[2] == 1 && hv.bytes[1] == 0x8000);
#endif
    fx(DST)->res.mapped_length = 0;                      /* the map lost its complete mapping */
    CHECK(sp_fence(&l) == ADRENO_LIST_E_CACHE);
    fx(DST)->res.mapped_length = fx(DST)->res.length;
    sp_done(&l);
}
/* C1a: CPU data written before a fence-only command buffer reaches the GPU in a later command buffer's IB. */
static void test_stale_read_fence_first(void)
{
    sp_setup();
    CHECK(sp_add(SRC, VA(0), 0x4000) && sp_add(DST, VA(1), 0x4000));
    static const uint32_t ids[] = {SRC, DST}; static const uint16_t us[] = {R, RW};
    struct adreno_resource_list a, b;
    cpu_fill(SRC, 0, 0x4000, 0x12000000);
    CHECK(sp_list(&a, slots_a, ids, us, 2) == 0);
    CHECK(sp_fence(&a) == 0);
    sp_done(&a);
    CHECK(sp_list(&b, slots_b, ids, us, 2) == 0);
    CHECK(sp_copy(&b, SRC, 0, DST, 0, 0x4000) == 0);
    CHECK(sp_fence(&b) == 0);
    CHECK(cpu_equals(DST, 0, 0x4000, 0x12000000));
    sp_done(&b);
}
/* C1a/C13: FILL32 then an IB in one list; the fill maintains only its own range. */
static void test_stale_read_fill_then_ib(void)
{
    sp_setup();
    CHECK(sp_add(SRC, VA(0), 0x4000) && sp_add(DST, VA(1), 0x4000) && sp_add(DST2, VA(2), 0x4000));
    static const uint32_t ids[] = {SRC, DST, DST2}; static const uint16_t us[] = {R, RW, RW};
    struct adreno_resource_list l;
    cpu_fill(SRC, 0, 0x4000, 0x13000000);
    CHECK(sp_list(&l, slots_a, ids, us, 3) == 0);
    count_reset();
    CHECK(sp_fill(&l, DST, 0x100, 0x200, 0xfeedf00d) == 0);
#if ADRENO_CACHE_SPARSE
    CHECK(hv.calls[1] == 1 && hv.bytes[1] == 0x200 && hv.calls[2] == 1 && hv.bytes[2] == 0x200);
#else
    CHECK(hv.calls[1] == 3 && hv.bytes[1] == 0xc000 && hv.calls[2] == 2 && hv.bytes[2] == 0x8000);
#endif
    count_reset();
    CHECK(sp_copy(&l, SRC, 0, DST2, 0, 0x4000) == 0);
    CHECK(hv.calls[1] == 3 && hv.bytes[1] == 0xc000 && hv.calls[2] == 2);   /* the IB still owns every map */
    count_reset();
    CHECK(sp_fence(&l) == 0);
#if ADRENO_CACHE_SPARSE
    CHECK(hv.calls[1] + hv.calls[2] == 0);
#endif
    CHECK(cpu_equals(DST2, 0, 0x4000, 0x13000000));
    for (uint64_t o = 0; o < 0x4000; o += 4)
        CHECK(m_rd(0, fx(DST)->pa + o) == (o >= 0x100 && o < 0x300 ? 0xfeedf00du : 0x69696969u));
    sp_done(&l);
}
/* C1c: a FILL32 range clean does not count as cleaning the map; CPU bytes outside it reach the next IB. */
static void test_partial_clean_no_mark(void)
{
    sp_setup();
    CHECK(sp_add(SRC, VA(0), 0x4000) && sp_add(DST, VA(1), 0x4000));
    static const uint32_t ids[] = {SRC, DST}; static const uint16_t us[] = {RW, RW};
    struct adreno_resource_list l;
    cpu_fill(SRC, 0, 0x4000, 0x14000000);
    CHECK(sp_list(&l, slots_a, ids, us, 2) == 0);
    CHECK(sp_fill(&l, SRC, 0, 64, 0xabababab) == 0);
    CHECK(sp_copy(&l, SRC, 0, DST, 0, 0x4000) == 0);
    CHECK(sp_fence(&l) == 0);
    for (uint64_t o = 0; o < 0x4000; o += 4)
        CHECK(m_rd(0, fx(DST)->pa + o) == (o < 64 ? 0xababababu : 0x14000000u + (uint32_t)o));
    sp_done(&l);
}
/* C1c/C6: epochs never repeat. List A cleans SRC; the CPU rewrites it; list B (A still prepared) sees the new bytes;
 * A re-prepared after completion (a new epoch, as a resident map reused by a later command buffer) cleans again. */
static void test_epoch_unique_across_lists(void)
{
    sp_setup();
    CHECK(sp_add(SRC, VA(0), 0x4000) && sp_add(DST, VA(1), 0x4000) && sp_add(DST2, VA(2), 0x4000));
    static const uint32_t ia[] = {SRC, DST}, ib_[] = {SRC, DST2}; static const uint16_t us[] = {R, RW};
    struct adreno_resource_list a, b;
    /* The same list re-prepared (a resident map in the next command buffer): it cleans again. */
    cpu_fill(SRC, 0, 0x4000, 0x05000000);
    CHECK(sp_list(&a, slots_a, ia, us, 2) == 0);
    CHECK(sp_copy(&a, SRC, 0, DST, 0, 0x4000) == 0);
    CHECK(sp_fence(&a) == 0);
    CHECK(adreno_resource_list_complete(&a, &sp_ops) == 0);
    cpu_fill(SRC, 0, 0x4000, 0x45000000);
    CHECK(adreno_resource_list_prepare(&a, &sp_ops) == 0);
    CHECK(sp_copy(&a, SRC, 0, DST, 0, 0x4000) == 0);
    CHECK(cpu_equals(DST, 0, 0x4000, 0x45000000));
    sp_done(&a);
    cpu_fill(SRC, 0, 0x4000, 0x15000000);
    CHECK(sp_list(&a, slots_a, ia, us, 2) == 0);
    CHECK(sp_copy(&a, SRC, 0, DST, 0, 0x4000) == 0);
    CHECK(cpu_equals(DST, 0, 0x4000, 0x15000000));
    cpu_fill(SRC, 0, 0x4000, 0x25000000);
    CHECK(sp_list(&b, slots_b, ib_, us, 2) == 0);
    CHECK(sp_copy(&b, SRC, 0, DST2, 0, 0x4000) == 0);
    CHECK(cpu_equals(DST2, 0, 0x4000, 0x25000000));
    CHECK(sp_fence(&b) == 0);
    sp_done(&b);
    CHECK(sp_fence(&a) == 0);
    CHECK(adreno_resource_list_complete(&a, &sp_ops) == 0);
    cpu_fill(SRC, 0, 0x4000, 0x35000000);
    CHECK(adreno_resource_list_prepare(&a, &sp_ops) == 0);
    count_reset();
    CHECK(sp_copy(&a, SRC, 0, DST, 0, 0x4000) == 0);
    CHECK(hv.calls[1] == 2);
    CHECK(cpu_equals(DST, 0, 0x4000, 0x35000000));
    sp_done(&a);
}
/* C2a/b: two IBs write DST; the CPU read in between refills its lines; after the second IB it sees the second copy. */
static void test_readback_two_ibs(void)
{
    sp_setup();
    CHECK(sp_add(SRC, VA(0), 0x4000) && sp_add(AUX, VA(3), 0x4000) && sp_add(DST, VA(1), 0x4000));
    static const uint32_t ids[] = {SRC, AUX, DST}; static const uint16_t us[] = {R, R, RW};
    struct adreno_resource_list l;
    cpu_fill(SRC, 0, 0x4000, 0x16000000);
    cpu_fill(AUX, 0, 0x4000, 0x26000000);
    cpu_touch(DST, 0x4000);                              /* stale lines before any GPU write */
    CHECK(sp_list(&l, slots_a, ids, us, 3) == 0);
    count_reset();
    CHECK(sp_copy(&l, SRC, 0, DST, 0, 0x4000) == 0);
    CHECK(hv.calls[1] == 3 && hv.calls[2] == 1);
    CHECK(cpu_equals(DST, 0, 0x4000, 0x16000000));       /* the CPU's cache now holds DST again */
    count_reset();
    CHECK(sp_copy(&l, AUX, 0, DST, 0, 0x4000) == 0);
#if ADRENO_CACHE_SPARSE
    CHECK(hv.calls[1] == 0 && hv.calls[2] == 1);         /* the list already owns every map; DST invalidated again */
#else
    CHECK(hv.calls[1] == 3 && hv.calls[2] == 1);
#endif
    CHECK(cpu_equals(DST, 0, 0x4000, 0x26000000));
    CHECK(sp_fence(&l) == 0);
    sp_done(&l);
}
/* C2c/C14: a fill of 8 bytes at offset 4; the stale line around it is invalidated whole. */
static void test_fill_readback_rounding(void)
{
    sp_setup();
    CHECK(sp_add(DST, VA(1), 0x4000));
    static const uint32_t ids[] = {DST}; static const uint16_t us[] = {RW};
    struct adreno_resource_list l;
    cpu_touch(DST, 0x4000);
    CHECK(sp_list(&l, slots_a, ids, us, 1) == 0);
    count_reset();
    CHECK(sp_fill(&l, DST, 4, 8, 0x5a5a5a5a) == 0);
#if ADRENO_CACHE_SPARSE
    CHECK(hv.calls[1] == 1 && hv.bytes[1] == 64 && hv.calls[2] == 1 && hv.bytes[2] == 64);
#else
    CHECK(hv.calls[1] == 1 && hv.bytes[1] == 0x4000 && hv.calls[2] == 1 && hv.bytes[2] == 0x4000);
#endif
    for (uint64_t o = 0; o < 0x4000; o += 4)
        CHECK(m_rd(0, fx(DST)->pa + o) == (o == 4 || o == 8 ? 0x5a5a5a5au : 0x69696969u));
    CHECK(sp_fill(&l, DST, 0x4000 - 4, 4, 0x77777777) == 0);       /* the last word: the last line */
    CHECK(m_rd(0, fx(DST)->pa + 0x3ffc) == 0x77777777u);
    CHECK(sp_fence(&l) == 0);
    sp_done(&l);
}
/* C7: duplicate entries [X R, Y R, X RW, X R]: one clean per map, one invalidate of X, and the GPU write is visible. */
static void test_dup_entries(void)
{
    sp_setup();
    CHECK(sp_add(DST, VA(1), 0x4000) && sp_add(SRC, VA(0), 0x4000));
    static const uint32_t ids[] = {DST, SRC, DST, DST}; static const uint16_t us[] = {R, R, RW, R};
    struct adreno_resource_list l;
    cpu_fill(SRC, 0, 0x4000, 0x17000000);
    cpu_touch(DST, 0x4000);
    CHECK(sp_list(&l, slots_a, ids, us, 4) == 0);
    count_reset();
    CHECK(sp_copy(&l, SRC, 0, DST, 0, 0x4000) == 0);
#if ADRENO_CACHE_SPARSE
    CHECK(hv.calls[1] == 2 && hv.calls[2] == 1);
#else
    CHECK(hv.calls[1] == 4 && hv.calls[2] == 1);
#endif
    CHECK(cpu_equals(DST, 0, 0x4000, 0x17000000));
    CHECK(sp_fence(&l) == 0);
    sp_done(&l);
}
/* C4: two maps of the same pages (an IOSurface in two processes) in two lists. */
static void test_alias_two_lists(void)
{
    sp_setup();
    CHECK(sp_add(SRC, VA(0), 0x4000) && sp_add(DST, VA(1), 0x4000) && sp_add(DST2, VA(2), 0x4000));
    CHECK(sp_alias(AUX, VA(3), SRC) != 0);
    static const uint32_t ia[] = {SRC, DST}, ib_[] = {AUX, DST2}, ic[] = {SRC, AUX, DST};
    static const uint16_t us[] = {R, RW}, uc[] = {R, R, RW};
    struct adreno_resource_list a, b;
    cpu_fill(SRC, 0, 0x4000, 0x18000000);
    CHECK(sp_list(&a, slots_a, ia, us, 2) == 0);
    CHECK(sp_copy(&a, SRC, 0, DST, 0, 0x4000) == 0);
    CHECK(cpu_equals(DST, 0, 0x4000, 0x18000000));
    cpu_fill(SRC, 0, 0x4000, 0x28000000);                /* the CPU writes the shared pages again */
    CHECK(sp_list(&b, slots_b, ib_, us, 2) == 0);
    CHECK(sp_copy(&b, AUX, 0, DST2, 0, 0x4000) == 0);
    CHECK(cpu_equals(DST2, 0, 0x4000, 0x28000000));
    CHECK(sp_fence(&b) == 0); sp_done(&b);
    CHECK(sp_fence(&a) == 0); sp_done(&a);
    cpu_fill(SRC, 0, 0x4000, 0x38000000);
    CHECK(sp_list(&a, slots_a, ic, uc, 3) == 0);         /* both aliases in one list */
    CHECK(sp_copy(&a, AUX, 0, DST, 0, 0x4000) == 0);
    CHECK(cpu_equals(DST, 0, 0x4000, 0x38000000));
    CHECK(sp_fence(&a) == 0); sp_done(&a);
}
/* C10: a CPU store after commit, between two IBs of one command buffer: a data race. Today the second IB's clean
 * publishes it; sparse reads the old memory. Either way it stays in this list's own map. */
static void test_racy_write_documented(void)
{
    sp_setup();
    CHECK(sp_add(SRC, VA(0), 0x4000) && sp_add(DST, VA(1), 0x4000) && sp_add(DST2, VA(2), 0x4000));
    static const uint32_t ids[] = {SRC, DST, DST2}; static const uint16_t us[] = {R, RW, RW};
    struct adreno_resource_list l;
    cpu_fill(SRC, 0, 0x4000, 0x19000000);
    CHECK(sp_list(&l, slots_a, ids, us, 3) == 0);
    CHECK(sp_copy(&l, SRC, 0, DST, 0, 0x4000) == 0);
    cpu_fill(SRC, 0, 0x4000, 0x29000000);                /* racy: after commit, during GPU ownership */
    CHECK(sp_copy(&l, SRC, 0, DST2, 0, 0x4000) == 0);
#if ADRENO_CACHE_SPARSE
    CHECK(cpu_equals(DST2, 0, 0x4000, 0x19000000));
    CHECK(cpu_equals(SRC, 0, 0x4000, 0x29000000));       /* the racy store is still the CPU's, not lost */
#else
    CHECK(cpu_equals(DST2, 0, 0x4000, 0x29000000));
#endif
    CHECK(sp_fence(&l) == 0);
    sp_done(&l);
}
/* C14: the range helper's arithmetic against a 3 MiB map (no monitor: a counting callback). */
#if ADRENO_CACHE_SPARSE
static struct { unsigned n; uint64_t at[8], bytes[8]; } rc;
static int rc_cb(void *ctx, uint64_t address, uint64_t bytes, unsigned direction)
{
    (void)ctx; (void)direction;
    if (rc.n < 8) { rc.at[rc.n] = address; rc.bytes[rc.n] = bytes; }
    rc.n++;
    return 0;
}
#endif
static void test_range_arithmetic(void)
{
#if ADRENO_CACHE_SPARSE
    const uint64_t va = ADRENO_WINDOW_BASE + 0x2000000;
    struct adreno_resource r = {va, 0x300000, 0x2ff000, 0x300000, ADRENO_RESOURCE_RESERVED | ADRENO_RESOURCE_PINNED};
    memset(&rc, 0, sizeof rc);
    CHECK(adreno_resource_cache_range(&r, ADRENO_CACHE_TO_DEVICE, 4, 8, rc_cb, 0) == 0 && rc.n == 1 &&
          rc.at[0] == va && rc.bytes[0] == 64);
    memset(&rc, 0, sizeof rc);
    CHECK(adreno_resource_cache_range(&r, ADRENO_CACHE_FROM_DEVICE, 0x2ff000 - 1, 1, rc_cb, 0) == 0 && rc.n == 1 &&
          rc.at[0] == va + 0x2ff000 - 64 && rc.bytes[0] == 64);
    memset(&rc, 0, sizeof rc);
    CHECK(adreno_resource_cache_range(&r, ADRENO_CACHE_TO_DEVICE, 0x40, 0x180000, rc_cb, 0) == 0 && rc.n == 2 &&
          rc.at[0] == va + 0x40 && rc.bytes[0] == ADRENO_CACHE_MAX_BYTES &&
          rc.at[1] == va + 0x40 + ADRENO_CACHE_MAX_BYTES && rc.bytes[1] == 0x80000);
    memset(&rc, 0, sizeof rc);
    CHECK(adreno_resource_cache_range(&r, ADRENO_CACHE_TO_DEVICE, 0x2ff000, 4, rc_cb, 0) == ADRENO_RESOURCE_E_RANGE);
    CHECK(adreno_resource_cache_range(&r, ADRENO_CACHE_TO_DEVICE, 0, 0, rc_cb, 0) == ADRENO_RESOURCE_E_RANGE);
    CHECK(adreno_resource_cache_range(&r, ADRENO_CACHE_TO_DEVICE, 8, UINT64_MAX - 4, rc_cb, 0) == ADRENO_RESOURCE_E_RANGE);
    CHECK(adreno_resource_cache_range(&r, 3, 0, 64, rc_cb, 0) == ADRENO_RESOURCE_E_STATE);
    CHECK(adreno_resource_cache_range(&r, 0, 0, 64, rc_cb, 0) == 0 && rc.n == 0);   /* direction 0 validates only */
    r.mapped_length = 0;
    CHECK(adreno_resource_cache_range(&r, ADRENO_CACHE_TO_DEVICE, 0, 64, rc_cb, 0) == ADRENO_RESOURCE_E_STATE);
    CHECK(rc.n == 0);
#endif
}

/* ---- maintenance volume: one command buffer shaped like the A16 run's, today and sparse ---------------------
 * The plug-in's commit (AdrenoCommandBuffer.m adrenoCommit): FILL32s, IB packages, then the FENCE, all against one
 * list. Here: 12 maps (one 64 KiB render target written, 9 read 16 KiB textures, one 16 KiB staging arena written
 * by CP_MEMCPY, one read buffer listed twice with different usage), one clear fill, two packages, one fence. */
static void volume(void)
{
    sp_setup();
    uint32_t ids[14]; uint16_t us[14]; unsigned n = 0;
    CHECK(sp_add(0x40, VA(0), 0x10000) != 0); ids[n] = 0x40; us[n++] = RW;          /* render target */
    for (unsigned i = 0; i < 9; i++) { CHECK(sp_add(0x41 + i, VA(1 + i), 0x4000) != 0); ids[n] = 0x41 + i; us[n++] = R; }
    CHECK(sp_add(0x50, VA(10), 0x4000) != 0); ids[n] = 0x50; us[n++] = RW;           /* staging arena */
    CHECK(sp_add(0x51, VA(11), 0x4000) != 0); ids[n] = 0x51; us[n++] = R;            /* app buffer */
    ids[n] = 0x51; us[n++] = RW;                                                        /* widened later */
    for (unsigned i = 0; i < 9; i++) cpu_fill(0x41 + i, 0, 0x4000, 0x60000000 + (i << 16));
    cpu_fill(0x51, 0, 0x4000, 0x70000000);
    struct adreno_resource_list l;
    CHECK(sp_list(&l, slots_a, ids, us, n) == 0);
    count_reset();
    CHECK(sp_fill(&l, 0x40, 0, 0x4000, 0) == 0);
    CHECK(sp_copy(&l, 0x51, 0, 0x50, 0, 0x1000) == 0);
    CHECK(sp_copy(&l, 0x50, 0, 0x40, 0x4000, 0x1000) == 0);
    CHECK(sp_fence(&l) == 0);
    CHECK(cpu_equals(0x40, 0x4000, 0x1000, 0x70000000));
    printf("volume: one command buffer (FILL32, 2 IBs, FENCE; 12 maps 240 KiB, 13 entries 256 KiB, 96 KiB written): "
           "TO_DEVICE %u calls %llu KiB, FROM_DEVICE %u calls %llu KiB (sparse %d)\n",
           hv.calls[1], (unsigned long long)(hv.bytes[1] >> 10), hv.calls[2], (unsigned long long)(hv.bytes[2] >> 10),
           ADRENO_CACHE_SPARSE);
#if ADRENO_CACHE_SPARSE
    /* fill: its 16 KiB both ways; IB1: every map once (240 KiB), the 3 written maps (96 KiB); IB2: the written maps */
    CHECK(hv.bytes[1] == 0x4000 + 0x3c000 && hv.bytes[2] == 0x4000 + 2 * 0x18000);
#else
    /* each of the 4 kernel commands: every entry (256 KiB), every Write entry (96 KiB) */
    CHECK(hv.bytes[1] == 4 * 0x40000 && hv.bytes[2] == 4 * 0x18000);
#endif
    sp_done(&l);
}

/* ---- read-only replay of recorded plug-in command buffers ----------------------------------------------------
 * DIR/list.bin (the IOGPU segment resource list), DIR/commands.bin (the kernel commands), DIR/resources.txt ("id va
 * length"), optional DIR/resource-ID.initial.bin (written by the CPU before the commit, as the capture tools do).
 * Every kernel command runs through the kext call sites above; nothing is written to DIR. Per directory: the
 * kernel commands, results, maintenance bytes, and an FNV-1a digest of every fixture's bytes as the CPU reads them
 * after the last command (the "pixels": it must be the same with and without ADRENO_CACHE_SPARSE). */
static struct { uint64_t dirs, skipped, commands[3], to, from, to_calls, from_calls; } rt;
static void replay_dir(const char *dir)
{
    size_t list_bytes, command_bytes, fixtures_bytes;
    uint8_t *wire = read_all(dir, "list.bin", &list_bytes, 0);
    uint8_t *commands = read_all(dir, "commands.bin", &command_bytes, 0);
    char *fixtures = (char *)read_all(dir, "resources.txt", &fixtures_bytes, 0);
    if (!wire || !commands || !fixtures) { printf("replay %s: skipped (no list/commands/resources)\n", dir); rt.skipped++; goto out; }
    sp_setup();
    for (char *line = strtok(fixtures, "\n"); line; line = strtok(0, "\n")) {
        unsigned long long id, va, length;
        if (sscanf(line, "%llx %llx %llx", &id, &va, &length) != 3 || !sp_add((uint32_t)id, va, length)) {
            printf("replay %s: skipped (fixture %s does not fit the model)\n", dir, line); rt.skipped++; goto out;
        }
    }
    for (unsigned i = 0; i < ibfx_count; i++) {
        char name[80]; size_t bytes;
        snprintf(name, sizeof name, "resource-%x.initial.bin", ibfx[i].id);
        uint8_t *blob = read_all(dir, name, &bytes, 0);
        if (blob && bytes == ibfx[i].res.logical_length && !(bytes & 3))
            for (size_t o = 0; o < bytes; o += 4) { uint32_t v; memcpy(&v, blob + o, 4); m_wr(0, ibfx[i].pa + o, v); }
        free(blob);
    }
    static uint8_t copy[32 + 64 * ADRENO_LIST_MAX_GROUPS];
    static struct adreno_resource_entry entries[IB_REPLAY_CAPACITY];
    struct adreno_resource_list list = {0};
    uint64_t snapshot = 0, capacity = 0;
    if (adreno_resource_list_measure(wire, list_bytes, &snapshot, &capacity) || capacity > IB_REPLAY_CAPACITY ||
        adreno_resource_list_acquire(&list, wire, list_bytes, copy, sizeof copy, entries, IB_REPLAY_CAPACITY, &sp_ops) ||
        adreno_resource_list_prepare(&list, &sp_ops)) {
        printf("replay %s: skipped (list refused)\n", dir); rt.skipped++; goto out;
    }
#if ADRENO_CACHE_SPARSE
    list.cache = &sp_cache_ops;
#endif
    count_reset();
    char kinds[256] = ""; size_t k = 0;
    for (size_t at = 0; at + 8 <= command_bytes;) {
        uint32_t type, size;
        memcpy(&type, commands + at, 4); memcpy(&size, commands + at + 4, 4);
        if (size < 8 || size % 4 || size > command_bytes - at) break;
        int result = sp_command(&list, commands + at, size);
        const char *t = type == ADRENO_KCMD_FENCE ? "F" : type == ADRENO_KCMD_FILL32 ? "C" : type == ADRENO_KCMD_IB ? "I" : "?";
        if (k < sizeof kinds - 16) k += (size_t)snprintf(kinds + k, sizeof kinds - k, "%s%s%d", k ? " " : "", t, result);
        if (type >= ADRENO_KCMD_FENCE && type <= ADRENO_KCMD_IB) rt.commands[type - ADRENO_KCMD_FENCE]++;
        if (result && result != ADRENO_SUBMIT_GENERIC) break;
        at += size;
    }
    uint64_t digest = 1469598103934665603ull;
    for (unsigned i = 0; i < ibfx_count; i++)
        for (uint64_t o = 0; o < ibfx[i].res.logical_length; o += 4) {
            uint32_t v = m_rd(0, ibfx[i].pa + o);
            for (unsigned b = 0; b < 4; b++) { digest ^= (v >> (8 * b)) & 0xff; digest *= 1099511628211ull; }
        }
    printf("replay %s: entries %llu maps %u [%s] TO %u calls %llu B, FROM %u calls %llu B, digest %016llx\n", dir,
           (unsigned long long)list.count, ibfx_count, kinds, hv.calls[1], (unsigned long long)hv.bytes[1], hv.calls[2],
           (unsigned long long)hv.bytes[2], (unsigned long long)digest);
    rt.dirs++; rt.to += hv.bytes[1]; rt.from += hv.bytes[2]; rt.to_calls += hv.calls[1]; rt.from_calls += hv.calls[2];
    if (!(list.ready & ADRENO_LIST_FROZEN)) CHECK(adreno_resource_list_release(&list, &sp_ops) == 0);
out:
    free(wire); free(commands); free(fixtures);
}

int sparse_main(int argc, char **argv);
int sparse_main(int argc, char **argv)
{
    dram = calloc(1, RAM_SIZE); cache = calloc(1, RAM_SIZE);
    ib_arena = aligned_alloc(0x4000, ADRENO_IB_ARENA_BYTES);
    if (!dram || !cache || !ib_arena) return 2;
    checks = failures = 0;
    CHECK(adreno_ib_tables_init(&ib_tables) == 0);
    if (argc == 2 && !strcmp(argv[1], "--volume")) { volume(); return failures ? 1 : 0; }
    if (argc >= 3 && !strcmp(argv[1], "--replay")) {
        for (int i = 2; i < argc; i++) replay_dir(argv[i]);
        printf("replay total (sparse %d): %llu command buffers (%llu skipped), FENCE %llu FILL32 %llu IB %llu; "
               "TO_DEVICE %llu calls %llu B, FROM_DEVICE %llu calls %llu B\n", ADRENO_CACHE_SPARSE,
               (unsigned long long)rt.dirs, (unsigned long long)rt.skipped, (unsigned long long)rt.commands[0],
               (unsigned long long)rt.commands[1], (unsigned long long)rt.commands[2], (unsigned long long)rt.to_calls,
               (unsigned long long)rt.to, (unsigned long long)rt.from_calls, (unsigned long long)rt.from);
        return failures ? 1 : 0;
    }
    if (argc != 1) return 64;
    test_fence_scope(); test_stale_read_fence_first(); test_stale_read_fill_then_ib(); test_partial_clean_no_mark();
    test_epoch_unique_across_lists(); test_readback_two_ibs(); test_fill_readback_rounding(); test_dup_entries();
    test_alias_two_lists(); test_racy_write_documented(); test_range_arithmetic(); volume();
    printf("%s: %u cache ownership checks (sparse %d): fence/fill/IB scopes, stale GPU reads, readback, aliases, "
           "duplicates, epochs, racy store, range arithmetic\n", failures ? "FAIL" : "PASS", checks, ADRENO_CACHE_SPARSE);
    free(dram); free(cache); free(ib_arena);
    return failures ? 1 : 0;
}
