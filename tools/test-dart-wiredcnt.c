/* SPDX-License-Identifier: MIT */
/* SNAP_DART_WIREDCNT (compat/dart-wiredcnt.h): ADRENO_GUEST_UNMAP must leave
 * XNU's IOMMU table count exactly where t8110dart_unmap would.
 *
 * The SPTM DART model (compat/sptm-dart.c), the HVC (compat/adreno.c
 * adreno_guest_unmap with the SMMU mirror) and the decider run unchanged; XNU's
 * t8110dart side is a transcription of what 26A428 does with a leaf table's
 * count: map +(invalid->valid leaves), unmap -(valid leaves), iovmalloc and
 * iovmfree touching only the parent, the leaf table freed (T8110DART
 * UNMAP_TABLE) by iovmfree once its count is 0, and the int16
 * overflow/underflow panic of pmap_ref_iommu_table. Its descriptor chain is
 * laid out in guest RAM exactly as the decider follows it -- through vm_pages,
 * or for a table below vm_pages_first_pnum through vm_pages_radix_root -- under
 * template bodies whose ADRP and BL words really point at the globals and at
 * the radix function.
 *
 * Failure inventory: the v29 leak (rewires of the same IOVA overflow the
 * count -- reproduced without the fix); the v46 leak (a table below vm_pages
 * refused as unmanaged on every clear -- reproduced by the old decider, see
 * tools/test-dart-wiredcnt.py); the v40 one-time leak (the first clear of a
 * fresh table refused as LOW); a table freed through T8110DART UNMAP_TABLE,
 * which the monitor does not implement, once counts are exact (the held
 * reference keeps it, once, and a stale one is refused); a table no clear
 * touched keeping XNU's own lifecycle; a rewire to different pages; partial
 * clears over holes; XNU-path unmaps sharing the table; SPTM table and
 * data-frame references balanced; radix trees of 0..3 levels, including the
 * 32-bit shift; every refusal (template absent or ambiguous, VA alias,
 * globals, unmanaged above vm_pages, pvh, descriptor type/id, count pointer,
 * count too low, stale held reference, wrong walk, a commit race, and for the
 * radix path a changed call site, a changed radix function, pnum below
 * pmap_first_pnum, a null root, a zero node or page word, an unreadable root)
 * leaving the clear done, XNU memory byte-identical and the reason counted;
 * the templates matching the real 26A428 words and decoding the real globals.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra \
 *    -Werror -Icompat -Ishadow -I../q1n1/platform/uefi tools/test-dart-wiredcnt.c \
 *    compat/sptm-dart.c compat/sptm-refs.c compat/sptm.c compat/dart.c compat/device.c \
 *    compat/adreno.c compat/irq-forward.c compat/aes.c compat/aic.c compat/sep-pnon.c \
 *    compat/sep-xars.c compat/sep-sks-endpoint.c compat/sep-sks.c compat/watchdog.c \
 *    ../q1n1/platform/uefi/sha256.c -o build/test-dart-wiredcnt && build/test-dart-wiredcnt
 * -DDWC_PRE_CHANGE=1 serves the HVC without the bookkeeping (the v29 monitor):
 * the balance checks must then fail. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sptm-dart.h"
#include "sptm-refs.h"
#include "adreno.h"
#include "adreno-guest.h"
#include "dart-wiredcnt.h"
#ifndef DWC_PRE_CHANGE
#define DWC_PRE_CHANGE 0
#endif

#define BASE 0x8c0000000UL
#define SIZE 0x1000000UL                     /* 16 MiB of guest RAM */
#define FM (BASE + 0x4000)
#define ROOT (BASE + 0x40000)
#define LEAF (BASE + 0x44000)
#define LIST (BASE + 0x48000)
#define DATA (BASE + 0x400000)               /* 512 data frames: two page sets */
#define XNU (BASE + 0xd00000)                /* XNU's structures and text */
#define GPA (XNU)                            /* vm_first/last_phys, first_pnum, vm_pages */
#define GPB (XNU + 0x4000)                   /* vm_pages_count at +0x270 */
#define GPC (XNU + 0x8000)                   /* pmap_first_pnum at +0x5f0 */
#define GPD (XNU + 0xc000)                   /* vm_pages_radix_root at +0x300 */
#define PTD (XNU + 0x10000)
#define INFO (XNU + 0x10400)
#define RPAGE (XNU + 0x10800)                /* the vm_page the radix tree names */
#define RNODE (XNU + 0x11000)                /* five 1 KiB radix nodes */
#define VMP (XNU + 0x14000)                  /* vm_pages[1024], 64 KiB */
#define TEXT (XNU + 0x24000)                 /* 0x8000 bytes of "kernel text" */
#define TEXT_WORDS 0x2000u
#define XNU_END (XNU + 0x2c000)
#define KVA 0xfffffe0010000000UL             /* VA of BASE */
#define VA(pa) (KVA + ((pa) - BASE))
#define ID 31u
#define PAGES 256u
static uint8_t ram[SIZE];
static struct dart_state state;
static struct sptm_ref_batch refs;
static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; printf("FAIL %d: %s\n", __LINE__, #x); } } while (0)
static uint8_t *meta(uint64_t pa) { return ram + (FM - BASE) + ((pa - BASE) >> 14) * 16; }
static uint64_t get(uint64_t pa) { uint64_t v; memcpy(&v, ram + (pa - BASE), 8); return v; }
static void put(uint64_t pa, uint64_t v) { memcpy(ram + (pa - BASE), &v, 8); }
static uint16_t get16(uint64_t pa) { uint16_t v; memcpy(&v, ram + (pa - BASE), 2); return v; }
static void put16(uint64_t pa, uint16_t v) { memcpy(ram + (pa - BASE), &v, 2); }
static void put32(uint64_t pa, uint32_t v) { memcpy(ram + (pa - BASE), &v, 4); }
static volatile uint8_t *map(void *ctx, uint64_t pa, uint64_t n)
{ return ctx == ram && pa >= BASE && pa < BASE + SIZE && n && n <= BASE + SIZE - pa ? ram + (pa - BASE) : 0; }
static void publish(void *ctx, uint64_t pa, uint64_t n) { CHECK(map(ctx, pa, n) != 0); }
static struct sptm_memory mem;

/* The real 26A428 words (kernelcache.release.mac17p). */
static const uint32_t real[DWC_TEMPLATE_WORDS] = {      /* pmap_ref_iommu_table */
    0xd503237f, 0xd10183ff, 0xa90357f6, 0xa9044ff4, 0xa9057bfd, 0x910143fd, 0xaa0103f4,
    0xaa0003f3, 0xf0fe1da8, 0xf940f908, 0xf0fe1da9, 0xf940fd29, 0xeb08005f, 0xfa492042,
    0x54000a02, 0xaa0303f5, 0xd34efc40, 0xf0fe1da8, 0xb9400108, 0x90fe1949, 0xb9427129,
    0x0b080129, 0x6b00013f, 0x540003c9, 0x6b080008, 0x54000523, 0xf0fe1da9, 0xf9400929,
    0x8b081920, 0xf9401808, 0x92400909, 0xf1000d3f, 0x540002e1, 0x927df108, 0xd2ec9809,
    0xaa090108, 0xf9400109, 0x53037d2a, 0xd34bfd29, 0x6b2a027f, 0x7a490280, 0x540003a1,
    0xf9400909, 0x78350129, 0x0b29a2aa, 0x6b2aa15f, 0x54000461, 0x13003d20, 0xa9457bfd,
};
#define REAL_VA 0xfffffe000ba755d4UL
static const uint32_t real_call[4] = {0xaa0203f6, 0x97fe7543, 0xaa1603e2, 0x17ffffd8};   /* words 66..69 */
#define REAL_RADIX_VA 0xfffffe000ba12becUL                                              /* its BL target */
static const uint32_t real_radix_adrp[4] = {0xd0fe1c68, 0xb945f108, 0xf0fe1c49, 0xf9418129}; /* words 1,2,5,6 */

static uint32_t adrp(unsigned rd, uint64_t pc, uint64_t target)
{
    int64_t pages = (int64_t)((target & ~0xfffUL) - (pc & ~0xfffUL)) / 4096;
    uint64_t imm = (uint64_t)pages & 0x1fffff;
    return 0x90000000u | (uint32_t)((imm & 3) << 29) | (uint32_t)((imm >> 2) << 5) | rd;
}
static uint32_t bl(uint64_t pc, uint64_t target)
{
    return 0x94000000u | (uint32_t)(((int64_t)(target - pc) / 4) & 0x3ffffff);
}
#define FUNC_INDEX 1000u                     /* word index of the body in TEXT */
#define RADIX_INDEX 5000u                    /* word index of vm_page_find_canonical_radix */
static uint64_t root_target = GPD;           /* where the radix ADRP+LDR points */
static void place_radix(uint64_t at_index)
{
    uint64_t va = VA(TEXT) + 4 * at_index;
    uint32_t w[DWC_RADIX_WORDS];
    memcpy(w, dwc_radix_value, sizeof(w));
    w[DWC_RADIX_MIN] = adrp(8, va + 4 * DWC_RADIX_MIN, VA(GPC));
    w[DWC_RADIX_ROOT] = root_target == GPD ? adrp(9, va + 4 * DWC_RADIX_ROOT, VA(GPD))
                                           : adrp(9, va + 4 * DWC_RADIX_ROOT, root_target);
    memcpy(ram + (TEXT - BASE) + 4 * at_index, w, sizeof(w));
}
static void place_template(uint64_t at_index)
{
    uint64_t va = VA(TEXT) + 4 * at_index;
    uint32_t w[DWC_CALL_AT + 4];
    for (unsigned i = 0; i < DWC_CALL_AT + 4; i++) w[i] = 0xd503201f;
    memcpy(w, dwc_value, sizeof(dwc_value));
    static const uint64_t targets[DWC_ADRP_WORDS] = {GPA, GPA, GPA, GPB, GPA};
    for (unsigned k = 0; k < DWC_ADRP_WORDS; k++) {
        unsigned a = dwc_globals_at[k][0];
        w[a] = adrp(w[a] & 31, va + 4 * a, VA(targets[k]));
    }
    memcpy(w + DWC_CALL_AT, dwc_call_value, sizeof(dwc_call_value));
    w[DWC_CALL_AT + 1] = bl(va + 4 * (DWC_CALL_AT + 1), VA(TEXT) + 4 * RADIX_INDEX);
    memcpy(ram + (TEXT - BASE) + 4 * at_index, w, sizeof(w));
}
static uint32_t pack(uint64_t pa) { return (uint32_t)((VA(pa) - DWC_PACKED_BASE) >> 6); }
static uint64_t pvh_of(void) { return (VA(PTD) & 0x9b3ffffffffffffcUL) | 0x0400000000000000UL | 3; }
#define LEAF_PNUM (LEAF >> 14)
/* vm_pages_radix_root for a tree of `levels` reaching LEAF at key. */
static void radix_tree(unsigned levels, uint32_t key)
{
    memset(ram + (RNODE - BASE), 0, 0x1400);
    put32(GPC + 0x5f0, (uint32_t)(LEAF_PNUM - key));                /* pmap_first_pnum */
    put(GPD + 0x300, VA(RNODE + 0x400 * levels) | levels);
    for (unsigned level = levels; level; level--)
        put32(RNODE + 0x400 * level + 4 * ((key >> ((8 * level) & 31)) & 0xff), pack(RNODE + 0x400 * (level - 1)));
    put32(RNODE + 4 * (key & 0xff), pack(RPAGE));
}
static int radix;                            /* LEAF below vm_pages_first_pnum */
static void xnu_layout(void)
{
    memset(ram + (XNU - BASE), 0, XNU_END - XNU);
    for (unsigned i = 0; i < TEXT_WORDS; i++) put32(TEXT + 4 * i, 0xd503201f);    /* nop */
    root_target = GPD;
    place_template(FUNC_INDEX);
    place_radix(RADIX_INDEX);
    put(GPA + 0x1f0, BASE);                         /* vm_first_phys */
    put(GPA + 0x1f8, BASE + SIZE);                  /* vm_last_phys */
    put32(GPA + 0, (uint32_t)(radix ? LEAF_PNUM + 1 : BASE >> 14));  /* vm_pages_first_pnum */
    put32(GPB + 0x270, SIZE >> 14);                 /* vm_pages_count */
    put(GPA + 0x10, VA(VMP));                       /* vm_pages */
    /* pvh: the descriptor pointer with XNU's high flag bits recycled. */
    if (radix) { put(RPAGE + 0x30, pvh_of()); radix_tree(2, 0x10214); }
    else put(VMP + ((LEAF - BASE) >> 14) * 64 + 0x30, pvh_of());
    put(PTD, (uint64_t)DWC_IOMMU_TYPE << 3 | (uint64_t)ID << 11);
    put(PTD + 0x10, VA(INFO));
    put16(INFO, 0);
}

static struct sptm_memory memory(void)
{
    memset(ram, 0, SIZE); memset(&refs, 0, sizeof(refs));
    for (unsigned level = 1; level < 3; level++) {
        uint8_t e[16] = {0, 0, 24, 0, 0, 0, 5, 0, ID, 0, (uint8_t)level, 0, 0, 0, 0, 0};
        memcpy(meta(level == 1 ? ROOT : LEAF), e, 16);
    }
    for (unsigned i = 0; i < 2 * PAGES; i++) meta(DATA + i * 0x4000)[2] = 11;
    meta(LIST)[2] = 11;
    xnu_layout();
    return (struct sptm_memory){.frame_map_pa = FM, .frame_low = BASE, .frame_high = BASE + SIZE,
        .alloc_low = ROOT, .alloc_high = BASE + SIZE, .map = map, .publish = publish, .ctx = ram, .refs = &refs};
}
static void powered(void)
{
    dart_init(&state);
    state.initialized_ids = state.powered_ids = 1U << ID;
    state.tcr[0] = state.tcr[1] = 1;
}
/* The table under test: the window's first (slot 32), or with -DADRENO_VA_WIDE=1 slot 200 (6.25 GiB), past the
 * default bitmap's 128 slots (agents/gpu-va-wide V15). */
#ifndef DWC_TEST_VA
#if ADRENO_VA_WIDE
#define DWC_TEST_VA (200UL << 25)
#else
#define DWC_TEST_VA ADRENO_WINDOW_BASE
#endif
#endif
static uint64_t va0 = DWC_TEST_VA;
static void attach(void)                     /* t8110dart_iovmalloc creating the leaf table */
{
    CHECK(sptm_dart_map_table(&mem, &state, ID, 0, va0, 1, ROOT) == SPTM_OK);
    CHECK(sptm_dart_map_table(&mem, &state, ID, 0, va0, 2, LEAF) == SPTM_OK);
}

/* --- XNU's t8110dart bookkeeping for the leaf table, as 26A428 does it ----- */
static int overflowed, unmap_table;        /* XNU would call T8110DART UNMAP_TABLE */
static uint16_t count(void) { return get16(INFO); }
static void ref(int amount)                  /* pmap_ref_iommu_table */
{
    int16_t prior = (int16_t)count();
    int sum = prior + amount;
    if (sum != (int16_t)sum) { overflowed = 1; return; }     /* the v29/v46 panic */
    put16(INFO, (uint16_t)(int16_t)sum);
}
static uint64_t leaf_of(uint64_t iova) { return sptm_dart_leaf(&mem, &state, ID, 0, iova); }
static void xnu_map(uint64_t iova, unsigned n, unsigned set)
{
    unsigned added = 0;
    for (unsigned i = 0; i < n; i++) {
        added += !(leaf_of(iova + i * 0x4000ul) & 1);
        put(LIST + 8 * i, DATA + ((set * PAGES + (unsigned)((iova - va0) >> 14) + i) % (2 * PAGES)) * 0x4000ul);
    }
    CHECK(sptm_dart_map(&mem, &state, ID, 0, iova, LIST, n * 0x4000ul, 0) == SPTM_OK);
    ref((int)added);
}
static void xnu_unmap(uint64_t iova, unsigned n)
{
    unsigned removed = 0;
    for (unsigned i = 0; i < n; i++) removed += (unsigned)(leaf_of(iova + i * 0x4000ul) & 1);
    CHECK(sptm_dart_unmap(&mem, &state, ID, 0, iova, n * 0x4000ul, 2) == SPTM_OK);
    ref(-(int)removed);
}
static void xnu_iovmfree(void)               /* the leaf table's part of t8110dart_iovmfree */
{
    if (count() == 0) {
        for (unsigned i = 0; i < 2048; i++) CHECK(get(LEAF + 8 * i) == 0);  /* never with live leaves */
        unmap_table = 1;
    }
}

/* --- the HVC: adreno_guest_unmap with the monitor's unmap -------------------- */
#define ARENA 0xfcc00000UL
static uint8_t *arena;
static uint32_t o_rd(void *c, uint64_t pa)
{
    (void)c;
    if (pa == ADRENO_CX_CFG_GDSCR) return 1u << 16;
    if (pa == ADRENO_CB0 + ADRENO_CB_TLBSTATUS) return 0;
    abort();
}
static void o_wr(void *c, uint64_t pa, uint32_t v)
{
    (void)c; (void)v;
    if (pa != ADRENO_CB0 + ADRENO_CB_TLBSYNC && pa != ADRENO_CB0 + ADRENO_CB_TLBIASID) abort();
}
static uint64_t o_rd64(void *c, uint64_t pa) { (void)c; uint64_t v; memcpy(&v, arena + (pa - ARENA), 8); return v; }
static void o_wr64(void *c, uint64_t pa, uint64_t v) { (void)c; memcpy(arena + (pa - ARENA), &v, 8); }
static void o_clean(void *c, uint64_t pa, uint64_t n) { (void)c; (void)pa; (void)n; }
static uint64_t t;
static uint64_t o_now(void *c) { (void)c; return t += 10; }
static const struct adreno_ops gops = {0, o_rd, o_wr, o_rd64, o_wr64, o_clean, o_now, 0, 1000000, 0};
static struct adreno_params gp;
static struct adreno_state gs;

static uint64_t dstate[DWC_WORDS], dpins[DWC_PIN_WORDS];
#define SLOT (DWC_TEST_VA >> 25)
_Static_assert(SLOT < 64 * DWC_PIN_WORDS, "the pin bitmap covers the slot under test");
static uint64_t pins_sum(void) { uint64_t v = 0; for (unsigned i = 0; i < DWC_PIN_WORDS; i++) v += dpins[i]; return v; }
static uint64_t text_delta = KVA - BASE;
static int race_once;
static uint64_t w_kva(void *ctx, uint64_t va)
{
    (void)ctx;
    return va >= KVA && va < KVA + SIZE ? BASE + (va - KVA) : 0;
}
static uint64_t w_read(void *ctx, uint64_t pa, unsigned size)
{
    (void)ctx;
    CHECK(pa >= BASE && pa + size <= BASE + SIZE);
    uint64_t v = 0; memcpy(&v, ram + (pa - BASE), size); return v;
}
static int w_cas16(void *ctx, uint64_t pa, uint16_t expected, uint16_t desired)
{
    (void)ctx;
    if (race_once) { race_once = 0; put16(pa, 0); return 0; }   /* a concurrent XNU decrement */
    if (get16(pa) != expected) return 0;
    put16(pa, desired); return 1;
}
static uint64_t w_table_wrong;
static uint64_t w_table(void *ctx, uint64_t iova)
{
    (void)ctx;
    if (w_table_wrong) return w_table_wrong;
    uint64_t v = get(ROOT + 8 * ((iova >> 25) & 2047));
    return (v & 1) ? (v & 0x3ffffffc00UL) << 4 : 0;
}
static uint64_t w_leaf(void *ctx, uint64_t iova) { (void)ctx; return leaf_of(iova); }
static int w_unmap(void *ctx, uint64_t iova, uint64_t size)
{
    (void)ctx;
    return sptm_dart_unmap(&mem, &state, ID, 0, iova, size, 2);
}
static uint64_t hvc_leaf(void *ctx, uint64_t iova) { (void)ctx; return leaf_of(iova); }
static int plain;                            /* serve the HVC as the v29 monitor did */
static int hvc_unmap(void *ctx, uint64_t iova, uint64_t size)     /* probes/xnuboot.c gpu_unmap */
{
    if (DWC_PRE_CHANGE || plain) return w_unmap(ctx, iova, size);
    const struct dwc_ops o = {0, BASE, BASE + SIZE,
        (const volatile uint32_t *)(ram + (TEXT - BASE)), TEXT, TEXT_WORDS, text_delta, ID,
        w_kva, w_read, w_cas16, w_table, w_leaf, w_unmap};
    return dwc_unmap(&o, dstate, dpins, iova, size);
}
static int kext_clear(uint64_t iova, uint64_t size)                /* AdrenoMemoryMap::clearPages */
{
    uint64_t r[4] = {ADRENO_GUEST_UNMAP, iova, size, 0};
    int e = adreno_guest_unmap(&gops, &gp, &gs, r, hvc_leaf, hvc_unmap, 0, BASE, BASE + SIZE);
    CHECK(e == 0 && r[1] == size && r[2] == 0);
    return e;
}

static void start(void)
{
    mem = memory();
    powered();
    attach();
    memset(arena, 0, 32 << 20);
    gp = (struct adreno_params){.flags = ADRENO_F_ENABLE | ADRENO_F_DART, .arena_base = ARENA,
        .arena_size = 32 << 20, .pool_pa = ARENA + 0x1400000};
    gs = (struct adreno_state){.status = ADRENO_S_ADOPTED | ADRENO_S_ATTACHED};
    memset(dstate, 0, sizeof(dstate)); memset(dpins, 0, sizeof(dpins));
    overflowed = unmap_table = race_once = 0; w_table_wrong = 0; text_delta = KVA - BASE;
}
static int leaves_clear(uint64_t iova, unsigned n)
{
    for (unsigned i = 0; i < n; i++) if (leaf_of(iova + i * 0x4000ul)) return 0;
    return 1;
}
static int pinned(void) { return (int)((dpins[SLOT / 64] >> (SLOT % 64)) & 1); }
static int data_refs_clear(void)
{
    for (unsigned i = 0; i < 2 * PAGES; i++) {
        uint8_t *e = meta(DATA + i * 0x4000);
        for (unsigned b = 8; b < 16; b++) if (e[b]) return 0;
    }
    return 1;
}
static unsigned table_refs(void) { return meta(LEAF)[4] | (unsigned)meta(LEAF)[5] << 8; }

/* 1. The v29 leak and its fix: 200 unwire/rewire cycles of 256 pages, every
 * other cycle onto different physical pages, inserted 4 pages per call --
 * with the table in vm_pages and below it (the v46 table). */
static void test_cycles(int fix_expected)
{
    start();
    unsigned cycles = 200, worst = 0;
    for (unsigned c = 0; c < cycles && !overflowed; c++) {
        for (unsigned i = 0; i < PAGES; i += 4) xnu_map(va0 + i * 0x4000ul, 4, c & 1);
        if (count() > worst) worst = count();
        kext_clear(va0, PAGES * 0x4000ul);
        CHECK(leaves_clear(va0, PAGES));
    }
    if (!fix_expected) {                                   /* documents the bug */
        CHECK(overflowed);
        return;
    }
    CHECK(!overflowed);
    CHECK(count() == 1 && pinned());                       /* no leaves + the held reference */
    CHECK(worst == PAGES + 1);
    CHECK(dstate[DWC_COMMITS] == cycles && dstate[DWC_ENTRIES] == (uint64_t)cycles * PAGES);
    CHECK(dstate[DWC_REFUSALS] == 0);
    CHECK(dstate[DWC_LOCATED] == TEXT + 4 * FUNC_INDEX);
    CHECK(table_refs() == 1 && data_refs_clear());
    xnu_unmap(va0, PAGES);                                 /* freePages: iovmUnmapMemory */
    xnu_iovmfree();
    CHECK(count() == 1 && !unmap_table);                   /* the table stays, as before */
    xnu_map(va0, 4, 0);                                    /* a later reservation reuses it */
    kext_clear(va0, 4 * 0x4000ul);
    xnu_iovmfree();
    CHECK(count() == 1 && !unmap_table && pins_sum() == UINT64_C(1) << (SLOT % 64));
    CHECK(gs.live_pages == 0);
}

/* 2. The v40 refusal: the first clear of a fresh table whose valid leaves all
 * lie in the clear (count == n exactly) commits instead of leaking n. */
static void test_first_clear(void)
{
    start();
    xnu_map(va0, 16, 0);
    CHECK(count() == 16);
    kext_clear(va0, 16 * 0x4000ul);
    CHECK(count() == 1 && pinned() && dstate[DWC_COMMITS] == 1 && dstate[DWC_REFUSALS] == 0);
    xnu_map(va0, 16, 1);
    kext_clear(va0, 16 * 0x4000ul);
    CHECK(count() == 1 && dstate[DWC_COMMITS] == 2 && dstate[DWC_ENTRIES] == 32);
}

/* 3. Holes (a rolled-back insert), XNU-path unmaps and a second reservation. */
static void test_mixed(void)
{
    start();
    xnu_map(va0, 10, 0);                                   /* A: 10 of 16 pages */
    xnu_map(va0 + 0x200000, 8, 1);                         /* B, same table */
    CHECK(count() == 18);
    kext_clear(va0, 16 * 0x4000ul);                        /* A's clear over 6 holes */
    CHECK(count() == 8 + 1 && dstate[DWC_ENTRIES] == 10 && pinned());
    xnu_unmap(va0 + 0x200000, 4);                          /* half of B the XNU way */
    CHECK(count() == 4 + 1);
    kext_clear(va0 + 0x200000, 8 * 0x4000ul);              /* the rest of B: 4 valid */
    CHECK(count() == 1 && dstate[DWC_ENTRIES] == 14);      /* one held reference, not two */
    kext_clear(va0 + 0x200000, 8 * 0x4000ul);              /* again: nothing valid, no-op */
    CHECK(count() == 1 && dstate[DWC_COMMITS] == 2 && dstate[DWC_REFUSALS] == 0);
    xnu_iovmfree();                                        /* B goes: the table stays */
    CHECK(count() == 1 && !unmap_table);
    xnu_map(va0, 16, 1);                                   /* A rewired onto other pages */
    CHECK(count() == 17);
    kext_clear(va0, 16 * 0x4000ul);
    CHECK(count() == 1);
    xnu_iovmfree();
    CHECK(count() == 1 && !unmap_table && !overflowed);
    CHECK(table_refs() == 1 && data_refs_clear());
}

/* 4. Radix trees of 0..4 levels, the 32-bit shift included (level 4
 * indexes by the low byte again, as LSR Wd, Wn, Wm shifts by Wm mod 32; 3 levels shift by 24, 16, 8; every key stays
 * below the table's pnum, as pnum >= pmap_first_pnum requires). */
static void test_radix_levels(void)
{
    static const uint32_t keys[] = {0x14, 0x214, 0x10214, 0x210214, 0x10214};
    for (unsigned levels = 0; levels < 5; levels++) {
        radix = 1;
        start();
        radix_tree(levels, keys[levels]);
        xnu_map(va0, 8, 0);
        kext_clear(va0, 8 * 0x4000ul);
        CHECK(count() == 1 && dstate[DWC_COMMITS] == 1 && dstate[DWC_REFUSALS] == 0);
    }
    radix = 0;
}

/* 5. Every refusal clears exactly as before and writes nothing of XNU's. */
enum corrupt {
    C_TEMPLATE, C_TWICE, C_ALIAS, C_ORDER, C_GLOBAL_VA, C_RANGE, C_ABOVE, C_PVH, C_PTD_TYPE,
    C_PTD_ID, C_PTD_USER, C_INFO, C_LOW, C_STALE_PIN, C_WALK, C_RACE,
    C_CALL, C_CALL_BL, C_RADIX_TEXT, C_RADIX_MIN, C_RADIX_NULL, C_RADIX_NODE, C_RADIX_PAGE,
    C_RADIX_ROOT_VA, C_COUNT
};
static const unsigned expect[C_COUNT] = {
    DWC_R_NOT_FOUND, DWC_R_NOT_FOUND, DWC_R_ALIAS, DWC_R_GLOBAL, DWC_R_GLOBAL, DWC_R_UNMANAGED,
    DWC_R_UNMANAGED, DWC_R_PVH, DWC_R_PTD, DWC_R_PTD, DWC_R_PTD, DWC_R_INFO, DWC_R_LOW,
    DWC_R_LOW, DWC_R_WALK, DWC_R_RACE,
    DWC_R_RADIX, DWC_R_RADIX, DWC_R_RADIX, DWC_R_RADIX, DWC_R_RADIX, DWC_R_RADIX, DWC_R_RADIX,
    DWC_R_RADIX};
static void test_refusals(void)
{
    static uint8_t before[XNU_END - XNU];
    for (unsigned k = 0; k < C_COUNT; k++) {
        radix = k >= C_CALL;
        start();
        xnu_map(va0, 8, 0);
        uint16_t was = count();
        switch (k) {
        case C_TEMPLATE: put32(TEXT + 4 * (FUNC_INDEX + 30), 0x92400908); break;  /* and x8 */
        case C_TWICE: place_template(FUNC_INDEX + 200); break;
        case C_ALIAS: text_delta += 0x4000; break;
        case C_ORDER: put(GPA + 0x1f8, BASE); break;                 /* last <= first */
        case C_GLOBAL_VA: {                                          /* vm_pages_count unmapped */
            uint64_t va = VA(TEXT) + 4 * (FUNC_INDEX + 19);
            put32(TEXT + 4 * (FUNC_INDEX + 19), adrp(9, va, KVA + SIZE + 0x8000)); } break;
        case C_RANGE: put(GPA + 0x1f0, LEAF + 0x4000); break;       /* table below vm_first_phys */
        case C_ABOVE: put32(GPA, (uint32_t)(LEAF_PNUM - (SIZE >> 14))); break;   /* above vm_pages */
        case C_PVH: put(VMP + ((LEAF - BASE) >> 14) * 64 + 0x30, (VA(PTD) & ~7UL) | 2); break;
        case C_PTD_TYPE: put(PTD, 4UL << 3 | (uint64_t)ID << 11); break;
        case C_PTD_ID: put(PTD, (uint64_t)DWC_IOMMU_TYPE << 3 | 30UL << 11); break;
        case C_PTD_USER: put(VMP + ((LEAF - BASE) >> 14) * 64 + 0x30, 0x1000ul | 3); break;
        case C_INFO: put(PTD + 0x10, 0); break;
        case C_LOW: put16(INFO, 7); was = 7; break;                 /* fewer than the 8 valid */
        case C_STALE_PIN: dpins[SLOT / 64] |= UINT64_C(1) << (SLOT % 64); break; /* not held here */
        case C_WALK: w_table_wrong = LIST; break;
        case C_RACE: race_once = 1; break;
        case C_CALL: put32(TEXT + 4 * (FUNC_INDEX + DWC_CALL_AT), 0xaa0303f6); break; /* mov x22, x3 */
        case C_CALL_BL: put32(TEXT + 4 * (FUNC_INDEX + DWC_CALL_AT + 1), 0xd503201f); break;
        case C_RADIX_TEXT: put32(TEXT + 4 * (RADIX_INDEX + 40), 0x12001d6a); break;
        case C_RADIX_MIN: radix_tree(2, 0xffffffffu); break;        /* pnum < min; the wrapped key's path exists */
        case C_RADIX_NULL: put(GPD + 0x300, 2); break;               /* levels, no node */
        case C_RADIX_NODE: put32(RNODE + 0x400 * 2 + 4 * 1, 0); break;
        case C_RADIX_PAGE: put32(RNODE + 4 * 0x14, 0); break;
        case C_RADIX_ROOT_VA: root_target = KVA + SIZE + 0x4000; place_radix(RADIX_INDEX); break;
        }
        memcpy(before, ram + (XNU - BASE), sizeof(before));
        kext_clear(va0, 8 * 0x4000ul);
        CHECK(leaves_clear(va0, 8) && table_refs() == 1 && data_refs_clear());
        if (k != C_RACE) CHECK(!memcmp(before, ram + (XNU - BASE), sizeof(before)) && count() == was);
        else CHECK(count() == 0);                         /* only the simulated XNU write */
        CHECK(dstate[DWC_COMMITS] == 0 && dstate[DWC_REFUSALS] == 1 && pinned() == (k == C_STALE_PIN));
        CHECK((dstate[DWC_LAST] & 0xff) == expect[k] && (dstate[DWC_LAST] >> 8) == (k == C_WALK ? LIST : LEAF));
        if (k == C_TEMPLATE || k == C_TWICE) CHECK(dstate[DWC_LOCATED] == DWC_LOCATE_FAILED);
        if ((dstate[DWC_LAST] & 0xff) != expect[k]) printf("  case %u: reason %llu\n", k,
                                                           (unsigned long long)(dstate[DWC_LAST] & 0xff));
    }
    radix = 0;
    /* The search is not repeated after a failure. */
    start();
    put32(TEXT + 4 * (FUNC_INDEX + 5), 0);
    xnu_map(va0, 4, 0);
    kext_clear(va0, 4 * 0x4000ul);
    place_template(FUNC_INDEX);                            /* too late: stays refused */
    xnu_map(va0, 4, 0);
    kext_clear(va0, 4 * 0x4000ul);
    CHECK(dstate[DWC_REFUSALS] == 2 && dstate[DWC_LOCATED] == DWC_LOCATE_FAILED);
}

/* 5b. A table no HVC clear touched keeps XNU's own lifecycle (no held reference). */
static void test_xnu_only(void)
{
    start();
    xnu_map(va0, 12, 0);
    xnu_unmap(va0, 12);
    kext_clear(va0, 12 * 0x4000ul);                        /* nothing valid: no bookkeeping */
    CHECK(count() == 0 && !pinned() && dstate[DWC_COMMITS] == 0 && dstate[DWC_REFUSALS] == 0);
    CHECK(dstate[DWC_LOCATED] == 0);                       /* nothing needed the search */
    xnu_iovmfree();
    CHECK(unmap_table);                                    /* exactly what XNU does today */
}

/* 6. A clear the SPTM model refuses changes no count: the HVC fails as before. */
static void test_unmap_failure(void)
{
    static uint8_t before[XNU_END - XNU];
    start();
    xnu_map(va0, 8, 0);
    meta(LEAF)[4] = 3;                                     /* refs != entries + 1 */
    memcpy(before, ram + (XNU - BASE), sizeof(before));
    uint64_t r[4] = {ADRENO_GUEST_UNMAP, va0, 8 * 0x4000ul, 0};
    int e = adreno_guest_unmap(&gops, &gp, &gs, r, hvc_leaf, hvc_unmap, 0, BASE, BASE + SIZE);
    CHECK(e == ADRENO_E_DART && r[2] == SPTM_BAD_REFERENCE);
    CHECK(!memcmp(before, ram + (XNU - BASE), sizeof(before)) && count() == 8 && !pinned());
    CHECK(dstate[DWC_COMMITS] == 0 && dstate[DWC_REFUSALS] == 0 && !leaves_clear(va0, 8));
}

/* 7. The templates: the real words, ADRP-only freedom, uniqueness, the call. */
static void test_template(void)
{
    uint32_t w[300];
    for (unsigned i = 0; i < 300; i++) w[i] = 0xd503201f;
    memcpy(w + 100, real, sizeof(real));
    CHECK(dwc_match(real));
    CHECK(dwc_locate(w, 300) == 100);
    struct dwc_globals g;
    dwc_decode(real, REAL_VA, &g);
    static const uint64_t globals[DWC_ADRP_WORDS] = {0xfffffe0007e2c1f0UL, 0xfffffe0007e2c1f8UL,
        0xfffffe0007e2c000UL, 0xfffffe0007d9d270UL, 0xfffffe0007e2c010UL};
    static const unsigned sizes[DWC_ADRP_WORDS] = {8, 8, 4, 4, 8};
    for (unsigned k = 0; k < DWC_ADRP_WORDS; k++) CHECK(g.va[k] == globals[k] && g.size[k] == sizes[k]);
    /* ADRP immediates may differ in another link; nothing else may. */
    for (unsigned i = 0; i < DWC_TEMPLATE_WORDS; i++) {
        uint32_t saved = w[100 + i];
        w[100 + i] ^= dwc_mask(i) == DWC_ADRP_MASK ? 0x00ffffe0u : 0x00000400u;
        CHECK(dwc_locate(w, 300) == (dwc_mask(i) == DWC_ADRP_MASK ? 100 : -1));
        w[100 + i] = saved;
    }
    memcpy(w + 200, real, sizeof(real));
    CHECK(dwc_locate(w, 300) == -1);                      /* ambiguous */
    CHECK(dwc_locate(w, 120) == -1 && dwc_locate(w + 100, DWC_TEMPLATE_WORDS) == 0);
    CHECK(dwc_locate(w + 100, DWC_TEMPLATE_WORDS - 1) == -1);
    /* The fixed layout constants are the template's own words. */
    CHECK(real[28] == 0x8b081920 && real[29] == 0xf9401808 && real[31] == 0xf1000d3f &&
          real[34] == 0xd2ec9809 && real[42] == 0xf9400909 && real[DWC_ANCHOR] == 0x78350129);
    /* The b.lo at word 25 lands on the call site; its BL names the radix
     * function; its B returns to word 29 (ldr x8, [x0, #0x30]). */
    CHECK(real[25] == 0x54000523 && 25 + ((real[25] >> 5) & 0x7ffff) == DWC_CALL_AT);
    for (unsigned i = 0; i < 4; i++) CHECK((real_call[i] & dwc_call_mask[i]) == dwc_call_value[i]);
    int64_t words = (int64_t)(real_call[1] & 0x3ffffff) - (1 << 26);
    CHECK(REAL_VA + 4 * (DWC_CALL_AT + 1) + (uint64_t)(words * 4) == REAL_RADIX_VA);
    CHECK(DWC_CALL_AT + 3 + ((int64_t)(real_call[3] & 0x3ffffff) - (1 << 26)) == 29);
    uint32_t r[DWC_RADIX_WORDS];
    memcpy(r, dwc_radix_value, sizeof(r));
    r[1] = real_radix_adrp[0]; r[2] = real_radix_adrp[1]; r[5] = real_radix_adrp[2]; r[6] = real_radix_adrp[3];
    CHECK(dwc_radix_match(r));
    CHECK(dwc_adrp(r[1], REAL_RADIX_VA + 4) + ((r[2] >> 10) & 0xfff) * 4 == 0xfffffe0007da05f0UL);
    CHECK(dwc_adrp(r[5], REAL_RADIX_VA + 20) + ((r[6] >> 10) & 0xfff) * 8 == 0xfffffe0007d9d300UL);
    r[40] ^= 1; CHECK(!dwc_radix_match(r)); r[40] ^= 1;
    r[1] ^= 0x00ffffe0u; CHECK(dwc_radix_match(r));
    CHECK(r[7] == 0x1200092a && r[19] == 0xb2575bec);    /* and w10, w9, #7; mov x12, #-0x20000000000 */
}

int main(void)
{
    arena = calloc(1, 32 << 20);
    test_template();
    plain = 1; test_cycles(0); plain = 0;              /* the v29 leak, reproduced */
    test_cycles(1);
    radix = 1; plain = 1; test_cycles(0); plain = 0;   /* the same table below vm_pages */
    test_cycles(1); radix = 0;
    test_first_clear();
    test_mixed();
    test_radix_levels();
    test_refusals();
    test_xnu_only();
    test_unmap_failure();
    free(arena);
    if (failures) { printf("FAILED: %u of %u DART wiredcnt checks\n", failures, checks); return 1; }
    printf("PASS: %u DART wiredcnt checks (200 rewires balanced in vm_pages and below it, first clear, "
           "mixed, radix 0..4 levels, %u refusals, templates)\n", checks, (unsigned)C_COUNT);
    return 0;
}
