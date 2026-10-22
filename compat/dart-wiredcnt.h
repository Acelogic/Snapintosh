/* SPDX-License-Identifier: MIT */
/* SNAP_DART_WIREDCNT (probes/xnuboot.c gpu_unmap): keep XNU's IOMMU table
 * reference count balanced when ADRENO_GUEST_UNMAP clears guest DART leaves.
 *
 * The leak. The Adreno kext inserts pages with IOMapper::iovmInsert, i.e.
 * XNU's t8110dart_map, which reads each leaf and adds the invalid->valid
 * transitions to the 16-bit wiredcnt of the leaf table's page-table descriptor
 * (pmap_ref_iommu_table). It clears them with ADRENO_GUEST_UNMAP, which the
 * monitor serves with sptm_dart_unmap directly, so XNU's t8110dart_unmap -- the
 * only path that subtracts -- never runs. The kext keeps the IOVA across
 * unwire/rewire, so every rewire adds the same pages again until the count
 * passes 32767 and pmap_ref_iommu_table panics ("ptd %p wiredcnt overflow/
 * underflow", installed-fresh-20261017-v29, ~443k cleared pages).
 *
 * The fix. For the one leaf table an ADRENO_GUEST_UNMAP call touches, count
 * the valid leaves it is about to clear (n) and, after sptm_dart_unmap has
 * cleared them, subtract n from that table's wiredcnt -- what
 * t8110dart_unmap's pmap_ref_iommu_table(5, id, table, -n) would have done.
 * A leaf table's count is exactly its valid leaves as XNU counted them
 * (t8110dart_iovmalloc adds a reference to the *parent* when it creates a
 * leaf table, never to the leaf table itself), so count >= n before the
 * subtraction; anything less means the model is wrong. (The first version
 * required n + 1, assuming a per-reservation reference: it refused the first
 * clear of every fresh table whose valid leaves all lay in the clear, leaking
 * that n once per table -- v40's eleven LOW refusals.)
 *
 * One reference held per table. With exact counts XNU would free a DART leaf
 * table at t8110dart_iovmfree once its count is 0 (T8110DART UNMAP_TABLE,
 * table 3 endpoint 1, and a retype back to default).
 * The monitor's SPTM model implements neither; both were unreachable while
 * the leak kept every rewired table's count high. So the first subtraction on
 * a table also adds one reference the monitor keeps (pins[], by level-1
 * slot): the table lives exactly as long as it did before -- for the run --
 * and no new SPTM path opens. At most 96 tables (the 3 GiB window / 32 MiB),
 * 1.5 MiB. A pinned slot must then show count >= n + 1.
 *
 * Finding the count, 26A428 (found by pattern, never by address). The monitor
 * searches const-sealed kernel text once for pmap_ref_iommu_table's body
 * (dwc_value/dwc_mask, exactly one match), decodes its five ADRP+LDR global
 * references (vm_first_phys, vm_last_phys, vm_pages_first_pnum, vm_pages_count,
 * vm_pages) and follows the same chain the function does:
 *   vm_first_phys <= table < vm_last_phys, pnum = table >> 14;
 *   page = vm_pages + 64 * (pnum - vm_pages_first_pnum) when
 *     vm_pages_first_pnum <= pnum < vm_pages_first_pnum + vm_pages_count;
 *   below vm_pages_first_pnum (early boot memory, outside vm_pages: v46's
 *     table 0x8cffbc000), page = vm_page_find_canonical_radix(pnum), the
 *     function pmap_ref_iommu_table itself calls there (its b.lo at word 25
 *     lands on dwc_call_*: mov x22,x2; bl F; mov x2,x22; b word 29). F must
 *     match dwc_radix_value; its two ADRP+LDR pairs name pmap_first_pnum and
 *     vm_pages_radix_root, and the walk is F's: key = pnum - pmap_first_pnum
 *     (pnum >= pmap_first_pnum, else XNU panics), node = root & ~7, then for
 *     each of root & 7 levels L, node = unpack(node[(key >> (8L mod 32)) &
 *     0xff]), page = unpack(node[key & 0xff]), unpack(w) = 0xfffffe0000000000
 *     | w << 6, every word nonzero;
 *   pvh = *(page + 0x30), (pvh & 7) == 3 (a page-table descriptor);
 *   ptd = (pvh & ~7) | 0x64c0000000000000;
 *   ((*ptd >> 3) & 0xff) == 5 (t8110 DART) and (uint32_t)(*ptd >> 11) == dart id;
 *   counter = *(uint16_t *)*(ptd + 0x10).
 * Every one of those constants is an exact word of the matched template. Each
 * pointer is translated with AT S1E1R and must land in owned guest RAM.
 *
 * Failure inventory (each declines the bookkeeping, counts the reason, and
 * leaves the unmap itself exactly as before -- never guess, never write):
 *   NOT_FOUND  the template is absent or matches more than once;
 *   ALIAS      the matched text's VA does not translate back to its PA;
 *   GLOBAL     a global is unreadable, misaligned or vm_first_phys >= last;
 *   UNMANAGED  the table is outside [vm_first_phys, vm_last_phys) or above
 *              vm_pages (XNU itself would dereference NULL there);
 *   PVH        its vm_page entry is unreadable or not a descriptor (type 3);
 *   PTD        the descriptor is not a kernel pointer, unreadable, or names
 *              another IOMMU type or DART;
 *   INFO       the count pointer is not a readable, aligned kernel pointer;
 *   LOW        count < n (+1 once pinned): subtracting would take it below
 *              zero (or below the held reference);
 *   WALK       the leaf table cannot be walked or disagrees with the SPTM
 *              model's own leaf lookup, or leaves survive the unmap;
 *   RACE       the count fell below that bound between the check and the commit;
 *   RADIX      below vm_pages: the call site or vm_page_find_canonical_radix
 *              does not match, a global is unreadable, pnum < pmap_first_pnum,
 *              more than the root's levels, or a zero node or page word.
 * And: a table freed through UNMAP_TABLE after a subtraction (prevented by
 * the held reference); a second held reference on the same table.
 * Not covered: a kernel that frees IOVA tables differently, or a second
 * producer of Adreno DART leaves other than t8110dart_map (none exists: the
 * monitor's mirror only copies native leaves). */
#pragma once
#include <stdint.h>

/* struct context.dart_wiredcnt[DWC_WORDS] and dart_wiredcnt_pins[DWC_PIN_WORDS]
 * (bit = level-1 slot, iova >> 25), present in every build. */
enum { DWC_LOCATED, DWC_COMMITS, DWC_ENTRIES, DWC_REFUSALS, DWC_LAST, DWC_WORDS };
#ifndef ADRENO_VA_WIDE
#define ADRENO_VA_WIDE 0
#endif
#if !ADRENO_VA_WIDE
#define DWC_PIN_WORDS 2u                         /* slots 0..127: the window ends at 4 GiB */
#else
#define DWC_PIN_WORDS 8u                         /* slots 0..511: ADRENO_VA_WIDE, the window ends at 16 GiB */
#endif
#define DWC_LOCATE_FAILED 1u      /* DWC_LOCATED after a failed search; else 0 or the text PA */

enum dart_wiredcnt_reason {
    DWC_OK, DWC_R_NOT_FOUND, DWC_R_ALIAS, DWC_R_GLOBAL, DWC_R_UNMANAGED, DWC_R_PVH,
    DWC_R_PTD, DWC_R_INFO, DWC_R_LOW, DWC_R_WALK, DWC_R_RACE, DWC_R_RADIX, DWC_REASONS
};

/* pmap_ref_iommu_table, 26A428 kernelcache.release.mac17p 0xfffffe000ba755d4
 * (KDK kernel.release.t8140 0xfffffe00075295d4), entry through the count
 * check. ADRP immediates are masked; every other word is exact. */
#define DWC_TEMPLATE_WORDS 49u
#define DWC_ADRP_MASK 0x9f00001fu
static const uint32_t dwc_value[DWC_TEMPLATE_WORDS] = {
    0xd503237f, 0xd10183ff, 0xa90357f6, 0xa9044ff4, 0xa9057bfd, 0x910143fd, 0xaa0103f4,
    0xaa0003f3, 0x90000008, 0xf940f908, 0x90000009, 0xf940fd29, 0xeb08005f, 0xfa492042,
    0x54000a02, 0xaa0303f5, 0xd34efc40, 0x90000008, 0xb9400108, 0x90000009, 0xb9427129,
    0x0b080129, 0x6b00013f, 0x540003c9, 0x6b080008, 0x54000523, 0x90000009, 0xf9400929,
    0x8b081920, 0xf9401808, 0x92400909, 0xf1000d3f, 0x540002e1, 0x927df108, 0xd2ec9809,
    0xaa090108, 0xf9400109, 0x53037d2a, 0xd34bfd29, 0x6b2a027f, 0x7a490280, 0x540003a1,
    0xf9400909, 0x78350129, 0x0b29a2aa, 0x6b2aa15f, 0x54000461, 0x13003d20, 0xa9457bfd,
};
#define DWC_ADRP_WORDS 5u
/* (ADRP word, LDR word, load size): vm_first_phys, vm_last_phys,
 * vm_pages_first_pnum, vm_pages_count, vm_pages. */
static const uint8_t dwc_globals_at[DWC_ADRP_WORDS][3] = {
    {8, 9, 8}, {10, 11, 8}, {17, 18, 4}, {19, 20, 4}, {26, 27, 8},
};
static inline uint32_t dwc_mask(unsigned i)
{
    for (unsigned g = 0; g < DWC_ADRP_WORDS; g++)
        if (dwc_globals_at[g][0] == i) return DWC_ADRP_MASK;
    return 0xffffffffu;
}
/* Constants the exact template words fix (word index in brackets). */
#define DWC_ANCHOR 43u                         /* [43] ldaddh w21, w9, [x9] */
#define DWC_VM_PAGE_SIZE 64u                   /* [28] add x0, x9, x8, lsl #6 */
#define DWC_PVH_OFFSET 0x30u                   /* [29] ldr x8, [x0, #0x30] */
#define DWC_PVH_TYPE_MASK 7u                   /* [30] and x9, x8, #0x7 */
#define DWC_PVH_TYPE_PTD 3u                    /* [31] cmp x9, #0x3 */
#define DWC_PVH_HIGH UINT64_C(0x64c0000000000000) /* [34] mov x9, #0x64c0... */
#define DWC_PTD_INFO 0x10u                     /* [42] ldr x9, [x8, #0x10] */
#define DWC_IOMMU_TYPE 5u                      /* t8110dart's pmap_ref_iommu_table(5,...),
                                                * also the SPTM frame metadata type */

static inline int dwc_match(const volatile uint32_t *w)
{
    for (unsigned i = 0; i < DWC_TEMPLATE_WORDS; i++)
        if ((w[i] & dwc_mask(i)) != dwc_value[i]) return 0;
    return 1;
}
/* Exactly one match among n words: its index, or -1. */
static inline int64_t dwc_locate(const volatile uint32_t *w, uint64_t n)
{
    int64_t found = -1;
    if (n < DWC_TEMPLATE_WORDS) return -1;
    for (uint64_t i = DWC_ANCHOR; i + (DWC_TEMPLATE_WORDS - DWC_ANCHOR) <= n; i++) {
        if (w[i] != dwc_value[DWC_ANCHOR] || !dwc_match(w + i - DWC_ANCHOR)) continue;
        if (found >= 0) return -1;
        found = (int64_t)(i - DWC_ANCHOR);
    }
    return found;
}
static inline uint64_t dwc_adrp(uint32_t insn, uint64_t pc)
{
    uint64_t imm = ((insn >> 29) & 3) | (((uint64_t)(insn >> 5) & 0x7ffff) << 2);
    int64_t pages = (imm & (1u << 20)) ? (int64_t)imm - (1 << 21) : (int64_t)imm;
    return (pc & ~UINT64_C(0xfff)) + (uint64_t)(pages * 4096);
}
/* The five global VAs of a matched body at va. */
struct dwc_globals { uint64_t va[DWC_ADRP_WORDS]; unsigned size[DWC_ADRP_WORDS]; };
static inline void dwc_decode(const volatile uint32_t *w, uint64_t va, struct dwc_globals *g)
{
    for (unsigned k = 0; k < DWC_ADRP_WORDS; k++) {
        unsigned a = dwc_globals_at[k][0], l = dwc_globals_at[k][1], size = dwc_globals_at[k][2];
        g->va[k] = dwc_adrp(w[a], va + 4u * a) + ((w[l] >> 10) & 0xfff) * size;
        g->size[k] = size;
    }
}

/* What the monitor supplies. read() is called only for a pa that passed
 * dwc_ram(); kva() is AT S1E1R (0 = no translation). */
struct dwc_ops {
    void *ctx;
    uint64_t mem_low, mem_high;                 /* owned guest RAM, end exclusive */
    const volatile uint32_t *text;              /* const-sealed kernel text, readable */
    uint64_t text_pa, text_words, text_delta;   /* its PA, length and VA - PA */
    uint64_t dart_id;                           /* SPTM_DART_ADRENO */
    uint64_t (*kva)(void *ctx, uint64_t va);
    uint64_t (*read)(void *ctx, uint64_t pa, unsigned size);
    int (*cas16)(void *ctx, uint64_t pa, uint16_t expected, uint16_t desired);
    uint64_t (*table)(void *ctx, uint64_t iova);   /* leaf table PA for iova, 0 = none */
    uint64_t (*leaf)(void *ctx, uint64_t iova);    /* the SPTM model's leaf for iova */
    int (*unmap)(void *ctx, uint64_t iova, uint64_t size);
};
static inline int dwc_ram(const struct dwc_ops *o, uint64_t pa, unsigned size)
{
    return pa && !(pa & (size - 1)) && pa >= o->mem_low && o->mem_high >= size &&
           pa <= o->mem_high - size;
}
/* A kernel VA's value, or a refusal. */
static inline int dwc_load(const struct dwc_ops *o, uint64_t va, unsigned size, uint64_t *value)
{
    if (va < UINT64_C(0xffff000000000000) || (va & (size - 1))) return 0;
    uint64_t pa = o->kva(o->ctx, va);
    if (!dwc_ram(o, pa, size) || ((pa ^ va) & 0xfff)) return 0;
    *value = o->read(o->ctx, pa, size);
    return 1;
}

/* The search, once: state[DWC_LOCATED] becomes the text PA or DWC_LOCATE_FAILED. */
static inline void dwc_find(const struct dwc_ops *o, uint64_t state[DWC_WORDS])
{
    if (state[DWC_LOCATED]) return;
    int64_t at = o->text && o->text_pa && o->text_words ? dwc_locate(o->text, o->text_words) : -1;
    state[DWC_LOCATED] = at < 0 ? DWC_LOCATE_FAILED : o->text_pa + 4u * (uint64_t)at;
}

/* vm_page_find_canonical_radix, 26A428 kernelcache 0xfffffe000ba12bec (KDK
 * kernel.release.t8140 0xfffffe00074c6bec, vm_resident.c:3183), entry
 * through its last ret. Words 1 and 5 are ADRP (masked): pmap_first_pnum
 * (word 2, ldr w) and vm_pages_radix_root (word 6, ldr x). */
#define DWC_RADIX_WORDS 107u
static const uint32_t dwc_radix_value[DWC_RADIX_WORDS] = {
    0xd503245f, 0x90000008, 0xb945f108, 0x6b080008, 0x54000ce3, 0x90000009, 0xf9418129,
    0x1200092a, 0xf27df129, 0x1a9f07eb, 0xf100013f, 0x7a401944, 0x54000980, 0x531d714b,
    0x1acb250b, 0x12001d6b, 0xb86b592e, 0x710001df, 0x1a9f07eb, 0xb2575bec, 0xaa0e1989,
    0x9a9f1129, 0x5100054d, 0x710001df, 0x7a4019a4, 0x540007e0, 0x531d71ab, 0x1acb250b,
    0x12001d6b, 0xb86b592d, 0x710001bf, 0x1a9f07eb, 0xaa0d1989, 0x9a9f1129, 0x5100094c,
    0x710001bf, 0x7a401984, 0x54000660, 0x531d718b, 0x1acb250b, 0x12001d6b, 0xb86b592e,
    0x710001df, 0x1a9f07eb, 0xb2575bec, 0xaa0e1989, 0x9a9f1129, 0x51000d4d, 0x710001df,
    0x7a4019a4, 0x540004c0, 0x531d71ab, 0x1acb250b, 0x12001d6b, 0xb86b592d, 0x710001bf,
    0x1a9f07eb, 0xaa0d1989, 0x9a9f1129, 0x5100114c, 0x710001bf, 0x7a401984, 0x54000340,
    0x531d718b, 0x1acb250b, 0x12001d6b, 0xb86b592e, 0x710001df, 0x1a9f07eb, 0xb2575bec,
    0xaa0e1989, 0x9a9f1129, 0x5100154d, 0x710001df, 0x7a4019a4, 0x540001a0, 0x531d71ab,
    0x1acb250b, 0x12001d6b, 0xb86b592d, 0x710001bf, 0x1a9f07eb, 0xaa0d1989, 0x9a9f1129,
    0x5100194a, 0x710001bf, 0x7a401944, 0x54000121, 0x3400022b, 0x12001d08, 0xb8685928,
    0xb2575be9, 0xaa081929, 0x7100011f, 0x9a8903e0, 0xd65f03c0, 0x531d714a, 0x1aca250a,
    0x12001d4a, 0xb86a592a, 0xb2575be9, 0xaa0a1929, 0x7100015f, 0x9a8903e9, 0x35fffe2a,
    0xd2800000, 0xd65f03c0,
};
#define DWC_RADIX_MIN 1u                       /* [1] adrp x8; [2] ldr w8, [x8, #0x5f0] */
#define DWC_RADIX_ROOT 5u                      /* [5] adrp x9; [6] ldr x9, [x9, #0x300] */
#define DWC_RADIX_LEVEL_MASK 7u                /* [7] and w10, w9, #0x7 */
#define DWC_PACKED_BASE UINT64_C(0xfffffe0000000000) /* [19] mov x12, #-0x20000000000 */
static inline int dwc_radix_match(const volatile uint32_t *w)
{
    for (unsigned i = 0; i < DWC_RADIX_WORDS; i++) {
        uint32_t mask = i == DWC_RADIX_MIN || i == DWC_RADIX_ROOT ? DWC_ADRP_MASK : 0xffffffffu;
        if ((w[i] & mask) != dwc_radix_value[i]) return 0;
    }
    return 1;
}
/* pmap_ref_iommu_table words 66..69, the b.lo at word 25's target: pnum below
 * vm_pages goes to F(pnum) and its result is the page word 29 loads pvh from. */
#define DWC_CALL_AT 66u
static const uint32_t dwc_call_value[4] = {0xaa0203f6, 0x94000000, 0xaa1603e2, 0x17ffffd8};
static const uint32_t dwc_call_mask[4] = {0xffffffffu, 0xfc000000u, 0xffffffffu, 0xffffffffu};

/* The vm_page of a pnum below vm_pages, as vm_page_find_canonical_radix finds
 * it. w/va/index: the matched pmap_ref_iommu_table body. */
static inline unsigned dwc_radix(const struct dwc_ops *o, const volatile uint32_t *w, uint64_t va,
                                 uint64_t index, uint64_t pnum, uint64_t *page)
{
    if (index + DWC_CALL_AT + 4 > o->text_words) return DWC_R_RADIX;
    for (unsigned i = 0; i < 4; i++)
        if ((w[DWC_CALL_AT + i] & dwc_call_mask[i]) != dwc_call_value[i]) return DWC_R_RADIX;
    int64_t words = (int64_t)(w[DWC_CALL_AT + 1] & 0x3ffffff);
    if (words & (1 << 25)) words -= 1 << 26;
    uint64_t f = va + 4 * (DWC_CALL_AT + 1) + (uint64_t)(words * 4), f_pa = f - o->text_delta;
    if (f_pa < o->text_pa || (f_pa & 3) || (f_pa - o->text_pa) / 4 + DWC_RADIX_WORDS > o->text_words ||
        o->kva(o->ctx, f) != f_pa) return DWC_R_RADIX;
    const volatile uint32_t *r = o->text + (f_pa - o->text_pa) / 4;
    if (!dwc_radix_match(r)) return DWC_R_RADIX;
    uint64_t min_va = dwc_adrp(r[DWC_RADIX_MIN], f + 4 * DWC_RADIX_MIN) +
                      ((r[DWC_RADIX_MIN + 1] >> 10) & 0xfff) * 4;
    uint64_t root_va = dwc_adrp(r[DWC_RADIX_ROOT], f + 4 * DWC_RADIX_ROOT) +
                       ((r[DWC_RADIX_ROOT + 1] >> 10) & 0xfff) * 8;
    uint64_t min, root, word;
    if (!dwc_load(o, min_va, 4, &min) || !dwc_load(o, root_va, 8, &root) || pnum < min)
        return DWC_R_RADIX;
    uint32_t key = (uint32_t)(pnum - min);
    uint64_t node = root & ~(uint64_t)DWC_RADIX_LEVEL_MASK;
    if (!node) return DWC_R_RADIX;
    for (unsigned level = (unsigned)(root & DWC_RADIX_LEVEL_MASK); level; level--) {
        /* lsr w, w8, w: a 32-bit shift by (8 * level) mod 32, as F executes it. */
        if (!dwc_load(o, node + 4 * ((key >> ((8 * level) & 31)) & 0xff), 4, &word) || !word)
            return DWC_R_RADIX;
        node = DWC_PACKED_BASE | word << 6;
    }
    if (!dwc_load(o, node + 4 * (key & 0xff), 4, &word) || !word) return DWC_R_RADIX;
    *page = DWC_PACKED_BASE | word << 6;
    return DWC_OK;
}

/* The count of the leaf table at table_pa: its PA and current value. */
static inline unsigned dwc_resolve(const struct dwc_ops *o, uint64_t located, uint64_t table_pa,
                                   uint64_t *counter_pa, uint16_t *count)
{
    if (located == 0 || located == DWC_LOCATE_FAILED) return DWC_R_NOT_FOUND;
    uint64_t index = (located - o->text_pa) / 4;
    if (located < o->text_pa || (located & 3) || index + DWC_TEMPLATE_WORDS > o->text_words)
        return DWC_R_NOT_FOUND;
    const volatile uint32_t *w = o->text + index;
    uint64_t va = located + o->text_delta;
    if (!dwc_match(w) || o->kva(o->ctx, va) != located) return DWC_R_ALIAS;
    struct dwc_globals g;
    dwc_decode(w, va, &g);
    uint64_t v[DWC_ADRP_WORDS];
    for (unsigned k = 0; k < DWC_ADRP_WORDS; k++)
        if (!dwc_load(o, g.va[k], g.size[k], &v[k])) return DWC_R_GLOBAL;
    uint64_t first = v[0], last = v[1], base = v[2], pages_count = v[3], pages = v[4];
    if (first >= last || ((first | last) & 0x3fff)) return DWC_R_GLOBAL;
    if (table_pa < first || table_pa >= last || (table_pa & 0x3fff)) return DWC_R_UNMANAGED;
    uint64_t pnum = table_pa >> 14, page;
    if (pnum >> 32) return DWC_R_UNMANAGED;                       /* ppnum_t is 32 bits */
    if (pnum >= base) {
        if (pnum - base >= pages_count) return DWC_R_UNMANAGED;
        page = pages + (pnum - base) * DWC_VM_PAGE_SIZE;
    } else {
        unsigned r = dwc_radix(o, w, va, index, pnum, &page);
        if (r) return r;
    }
    uint64_t pvh;
    if (!dwc_load(o, page + DWC_PVH_OFFSET, 8, &pvh) ||
        (pvh & DWC_PVH_TYPE_MASK) != DWC_PVH_TYPE_PTD) return DWC_R_PVH;
    uint64_t ptd = (pvh & ~(uint64_t)DWC_PVH_TYPE_MASK) | DWC_PVH_HIGH, word0, info;
    if (!dwc_load(o, ptd, 8, &word0) || ((word0 >> 3) & 0xff) != DWC_IOMMU_TYPE ||
        (uint32_t)(word0 >> 11) != (uint32_t)o->dart_id) return DWC_R_PTD;
    if (!dwc_load(o, ptd + DWC_PTD_INFO, 8, &info)) return DWC_R_PTD;
    uint64_t value;
    if (!dwc_load(o, info, 2, &value)) return DWC_R_INFO;
    *counter_pa = o->kva(o->ctx, info);
    *count = (uint16_t)value;
    return DWC_OK;
}

static inline void dwc_refuse(uint64_t state[DWC_WORDS], unsigned reason, uint64_t table_pa)
{
    state[DWC_REFUSALS]++;
    state[DWC_LAST] = (uint64_t)reason | (table_pa << 8);
}

/* ADRENO_GUEST_UNMAP's clear with XNU's bookkeeping. Returns o->unmap's result
 * unchanged; the bookkeeping never changes whether or what the unmap clears.
 * The caller holds the service lock (the only writer of leaves and state). */
static inline int dwc_unmap(const struct dwc_ops *o, uint64_t state[DWC_WORDS],
                            uint64_t pins[DWC_PIN_WORDS], uint64_t iova, uint64_t size)
{
    uint64_t first = iova & ~UINT64_C(0x3fff), slot = first >> 25;
    uint64_t pages = ((iova & 0x3fff) + size + 0x3fff) >> 14, table = 0, counter = 0;
    unsigned n = 0, reason = DWC_OK, pinned = 0;
    uint16_t count = 0;
    /* One leaf table: adreno_guest_unmap keeps the range inside a 32 MiB block. */
    if (!size || pages > 2048 || slot >= 64 * DWC_PIN_WORDS ||
        (slot != ((first + (pages - 1) * 0x4000) >> 25)))
        reason = DWC_R_WALK;
    else {
        pinned = (unsigned)((pins[slot / 64] >> (slot % 64)) & 1);
        table = o->table(o->ctx, first);
    }
    if (!reason && table) {
        if (!dwc_ram(o, table, 0x4000)) reason = DWC_R_WALK;
        for (uint64_t i = 0; !reason && i < pages; i++) {
            uint64_t at = first + i * 0x4000;
            uint64_t v = o->read(o->ctx, table + 8 * ((at >> 14) & 2047), 8);
            if (v != o->leaf(o->ctx, at)) reason = DWC_R_WALK;
            else n += (unsigned)(v & 1);
        }
    }
    if (!reason && n) {
        dwc_find(o, state);
        reason = dwc_resolve(o, state[DWC_LOCATED], table, &counter, &count);
        if (!reason && ((int16_t)count < 0 || (unsigned)count < n + pinned)) reason = DWC_R_LOW;
    }
    int r = o->unmap(o->ctx, iova, size);
    if (r) return r;
    if (!n && !reason) return 0;
    for (uint64_t i = 0; !reason && i < pages; i++)
        if (o->leaf(o->ctx, first + i * 0x4000)) reason = DWC_R_WALK;
    while (!reason) {
        uint16_t now = (uint16_t)o->read(o->ctx, counter, 2);
        if ((int16_t)now < 0 || (unsigned)now < n + pinned) { reason = DWC_R_RACE; break; }
        if (o->cas16(o->ctx, counter, now, (uint16_t)(now - n + !pinned))) {
            pins[slot / 64] |= UINT64_C(1) << (slot % 64);
            state[DWC_COMMITS]++;
            state[DWC_ENTRIES] += n;
            return 0;
        }
    }
    dwc_refuse(state, reason, table);
    return 0;
}
