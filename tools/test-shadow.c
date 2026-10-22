/* SPDX-License-Identifier: MIT */
/* The shadow must answer every address the same way the guest's own tables
 * would. That is the whole contract, and it is checkable directly: walk the
 * 16K guest and the 4K shadow at the same VA and compare. No hand-written
 * expectations, so the test does not encode the same misunderstanding as the
 * code it checks.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow \
 *    tools/test-shadow.c shadow/mmu.c shadow/shadow.c -o build/test-shadow
 */
#include <stdio.h>
#include <string.h>
#include "shadow.h"

static int checks, failures;

static void check(int condition, const char *label)
{
    if (condition) {
        checks++;
    } else {
        failures++;
        printf("FAIL: %s\n", label);
    }
}

#define RAM_BASE 0x40000000UL
#define RAM_SIZE (16UL << 20)
static uint8_t ram[RAM_SIZE];
static uint64_t next_table;
static unsigned allocations;

static int ram_read(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(out, &ram[pa - RAM_BASE], 8);
    return 0;
}

static int ram_write(void *ctx, uint64_t pa, uint64_t value)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(&ram[pa - RAM_BASE], &value, 8);
    return 0;
}

/* 4K tables for the shadow, handed out from the top half of the model. */
static uint64_t ram_alloc(void *ctx)
{
    (void)ctx;
    if (next_table + 0x1000 > RAM_BASE + RAM_SIZE) return 0;
    uint64_t table = next_table;
    next_table += 0x1000;
    memset(&ram[table - RAM_BASE], 0, 0x1000);
    allocations++;
    return table;
}

static uint64_t *slot(uint64_t table, uint32_t index)
{
    return (uint64_t *)&ram[(table - RAM_BASE) + 8UL * index];
}

#define LEAF  (PT_VALID | PT_AF | (3UL << 8) | (1UL << 6))    /* AF, SH inner, AP RW */
#define PAGE  (LEAF | PT_TABLE)                               /* level 3 leaf */

/* Compare guest and shadow across [start,end) at `step`. Returns mismatches. */
static int agree(const struct mmu_config *guest, const struct mmu_config *shadow,
                 uint64_t start, uint64_t end, uint64_t step, const char *what)
{
    int bad = 0;
    for (uint64_t va = start; va < end; va += step) {
        struct mmu_leaf g, s;
        if (mmu_walk(guest, va, ram_read, NULL, &g) < 0 ||
            mmu_walk(shadow, va, ram_read, NULL, &s) < 0) {
            printf("  walk failed at %#llx (%s)\n", (unsigned long long)va, what);
            return ++bad;
        }
        if (g.valid != s.valid) {
            printf("  %#llx: guest valid=%d shadow valid=%d (%s)\n",
                   (unsigned long long)va, g.valid, s.valid, what);
            if (++bad > 4) return bad;
            continue;
        }
        if (!g.valid) continue;
        if (g.pa != s.pa) {
            printf("  %#llx: guest PA %#llx shadow PA %#llx (%s)\n", (unsigned long long)va,
                   (unsigned long long)g.pa, (unsigned long long)s.pa, what);
            if (++bad > 4) return bad;
        }
        uint64_t ga = g.descriptor & PT_LEAF_ATTRS, sa = s.descriptor & PT_LEAF_ATTRS;
        if (ga != sa) {
            printf("  %#llx: attrs guest %#llx shadow %#llx (%s)\n", (unsigned long long)va,
                   (unsigned long long)ga, (unsigned long long)sa, what);
            if (++bad > 4) return bad;
        }
    }
    return bad;
}

int main(void)
{
    memset(ram, 0, sizeof(ram));
    next_table = RAM_BASE + (8UL << 20);

    /* Guest: 16K granule, T0SZ=28, level 2 root. One 32M block at index 1, and
     * a level-3 table at index 3 with two 16K pages in it. Index 0 and the rest
     * are holes, so the build has to handle unmapped regions too. */
    uint64_t g_root = RAM_BASE, g_l3 = RAM_BASE + 0x4000;
    *slot(g_root, 1) = 0x4000000UL | LEAF;                      /* 32M block */
    *slot(g_root, 3) = g_l3 | PT_VALID | PT_TABLE;
    *slot(g_l3, 0) = 0x80000000UL | PAGE;                       /* 16K page */
    *slot(g_l3, 5) = 0x80100000UL | PAGE | PT_NG;               /* different attrs */

    struct mmu_config guest = {.granule_shift = 14, .txsz = 28, .root = g_root};

    struct shadow shadow = {.txsz = 28, .alloc = ram_alloc,
                            .read = ram_read, .write = ram_write};
    shadow.root = ram_alloc(NULL);
    check(shadow.root != 0, "shadow root allocated");

    long inserted = shadow_build(&shadow, &guest, 0, 1UL << 36, ram_read, NULL);
    check(inserted == 3, "three guest leaves shadowed");
    printf("  built from %ld leaves using %u tables\n", inserted, allocations);

    struct mmu_config s_cfg = {.granule_shift = 12, .txsz = 28, .root = shadow.root};

    /* The 32M block: every 4K across it, plus both edges. */
    check(agree(&guest, &s_cfg, 0x2000000, 0x4000000, 0x1000, "32M block") == 0,
          "shadow agrees across the whole 32M block");
    /* The pages, and the hole between them. */
    check(agree(&guest, &s_cfg, 0x6000000, 0x6040000, 0x1000, "pages") == 0,
          "shadow agrees across the level 3 pages and the hole between them");
    /* A wide sweep including regions the guest never mapped. */
    check(agree(&guest, &s_cfg, 0, 0x10000000, 0x100000, "sweep") == 0,
          "shadow agrees over a wide sweep, holes included");

    /* Specific properties worth naming rather than inferring from the sweep. */
    struct mmu_leaf leaf;
    mmu_walk(&s_cfg, 0x2001000, ram_read, NULL, &leaf);
    check(leaf.valid && leaf.pa == 0x4001000, "block address resolves through the shadow");
    check(leaf.level == 2 && leaf.size == (2UL << 20),
          "a 32M guest block becomes 2M shadow blocks, not 4K pages");

    mmu_walk(&s_cfg, 0x6000000, ram_read, NULL, &leaf);
    check(leaf.valid && leaf.level == 3 && leaf.size == 0x1000,
          "a 16K guest page becomes 4K shadow pages");
    check(leaf.pa == 0x80000000, "page base address preserved");
    mmu_walk(&s_cfg, 0x6003000, ram_read, NULL, &leaf);
    check(leaf.valid && leaf.pa == 0x80003000,
          "the fourth 4K page of a 16K guest page is mapped");
    mmu_walk(&s_cfg, 0x6004000, ram_read, NULL, &leaf);
    check(!leaf.valid, "and nothing past the end of it is");

    mmu_walk(&s_cfg, 0x6014000, ram_read, NULL, &leaf);
    check(leaf.valid && (leaf.descriptor & PT_NG), "nG carried into the shadow");

    /* The contiguous hint describes a run in the granule that declared it, so
     * it must not survive the translation. */
    *slot(g_l3, 0) = 0x80000000UL | PAGE | PT_CONTIG;
    next_table = RAM_BASE + (8UL << 20);
    memset(&ram[next_table - RAM_BASE], 0, RAM_SIZE - (next_table - RAM_BASE));
    shadow.root = ram_alloc(NULL);
    s_cfg.root = shadow.root;
    check(shadow_build(&shadow, &guest, 0, 1UL << 36, ram_read, NULL) == 3, "rebuild ok");
    mmu_walk(&s_cfg, 0x6000000, ram_read, NULL, &leaf);
    check(leaf.valid && !(leaf.descriptor & PT_CONTIG),
          "the contiguous hint is dropped rather than carried across granules");

    /* An unreadable guest table must fail the build, not produce a shadow with
     * mappings quietly missing. */
    struct mmu_config broken = guest;
    broken.root = 0x900000000UL;
    check(shadow_build(&shadow, &broken, 0, 1UL << 30, ram_read, NULL) < 0,
          "an unreadable guest table fails the build");

    /* The clip bounds and the leaf must be in the SAME address space.
     *
     * mmu_walk reports leaf.base masked into the regime; a caller that clips
     * with a raw kernel VA hands shadow_map the unmasked address, and it then
     * indexes a level-0 slot the hardware never reads. For 0xfffffed000010000
     * at T1SZ 17 that is slot 509 against the hardware's 253 -- the mapping
     * lands somewhere real and is never found.
     *
     * This cost five MAP_PAGE calls that all reported success followed by a
     * level-1 translation fault on the page they had just mapped, and it was
     * invisible until a VA arrived with no prior shadow entry to mask it. */
    {
        const uint32_t t1sz = 17;
        const uint64_t raw = 0xfffffed000010000UL;
        const uint64_t off = raw & ((1UL << (64 - t1sz)) - 1);
        check(mmu_index(12, 0, raw) != mmu_index(12, 0, off),
              "raw and regime-space VAs index different level-0 slots");

        memset(&ram[next_table - RAM_BASE], 0, RAM_SIZE - (next_table - RAM_BASE));
        struct shadow s = {.txsz = t1sz, .root = ram_alloc(NULL),
                           .alloc = ram_alloc, .read = ram_read,
                           .write = ram_write, .ctx = NULL};
        struct mmu_leaf in = {.descriptor = 0xe4238000UL | 0x703, .base = off,
                              .size = 1UL << 14, .level = 3, .valid = 1};
        check(shadow_insert(&s, &in, off, off + (1UL << 14)) == 0,
              "inserting with regime-space bounds succeeds");

        struct mmu_config view = {.granule_shift = 12, .txsz = t1sz, .root = s.root};
        struct mmu_leaf back;
        check(mmu_walk(&view, off, ram_read, NULL, &back) == 0 && back.valid,
              "and the shadow then RESOLVES it -- insert succeeding is not "
              "the same as the mapping being present");
        check((back.descriptor & PT_OA_MASK & ~(back.size - 1)) == 0xe4238000UL,
              "to the right page");

        /* And the failure this replaced: clipping with the raw VA writes the
         * leaf where nothing walks, while still reporting success. */
        memset(&ram[next_table - RAM_BASE], 0, RAM_SIZE - (next_table - RAM_BASE));
        s.root = ram_alloc(NULL);
        view.root = s.root;
        check(shadow_insert(&s, &in, raw, raw + (1UL << 14)) == SHADOW_NOTHING,
              "clipping with a raw VA inserts nothing, and SAYS so rather than "
              "reporting plain success");
        check(mmu_walk(&view, off, ram_read, NULL, &back) == 0 && !back.valid,
              "...and the address does not resolve, which is what the old "
              "silent success hid");

        /* An invalid leaf is the other path that used to return 0. */
        struct mmu_leaf gone = in;
        gone.valid = 0;
        check(shadow_insert(&s, &gone, off, off + (1UL << 14)) == SHADOW_NOTHING,
              "an invalid leaf inserts nothing, and says so");
    }

    {
        struct shadow s = {.txsz=17, .root=ram_alloc(NULL), .alloc=ram_alloc,
                           .read=ram_read, .write=ram_write};
        struct mmu_config cfg = {.granule_shift=12, .txsz=17, .root=s.root};
        struct mmu_leaf leaf;
        check(!shadow_reserve(&s,0x1ff000,0x3000), "reserve across an L3 boundary");
        unsigned count=allocations;
        check(!mmu_walk(&cfg,0x200000,ram_read,NULL,&leaf) && !leaf.valid,
              "reserved VAs have no leaf mapping");
        check(!shadow_map(&s,0x200000,RAM_BASE,0x1000,PT_AF,PT_PXN),
              "map into a reserved table");
        check(allocations==count, "mapping a reserved VA needs no allocation");
        check(shadow_reserve(&s,0x200000,0x1000)<0, "reserve rejects a mapped leaf");
        check(shadow_reserve(&s,1,0x1000)<0 && shadow_reserve(&s,0,0)<0,
              "reserve rejects unaligned and empty requests");
        check(shadow_reserve(&s,(1UL<<47)-0x1000,0x2000)<0,
              "reserve cannot cross the VA regime");
    }

    if (failures) {
        printf("FAILED: %d of %d checks\n", failures, checks + failures);
        return 1;
    }
    printf("PASS: %d shadow emitter checks (native, sanitizers on)\n", checks);
    return 0;
}
