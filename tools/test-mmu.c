/* SPDX-License-Identifier: MIT */
/* Native tests for the software walker. No hardware, no EL2.
 *
 * The 16K cases are the point: the A16 cannot walk those tables, so software is
 * the only thing that ever will, and it has to agree with what the architecture
 * says the hardware would have done. The geometry here is cross-checked against
 * the hardware in probes/tgran16.c -- that probe builds a 16K L2 block at
 * T0SZ=28 and resolves VA 0x2001000 to PA 0x4001000 on a CPU that has 16K, and
 * the same case appears below.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow \
 *    tools/test-mmu.c shadow/mmu.c -o build/test-mmu
 */
#include <stdio.h>
#include <string.h>
#include "mmu.h"

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

/* A flat model of guest physical memory: tables live in one array and are
 * addressed by PA, so the walker exercises the same arithmetic it will on
 * hardware. */
#define RAM_BASE 0x40000000UL
#define RAM_SIZE (4UL << 20)
static uint8_t ram[RAM_SIZE];
static unsigned reads;

static int ram_read(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(out, &ram[pa - RAM_BASE], 8);
    reads++;
    return 0;
}

static uint64_t *entry(uint64_t table, uint32_t index)
{
    return (uint64_t *)&ram[(table - RAM_BASE) + 8UL * index];
}

#define LEAF (PT_VALID | PT_AF | (1UL << 8) | (1UL << 6))   /* AF, SH inner, AP RW */

int main(void)
{
    /* --- level geometry, the thing that differs between granules --- */
    check(mmu_start_level(14, 28) == 2, "16K T0SZ=28 starts at level 2");
    check(mmu_start_level(12, 28) == 1, "4K T0SZ=28 starts at level 1");
    check(mmu_start_level(14, 16) == 0, "16K T0SZ=16 starts at level 0");
    check(mmu_start_level(16, 16) == 1, "64K T0SZ=16 starts at level 1");
    check(mmu_start_level(14, 60) < 0, "an out-of-range T0SZ is rejected");

    check(mmu_level_size(14, 3) == (16UL << 10), "16K level 3 maps 16K");
    check(mmu_level_size(14, 2) == (32UL << 20), "16K level 2 maps 32M");
    check(mmu_level_size(12, 3) == (4UL << 10), "4K level 3 maps 4K");
    check(mmu_level_size(12, 2) == (2UL << 20), "4K level 2 maps 2M");
    check(mmu_level_size(12, 1) == (1UL << 30), "4K level 1 maps 1G");

    check(mmu_index(14, 2, 0x2001000) == 1, "16K level 2 indexes VA[35:25]");
    check(mmu_index(12, 1, 0x2001000) == 0, "4K level 1 indexes VA[38:30]");
    check(mmu_index(14, 3, 0x2001000) == 0, "16K level 3 indexes VA[24:14]");

    check(mmu_block_allowed(12, 1) && mmu_block_allowed(12, 2), "4K blocks at L1 and L2");
    check(!mmu_block_allowed(14, 1), "16K permits no L1 block");
    check(mmu_block_allowed(14, 2), "16K permits an L2 block");
    check(!mmu_block_allowed(16, 1), "64K permits no L1 block");

    /* --- the case the hardware probe resolves on a 16K-capable CPU --- */
    memset(ram, 0, sizeof(ram));
    uint64_t l2 = RAM_BASE;
    *entry(l2, 1) = 0x4000000UL | LEAF;          /* 32M block, matches tgran16.c */

    struct mmu_config cfg = {.granule_shift = 14, .txsz = 28, .root = l2};
    struct mmu_leaf leaf;
    check(mmu_walk(&cfg, 0x2001000, ram_read, NULL, &leaf) == 0, "16K walk runs");
    check(leaf.valid, "16K block is found");
    check(leaf.level == 2, "found at level 2");
    check(leaf.pa == 0x4001000, "resolves the address the hardware probe resolves");
    check(leaf.size == (32UL << 20), "block size is 32M");
    check(leaf.base == 0x2000000, "region base is block aligned");

    /* The same VA under 4K lands in entry 0, which is empty -- the discriminator
     * the hardware probe relies on. A walker that got this wrong would have
     * called a silent 4K fallback a success. */
    cfg.granule_shift = 12;
    check(mmu_walk(&cfg, 0x2001000, ram_read, NULL, &leaf) == 0, "4K walk runs");
    check(!leaf.valid, "4K finds nothing at the same VA");

    /* --- a full 16K three-level walk to a page --- */
    memset(ram, 0, sizeof(ram));
    uint64_t g_l2 = RAM_BASE, g_l3 = RAM_BASE + 0x4000;
    *entry(g_l2, 3) = g_l3 | PT_VALID | PT_TABLE;
    *entry(g_l3, 5) = 0x80000000UL | LEAF | PT_TABLE;      /* level 3 leaf sets bit 1 */

    cfg.granule_shift = 14;
    uint64_t va = (3UL << 25) | (5UL << 14) | 0x123;
    check(mmu_walk(&cfg, va, ram_read, NULL, &leaf) == 0, "16K page walk runs");
    check(leaf.valid, "16K page is found");
    check(leaf.level == 3, "found at level 3");
    check(leaf.pa == 0x80000123, "page offset carried through");
    check(leaf.size == (16UL << 10), "leaf size is one 16K page");
    check((leaf.descriptor & PT_LEAF_ATTRS) == (LEAF & PT_LEAF_ATTRS),
          "leaf attributes preserved for the shadow to copy");

    /* A level-3 descriptor with bit 1 clear is reserved, not a mapping. */
    *entry(g_l3, 5) = 0x80000000UL | PT_VALID | PT_AF;
    check(mmu_walk(&cfg, va, ram_read, NULL, &leaf) == 0, "reserved L3 walk runs");
    check(!leaf.valid, "a level 3 descriptor without bit 1 is not a mapping");

    /* An invalid entry is a missing mapping, distinct from a failed walk. */
    *entry(g_l3, 5) = 0;
    check(mmu_walk(&cfg, va, ram_read, NULL, &leaf) == 0, "invalid entry walks cleanly");
    check(!leaf.valid && leaf.level == 3, "reported unmapped at the level it stopped");

    /* Unreadable guest memory must fail the walk, never look unmapped: a shadow
     * built from a failed read would silently omit real mappings. */
    cfg.root = 0x900000000UL;
    check(mmu_walk(&cfg, va, ram_read, NULL, &leaf) < 0, "an unreadable table fails the walk");

    if (failures) {
        printf("FAILED: %d of %d checks\n", failures, checks + failures);
        return 1;
    }
    printf("PASS: %d software walker checks (native, sanitizers on)\n", checks);
    return 0;
}
