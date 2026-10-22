/* SPDX-License-Identifier: MIT */
/* The stage-2 map must hold exactly the ranges it was given, and nothing else.
 * That is checkable directly: build it, then walk it with the same walker the
 * shadow tests use and compare every page against the list. No hand-written
 * table layout, so the test does not encode the same misunderstanding as the
 * code it checks.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow \
 *    tools/test-stage2.c shadow/mmu.c shadow/shadow.c shadow/stage2.c -o build/test-stage2
 */
#include <stdio.h>
#include <string.h>
#include "stage2.h"

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

/* The tables live in a model of the work area. The addresses they map need no
 * backing: an identity entry for 0xda000000 is a number in a descriptor. */
static uint64_t RAM_BASE = 0x82500000UL;
#define RAM_SIZE (2UL << 20)
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

static void reset(struct shadow *s)
{
    memset(ram, 0, sizeof(ram));
    next_table = RAM_BASE;
    allocations = 0;
    s->root = ram_alloc(NULL);
}

#define TXSZ 28u                                  /* 36-bit IPA, as VTCR_EL2 has it */
#define IPA_LIMIT (1UL << (64 - TXSZ))

/* The device's own layout: DRAM declared at 0xda000000 for 384 MiB with the
 * 48 MiB reserve above it, the panel q1n1 reported, and 32 MiB of work area
 * from q1n1's heap. The alignments differ on purpose -- 2 MiB, 128 KiB and
 * 1 MiB -- so one list has to come out as blocks and pages together. */
static const struct stage2_range device[] = {
    {0xda000000, 0xf5000000, S2_AP_RW | S2_ATTRS, 0},       /* DRAM + reserve */
    {0xf9a20000, 0xfade4000, S2_AP_RW | S2_ATTRS, S2_XN},   /* panel */
    {0x82500000, 0x84500000, S2_AP_RO | S2_ATTRS, S2_XN},   /* work area */
};
#define DEVICE_RANGES (sizeof(device) / sizeof(device[0]))

static const struct stage2_range *range_of(uint64_t ipa)
{
    for (unsigned n = 0; n < DEVICE_RANGES; n++)
        if (ipa >= device[n].lo && ipa < device[n].hi) return &device[n];
    return NULL;
}

/* One page against the list: present exactly when a range holds it, mapped to
 * itself, carrying that range's permission and execute bits. 0 when it agrees. */
static int page_agrees(const struct mmu_config *cfg, uint64_t ipa, const char *what)
{
    struct mmu_leaf leaf;
    if (mmu_walk(cfg, ipa, ram_read, NULL, &leaf) < 0) {
        printf("  walk failed at %#llx (%s)\n", (unsigned long long)ipa, what);
        return 1;
    }
    const struct stage2_range *r = range_of(ipa);
    if (!r) {
        if (!leaf.valid) return 0;
        printf("  %#llx: mapped, but no range holds it (%s)\n", (unsigned long long)ipa, what);
        return 1;
    }
    if (!leaf.valid) {
        printf("  %#llx: absent, but %#llx..%#llx holds it (%s)\n", (unsigned long long)ipa,
               (unsigned long long)r->lo, (unsigned long long)r->hi, what);
        return 1;
    }
    if (leaf.pa != ipa) {
        printf("  %#llx: resolves to %#llx, not itself (%s)\n", (unsigned long long)ipa,
               (unsigned long long)leaf.pa, what);
        return 1;
    }
    uint64_t low = leaf.descriptor & PT_LEAF_ATTRS, upper = leaf.descriptor & PT_LEAF_UPPER;
    if (low != (r->low & PT_LEAF_ATTRS) || upper != r->upper) {
        printf("  %#llx: attrs low %#llx upper %#llx, wanted %#llx %#llx (%s)\n",
               (unsigned long long)ipa, (unsigned long long)low, (unsigned long long)upper,
               (unsigned long long)(r->low & PT_LEAF_ATTRS), (unsigned long long)r->upper,
               what);
        return 1;
    }
    return 0;
}

/* Sweep [start, end) at `step`. Returns mismatches, stopping after a few. */
static int sweep(const struct mmu_config *cfg, uint64_t start, uint64_t end,
                 uint64_t step, const char *what)
{
    int bad = 0;
    for (uint64_t ipa = start; ipa < end; ipa += step) {
        if (page_agrees(cfg, ipa, what)) bad++;
        if (bad > 4) break;
    }
    return bad;
}

static int table_is_empty(uint64_t table)
{
    for (unsigned n = 0; n < 512; n++) {
        uint64_t d;
        if (ram_read(NULL, table + 8UL * n, &d) || d) return 0;
    }
    return 1;
}

int main(void)
{
    struct shadow s = {.txsz = TXSZ, .alloc = ram_alloc, .read = ram_read,
                       .write = ram_write, .ctx = NULL};
    reset(&s);
    check(s.root != 0, "stage-2 root allocated");

    check(stage2_build(&s, device, DEVICE_RANGES) == 0, "the device's ranges build");
    printf("  built %u ranges using %u tables\n", (unsigned)DEVICE_RANGES, allocations);
    struct mmu_config map = {.granule_shift = 12, .txsz = TXSZ, .root = s.root};

    /* Every 4K page of every range, and every page in a 2 MiB margin on each
     * side of it. */
    int bad = 0;
    for (unsigned n = 0; n < DEVICE_RANGES; n++)
        bad += sweep(&map, device[n].lo - 0x200000, device[n].hi + 0x200000, 0x1000,
                     "ranges and their margins");
    check(bad == 0, "every page of every range maps to itself with that range's "
                    "permission, and the margins are absent");

    /* The rest of the 36-bit space, coarsely: nothing there. */
    check(sweep(&map, 0, IPA_LIMIT, 1UL << 21, "the whole IPA space at 2 MiB") == 0,
          "nothing outside the list is mapped anywhere in the 36-bit space");

    /* The edges by name, so a failure says which one. */
    struct mmu_leaf leaf;
    mmu_walk(&map, 0xd9fff000, ram_read, NULL, &leaf);
    check(!leaf.valid, "the page below DRAM is absent");
    mmu_walk(&map, 0xf5000000, ram_read, NULL, &leaf);
    check(!leaf.valid, "the page above the reserve is absent");
    mmu_walk(&map, 0xf4fff000, ram_read, NULL, &leaf);
    check(leaf.valid && leaf.pa == 0xf4fff000, "the last page of the reserve is present");
    mmu_walk(&map, 0, ram_read, NULL, &leaf);
    check(!leaf.valid, "address zero is absent");

    /* What each range has to be for the hardware. */
    mmu_walk(&map, 0xda000000, ram_read, NULL, &leaf);
    check((leaf.descriptor & S2_AP_RW) == S2_AP_RW && !(leaf.descriptor & S2_XN),
          "DRAM is read-write and executable");
    check(leaf.level == 2 && leaf.size == (2UL << 20), "DRAM is 2 MiB blocks, not a page per 4K");
    mmu_walk(&map, 0x82500000, ram_read, NULL, &leaf);
    check((leaf.descriptor & S2_AP_RW) == S2_AP_RO && (leaf.descriptor & S2_XN),
          "the work area is read-only and execute-never");
    mmu_walk(&map, 0xf9a20000, ram_read, NULL, &leaf);
    check((leaf.descriptor & S2_AP_RW) == S2_AP_RW && (leaf.descriptor & S2_XN),
          "the panel is read-write and execute-never");
    check(leaf.level == 3, "the panel's 128 KiB-aligned start is pages, not a block "
                           "reaching below it");
    check(allocations <= 8, "the whole map costs a handful of tables");

    /* Refusals: the reason is the list, and nothing is written. */
    struct shadow r = s;
    reset(&r);
    const struct stage2_range overlapping[] = {
        {0xda000000, 0xf5000000, S2_AP_RW | S2_ATTRS, 0},
        {0xe0000000, 0xe2000000, S2_AP_RO | S2_ATTRS, S2_XN},   /* inside the first */
    };
    check(stage2_build(&r, overlapping, 2) == STAGE2_BAD_RANGES,
          "overlapping ranges are refused");
    check(table_is_empty(r.root) && allocations == 1,
          "...and nothing was written before the refusal");
    const struct stage2_range unaligned[] = {{0xda000800, 0xf5000000, S2_AP_RW | S2_ATTRS, 0}};
    check(stage2_build(&r, unaligned, 1) == STAGE2_BAD_RANGES, "an unaligned range is refused");
    const struct stage2_range empty[] = {{0xda000000, 0xda000000, S2_AP_RW | S2_ATTRS, 0}};
    check(stage2_build(&r, empty, 1) == STAGE2_BAD_RANGES, "an empty range is refused");
    const struct stage2_range backwards[] = {{0xf5000000, 0xda000000, S2_AP_RW | S2_ATTRS, 0}};
    check(stage2_build(&r, backwards, 1) == STAGE2_BAD_RANGES, "a backwards range is refused");
    const struct stage2_range beyond[] = {
        {IPA_LIMIT - 0x1000, IPA_LIMIT + 0x1000, S2_AP_RW | S2_ATTRS, 0}};
    check(stage2_build(&r, beyond, 1) == STAGE2_BAD_RANGES,
          "a range past the 36-bit IPA width is refused");
    check(stage2_build(&r, device, 0) == STAGE2_BAD_RANGES,
          "an empty list is refused, not built as a map of nothing");
    check(table_is_empty(r.root) && allocations == 1, "no refusal left anything behind");
    /* Out of tables is a different failure, and says so differently. */
    next_table = RAM_BASE + RAM_SIZE;
    check(stage2_build(&r, device, DEVICE_RANGES) == -1,
          "running out of tables fails the build with -1, not with a partial map "
          "reported as built");

    /* The split: a guard needs one 4K page of a block to be its own entry. */
    reset(&s);
    check(stage2_build(&s, device, DEVICE_RANGES) == 0, "rebuilt");
    map.root = s.root;
    unsigned before = allocations;
    uint64_t l3 = stage2_split(&s, 0xda001000);
    check(l3 != 0, "a page inside a 2 MiB DRAM block can be split out");
    check(allocations == before + 1, "the split costs one table");
    check(stage2_split(&s, 0xda001000) == l3, "splitting again returns the same table");
    check(allocations == before + 1, "...and costs nothing");
    check(sweep(&map, 0xd9e00000, 0xda400000, 0x1000, "around the split") == 0,
          "every page around the split still maps to itself with DRAM's attributes");
    mmu_walk(&map, 0xda001000, ram_read, NULL, &leaf);
    check(leaf.valid && leaf.level == 3 && leaf.size == 0x1000,
          "the split page is a level-3 entry");
    mmu_walk(&map, 0xda200000, ram_read, NULL, &leaf);
    check(leaf.valid && leaf.level == 2, "the next block is still a block");

    /* The entry a guard writes, and what closing it does. */
    uint64_t slot = l3 + 8UL * ((0xda001000 >> 12) & 0x1ff), d = 0;
    ram_read(NULL, slot, &d);
    check((d & PT_OA_MASK) == 0xda001000 && (d & PT_TABLE) && (d & PT_VALID),
          "the slot names the page");
    ram_write(NULL, slot, d & ~PT_VALID);
    mmu_walk(&map, 0xda001000, ram_read, NULL, &leaf);
    check(!leaf.valid, "clearing the slot makes that one page absent");
    mmu_walk(&map, 0xda000000, ram_read, NULL, &leaf);
    check(leaf.valid, "...and its neighbour is untouched");
    ram_write(NULL, slot, d);

    /* Attributes survive a split: the work area stays read-only. */
    l3 = stage2_split(&s, 0x83000000);
    check(l3 != 0, "a work-area block can be split");
    mmu_walk(&map, 0x83000000, ram_read, NULL, &leaf);
    check(leaf.valid && (leaf.descriptor & S2_AP_RW) == S2_AP_RO && (leaf.descriptor & S2_XN),
          "the split pieces keep read-only and execute-never");
    check(sweep(&map, 0x82300000, 0x84700000, 0x1000, "work area after the split") == 0,
          "the whole work area and its margins still agree with the list");

    /* An absent page is not made present by asking to split it. */
    before = allocations;
    check(stage2_split(&s, 0xf5000000) == 0, "splitting an absent page returns nothing");
    check(allocations == before, "...and allocates nothing");
    mmu_walk(&map, 0xf5000000, ram_read, NULL, &leaf);
    check(!leaf.valid, "...and the page is still absent");
    check(stage2_split(&s, 0x10000000) == 0,
          "splitting under an absent level-1 entry returns nothing");

    /* A temporary execute permission change belongs to only one CPU. Build
     * six maps with the real emitter, split the same page in each, and open
     * each guard in turn while walking every other map independently. */
    reset(&s);
    struct shadow private[6];
    uint64_t slots[6], descriptors[6];
    const uint64_t guarded = 0xda001000;
    for (unsigned cpu = 0; cpu < 6; cpu++) {
        private[cpu] = s;
        if (cpu) private[cpu].root = ram_alloc(NULL);
        check(private[cpu].root != 0, "private stage-2 root allocated");
        check(stage2_build(&private[cpu], device, DEVICE_RANGES) == 0,
              "private stage-2 map builds");
        uint64_t table = stage2_split(&private[cpu], guarded);
        check(table != 0, "private guard split succeeds");
        slots[cpu] = table + 8 * ((guarded >> 12) & 511);
        check(ram_read(NULL, slots[cpu], &descriptors[cpu]) == 0,
              "private guard descriptor readable");
        check(ram_write(NULL, slots[cpu], descriptors[cpu] | S2_XN) == 0,
              "private guard closed");
        for (unsigned other = 0; other < cpu; other++)
            check(slots[cpu] != slots[other], "private guard leaf storage differs");
    }
    for (unsigned cpu = 0; cpu < 6; cpu++) {
        ram_write(NULL, slots[cpu], descriptors[cpu]);
        for (unsigned other = 0; other < 6; other++) {
            map.root = private[other].root;
            uint64_t desc;
            check(ram_read(NULL, slots[other], &desc) == 0,
                  "guard permissions readable");
            check(!!(desc & S2_XN) == (other != cpu),
                  "opening one guard leaves all other CPUs execute-never");
            check(page_agrees(&map, 0xf5000000, "private absent device") == 0,
                  "private map retains absent device hole");
            check(page_agrees(&map, RAM_BASE, "private work permissions") == 0,
                  "private map retains read-only work permissions");
        }
        ram_write(NULL, slots[cpu], descriptors[cpu] | S2_XN);
    }

    /* Lockdown must remove writes across every CPU without changing guards,
     * neighbouring pages, identity addresses or allocating during execution. */
    const uint64_t rolo=0xda001000,rohi=0xda805000;
    static uint8_t saved[RAM_SIZE];
    for(unsigned cpu=0;cpu<6;cpu++) {
        check(stage2_split(&private[cpu],rolo)!=0 &&
              stage2_split(&private[cpu],rohi-4096)!=0,"RoRgn boundaries prepared");
    }
    memcpy(saved,ram,sizeof(ram));
    for(unsigned cpu=0;cpu<6;cpu++)
        check(!stage2_readonly(&private[cpu],rolo,rohi,1),"all-CPU seal preflight");
    check(!memcmp(saved,ram,sizeof(ram)),"preflight never mutates mappings");
    before=allocations;
    for(unsigned cpu=0;cpu<6;cpu++) {
        check(!stage2_readonly(&private[cpu],rolo,rohi,0),"private map sealed");
        check(!stage2_readonly(&private[cpu],rolo,rohi,0),"sealing is idempotent");
        map.root=private[cpu].root;
        for(uint64_t at=rolo-4096;at<=rohi;at+=4096) {
            check(!mmu_walk(&map,at,ram_read,NULL,&leaf) && leaf.valid && leaf.pa==at &&
                  (leaf.descriptor&PT_AP)==(at>=rolo && at<rohi ? S2_AP_RO:S2_AP_RW),
                  "sealed interior with writable neighbours and identity PA");
        }
        uint64_t desc;ram_read(NULL,slots[cpu],&desc);
        check((desc&S2_XN) && !(desc&(1UL<<7)),"closed execute guard remains closed and read-only");
    }
    check(allocations==before,"sealing allocates no tables");
    memcpy(saved,ram,sizeof(ram));
    check(stage2_readonly(&private[0],rolo+1,rohi,0)!=0,"unaligned range refused");
    check(stage2_readonly(&private[0],rohi,rolo,0)!=0,"reversed range refused");
    check(stage2_readonly(&private[0],rohi,IPA_LIMIT+4096,0)!=0,"IPA overflow refused");
    check(stage2_readonly(&private[0],0xf4fff000,0xf5001000,0)!=0,"partially absent range refused");
    check(stage2_readonly(&private[0],0xdab01000,0xdac00000,0)!=0,"unprepared boundary refused");
    check(!memcmp(saved,ram,sizeof(ram)),"invalid requests leave all descriptors unchanged");
    ram_read(NULL,slots[0],&d);
    ram_write(NULL,slots[0],d+4096);
    memcpy(saved,ram,sizeof(ram));
    check(stage2_readonly(&private[0],rolo,rohi,0)!=0,"non-identity mapping refused");
    check(!memcmp(saved,ram,sizeof(ram)),"malformed map rejection has no writes");

    /* The external monitor arena uses physical bits above 32 for both table
     * storage and mapped addresses. Check the actual native descriptors, not
     * just the loader's requested range list. Keep the entire private context
     * absent even at the page next to the guest bootstrap reserve. */
    const uint64_t work = 0xae1000000UL, tables = 0xae129e000UL;
    const uint64_t work_end = 0xae9000000UL;
    const struct stage2_range external[] = {
        {0x8c0000000UL, work, S2_AP_RW | S2_ATTRS, 0},
        {0xf9a20000, 0xfade8000, S2_AP_RW | S2_ATTRS, S2_XN},
        {tables, work_end, S2_AP_RO | S2_ATTRS, S2_XN},
    };
    RAM_BASE = tables;
    reset(&s);
    check(!stage2_build(&s, external, 3), "high-memory external arena builds");
    map.root = s.root;
    for (uint64_t at = work; at < work_end + 4096; at += 4096) {
        int rc = mmu_walk(&map, at, ram_read, NULL, &leaf);
        int present = at >= tables && at < work_end;
        check(!rc && !!leaf.valid == present,
              "external work context and end guard are absent");
        if (present)
            check(leaf.pa == at && (leaf.descriptor & PT_AP) == S2_AP_RO &&
                  (leaf.descriptor & S2_XN),
                  "every external table page preserves high PA bits and RO/XN");
    }
    check(!mmu_walk(&map, work - 4096, ram_read, NULL, &leaf) && leaf.valid &&
          leaf.pa == work - 4096 && (leaf.descriptor & PT_AP) == S2_AP_RW,
          "last guest bootstrap page remains writable below private context");
    const uint64_t absent[] = {0xb9e40000UL, 0xba340000UL,
                              tables & 0xffffffffUL, work_end & 0xffffffffUL};
    for (unsigned i = 0; i < sizeof(absent) / sizeof(absent[0]); i++)
        check(!mmu_walk(&map, absent[i], ram_read, NULL, &leaf) && !leaf.valid,
              "q1n1 heap, locator and truncated high addresses remain absent");
    check(allocations < RAM_SIZE / 4096, "external map fits bounded table storage");

    if (failures) {
        printf("FAILED: %d of %d checks\n", failures, checks + failures);
        return 1;
    }
    printf("PASS: %d stage-2 map checks (native, sanitizers on)\n", checks);
    return 0;
}
