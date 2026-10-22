/* SPDX-License-Identifier: MIT */
/* compat/i2c-input.h against the real stage-2 builder: the keyboard's GENI page
 * and nothing else, and every malformed parameter block refused untouched.
 * Run by tools/test-i2c-input.py, which also binds the constants to
 * probes/i2cinput.py and builds the monitor with and without the define.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow -Icompat \
 *    tools/test-i2c-input.c shadow/mmu.c shadow/shadow.c shadow/stage2.c -o OUT
 *
 * Failure inventory (docs/A16-INPUT-INSTALLED-20261017.md section 2):
 *  - a window the loader names but the allow-list does not (another page of the
 *    QUP, the SE DMA page, a 16 KiB span, the touchpad's page under the keyboard
 *    flag, any non-zero address of a disabled device) must refuse, writing nothing;
 *  - a monitor built with the define and handed a default params blob reads
 *    whatever follows the blob: zeros, device-tree bytes or noise must refuse;
 *  - the mapped page must be Device-nGnRE, read-write, execute-never, identity;
 *  - every neighbouring page, the rest of the 16 KiB window and the touchpad's
 *    window must stay absent, so a stray access is a stage-2 fault;
 *  - the extra rows must fit the monitor's range array beside the Adreno's.
 */
#include <stdio.h>
#include <string.h>
#include "stage2.h"
#include "i2c-input.h"

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

static uint64_t RAM_BASE = 0x82500000UL;
#define RAM_SIZE (4UL << 20)
static uint8_t ram[RAM_SIZE];
static uint64_t next_table;

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
    return table;
}

#define TXSZ 28u
#define IPA_LIMIT (1UL << (64 - TXSZ))

/* The installed route's other rows (cycle.py installed-fresh: 8 GiB at
 * 0x8c0000000, the GOP panel, the work area, the three Adreno windows). */
static const struct stage2_range base_rows[] = {
    {0x8c0000000UL, 0xac0000000UL, S2_AP_RW | S2_ATTRS, 0},
    {0xf9a20000UL, 0xfade4000UL, S2_AP_RW | S2_ATTRS, S2_XN},
    {0x82500000UL, 0x84500000UL, S2_AP_RO | S2_ATTRS, S2_XN},
    {0x03D00000UL, 0x03D37000UL, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN},
    {0x03D3C000UL, 0x03D40000UL, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN},
    {0x03D9E000UL, 0x03DA0000UL, S2_AP_RO | S2_ATTRS_DEVICE, S2_XN},
};
#define BASE_ROWS (sizeof(base_rows) / sizeof(base_rows[0]))

static struct i2c_input_params keyboard(void)
{
    return (struct i2c_input_params){I2C_INPUT_MAGIC, I2C_INPUT_F_KEYBOARD,
                                     I2C_INPUT_KEYBOARD_PA, I2C_INPUT_KEYBOARD_PA + I2C_INPUT_PAGE, 0, 0};
}

/* -1, and the output untouched. */
static int refused(struct i2c_input_params p)
{
    struct stage2_range out[I2C_INPUT_STAGE2_MAX], sentinel[I2C_INPUT_STAGE2_MAX];
    memset(out, 0xa5, sizeof(out));
    memcpy(sentinel, out, sizeof(out));
    return i2c_input_rows(&p, out) == -1 && !memcmp(out, sentinel, sizeof(out));
}

static int present(const struct mmu_config *map, uint64_t ipa, struct mmu_leaf *leaf)
{
    return mmu_walk(map, ipa, ram_read, NULL, leaf) == 0 && leaf->valid;
}

/* Build the installed rows plus the block's rows, as vcpu_stage2_prepare does. */
static int build(const struct i2c_input_params *p, struct shadow *s, unsigned *count_out)
{
    struct stage2_range ranges[8 + I2C_INPUT_STAGE2_MAX];
    unsigned count = 0;
    memset(ram, 0, sizeof(ram));
    next_table = RAM_BASE + 0x200000;   /* tables above the modelled work area start */
    s->root = ram_alloc(NULL);
    for (unsigned n = 0; n < BASE_ROWS; n++) ranges[count++] = base_rows[n];
    int rows = i2c_input_rows(p, ranges + count);
    if (rows < 0) return -41;
    count += (unsigned)rows;
    *count_out = count;
    return stage2_build(s, ranges, count);
}

static uint64_t lcg = 0x9e3779b97f4a7c15UL;
static uint64_t next_random(void)
{
    lcg = lcg * 6364136223846793005UL + 1442695040888963407UL;
    return lcg ^ (lcg >> 29);
}

int main(void)
{
    struct shadow s = {.txsz = TXSZ, .alloc = ram_alloc, .read = ram_read, .write = ram_write};
    struct mmu_config map = {.granule_shift = 12, .txsz = TXSZ};
    struct mmu_leaf leaf;
    unsigned count = 0;

    /* 1. The keyboard block: one row, and the map holds exactly it. */
    struct i2c_input_params p = keyboard();
    struct stage2_range out[I2C_INPUT_STAGE2_MAX];
    check(i2c_input_rows(&p, out) == 1, "the keyboard block gives one row");
    check(out[0].lo == 0x0088C000UL && out[0].hi == 0x0088D000UL, "the row is IC20's first 4 KiB");
    check(out[0].low == (S2_AP_RW | S2_ATTRS_DEVICE) && out[0].upper == S2_XN,
          "the row is Device-nGnRE, read-write, execute-never");
    check(build(&p, &s, &count) == 0 && count == BASE_ROWS + 1, "the installed rows plus the page build");
    map.root = s.root;
    check(present(&map, 0x0088C000UL, &leaf) && leaf.pa == 0x0088C000UL && leaf.size == 0x1000,
          "IC20's page maps to itself as one 4 KiB page");
    check((leaf.descriptor & PT_LEAF_ATTRS) == ((S2_AP_RW | S2_ATTRS_DEVICE) & PT_LEAF_ATTRS) &&
          (leaf.descriptor & PT_LEAF_UPPER) == S2_XN, "the mapped leaf carries the device attributes");
    check(present(&map, 0x0088CE28UL, &leaf), "GENI_HW_PARAM_1 (0xe28), the highest register used, is mapped");
    for (uint64_t ipa = 0x0088D000UL; ipa < 0x00890000UL; ipa += 0x1000)
        check(!present(&map, ipa, &leaf), "the rest of the 16 KiB QUP window (SE DMA at +0x2000) is absent");
    check(!present(&map, 0x0088B000UL, &leaf), "the page below IC20 is absent");
    check(!present(&map, 0x00890000UL, &leaf), "the next serial engine is absent");
    check(!present(&map, 0x00B80000UL, &leaf), "the touchpad's controller is absent");
    check(!present(&map, 0x0F143000UL, &leaf), "TLMM GPIO 67 is absent (Phase 2 is not enabled)");
    check(!present(&map, 0x17000000UL, &leaf), "the GIC distributor is absent");
    {
        int stray = 0;
        for (uint64_t ipa = 0x00800000UL; ipa < 0x00C00000UL; ipa += 0x1000)
            stray += present(&map, ipa, &leaf) && ipa != 0x0088C000UL;
        check(stray == 0, "nothing else in 0x800000..0xc00000 is mapped, at 4 KiB");
        stray = 0;
        for (uint64_t ipa = 0; ipa < IPA_LIMIT; ipa += 1UL << 21) {
            int in_base = 0;
            for (unsigned n = 0; n < BASE_ROWS; n++)
                in_base |= ipa >= (base_rows[n].lo & ~0x1fffffUL) && ipa < base_rows[n].hi;
            if (!in_base && ipa != 0x00800000UL) stray += present(&map, ipa, &leaf);
        }
        check(stray == 0, "nothing outside the rows is mapped in the 36-bit space, at 2 MiB");
    }
    check(i2c_input_window(&p, 0x0088C000UL) && i2c_input_window(&p, 0x0088CFFFUL),
          "MAP_PAGE classifies the page as the input device");
    check(!i2c_input_window(&p, 0x0088D000UL) && !i2c_input_window(&p, 0x0088BFFFUL) &&
          !i2c_input_window(&p, 0x00B80000UL), "and nothing beside it");

    /* 2. Refusals: every field that differs from the allow-list. */
    p = keyboard(); p.magic ^= 1;                      check(refused(p), "a wrong magic is refused");
    p = keyboard(); p.magic = 0;                       check(refused(p), "a zero magic is refused");
    p = keyboard(); p.flags = 0;                       check(refused(p), "no enabled device is refused");
    p = keyboard(); p.flags |= 4;                      check(refused(p), "an unknown flag is refused");
    p = keyboard(); p.flags = 1UL << 32 | 1;           check(refused(p), "a high flag bit is refused");
    p = keyboard(); p.keyboard_pa += 0x1000; p.keyboard_end += 0x1000;
    check(refused(p), "IC20's second page is refused");
    p = keyboard(); p.keyboard_pa += 0x2000; p.keyboard_end += 0x2000;
    check(refused(p), "IC20's SE DMA page is refused");
    p = keyboard(); p.keyboard_end = I2C_INPUT_KEYBOARD_PA + 0x4000;
    check(refused(p), "the whole 16 KiB window is refused");
    p = keyboard(); p.keyboard_end = I2C_INPUT_KEYBOARD_PA;
    check(refused(p), "an empty window is refused");
    p = keyboard(); p.keyboard_pa = I2C_INPUT_TOUCHPAD_PA; p.keyboard_end = I2C_INPUT_TOUCHPAD_PA + 0x1000;
    check(refused(p), "the touchpad's page under the keyboard flag is refused");
    p = keyboard(); p.touchpad_pa = I2C_INPUT_TOUCHPAD_PA;
    check(refused(p), "a disabled device with an address is refused");
    p = keyboard(); p.touchpad_end = I2C_INPUT_TOUCHPAD_PA + 0x1000;
    check(refused(p), "a disabled device with an end is refused");
    p = (struct i2c_input_params){0};                  check(refused(p), "an all-zero block is refused");
    {
        /* A default loader's blob ends before these words: the monitor then
         * reads the device tree's first bytes (an Apple flattened tree starts
         * with node property counts), or zeros, or noise. */
        uint64_t tree[6] = {0x0000000a00000021UL, 0x6d616e0000000000UL, 0, 0, 0, 0};
        memcpy(&p, tree, sizeof(p));
        check(refused(p), "device-tree bytes where the block would be are refused");
        int accepted = 0;
        for (unsigned n = 0; n < 200000; n++) {
            uint64_t *w = (uint64_t *)&p;
            for (unsigned i = 0; i < I2C_INPUT_PARAMS_WORDS; i++) w[i] = next_random();
            if (n & 1) p.magic = I2C_INPUT_MAGIC;      /* half with the magic right */
            accepted += !refused(p);
        }
        check(accepted == 0, "200000 noise blocks (half with the magic) are all refused");
    }
    p = keyboard(); p.magic ^= 1;
    check(build(&p, &s, &count) == -41, "the stage-2 preparation stops with -41 on a refused block");

    /* 3. Both devices (the monitor admits the touchpad's page; the loader
     *    refuses to enable it until its controller is qualified). */
    p = keyboard();
    p.flags = I2C_INPUT_F_ALL;
    p.touchpad_pa = I2C_INPUT_TOUCHPAD_PA;
    p.touchpad_end = I2C_INPUT_TOUCHPAD_PA + I2C_INPUT_PAGE;
    check(i2c_input_rows(&p, out) == 2 && out[1].lo == 0x00B80000UL && out[1].hi == 0x00B81000UL,
          "both devices give two rows, keyboard first");
    check(build(&p, &s, &count) == 0 && count == BASE_ROWS + 2 && count <= 8 + I2C_INPUT_STAGE2_MAX,
          "the rows fit the monitor's array beside the Adreno's");
    map.root = s.root;
    check(present(&map, 0x00B80000UL, &leaf) && !present(&map, 0x00B81000UL, &leaf),
          "the touchpad's first page only");
    p.flags = I2C_INPUT_F_TOUCHPAD; p.keyboard_pa = p.keyboard_end = 0;
    check(i2c_input_rows(&p, out) == 1 && out[0].lo == 0x00B80000UL, "the touchpad alone gives its row");

    printf("%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures != 0;
}
