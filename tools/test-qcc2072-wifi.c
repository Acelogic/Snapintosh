/* SPDX-License-Identifier: MIT */
/* compat/qcc2072-wifi.h against the real stage-2 builder: the QCC2072's five
 * windows and nothing else, every malformed block or record refused untouched,
 * and the command-register store filter. Run by tools/test-qcc2072-wifi.py,
 * which also binds the constants to probes/qcc2072wifi.py and builds the monitor
 * with and without the define.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow -Icompat \
 *    tools/test-qcc2072-wifi.c shadow/mmu.c shadow/shadow.c shadow/stage2.c -o OUT
 *
 * Failure inventory (written before compat/qcc2072-wifi.h; its header lists the
 * monitor's, probes/qcc2072wifi.py the loader's):
 *  - a window the loader names but the allow-list does not (shifted, widened,
 *    shrunk, swapped order, the root port's DBI, a second ECAM function) must
 *    refuse, writing nothing; so must a block whose control-page record names
 *    other windows, or is zero, or is noise;
 *  - a monitor built with the define and handed a blob without the block reads
 *    whatever follows: zeros, device-tree bytes or noise must refuse;
 *  - BAR0/BAR2 Device-nGnRE read-write, the ECAM page Device-nGnRE read-only,
 *    the arena Normal-NC read-write, the control page Normal-NC read-only, all
 *    execute-never and identity;
 *  - every neighbour stays absent: the BAR0..BAR2 gap, BAR2's next page, the
 *    root port at 0x7_8000_0000, the next ECAM function, the arena's edges, the
 *    control page's next page;
 *  - only command stores of 2 and 6 (16 bits, or 32 with a zero status half) at
 *    ECAM + 4 are performed; BAR, MSI, PM, other widths and values are not;
 *  - the five rows fit the monitor's array beside the Adreno's and the input's.
 */
#include <stdio.h>
#include <string.h>
#include "stage2.h"
#include "i2c-input.h"
#include "qcc2072-wifi.h"

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
 * 0x8c0000000, the GOP panel, the work area, the three Adreno windows) and the
 * keyboard's and touchpad's GENI pages (--input --input-touchpad). */
static const struct stage2_range base_rows[] = {
    {0x8c0000000UL, 0xac0000000UL, S2_AP_RW | S2_ATTRS, 0},
    {0xf9a20000UL, 0xfade4000UL, S2_AP_RW | S2_ATTRS, S2_XN},
    {0x82500000UL, 0x84500000UL, S2_AP_RO | S2_ATTRS, S2_XN},
    {0x03D00000UL, 0x03D37000UL, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN},
    {0x03D3C000UL, 0x03D40000UL, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN},
    {0x03D9E000UL, 0x03DA0000UL, S2_AP_RO | S2_ATTRS_DEVICE, S2_XN},
    {0x0088C000UL, 0x0088D000UL, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN},
    {0x00B80000UL, 0x00B81000UL, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN},
};
#define BASE_ROWS (sizeof(base_rows) / sizeof(base_rows[0]))

static struct qcc2072_wifi_params block(void)
{
    return (struct qcc2072_wifi_params){
        QCC2072_WIFI_MAGIC, QCC2072_WIFI_F_ENABLE,
        QCC2072_WIFI_BAR0_PA, QCC2072_WIFI_BAR0_PA + QCC2072_WIFI_BAR0_BYTES,
        QCC2072_WIFI_DMA_PA, QCC2072_WIFI_DMA_PA + QCC2072_WIFI_DMA_BYTES,
        QCC2072_WIFI_BAR2_PA, QCC2072_WIFI_BAR2_PA + QCC2072_WIFI_BAR2_BYTES,
        QCC2072_WIFI_ECAM_PA, QCC2072_WIFI_ECAM_PA + QCC2072_WIFI_ECAM_BYTES,
        QCC2072_WIFI_CONTROL_PA, QCC2072_WIFI_CONTROL_PA + QCC2072_WIFI_CONTROL_BYTES};
}

/* probes/qcc2072wifi.record(): generation 1, the fixture cookie, the real inputs' offsets. */
static void make_record(uint64_t r[32])
{
    const uint64_t words[32] = {
        QCC2072_WIFI_RECORD_MAGIC, 1, 256, 1, 1, 0x5143435746495845UL, 0x111217cbUL, 0xe14f105bUL, 0x40100, 31,
        QCC2072_WIFI_BAR0_PA, QCC2072_WIFI_BAR0_BYTES, QCC2072_WIFI_BAR2_PA, QCC2072_WIFI_BAR2_BYTES,
        QCC2072_WIFI_ECAM_PA, QCC2072_WIFI_DMA_PA, QCC2072_WIFI_DMA_PA, QCC2072_WIFI_DMA_BYTES,
        QCC2072_WIFI_CONTROL_PA, 0, 7148724, 0x6d1000, 125476, 0x6f0000, 2048, 0x6f1000,
        0x8c0000000UL, 0x740000000UL, 64, 0, 0, 0};
    memcpy(r, words, sizeof(words));
}

static uint64_t record[32];

/* -1, and the output untouched. */
static int refused_with(struct qcc2072_wifi_params p, const uint64_t *r)
{
    struct stage2_range out[QCC2072_WIFI_STAGE2_MAX], sentinel[QCC2072_WIFI_STAGE2_MAX];
    memset(out, 0xa5, sizeof(out));
    memcpy(sentinel, out, sizeof(out));
    return qcc2072_wifi_rows(&p, r, out) == -1 && !memcmp(out, sentinel, sizeof(out));
}
static int refused(struct qcc2072_wifi_params p) { return refused_with(p, record); }

static int present(const struct mmu_config *map, uint64_t ipa, struct mmu_leaf *leaf)
{
    return mmu_walk(map, ipa, ram_read, NULL, leaf) == 0 && leaf->valid;
}

/* Build the installed rows plus the block's rows, as vcpu_stage2_prepare does. */
static int build(const struct qcc2072_wifi_params *p, const uint64_t *r, struct shadow *s, unsigned *count_out)
{
    struct stage2_range ranges[8 + I2C_INPUT_STAGE2_MAX + QCC2072_WIFI_STAGE2_MAX];
    unsigned count = 0;
    memset(ram, 0, sizeof(ram));
    next_table = RAM_BASE + 0x200000;
    s->root = ram_alloc(NULL);
    for (unsigned n = 0; n < BASE_ROWS; n++) ranges[count++] = base_rows[n];
    int rows = qcc2072_wifi_valid(p) ? qcc2072_wifi_rows(p, r, ranges + count) : -1;
    if (rows < 0) return -42;
    count += (unsigned)rows;
    *count_out = count;
    return stage2_build(s, ranges, count);
}

static int attrs(const struct mmu_leaf *leaf, uint64_t low)
{
    return (leaf->descriptor & PT_LEAF_ATTRS) == (low & PT_LEAF_ATTRS) &&
           (leaf->descriptor & PT_LEAF_UPPER) == S2_XN;
}

static uint64_t lcg = 0x9e3779b97f4a7c15UL;
static uint64_t next_random(void)
{
    lcg = lcg * 6364136223846793005UL + 1442695040888963407UL;
    return lcg ^ (lcg >> 29);
}

static int store(uint64_t ipa, unsigned size, uint64_t value, uint16_t *command)
{
    struct qcc2072_wifi_params p = block();
    *command = 0xdead;
    return qcc2072_wifi_command_store(&p, ipa, size, value, command);
}

int main(void)
{
    struct shadow s = {.txsz = TXSZ, .alloc = ram_alloc, .read = ram_read, .write = ram_write};
    struct mmu_config map = {.granule_shift = 12, .txsz = TXSZ};
    struct mmu_leaf leaf;
    unsigned count = 0;
    make_record(record);

    /* 1. The block: five rows in reg order, and the map holds exactly them. */
    struct qcc2072_wifi_params p = block();
    struct stage2_range out[QCC2072_WIFI_STAGE2_MAX];
    check(qcc2072_wifi_rows(&p, record, out) == 5, "the block gives five rows");
    check(out[0].lo == 0x78000000UL && out[0].hi == 0x78100000UL && out[0].low == (S2_AP_RW | S2_ATTRS_DEVICE),
          "BAR0: 1 MiB, Device-nGnRE, read-write");
    check(out[1].lo == 0xdc000000UL && out[1].hi == 0xe0000000UL && out[1].low == (S2_AP_RW | QCC2072_WIFI_S2_ATTRS_NC),
          "the arena: 64 MiB, Normal-NC, read-write");
    check(out[2].lo == 0x78200000UL && out[2].hi == 0x78201000UL && out[2].low == (S2_AP_RW | S2_ATTRS_DEVICE),
          "BAR2: 4 KiB, Device-nGnRE, read-write");
    check(out[3].lo == 0x780100000UL && out[3].hi == 0x780101000UL && out[3].low == (S2_AP_RO | S2_ATTRS_DEVICE),
          "the ECAM page: 4 KiB, Device-nGnRE, read-only");
    check(out[4].lo == 0xe0000000UL && out[4].hi == 0xe0001000UL && out[4].low == (S2_AP_RO | QCC2072_WIFI_S2_ATTRS_NC),
          "the control page: 4 KiB, Normal-NC, read-only");
    {
        int xn = 1;
        for (unsigned n = 0; n < 5; n++) xn &= out[n].upper == S2_XN;
        check(xn, "every window is execute-never");
    }
    check(QCC2072_WIFI_S2_ATTRS_NC == 0x714UL && (S2_AP_RW | QCC2072_WIFI_S2_ATTRS_NC) == 0x7d4UL,
          "Normal-NC is MemAttr 0b0101 with the inner-shareable, access-flag bits");
    check(build(&p, record, &s, &count) == 0 && count == BASE_ROWS + 5 &&
          count <= 8 + I2C_INPUT_STAGE2_MAX + QCC2072_WIFI_STAGE2_MAX,
          "the installed and input rows plus the five build, inside the monitor's array");
    map.root = s.root;
    check(present(&map, 0x78000000UL, &leaf) && leaf.pa == 0x78000000UL && attrs(&leaf, S2_AP_RW | S2_ATTRS_DEVICE),
          "BAR0 maps to itself with device attributes");
    check(present(&map, 0x780FF000UL, &leaf) && leaf.pa == 0x780FF000UL, "BAR0's last page (its 0x3278 window) maps");
    check(!present(&map, 0x78100000UL, &leaf) && !present(&map, 0x781FF000UL, &leaf), "the BAR0..BAR2 gap is absent");
    check(present(&map, 0x78200000UL, &leaf) && attrs(&leaf, S2_AP_RW | S2_ATTRS_DEVICE), "BAR2 maps");
    check(!present(&map, 0x78201000UL, &leaf) && !present(&map, 0x78203000UL, &leaf),
          "the rest of BAR2's 16 KiB guest page is absent");
    check(present(&map, 0x780100000UL, &leaf) && leaf.pa == 0x780100000UL && attrs(&leaf, S2_AP_RO | S2_ATTRS_DEVICE),
          "the endpoint's ECAM page maps read-only");
    check(!present(&map, 0x780000000UL, &leaf) && !present(&map, 0x7800FF000UL, &leaf),
          "the root port's DBI/ECAM (bus 0) is absent");
    check(!present(&map, 0x780101000UL, &leaf) && !present(&map, 0x780108000UL, &leaf),
          "the next functions' configuration is absent");
    check(!present(&map, 0x790000000UL, &leaf), "the iATU space is absent");
    check(present(&map, 0xdc000000UL, &leaf) && attrs(&leaf, S2_AP_RW | QCC2072_WIFI_S2_ATTRS_NC) &&
          present(&map, 0xdffff000UL, &leaf) && leaf.pa == 0xdffff000UL, "the whole arena maps Normal-NC");
    check(!present(&map, 0xdbfff000UL, &leaf), "the page below the arena is absent");
    check(present(&map, 0xe0000000UL, &leaf) && attrs(&leaf, S2_AP_RO | QCC2072_WIFI_S2_ATTRS_NC),
          "the control page maps read-only Normal-NC");
    check(!present(&map, 0xe0001000UL, &leaf) && !present(&map, 0xe0003000UL, &leaf),
          "the rest of the control page's 16 KiB guest page is absent");
    {
        static const uint64_t windows[][2] = {{0x78000000UL, 0x78100000UL}, {0x78200000UL, 0x78201000UL},
                                               {0x780100000UL, 0x780101000UL}, {0xdc000000UL, 0xe0000000UL},
                                               {0xe0000000UL, 0xe0001000UL}};
        int stray = 0;
        for (uint64_t ipa = 0x77000000UL; ipa < 0x7a000000UL; ipa += 0x1000) {
            int in = 0;
            for (unsigned w = 0; w < 5; w++) in |= ipa >= windows[w][0] && ipa < windows[w][1];
            stray += !in && present(&map, ipa, &leaf);
        }
        for (uint64_t ipa = 0x77F000000UL; ipa < 0x781000000UL; ipa += 0x1000)
            stray += ipa != 0x780100000UL && present(&map, ipa, &leaf);
        for (uint64_t ipa = 0xd8000000UL; ipa < 0xe8000000UL; ipa += 0x1000)
            stray += (ipa < 0xdc000000UL || ipa >= 0xe0001000UL) && present(&map, ipa, &leaf);
        check(stray == 0, "nothing else near the windows is mapped, at 4 KiB");
        stray = 0;
        for (uint64_t ipa = 0; ipa < IPA_LIMIT; ipa += 1UL << 21) {
            int in = 0;
            for (unsigned n = 0; n < BASE_ROWS; n++)
                in |= ipa >= (base_rows[n].lo & ~0x1fffffUL) && ipa < base_rows[n].hi;
            for (unsigned w = 0; w < 5; w++)
                in |= ipa >= (windows[w][0] & ~0x1fffffUL) && ipa < windows[w][1];
            stray += !in && present(&map, ipa, &leaf);
        }
        check(stray == 0, "nothing outside the rows is mapped in the 36-bit space, at 2 MiB");
    }
    check(qcc2072_wifi_window(&p, 0x78000000UL) && qcc2072_wifi_window(&p, 0xdfffffffUL) &&
          qcc2072_wifi_window(&p, 0x780100FFFUL) && qcc2072_wifi_window(&p, 0xe0000FFFUL) &&
          qcc2072_wifi_window(&p, 0x78200000UL), "MAP_PAGE classifies the five windows as the device");
    check(!qcc2072_wifi_window(&p, 0x78100000UL) && !qcc2072_wifi_window(&p, 0x780000000UL) &&
          !qcc2072_wifi_window(&p, 0xe0001000UL) && !qcc2072_wifi_window(&p, 0xdbffffffUL),
          "and nothing beside them");

    /* 2. Refusals: every field of the block that differs from the allow-list. */
    p = block(); p.magic ^= 1;                      check(refused(p), "a wrong magic is refused");
    p = block(); p.magic = I2C_INPUT_MAGIC;         check(refused(p), "the input block's magic is refused");
    p = block(); p.flags = 0;                       check(refused(p), "flags 0 is refused");
    p = block(); p.flags = 3;                       check(refused(p), "an unknown flag is refused");
    {
        uint64_t *w = (uint64_t *)&p;
        int all = 1;
        for (unsigned i = 2; i < QCC2072_WIFI_PARAMS_WORDS; i++) {
            static const uint64_t deltas[] = {0x1000, 0x4000, (uint64_t)-0x1000, 0x100000};
            for (unsigned d = 0; d < 4; d++) {
                p = block();
                w[i] += deltas[d];
                all &= refused(p);
            }
        }
        check(all, "every window shifted, widened or shrunk by a page, 16 KiB or 1 MiB is refused");
    }
    p = block(); p.ecam_pa = 0x780000000UL; p.ecam_end = 0x780001000UL;
    check(refused(p), "the root port's configuration page is refused");
    p = block(); p.ecam_pa += 0x1000; p.ecam_end += 0x1000;
    check(refused(p), "function 1's configuration page is refused");
    p = block(); p.bar2_end = QCC2072_WIFI_BAR2_PA + 0x4000;
    check(refused(p), "BAR2's whole 16 KiB is refused");
    p = block();
    {
        struct qcc2072_wifi_params q = p;
        q.bar0_pa = p.dma_pa; q.bar0_end = p.dma_end; q.dma_pa = p.bar0_pa; q.dma_end = p.bar0_end;
        check(refused(q), "swapped windows are refused");
    }
    p = (struct qcc2072_wifi_params){0};            check(refused(p), "an all-zero block is refused");
    {
        uint64_t tree[12] = {0x0000000a00000021UL, 0x6d616e0000000000UL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        memcpy(&p, tree, sizeof(p));
        check(refused(p), "device-tree bytes where the block would be are refused");
        /* With the input built in but not enabled, the monitor's block starts
         * where the input words would; with it enabled the words before it are
         * the input block's. Both must refuse when named as this block. */
        struct i2c_input_params i2c = {I2C_INPUT_MAGIC, I2C_INPUT_F_KEYBOARD, I2C_INPUT_KEYBOARD_PA,
                                       I2C_INPUT_KEYBOARD_PA + I2C_INPUT_PAGE, 0, 0};
        memset(&p, 0, sizeof(p));
        memcpy(&p, &i2c, sizeof(i2c));
        check(refused(p), "an input block where this block would be is refused");
        int accepted = 0;
        for (unsigned n = 0; n < 200000; n++) {
            uint64_t *w = (uint64_t *)&p;
            for (unsigned i = 0; i < QCC2072_WIFI_PARAMS_WORDS; i++) w[i] = next_random();
            if (n & 1) { p.magic = QCC2072_WIFI_MAGIC; p.flags = QCC2072_WIFI_F_ENABLE; }
            accepted += !refused(p);
        }
        check(accepted == 0, "200000 noise blocks (half with magic and flags) are all refused");
    }
    /* The control page's record must name the same windows. */
    {
        static const unsigned fields[] = {0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 28, 29, 30, 31};
        int all = 1;
        for (unsigned f = 0; f < sizeof(fields) / sizeof(fields[0]); f++) {
            uint64_t r[32];
            make_record(r);
            r[fields[f]] ^= 0x1000;
            all &= refused_with(block(), r);
        }
        check(all, "a record differing in any fixed field is refused");
        uint64_t r[32];
        make_record(r); r[4] = 0;                   check(refused_with(block(), r), "generation 0 is refused");
        make_record(r); r[5] = 0;                   check(refused_with(block(), r), "cookie 0 is refused");
        memset(r, 0, sizeof(r));                    check(refused_with(block(), r), "an all-zero control page is refused");
        check(refused_with(block(), NULL), "no control page is refused");
        make_record(r); r[19] = 12345; r[26] = 0x100000000UL;
        p = block();
        check(qcc2072_wifi_rows(&p, r, out) == 5, "the firmware offsets and guest range are the provider's to check");
    }
    p = block(); p.magic ^= 1;
    check(build(&p, record, &s, &count) == -42, "the stage-2 preparation stops with -42 on a refused block");
    {
        uint64_t r[32];
        make_record(r); r[15] = 0xd8000000UL;
        p = block();
        check(build(&p, r, &s, &count) == -42, "and with -42 on a refused record");
    }

    /* 3. The command-register store filter. */
    uint16_t command;
    const uint64_t cmd = QCC2072_WIFI_ECAM_PA + QCC2072_WIFI_COMMAND;
    check(store(cmd, 2, 6, &command) && command == 6, "a 16-bit store of 6 (bus master on) is performed");
    check(store(cmd, 2, 2, &command) && command == 2, "a 16-bit store of 2 (bus master off) is performed");
    check(store(cmd, 4, 6, &command) && command == 6, "a 32-bit store of 6 with a zero status half is performed");
    check(store(cmd, 2, 0x10006, &command) && command == 6, "a 16-bit store narrows like the hardware");
    check(!store(cmd, 4, 0x00100006, &command) && command == 0xdead, "a 32-bit store with status bits is not");
    check(!store(cmd, 2, 0, &command), "memory decode off is not performed");
    check(!store(cmd, 2, 7, &command), "I/O space enable is not performed");
    check(!store(cmd, 2, 4, &command), "bus master without memory decode is not performed");
    check(!store(cmd, 2, 0x406, &command), "INTx disable and other bits are not performed");
    check(!store(cmd, 1, 6, &command), "a byte store is not performed");
    check(!store(cmd, 8, 6, &command), "a 64-bit store is not performed");
    check(!store(QCC2072_WIFI_ECAM_PA + 0x10, 4, 0x78000004UL, &command), "a BAR0 store is not performed");
    check(!store(QCC2072_WIFI_ECAM_PA + 0x18, 4, 0x78200004UL, &command), "a BAR2 store is not performed");
    check(!store(QCC2072_WIFI_ECAM_PA + 0x6, 2, 0xffff, &command), "a status store is not performed");
    check(!store(QCC2072_WIFI_ECAM_PA + 0x44, 2, 3, &command), "a power-state store is not performed");
    check(!store(QCC2072_WIFI_ECAM_PA + 0x52, 2, 1, &command), "an MSI control store is not performed");
    check(!store(QCC2072_WIFI_ECAM_PA + 0x1004, 2, 6, &command), "function 1's command register is not written");
    check(!store(0x780000004UL, 2, 6, &command), "the root port's command register is not written");
    {
        struct qcc2072_wifi_params bad = block();
        bad.magic ^= 1;
        check(!qcc2072_wifi_command_store(&bad, cmd, 2, 6, &command), "nothing is performed without a valid block");
        bad = block(); bad.ecam_pa += 0x1000; bad.ecam_end += 0x1000;
        check(!qcc2072_wifi_command_store(&bad, bad.ecam_pa + 4, 2, 6, &command),
              "a block naming another function performs nothing there");
    }

    printf("%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures != 0;
}
