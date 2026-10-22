/* SPDX-License-Identifier: MIT */
/* compat/s2-fault-retry.h on the host (tools/test-s2-fault-retry.py).
 *
 *   test-s2-fault-retry                 the unit checks; prints PASS: N checks
 *   test-s2-fault-retry --replay WORK BASE ROOT MEM_LO MEM_HI ESR FAR HPFAR IPA_AT
 *                                       one fault judged against a run's work dump
 *                                       (registers taken as this vCPU's; STAGE1
 *                                       retried only when built with
 *                                       -DSNAP_S2_FAULT_RETRY_STAGE1=1): prints
 *                                       "level L ipa_hw I verdict V kind K hw M d1 d2 d3 at M d1 d2 d3"
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s2-fault-retry.h"

/* --replay judges as the monitor built with or without the STAGE1 retry. */
#ifndef SNAP_S2_FAULT_RETRY_STAGE1
#define SNAP_S2_FAULT_RETRY_STAGE1 0
#endif

static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; \
    fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); } } while (0)

/* A small physical memory: 64 pages at 0x40000000. */
#define MEM_BASE UINT64_C(0x40000000)
#define MEM_PAGES 64u
static uint64_t mem[MEM_PAGES * 512];
static unsigned reads;
static int mread(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    reads++;
    if (pa < MEM_BASE || pa + 8 > MEM_BASE + MEM_PAGES * 4096 || (pa & 7)) return -1;
    *out = mem[(pa - MEM_BASE) / 8];
    return 0;
}
static void put(uint64_t pa, uint64_t v) {mem[(pa - MEM_BASE) / 8] = v;}
static uint64_t page(unsigned n) {return MEM_BASE + 4096 * (uint64_t)n;}

#define TABLE 3u
#define PAGE_RW UINT64_C(0x7ff)      /* valid, page, normal WB, RW, inner, AF */
#define BLOCK_RW UINT64_C(0x7fd)     /* the same as a block */

static void translation(void)
{
    for (unsigned ec = 0; ec < 64; ec++)
        for (unsigned fsc = 0; fsc < 64; fsc++) {
            uint64_t esr = (uint64_t)ec << 26 | 1u << 25 | fsc;
            int want = (ec == 0x24 || ec == 0x20) && fsc >= 4 && fsc <= 7 ? (int)fsc - 4 : -1;
            CHECK(s2_retry_translation(esr) == want);
        }
    /* The three stops: v62 and v63 level 2, v65 level 1; a write with ISV clear. */
    CHECK(s2_retry_translation(0x92000046) == 2);
    CHECK(s2_retry_translation(0x92000045) == 1);
    CHECK(s2_retry_translation(0x9200004f) == -1);   /* permission, level 3: an S2RO frame written */
    CHECK(s2_retry_translation(0x9200004b) == -1);   /* access flag */
    CHECK(s2_retry_translation(0x96000045) == -1);   /* EC 0x25: the monitor's own */
}

static void hpfar(void)
{
    /* v65: FAR 0x103d08000, the reported IPA 0x9a5ce3000. */
    uint64_t h = (UINT64_C(0x9a5ce3000) >> 12) << 4;
    CHECK(s2_retry_hpfar_ipa(h, 0x103d08000, 0x92000045) == UINT64_C(0x9a5ce3000));
    CHECK(s2_retry_hpfar_ipa(h, 0x75a18a6030, 0x92000046) == UINT64_C(0x9a5ce3030));
    /* S1PTW: HPFAR names a table page, FAR the data address: no offset. */
    CHECK(s2_retry_hpfar_ipa(h, 0x75a18a6030, 0x92000046 | 1u << 7) == UINT64_C(0x9a5ce3000));
    /* NS (bit 63), RES0 bits [62:44] and the RES0 low nibble are not address. */
    CHECK(s2_retry_hpfar_ipa(h | UINT64_C(1) << 63 | 0xf, 0x10, 0x92000045) == UINT64_C(0x9a5ce3010));
    CHECK(s2_retry_hpfar_ipa(h | UINT64_C(1) << 50 | UINT64_C(1) << 44, 0x10, 0x92000045) == UINT64_C(0x9a5ce3010));
}

static void registers(void)
{
    uint64_t want = s2_retry_vtcr(28, 4);
    CHECK(want == (28 | 1u << 6 | 1u << 8 | 1u << 10 | 3u << 12 | UINT64_C(4) << 16));
    uint64_t vttbr = UINT64_C(0xae30ad000) | UINT64_C(1) << 48;
    CHECK(s2_retry_registers_ok(vttbr, vttbr, want, want, 1));
    CHECK(s2_retry_registers_ok(vttbr, vttbr, want | UINT64_C(1) << 31, want, 0x80000001)); /* RES1 bit 31 */
    CHECK(!s2_retry_registers_ok(vttbr, vttbr, want, want, 0x80000000));                    /* VM clear */
    CHECK(!s2_retry_registers_ok(vttbr ^ 0x1000, vttbr, want, want, 1));                    /* another root */
    CHECK(!s2_retry_registers_ok(vttbr ^ UINT64_C(3) << 48, vttbr, want, want, 1));         /* another VMID */
    CHECK(!s2_retry_registers_ok(vttbr, vttbr, want ^ 4, want, 1));                         /* T0SZ */
    CHECK(!s2_retry_registers_ok(vttbr, vttbr, want ^ 1u << 6, want, 1));                   /* SL0 */
    CHECK(!s2_retry_registers_ok(vttbr, vttbr, want | 1u << 14, want, 1));                  /* TG0 */
    CHECK(!s2_retry_registers_ok(vttbr, vttbr, want | 1u << 19, want, 1));                  /* VS */
    CHECK(!s2_retry_registers_ok(vttbr, vttbr, want ^ UINT64_C(1) << 16, want, 1));         /* PS */
}

/* A tree: root page 0 (L1), L2 page 1 for IPA 1G..2G, L3 page 2 for the 2M
 * at 1G+0x200000, a 2M block at 1G, a 1G block at 2G, a hole at 3G. */
static uint64_t build(void)
{
    memset(mem, 0, sizeof(mem));
    uint64_t g = UINT64_C(1) << 30;
    put(page(0) + 8 * 1, page(1) | TABLE);
    put(page(0) + 8 * 2, (2 * g) | BLOCK_RW);
    put(page(1) + 8 * 0, g | BLOCK_RW);
    put(page(1) + 8 * 1, page(2) | TABLE);
    for (unsigned n = 0; n < 512; n++) if (n != 7) put(page(2) + 8 * n, (g + 0x200000 + 4096 * (uint64_t)n) | PAGE_RW);
    put(page(1) + 8 * 2, (g + 0x800000) | BLOCK_RW);                /* a block mapping another 2M */
    put(page(1) + 8 * 3, page(3) | TABLE);
    put(page(3) + 8 * 0, (g + 0x600000) | 1);                       /* level 3, bit 1 clear: reserved */
    put(page(3) + 8 * 1, (g + 0x9000) | PAGE_RW);                   /* a page mapped elsewhere */
    /* Past T0SZ 28's 64 level-1 entries: never part of the table. */
    put(page(0) + 8 * 66, ((UINT64_C(1) << 36) + 2 * g) | BLOCK_RW);
    return page(0);
}

static void walk(void)
{
    uint64_t root = build(), d[3], g = UINT64_C(1) << 30;
    CHECK(s2_retry_walk(mread, 0, root, 28, g + 0x200000 + 0x5123, d));
    CHECK(d[0] == (page(1) | TABLE) && d[1] == (page(2) | TABLE) && d[2] == ((g + 0x205000) | PAGE_RW));
    CHECK(!s2_retry_walk(mread, 0, root, 28, g + 0x200000 + 7 * 4096, d));  /* invalid L3 */
    CHECK(d[2] == 0 && d[1] == (page(2) | TABLE));
    CHECK(s2_retry_walk(mread, 0, root, 28, g + 0x1234, d));                /* 2M block */
    CHECK(d[1] == (g | BLOCK_RW) && d[2] == 0);
    CHECK(s2_retry_walk(mread, 0, root, 28, 2 * g + 0x3456789, d));         /* 1G block */
    CHECK(d[0] == (2 * g | BLOCK_RW) && !d[1] && !d[2]);
    CHECK(!s2_retry_walk(mread, 0, root, 28, 3 * g, d));                    /* L1 hole: a level-1 fault */
    CHECK(d[0] == 0 && d[1] == 0);
    CHECK(!s2_retry_walk(mread, 0, root, 28, g + 0x400000, d));             /* block mapped elsewhere */
    CHECK(!s2_retry_walk(mread, 0, root, 28, g + 0x600000, d));             /* reserved at level 3 */
    CHECK(!s2_retry_walk(mread, 0, root, 28, g + 0x601000, d));             /* page mapped elsewhere */
    CHECK(!s2_retry_walk(mread, 0, root, 28, UINT64_C(1) << 36, d));        /* outside T0SZ 28 */
    CHECK(!s2_retry_walk(mread, 0, root, 28, (UINT64_C(1) << 36) + 2 * g + 0x5000, d));
    CHECK(!s2_retry_walk(mread, 0, root, 40, g, d));                        /* not the monitor's VTCR */
    CHECK(!s2_retry_walk(mread, 0, root + 0x100000, 28, g, d));             /* a root outside memory */
    /* The VMID and CnP bits of a VTTBR are not the root. */
    CHECK(s2_retry_walk(mread, 0, root | UINT64_C(5) << 48, 28, g + 0x205000, d));
}

static void bounds(void)
{
    struct s2_retry_cpu cpu;
    memset(&cpu, 0, sizeof(cpu));
    const uint64_t hz = 24000000;
    /* The same access: twice resumed, the third stops. */
    CHECK(s2_retry_decide(&cpu, 100, hz, 0x1924d6388, 0x103d08000) == S2_RETRY_RESUME);
    CHECK(s2_retry_decide(&cpu, 101, hz, 0x1924d6388, 0x103d08000) == S2_RETRY_RESUME);
    CHECK(s2_retry_decide(&cpu, 102, hz, 0x1924d6388, 0x103d08000) == S2_RETRY_STOP_REPEAT);
    /* Another FAR at the same PC (a loop on its next page) is a new access. */
    memset(&cpu, 0, sizeof(cpu));
    CHECK(s2_retry_decide(&cpu, 100, hz, 0x1924d6388, 0x103d08000) == S2_RETRY_RESUME);
    CHECK(s2_retry_decide(&cpu, 101, hz, 0x1924d6388, 0x103d0c000) == S2_RETRY_RESUME);
    CHECK(s2_retry_decide(&cpu, 102, hz, 0x1924d6388, 0x103d08000) == S2_RETRY_RESUME);
    CHECK(cpu.repeats == 1);
    /* An access in between resets the run. */
    CHECK(s2_retry_decide(&cpu, 103, hz, 0x1924d6388, 0x103d08000) == S2_RETRY_RESUME);
    CHECK(cpu.repeats == 2);
    CHECK(s2_retry_decide(&cpu, 104, hz, 0x18c8a0d48, 0x75a18a6030) == S2_RETRY_RESUME);
    CHECK(s2_retry_decide(&cpu, 105, hz, 0x1924d6388, 0x103d08000) == S2_RETRY_RESUME);
    CHECK(cpu.repeats == 1);
    /* The rate: 1000 distinct accesses in a second resume, the 1001st stops;
     * a second later the window starts again. */
    memset(&cpu, 0, sizeof(cpu));
    unsigned resumed = 0;
    for (unsigned n = 0; n < S2_RETRY_RATE_MAX; n++)
        resumed += s2_retry_decide(&cpu, 1000 + n, hz, 0x1000 + 4 * n, 0x2000) == S2_RETRY_RESUME;
    CHECK(resumed == S2_RETRY_RATE_MAX);
    CHECK(s2_retry_decide(&cpu, 1000 + hz - 1, hz, 0x9000, 0x2000) == S2_RETRY_STOP_RATE);
    CHECK(s2_retry_decide(&cpu, 1000 + hz, hz, 0x9004, 0x2000) == S2_RETRY_RESUME);
    CHECK(cpu.window_count == 1 && cpu.window_start == 1000 + hz);
    /* A counter that wrapped (now before the window) starts a new window. */
    CHECK(s2_retry_decide(&cpu, 5, hz, 0x9008, 0x2000) == S2_RETRY_RESUME);
}

static void judge(void)
{
    struct s2_retry_cpu cpu;
    memset(&cpu, 0, sizeof(cpu));
    enum s2_retry_kind kind;
    /* MAPPED resumes whatever the STAGE1 switch says. */
    CHECK(s2_retry_judge(&cpu, 1, 1, 1, 0, 10, 100, 0x10, 0x20, &kind) == S2_RETRY_RESUME && kind == S2_RETRY_MAPPED);
    CHECK(s2_retry_judge(&cpu, 1, 1, 0, 1, 10, 100, 0x12, 0x20, &kind) == S2_RETRY_RESUME && kind == S2_RETRY_MAPPED);
    /* STAGE1 stops without SNAP_S2_FAULT_RETRY_STAGE1, resumes with it. */
    CHECK(s2_retry_judge(&cpu, 1, 0, 1, 0, 11, 100, 0x14, 0x20, &kind) == S2_RETRY_STOP_STAGE1 && kind == S2_RETRY_STAGE1);
    CHECK(s2_retry_judge(&cpu, 1, 0, 1, 1, 11, 100, 0x16, 0x20, &kind) == S2_RETRY_RESUME && kind == S2_RETRY_STAGE1);
    CHECK(s2_retry_judge(&cpu, 1, 0, 0, 1, 12, 100, 0x18, 0x20, &kind) == S2_RETRY_STOP_UNMAPPED && kind == S2_RETRY_NONE);
    CHECK(s2_retry_judge(&cpu, 1, 0, 0, 0, 12, 100, 0x18, 0x20, &kind) == S2_RETRY_STOP_UNMAPPED && kind == S2_RETRY_NONE);
    CHECK(s2_retry_judge(&cpu, 0, 1, 1, 1, 13, 100, 0x1c, 0x20, &kind) == S2_RETRY_STOP_REGISTERS && kind == S2_RETRY_MAPPED);
    CHECK(s2_retry_judge(&cpu, 0, 0, 1, 1, 13, 100, 0x1e, 0x20, &kind) == S2_RETRY_STOP_REGISTERS && kind == S2_RETRY_STAGE1);
    /* Refusals do not count toward the bounds. */
    CHECK(cpu.window_count == 3 && cpu.last_pc == 0x16);
}

static void ring(void)
{
    static struct s2_retry_state s;
    memset(&s, 0, sizeof(s));
    for (unsigned n = 0; n < S2_RETRY_RING + 3; n++) {
        struct s2_retry_entry e;
        memset(&e, 0xa5, sizeof(e));
        e.elr = 0x1000 + n;
        s2_retry_note(&s, &e, n % S2_RETRY_CPUS, (int)(n & 3), n % 3 ? S2_RETRY_MAPPED : S2_RETRY_STAGE1,
                      n % 5 ? S2_RETRY_RESUME : S2_RETRY_STOP_REPEAT);
    }
    unsigned total = S2_RETRY_RING + 3, stopped = 0, mapped = 0;
    for (unsigned n = 0; n < total; n++) {stopped += !(n % 5); mapped += !(n % 5) ? 0 : !!(n % 3);}
    CHECK(s.next == total && s.faults == total);
    CHECK(s.stopped == stopped && s.resumed == total - stopped);
    CHECK(s.mapped == mapped && s.stage1 == total - stopped - mapped);
    uint64_t per = 0;
    for (unsigned i = 0; i < S2_RETRY_CPUS; i++) per += s.cpu[i].resumed + s.cpu[i].stopped;
    CHECK(per == total);
    /* The oldest three were overwritten; every slot holds its newest entry. */
    for (unsigned i = 0; i < S2_RETRY_RING; i++) {
        uint64_t seq = s.ring[i].seq;
        CHECK(seq >= 4 && seq <= total && (seq - 1) % S2_RETRY_RING == i);
        unsigned n = (unsigned)seq - 1;
        CHECK(s.ring[i].elr == 0x1000 + n);
        CHECK((s.ring[i].info & 0xff) == n % S2_RETRY_CPUS && ((s.ring[i].info >> 8) & 0xff) == (n & 3));
        CHECK(((s.ring[i].info >> 24) & 0xff) == (n % 5 ? S2_RETRY_RESUME : S2_RETRY_STOP_REPEAT));
        CHECK(s.ring[i].hpfar == UINT64_C(0xa5a5a5a5a5a5a5a5));
    }
}

/* --replay: a run's work dump as the memory. */
static uint8_t *dump;
static size_t dump_size;
static uint64_t dump_base;
static int dread(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    if (pa < dump_base || pa - dump_base + 8 > dump_size) return -1;
    memcpy(out, dump + (pa - dump_base), 8);
    return 0;
}
static int replay(char **argv)
{
    FILE *f = fopen(argv[0], "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END);
    dump_size = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    dump = malloc(dump_size);
    if (!dump || fread(dump, 1, dump_size, f) != dump_size) return 2;
    fclose(f);
    uint64_t v[8];
    for (unsigned i = 0; i < 8; i++) v[i] = strtoull(argv[1 + i], 0, 0);
    dump_base = v[0];
    uint64_t root = v[1], lo = v[2], hi = v[3], esr = v[4], far = v[5], hp = v[6], ipa_at = v[7];
    uint64_t dh[3], da[3];
    int level = s2_retry_translation(esr);
    uint64_t ipa_hw = s2_retry_hpfar_ipa(hp, far, esr);
    int hw = s2_retry_dram(ipa_hw, lo, hi) && s2_retry_walk(dread, 0, root, 28, ipa_hw, dh);
    int at = ipa_at && s2_retry_dram(ipa_at, lo, hi) && s2_retry_walk(dread, 0, root, 28, ipa_at, da);
    if (!s2_retry_dram(ipa_hw, lo, hi)) dh[0] = dh[1] = dh[2] = 0;
    if (!(ipa_at && s2_retry_dram(ipa_at, lo, hi))) da[0] = da[1] = da[2] = 0;
    struct s2_retry_cpu cpu;
    memset(&cpu, 0, sizeof(cpu));
    enum s2_retry_kind kind;
    enum s2_retry_verdict verdict = level < 0 ? S2_RETRY_STOP_UNMAPPED :
        s2_retry_judge(&cpu, 1, hw, at, SNAP_S2_FAULT_RETRY_STAGE1, 1, 24000000, 0x1000, far, &kind);
    if (level < 0) kind = S2_RETRY_NONE;
    printf("level %d ipa_hw %#" PRIx64 " verdict %d kind %d hw %d %#" PRIx64 " %#" PRIx64 " %#" PRIx64
           " at %d %#" PRIx64 " %#" PRIx64 " %#" PRIx64 "\n", level, ipa_hw, (int)verdict, (int)kind,
           hw, dh[0], dh[1], dh[2], at, da[0], da[1], da[2]);
    free(dump);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 11 && !strcmp(argv[1], "--replay")) return replay(argv + 2);
    if (argc != 1) {fprintf(stderr, "usage: see the header\n"); return 2;}
    translation();
    hpfar();
    registers();
    walk();
    bounds();
    judge();
    ring();
    if (failures) {printf("FAILED: %u of %u checks\n", failures, checks); return 1;}
    printf("PASS: %u checks\n", checks);
    return 0;
}
