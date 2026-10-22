/* SPDX-License-Identifier: MIT */
/* Does this CPU's MMU actually walk a 16K-granule translation table?
 *
 * ID_AA64MMFR0_EL1.TGran16 says no, but that field is exactly the kind of thing
 * a vendor has been caught lying about -- the Huawei Qingyun fused off PAuth in
 * ID_AA64ISAR1_EL1 while the silicon had it. Writing the encodings to TCR_EL1
 * and reading them back proves nothing either: TCR fields are storage, and the
 * granule is only validated when a walk happens.
 *
 * So do a walk. AT S1E1R runs the real hardware table walker over the EL1&0
 * regime and reports the outcome in PAR_EL1, without ever entering EL1 and
 * without dereferencing the result.
 *
 * Three trials, in this order, because the first two are what make the third
 * mean anything:
 *   A  4K granule, valid table    -> must resolve. Proves the harness works.
 *   B  4K granule, empty table    -> must fault. Proves SCTLR_EL1.M really took
 *                                    effect; with M=0 a walk is bypassed and
 *                                    PAR reports success with PA==VA, which
 *                                    would make trial C a false pass.
 *   C  16K granule, valid table   -> the question.
 *
 * Both granules share one table. With T0SZ=28 (36-bit VA) the 4K regime starts
 * at level 1 (1GB blocks, index VA[35:30]) and the 16K regime starts at level 2
 * (32MB blocks, index VA[35:25]); entry 0 of each is the same descriptor, and
 * VA 0x1000 indexes 0 either way. The block maps to PA 0, which is never
 * accessed -- only the table itself is read, and that lives in the heap.
 *
 * x0 = out buffer, x1 = table base, which must be 16K aligned and 16K long.
 */
typedef unsigned long u64;

#define RD(reg)      ({ u64 v_; __asm__ volatile("mrs %0, " reg : "=r"(v_)); v_; })
#define WR(reg, v)   __asm__ volatile("msr " reg ", %0" :: "r"((u64)(v)))
#define ISB()        __asm__ volatile("isb")
#define FLUSH()      __asm__ volatile("dsb ish; tlbi vmalle1is; dsb ish; isb")

/* Block descriptor: valid block, AttrIndx 0, AP RW, inner shareable, AF set.
 * Without AF the walk takes an Access Flag fault and the result is ambiguous. */
#define BLOCK 0x741UL

/* T0SZ 28, IRGN0/ORGN0 write-back, SH0 inner, EPD1 (no TTBR1 walks), IPS 44-bit. */
#define TCR_BASE (28UL | (1UL << 8) | (1UL << 10) | (3UL << 12) | (1UL << 23) | (4UL << 32))
#define TCR_4K   (TCR_BASE)                  /* TG0 = 0b00 */
#define TCR_16K  (TCR_BASE | (2UL << 14))    /* TG0 = 0b10 */

/* SCTLR_EL1 RES1 bits for ARMv8.1+, plus M. Leaving RES1 clear is UNPREDICTABLE. */
#define SCTLR_ON ((1UL << 11) | (1UL << 20) | (1UL << 22) | (1UL << 23) | \
                  (1UL << 28) | (1UL << 29) | 1UL)

/* The discriminator.
 *
 * A first cut mapped entry 0 and translated VA 0x1000, and both granules
 * answered PA 0x1000 -- because at T0SZ=28 the 4K regime indexes VA[35:30] and
 * the 16K regime indexes VA[35:25], and VA 0x1000 is index 0 in both. That
 * cannot tell "16K walked" from "TG0=0b10 was ignored and it walked as 4K",
 * which is precisely what the architecture permits an implementation to do with
 * an unsupported granule.
 *
 * So map only entry 1 and translate PROBE_VA. Under 16K that is index 1, valid,
 * and resolves into a distinctive PA. Under 4K it is index 0, which is empty,
 * and faults. The two interpretations now disagree. */
#define PROBE_VA  0x2001000UL          /* 32MB + 4K */
#define FAR_BLOCK 0x4000000UL          /* 32MB-aligned, nothing else maps here */
#define EXPECT_16K (FAR_BLOCK | 0x1000UL)

static u64 walk(u64 tcr, u64 table, int valid)
{
    u64 *entry = (u64 *)table;
    for (unsigned n = 0; n < 16384 / 8; n++) entry[n] = 0;
    if (valid) entry[0] = BLOCK;

    WR("mair_el1", 0xffUL);          /* attr0 = Normal write-back */
    WR("ttbr0_el1", table);
    WR("tcr_el1", tcr);
    ISB();
    WR("sctlr_el1", SCTLR_ON);
    FLUSH();

    __asm__ volatile("at s1e1r, %0" :: "r"(0x1000UL));
    ISB();
    return RD("par_el1");
}

/* Only entry 1 is mapped, and it points somewhere unmistakable. */
static u64 walk_far(u64 tcr, u64 table)
{
    u64 *entry = (u64 *)table;
    for (unsigned n = 0; n < 16384 / 8; n++) entry[n] = 0;
    entry[1] = FAR_BLOCK | BLOCK;

    WR("mair_el1", 0xffUL);
    WR("ttbr0_el1", table);
    WR("tcr_el1", tcr);
    ISB();
    WR("sctlr_el1", SCTLR_ON);
    FLUSH();

    __asm__ volatile("at s1e1r, %0" :: "r"(PROBE_VA));
    ISB();
    return RD("par_el1");
}

void tgran16_probe(u64 *out, u64 table);
void tgran16_probe(u64 *out, u64 table)
{
    u64 hcr = RD("hcr_el2");
    u64 sctlr = RD("sctlr_el1"), tcr = RD("tcr_el1");
    u64 ttbr = RD("ttbr0_el1"), mair = RD("mair_el1");

    /* AT S1E1R only walks the EL1&0 regime when that regime is live: TGE routes
     * it to EL2 instead, and VM would fold stage 2 into the answer.
     *
     * RW must be set too, or EL1 is AArch32 and the walker reads 32-bit
     * descriptors -- the 64-bit tables below then mean nothing and every trial
     * faults. On parts with no AArch32 at EL1 this bit is RES1 and the bug is
     * invisible; it only showed up against QEMU's -cpu max, which does offer
     * AArch32 and so leaves RW clear. */
    WR("hcr_el2", (hcr & ~((1UL << 27) | 1UL)) | (1UL << 31));
    ISB();

    out[0] = hcr;
    out[1] = walk(TCR_4K, table, 1);       /* A: must resolve */
    out[2] = walk(TCR_4K, table, 0);       /* B: must fault */
    out[3] = walk_far(TCR_4K, table);      /* C: must fault -- 4K indexes entry 0 */
    out[4] = walk_far(TCR_16K, table);     /* D: the question */
    out[5] = RD("id_aa64mmfr0_el1");
    out[6] = EXPECT_16K;

    WR("sctlr_el1", sctlr);
    WR("tcr_el1", tcr);
    WR("ttbr0_el1", ttbr);
    WR("mair_el1", mair);
    FLUSH();
    WR("hcr_el2", hcr);
    ISB();
}
