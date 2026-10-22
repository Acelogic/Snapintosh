/* SPDX-License-Identifier: MIT */
/* Native tests for the AGX model. No hardware, no EL2, no GPU.
 *
 * What these can and cannot show, stated up front, because the distinction is
 * the whole value of the harness:
 *
 *   They CAN show that the table arithmetic and the mailbox state machine do
 *   what the sources they were derived from say -- that agx_uat_leaf_pte()
 *   reproduces m1n1-j700's expression bit for bit, that a walk finds what a
 *   build put there, that SET_CTX_ID refuses the cases real SPTM refuses.
 *
 *   They CANNOT show that any of it matches Apple silicon. Agreement with
 *   m1n1-j700 is not evidence: both sides come from the same reverse
 *   engineering, so an error there is reproduced faithfully here and passes.
 *   That is emuasi/device's soundness statement and it applies unchanged.
 *
 * The fixed vectors below were computed by hand from the expressions in
 * m1n1-j700/src/sptm/uat.c, not captured from this model, so they fail if the
 * model drifts. Every run prints agx_unmodelled(), so a green result reads as
 * "no known regressions", never as "matches hardware".
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Igpu \
 *    gpu/test-agx.c gpu/agx-uat.c gpu/agx-asc.c -o build/test-agx
 */
#include <stdio.h>
#include <string.h>
#include "agx.h"

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

static void check_eq(uint64_t got, uint64_t want, const char *label)
{
    if (got == want) {
        checks++;
    } else {
        failures++;
        printf("FAIL: %s\n      got  0x%016llx\n      want 0x%016llx\n",
               label, (unsigned long long)got, (unsigned long long)want);
    }
}

/* A flat model of physical memory, addressed by PA, so the model performs the
 * same arithmetic it will against real memory. */
#define RAM_BASE 0x800000000ULL
#define RAM_SIZE (2UL << 20)
static unsigned char ram[RAM_SIZE];
static unsigned reads, writes;

static int ram_read(void *ctx, uint64_t pa, uint64_t *out)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(out, &ram[pa - RAM_BASE], 8);
    reads++;
    return 0;
}

static int ram_write(void *ctx, uint64_t pa, uint64_t value)
{
    (void)ctx;
    if (pa < RAM_BASE || pa + 8 > RAM_BASE + RAM_SIZE) return -1;
    memcpy(&ram[pa - RAM_BASE], &value, 8);
    writes++;
    return 0;
}

static uint64_t *cell(uint64_t pa)
{
    return (uint64_t *)&ram[pa - RAM_BASE];
}

static const struct agx_mem MEM = { ram_read, ram_write, 0 };

/* ------------------------------------------------------------------- UAT */

static void test_uat_geometry(void)
{
    /* 16K granule, 11 index bits: L1 va[46:36], L2 va[35:25], L3 va[24:14]. */
    check_eq(agx_uat_index(1, 1ULL << 36), 0x01, "L1 indexes from va[36]");
    check_eq(agx_uat_index(1, 0x10ULL << 36), 0x10, "L1 indexes va[46:36]");
    check_eq(agx_uat_index(1, (1ULL << 35)), 0, "L1 ignores bits below 36");
    check_eq(agx_uat_index(2, 0x0000000002000000ULL), 0x01, "L2 indexes va[35:25]");
    check_eq(agx_uat_index(3, 0x0000000000004000ULL), 0x01, "L3 indexes va[24:14]");
    check_eq(agx_uat_index(3, 0x0000000000003fffULL), 0, "sub-page bits do not index");
    check_eq(agx_uat_index(2, ~0ULL), 0x7ff, "an index is 11 bits wide");
    check_eq(agx_uat_index(4, 0x1000), 0, "an out-of-range level yields 0");

    check_eq(AGX_UAT_PAGE_SIZE, 16384, "the UAT page is 16K");
}

static void test_uat_leaf_pte(void)
{
    /* Worked through m1n1-j700's uat_leaf_pte() by hand.
     *
     * options = 0, type = 0:
     *   idx  = 0 -> attr = uat_attr_table[0] = 0
     *   perm = 3, os_ng = 0x800 (type & 10 == 0)
     *   -> 0x800 | (0 << 53) | pa | 3 | (0 << 6) | 0x0080000000000400
     */
    check_eq(agx_uat_leaf_pte(0, 0x800004000ULL, 0),
             0x0080000000000C03ULL | 0x800004000ULL,
             "options 0, type 0: nG set, AttrIndex 0, perm 3");

    /* type 2 clears nG (bit 1 of `type & 10`). */
    check_eq(agx_uat_leaf_pte(2, 0x800004000ULL, 0),
             0x0080000000000403ULL | 0x800004000ULL,
             "type 2 is global: nG clear");

    /* options bit 3 -> perm 0xb; bit 2 -> perm 7; bit 3 wins because it is
     * tested first and bit 2 overwrites it, so BOTH set gives 7. That
     * ordering is the model's, copied from the source, and is pinned here so
     * a reordering is caught. */
    check_eq(agx_uat_leaf_pte(0, 0x800004000ULL, 8) & 0xf,
             0xbULL, "options bit 3 selects perm 0xb");
    check_eq(agx_uat_leaf_pte(0, 0x800004000ULL, 4) & 0xf,
             0x7ULL, "options bit 2 selects perm 7");
    check_eq(agx_uat_leaf_pte(0, 0x800004000ULL, 12) & 0xf,
             0x7ULL, "with both set, bit 2 wins");

    /* options = 1 -> idx = 4 -> attr = 4 -> bits 53 = 0, bits 7:6 = 1. */
    check_eq((agx_uat_leaf_pte(0, 0, 1) >> 6) & 3, 1, "attr 4 puts 1 in bits 7:6");
    check_eq((agx_uat_leaf_pte(0, 0, 1) >> 53) & 3, 0, "attr 4 puts 0 in bits 54:53");

    /* options = 3 -> idx = 12 -> attr = 6 -> bits 54:53 = 2, bits 7:6 = 1. */
    check_eq((agx_uat_leaf_pte(0, 0, 3) >> 53) & 3, 2, "attr 6 puts 2 in bits 54:53");

    /* The 0xff entries fold to attribute 0 rather than escaping into the PTE.
     * options = 0x102 -> idx = 2|8|1 = 11 -> table[11] = 0xff -> 0. */
    check_eq((agx_uat_leaf_pte(0, 0, 0x102) >> 53) & 3, 0, "0xff folds to attr 0");
    check_eq((agx_uat_leaf_pte(0, 0, 0x102) >> 6) & 3, 0, "0xff folds low bits too");

    /* The address is masked to the 4K-aligned field, not the 16K page. */
    check_eq(agx_uat_leaf_pte(0, 0xffffffffffffffffULL, 0) & AGX_UAT_PTE_ADDR_MASK,
             AGX_UAT_PTE_ADDR_MASK, "the OA field is 48-bit, 4K-aligned");
}

static void test_uat_ttbr(void)
{
    /* (root & 0x3ffffffc000) | (ctx << 48) | 1 */
    check_eq(agx_uat_ttbr(0x800004000ULL, 5),
             0x0005000800004001ULL, "TTBR carries ctx in bits 63:48 and VALID");
    check_eq(agx_uat_ttbr(0xffffffffffffffffULL, 0) & ~0ULL,
             AGX_UAT_TTBR_ADDR_MASK | 1ULL, "the TTBR address field is bits 41:14");
}

static void test_uat_walk(void)
{
    struct agx_uat uat;
    uint64_t l1 = RAM_BASE, l2 = RAM_BASE + 0x4000, l3 = RAM_BASE + 0x8000;
    uint64_t va = (1ULL << 36) | (2ULL << 25) | (3ULL << 14);
    uint64_t pte = 0;

    memset(ram, 0, sizeof ram);
    agx_uat_init(&uat, &MEM);

    /* An unmapped VA is an answer, not an error. */
    check(agx_uat_walk(&uat, l1, va, &pte) == 0, "a walk of an empty table succeeds");
    check_eq(pte, 0, "and reports no mapping");

    *cell(l1 + 8 * agx_uat_index(1, va)) = l2 | 3;
    *cell(l2 + 8 * agx_uat_index(2, va)) = l3 | 3;
    *cell(l3 + 8 * agx_uat_index(3, va)) = agx_uat_leaf_pte(0, 0x800040000ULL, 0);

    check(agx_uat_walk(&uat, l1, va, &pte) == 0, "a walk of a built table succeeds");
    check_eq(pte & AGX_UAT_PTE_ADDR_MASK, 0x800040000ULL, "and resolves the leaf");

    /* A neighbouring VA in the same L3 is still unmapped: the walk is not
     * returning the last thing it saw. */
    check(agx_uat_walk(&uat, l1, va + AGX_UAT_PAGE_SIZE, &pte) == 0, "neighbour walks");
    check_eq(pte, 0, "neighbour is unmapped");

    /* An unreadable table is reported as a failed walk, never as unmapped. */
    check(agx_uat_walk(&uat, 0x40000000ULL, va, &pte) == -1,
          "a root outside memory fails the walk rather than reporting unmapped");
    check(agx_uat_walk(&uat, 0, va, &pte) == -1, "a null root is refused");
    check(agx_uat_walk(&uat, l1 + 1, va, &pte) == -1, "a misaligned root is refused");

    /* A table descriptor pointing somewhere unreadable also fails. */
    *cell(l1 + 8 * agx_uat_index(1, va)) = 0x40000000ULL | 3;
    check(agx_uat_walk(&uat, l1, va, &pte) == -1, "an unreadable L2 fails the walk");
}

static void test_uat_state_slots(void)
{
    struct agx_uat uat;
    uint64_t handle = RAM_BASE + 0x10000;
    uint64_t regs[5] = { 0 }, rc = 0xdead;

    memset(ram, 0, sizeof ram);
    agx_uat_init(&uat, &MEM);

    regs[0] = handle;
    regs[1] = RAM_BASE;             /* root0 */
    regs[2] = RAM_BASE + 0x4000;    /* root1 */
    regs[3] = 4;                    /* type */
    check(agx_uat_call(&uat, AGX_UAT_FN_INIT_STATE, regs, &rc) == 0, "INIT_STATE handled");
    check_eq(rc, 0, "INIT_STATE answers 0");

    /* The roots are published back into XNU's own state object. This is the
     * part that cannot be skipped: XNU reads these fields itself. */
    check_eq(*cell(handle + AGX_UAT_STATE_ROOT0), RAM_BASE, "root0 written back");
    check_eq(*cell(handle + AGX_UAT_STATE_ROOT1), RAM_BASE + 0x4000, "root1 written back");

    /* A handle that is not a plausible PA is refused, not stored. */
    regs[0] = 0x1234;
    check(agx_uat_call(&uat, AGX_UAT_FN_INIT_STATE, regs, &rc) == 0, "bad handle handled");
    check(uat.refused == 1, "and counted as refused");

    /* A call on an unknown handle is refused rather than creating state. */
    regs[0] = RAM_BASE + 0x20000;
    check(agx_uat_call(&uat, AGX_UAT_FN_DESTROY_STATE, regs, &rc) == 0, "DESTROY handled");
    check(uat.refused == 2, "DESTROY on an unknown handle is refused");
}

static void test_uat_ctx_id(void)
{
    struct agx_uat uat;
    uint64_t handle = RAM_BASE + 0x10000;
    uint64_t ctx_table = RAM_BASE + 0x20000;
    uint64_t regs[5] = { 0 }, rc = 0;

    memset(ram, 0, sizeof ram);
    agx_uat_init(&uat, &MEM);
    uat.ctx_table_pa = ctx_table;

    regs[0] = handle; regs[1] = RAM_BASE; regs[2] = RAM_BASE + 0x4000; regs[3] = 4;
    agx_uat_call(&uat, AGX_UAT_FN_INIT_STATE, regs, &rc);

    /* SET_CTX_ID publishes both TTBRs and asks for a global invalidation. */
    regs[0] = handle; regs[1] = 5;
    check(agx_uat_call(&uat, AGX_UAT_FN_SET_CTX_ID, regs, &rc) == 0, "SET_CTX_ID handled");
    check_eq(*cell(ctx_table + 5 * 16), agx_uat_ttbr(RAM_BASE, 5), "TTBR0 published");
    check_eq(*cell(ctx_table + 5 * 16 + 8), agx_uat_ttbr(RAM_BASE + 0x4000, 5),
             "TTBR1 published from root1 for type 4");
    check_eq(uat.tlbi_all, 1, "SET_CTX_ID asks for a global invalidation");

    /* Binding twice is refused. */
    check(agx_uat_call(&uat, AGX_UAT_FN_SET_CTX_ID, regs, &rc) == 0, "second bind handled");
    check(uat.refused == 1, "a state already bound is refused");

    /* A bound state cannot be destroyed -- that would leave the GMMU pointed
     * at an address space nothing owns. */
    regs[0] = handle;
    agx_uat_call(&uat, AGX_UAT_FN_DESTROY_STATE, regs, &rc);
    check(uat.refused == 2, "DESTROY of a bound state is refused");

    /* REMOVE_CTX_ID clears VALID only and keeps the payload. That is what
     * makes the reuse below legal, and requiring zero would break it. */
    check(agx_uat_call(&uat, AGX_UAT_FN_REMOVE_CTX_ID, regs, &rc) == 0, "REMOVE handled");
    check_eq(*cell(ctx_table + 5 * 16) & 1, 0, "TTBR0 invalidated");
    check_eq(*cell(ctx_table + 5 * 16) & AGX_UAT_TTBR_ADDR_MASK,
             RAM_BASE & AGX_UAT_TTBR_ADDR_MASK, "and its payload retained");
    check_eq(uat.tlbi_all, 2, "REMOVE_CTX_ID invalidates too");

    /* Now the slot can be reused, with a non-zero but invalid entry sitting
     * in it. This is the regression the m1n1-j700 comment was written for. */
    regs[1] = 5;
    check(agx_uat_call(&uat, AGX_UAT_FN_SET_CTX_ID, regs, &rc) == 0, "rebind handled");
    check(uat.refused == 2, "rebinding into an invalid-but-nonzero slot is allowed");
    check_eq(*cell(ctx_table + 5 * 16) & 1, 1, "and revalidates the slot");

    /* A context id outside the 64-slot table is refused. */
    agx_uat_call(&uat, AGX_UAT_FN_REMOVE_CTX_ID, regs, &rc);
    regs[1] = AGX_UAT_MAX_CTX;
    agx_uat_call(&uat, AGX_UAT_FN_SET_CTX_ID, regs, &rc);
    check(uat.refused == 3, "ctx_id >= 64 is refused");
}

static void test_uat_unmodelled_endpoints(void)
{
    struct agx_uat uat;
    uint64_t regs[5] = { 0 }, rc = 0;
    const uint32_t silent[] = {
        AGX_UAT_FN_MAP_BEGIN, AGX_UAT_FN_MAP_CONTINUE,
        AGX_UAT_FN_PREP_FW_UNMAP_BEGIN, AGX_UAT_FN_PREP_FW_UNMAP_CONTINUE,
        AGX_UAT_FN_UNMAP_BEGIN, AGX_UAT_FN_UNMAP_CONTINUE,
        AGX_UAT_FN_GET_INFO, AGX_UAT_FN_UNNAMED_13,
    };

    agx_uat_init(&uat, &MEM);
    for (unsigned i = 0; i < sizeof silent / sizeof *silent; i++)
        check(agx_uat_call(&uat, silent[i], regs, &rc) == -1,
              "an unmodelled endpoint returns -1 rather than answering 0");
    check_eq(uat.unhandled, sizeof silent / sizeof *silent,
             "and every one of them is counted");

    /* Out of range is distinct from unmodelled-but-real: both return -1, but
     * neither is allowed to run off the counter array. */
    check(agx_uat_call(&uat, AGX_UAT_ENDPOINTS, regs, &rc) == -1, "endpoint 14 refused");
    check(agx_uat_call(&uat, 0xffffffff, regs, &rc) == -1, "a wild endpoint is refused");

    check(strcmp(agx_uat_endpoint_name(AGX_UAT_FN_SET_CTX_ID), "SET_CTX_ID") == 0,
          "endpoint names resolve");
    check(strcmp(agx_uat_endpoint_name(13), "<unnamed 13>") == 0,
          "endpoint 13 is named as unknown, not invented");
}

/* ------------------------------------------------------------------- ASC */

static void mbox_send(struct agx_device *dev, unsigned which, uint32_t ep, uint64_t msg)
{
    uint64_t base = dev->asc[which].base + AGX_ASC_MBOX_OFFSET;

    agx_mmio_write(dev, base + AGX_ASC_MBOX_A2I_SEND0, 8, msg);
    agx_mmio_write(dev, base + AGX_ASC_MBOX_A2I_SEND1, 8, ep);
}

static int mbox_recv(struct agx_device *dev, unsigned which, uint32_t *ep, uint64_t *msg)
{
    uint64_t base = dev->asc[which].base + AGX_ASC_MBOX_OFFSET;
    uint64_t ctrl = 0, tag = 0;

    agx_mmio_read(dev, base + AGX_ASC_MBOX_I2A_CONTROL, 8, &ctrl);
    if (ctrl & AGX_ASC_MBOX_CTRL_EMPTY)
        return -1;
    agx_mmio_read(dev, base + AGX_ASC_MBOX_I2A_RECV1, 8, &tag);
    agx_mmio_read(dev, base + AGX_ASC_MBOX_I2A_RECV0, 8, msg);
    *ep = (uint32_t)tag;
    return 0;
}

static uint64_t mgmt_of(uint64_t type, uint64_t payload)
{
    return ((type & 0xffULL) << 52) | payload;
}

static void test_asc_windows(void)
{
    struct agx_device dev;
    uint64_t v = 0;

    agx_init(&dev, &MEM);

    /* Every other GPU window the ADT names lies INSIDE sgx reg[0]: the 64 MiB
     * `sgx` block is the whole GPU, and gfx-asc, gfx1-asc and both aux regs
     * are sub-windows of it. So window order in the decoder is load-bearing --
     * matching sgx first would swallow both mailboxes. These assertions fail
     * if anyone reorders it. */
    check(AGX_ASC0_BASE > AGX_SGX_BASE &&
          AGX_ASC0_BASE + AGX_ASC_SIZE <= AGX_SGX_BASE + AGX_SGX_SIZE,
          "gfx-asc is inside sgx reg[0]");
    check(AGX_ASC1_BASE > AGX_SGX_BASE &&
          AGX_ASC1_BASE + AGX_ASC_SIZE <= AGX_SGX_BASE + AGX_SGX_SIZE,
          "gfx1-asc is inside sgx reg[0]");
    check(AGX_SGX_SUB_BASE > AGX_SGX_BASE &&
          AGX_SGX_SUB_BASE + AGX_SGX_SUB_SIZE <= AGX_SGX_BASE + AGX_SGX_SIZE,
          "sgx reg[1] is inside sgx reg[0], as the ADT has it");

    /* The mailbox registers must reach the ASC, not the sgx catch-all. A
     * CPU_CONTROL write that lands in sgx would silently never boot anything. */
    check(agx_mmio_write(&dev, AGX_ASC0_BASE + AGX_ASC_CPU_CONTROL, 4, 0) == 0,
          "ASC0 CPU_CONTROL decodes to the ASC, not to sgx");
    check(agx_mmio_write(&dev, AGX_ASC1_BASE + AGX_ASC_CPU_CONTROL, 4, 0) == 0,
          "ASC1 CPU_CONTROL decodes to the ASC, not to sgx");
    check(agx_mmio_read(&dev, AGX_ASC0_BASE, 8, &v) == -1,
          "an undecoded offset in the ASC window is reported, not claimed");

    /* Addresses in sgx but in neither ASC fall through to the sgx catch-all. */
    check(agx_mmio_read(&dev, AGX_SGX_BASE, 8, &v) == -1, "sgx base decodes as sgx");
    check(agx_mmio_read(&dev, AGX_SGX_SUB_BASE, 8, &v) == -1, "so does sgx reg[1]");
    check(agx_mmio_read(&dev, AGX_SGX_BASE + AGX_SGX_SIZE, 8, &v) == -2,
          "one past sgx is not ours at all");
    check(agx_mmio_read(&dev, 0, 8, &v) == -2, "and neither is PA 0");

    /* Odd sizes are refused rather than widened. */
    check(agx_mmio_read(&dev, AGX_ASC0_BASE, 2, &v) == -2, "a 2-byte read is refused");
    check(agx_mmio_read(&dev, AGX_ASC0_BASE, 16, &v) == -2, "a 16-byte read is refused");
}

static void test_asc_boot(void)
{
    struct agx_device dev;
    uint64_t v = 0, msg = 0;
    uint32_t ep = 0;

    agx_init(&dev, &MEM);

    check(!agx_asc_booted(&dev.asc[0]), "the ASC starts stopped");
    check(mbox_recv(&dev, 0, &ep, &msg) == -1, "and says nothing");

    /* Starting the CPU makes the coprocessor announce itself. */
    agx_mmio_write(&dev, AGX_ASC0_BASE + AGX_ASC_CPU_CONTROL, 4,
                   AGX_ASC_CPU_CONTROL_START);
    agx_mmio_read(&dev, AGX_ASC0_BASE + AGX_ASC_CPU_CONTROL, 4, &v);
    check_eq(v, AGX_ASC_CPU_CONTROL_START, "CPU_CONTROL reads back");

    check(mbox_recv(&dev, 0, &ep, &msg) == 0, "a message appears");
    check_eq(ep, AGX_RTKIT_EP_MGMT, "on the management endpoint");
    check_eq((msg >> 52) & 0xff, AGX_MGMT_MSG_HELLO, "and it is HELLO");
    check_eq(msg & 0xffff, AGX_RTKIT_MIN_VERSION, "carrying the minimum version");
    check_eq((msg >> 16) & 0xffff, AGX_RTKIT_MAX_VERSION, "and the maximum");
    check(!agx_asc_booted(&dev.asc[0]), "not booted until the handshake finishes");

    /* Agree a version. */
    mbox_send(&dev, 0, AGX_RTKIT_EP_MGMT,
              mgmt_of(AGX_MGMT_MSG_HELLO_ACK, AGX_RTKIT_MAX_VERSION));
    agx_asc_step(&dev.asc[0]);
    check_eq(dev.asc[0].version, AGX_RTKIT_MAX_VERSION, "the version is agreed");

    check(mbox_recv(&dev, 0, &ep, &msg) == 0, "the endpoint map follows");
    check_eq((msg >> 52) & 0xff, AGX_MGMT_MSG_EPMAP, "and it is EPMAP");
    /* != 0, not a bare truncation: bit 51 does not survive the int conversion
     * `check` would otherwise perform, and the test would pass on nothing. */
    check((msg & (1ULL << 51)) != 0, "with DONE set, so no second window is promised");
    check((msg & (1ULL << AGX_RTKIT_EP_SYSLOG)) != 0, "syslog is offered");

    /* Start an endpoint; that completes the boot. */
    mbox_send(&dev, 0, AGX_RTKIT_EP_MGMT,
              mgmt_of(AGX_MGMT_MSG_START_EP, (uint64_t)AGX_RTKIT_EP_SYSLOG << 32));
    agx_asc_step(&dev.asc[0]);
    check(agx_asc_booted(&dev.asc[0]), "the coprocessor is now running");
    check(dev.asc[0].ep_started & (1U << AGX_RTKIT_EP_SYSLOG), "and the endpoint is up");

    /* A version outside the offered range is rejected, not accepted quietly. */
    {
        struct agx_device d2;

        agx_init(&d2, &MEM);
        agx_mmio_write(&d2, AGX_ASC0_BASE + AGX_ASC_CPU_CONTROL, 4,
                       AGX_ASC_CPU_CONTROL_START);
        mbox_recv(&d2, 0, &ep, &msg);
        mbox_send(&d2, 0, AGX_RTKIT_EP_MGMT, mgmt_of(AGX_MGMT_MSG_HELLO_ACK, 99));
        agx_asc_step(&d2.asc[0]);
        check_eq(d2.asc[0].version, 0, "an out-of-range version is not agreed");
        check(d2.asc[0].unknown_writes == 1, "and it is counted");
    }

    /* Stopping the CPU resets it, and the base survives the reset. */
    agx_mmio_write(&dev, AGX_ASC0_BASE + AGX_ASC_CPU_CONTROL, 4, 0);
    check(!agx_asc_booted(&dev.asc[0]), "clearing START stops the coprocessor");
    check_eq(dev.asc[0].base, AGX_ASC0_BASE, "and the window base survives");
    check_eq(dev.asc[0].ep_started, 0, "endpoint state is dropped");

    /* The second die is independent: starting die 0 did nothing to die 1. */
    check(!agx_asc_booted(&dev.asc[1]), "die 1 is untouched");
    check_eq(dev.asc[1].i2a.count, 0, "and silent");
}

static void test_asc_power_acks(void)
{
    struct agx_device dev;
    uint64_t msg = 0;
    uint32_t ep = 0;

    agx_init(&dev, &MEM);
    agx_mmio_write(&dev, AGX_ASC0_BASE + AGX_ASC_CPU_CONTROL, 4, AGX_ASC_CPU_CONTROL_START);
    mbox_recv(&dev, 0, &ep, &msg);           /* drain HELLO */

    mbox_send(&dev, 0, AGX_RTKIT_EP_MGMT, mgmt_of(AGX_MGMT_MSG_IOP_PWR_STATE, 0x220));
    agx_asc_step(&dev.asc[0]);
    check(mbox_recv(&dev, 0, &ep, &msg) == 0, "IOP_PWR_STATE is answered");
    check_eq((msg >> 52) & 0xff, AGX_MGMT_MSG_IOP_PWR_ACK, "with IOP_PWR_ACK");
    check_eq(msg & 0xffff, 0x220, "echoing the requested state");

    /* Traffic to an endpoint we never offered is counted, not acted on. */
    mbox_send(&dev, 0, 17, 0);
    agx_asc_step(&dev.asc[0]);
    check(dev.asc[0].unknown_writes >= 1, "traffic to an unserved endpoint is counted");
}

static void test_fifo_overflow(void)
{
    struct agx_fifo f;
    struct agx_msg m = { 0x1122334455667788ULL, 7 };
    struct agx_msg got;

    memset(&f, 0, sizeof f);
    for (unsigned i = 0; i < AGX_MBOX_DEPTH; i++) {
        m.msg0 = i;
        check(agx_fifo_push(&f, &m) == 0, "a push into a non-full FIFO succeeds");
    }
    check(agx_fifo_push(&f, &m) == -1, "a push into a full FIFO is refused");
    check_eq(f.overflow, 1, "and counted rather than wrapping over live data");

    /* FIFO order is preserved and the ring wraps correctly. */
    for (unsigned i = 0; i < AGX_MBOX_DEPTH; i++) {
        check(agx_fifo_pop(&f, &got) == 0, "a pop from a non-empty FIFO succeeds");
        check_eq(got.msg0, i, "in order");
    }
    check(agx_fifo_pop(&f, &got) == -1, "a pop from an empty FIFO is refused");
    check_eq(f.count, 0, "and the FIFO is empty");
}

int main(void)
{
    test_uat_geometry();
    test_uat_leaf_pte();
    test_uat_ttbr();
    test_uat_walk();
    test_uat_state_slots();
    test_uat_ctx_id();
    test_uat_unmodelled_endpoints();

    test_asc_windows();
    test_asc_boot();
    test_asc_power_acks();
    test_fifo_overflow();

    printf("\nNot modelled (a green run below means no known regressions,\n"
           "not that this matches Apple silicon):\n");
    for (const char *const *p = agx_unmodelled(); *p; p++)
        printf("  - %s\n", *p);

    printf("\n%d checks, %d failures (%u memory reads, %u writes)\n",
           checks, failures, reads, writes);
    return failures != 0;
}
