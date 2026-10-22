/* SPDX-License-Identifier: MIT */
/* Portions (constants and expressions marked [M1N1]) from m1n1, https://github.com/AsahiLinux/m1n1:
 * Copyright The Asahi Linux Contributors, MIT. */
/* A virtual Apple AGX GPU, for the stock AGX kexts to bind to.
 *
 * Two separate things live behind that name, and they are separate here:
 *
 *   1. The GMMU/UAT -- the GPU's page tables. XNU never writes them. It asks
 *      the monitor to, through SPTM domain 0, table 7, and the kernelcache has
 *      14 stubs for it. Those calls arrive at EL2 whether or not anything
 *      resembling a GPU exists, which is why this half has the near deadline.
 *      See agx-uat.c.
 *
 *   2. The GFX coprocessor -- an ASC (`iop,ascwrap-v6`) running Apple's own
 *      firmware, reached through a mailbox and then RTKit. Command submission
 *      is a ring in shared memory that the firmware reads; the kext does not
 *      poke a command register. See agx-asc.c.
 *
 * Everything here is addressed by physical address and reaches memory through
 * callbacks, so the whole model runs natively under sanitizers in test-agx.c
 * with no hardware and no EL2 -- the same arrangement shadow/mmu.h uses.
 *
 * WHAT IS EVIDENCE HERE. Every address and bit in this file came from one of:
 *   [ADT]  DeviceTree.j700ap, printed by gpu/agx-inventory.py --dt
 *   [KC]   kernelcache.release.mac17p, printed by gpu/agx-inventory.py
 *   [M1N1] m1n1 (AsahiLinux) and the author's J700 research fork (asc.c, rtkit.c, sptm/uat.c), which was
 *          reverse-engineered against this same SoC
 * Anything with no tag is a guess and must not be here. agx_unmodelled() lists
 * the things known to exist that are deliberately absent.
 */
#pragma once
#include <stdint.h>

/* ------------------------------------------------------------------ memory */

/* Read/write 8 bytes of guest physical memory. Non-zero means the access could
 * not be performed, which is not the same as reading zero and must never be
 * collapsed into it: a UAT endpoint that cannot read a table has to refuse,
 * not install a mapping over whatever was in the register. */
typedef int (*agx_read64_fn)(void *ctx, uint64_t pa, uint64_t *out);
typedef int (*agx_write64_fn)(void *ctx, uint64_t pa, uint64_t value);

struct agx_mem {
    agx_read64_fn read64;
    agx_write64_fn write64;
    void *ctx;
};

/* ------------------------------------------------------- MMIO windows [ADT] */

/* /device-tree/arm-io/sgx, compatible "gpu,t8140". Two reg entries, and the
 * second lies inside the first -- Apple names a sub-window separately rather
 * than describing a second block. Both are reproduced; nothing is merged. */
#define AGX_SGX_BASE        0x270000000ULL
#define AGX_SGX_SIZE          0x4000000ULL
#define AGX_SGX_SUB_BASE    0x270d00000ULL
#define AGX_SGX_SUB_SIZE       0x12c000ULL

/* /device-tree/arm-io/gfx-asc and gfx1-asc, compatible "iop,ascwrap-v6".
 * Two dies, one ASC each, each with its own firmware image. */
#define AGX_ASC0_BASE       0x272600000ULL
#define AGX_ASC1_BASE       0x272e00000ULL
#define AGX_ASC_SIZE            0x88000ULL
#define AGX_ASC0_AUX_BASE   0x272050000ULL   /* reg[1], 8 bytes, purpose unknown */
#define AGX_ASC1_AUX_BASE   0x272850000ULL
#define AGX_ASC_AUX_SIZE             8ULL

/* The mailbox block sits at +0x8000 inside the ASC window. [M1N1 asc.c:53] */
#define AGX_ASC_MBOX_OFFSET     0x8000ULL

/* The two offsets /device-tree/arm-io/sgx names in `meta-sw-interrupt`:
 *     0x1014048 0x3 0x1014248 0x3 0x4000
 * Both land inside sgx reg[0]. The pairs are read as (offset, value) and the
 * trailing 0x4000 as a stride, but THAT READING IS NOT ESTABLISHED -- see
 * agx_unmodelled(). The offsets themselves are quoted, not inferred. */
#define AGX_SGX_META_SW_IRQ0    0x1014048ULL
#define AGX_SGX_META_SW_IRQ1    0x1014248ULL

/* ------------------------------------------------- ASC mailbox registers [M1N1] */

#define AGX_ASC_CPU_CONTROL         0x44
#define AGX_ASC_CPU_CONTROL_START   0x10

#define AGX_ASC_MBOX_CTRL_FULL      (1U << 16)
#define AGX_ASC_MBOX_CTRL_EMPTY     (1U << 17)

#define AGX_ASC_MBOX_A2I_CONTROL    0x110   /* AP -> IOP */
#define AGX_ASC_MBOX_A2I_SEND0      0x800
#define AGX_ASC_MBOX_A2I_SEND1      0x808
#define AGX_ASC_MBOX_A2I_RECV0      0x810
#define AGX_ASC_MBOX_A2I_RECV1      0x818

#define AGX_ASC_MBOX_I2A_CONTROL    0x114   /* IOP -> AP */
#define AGX_ASC_MBOX_I2A_SEND0      0x820
#define AGX_ASC_MBOX_I2A_SEND1      0x828
#define AGX_ASC_MBOX_I2A_RECV0      0x830
#define AGX_ASC_MBOX_I2A_RECV1      0x838

/* An ASC message is 96 bits: 64 of payload and a 32-bit tag whose low 8 bits
 * are the RTKit endpoint. [M1N1 asc.h, rtkit.c] */
struct agx_msg {
    uint64_t msg0;
    uint32_t msg1;
};

#define AGX_MBOX_DEPTH 16

struct agx_fifo {
    struct agx_msg slot[AGX_MBOX_DEPTH];
    uint32_t head, tail, count;
    uint32_t overflow;        /* messages dropped because the FIFO was full */
};

/* ------------------------------------------------------- RTKit [M1N1 rtkit.c] */

#define AGX_RTKIT_EP_MGMT       0
#define AGX_RTKIT_EP_CRASHLOG   1
#define AGX_RTKIT_EP_SYSLOG     2
#define AGX_RTKIT_EP_DEBUG      3
#define AGX_RTKIT_EP_IOREPORT   4
#define AGX_RTKIT_EP_OSLOG      8

#define AGX_MGMT_MSG_HELLO          1
#define AGX_MGMT_MSG_HELLO_ACK      2
#define AGX_MGMT_MSG_START_EP       5
#define AGX_MGMT_MSG_IOP_PWR_STATE  6
#define AGX_MGMT_MSG_IOP_PWR_ACK    7
#define AGX_MGMT_MSG_EPMAP          8
#define AGX_MGMT_MSG_AP_PWR_STATE   0xb

#define AGX_RTKIT_MIN_VERSION  11
#define AGX_RTKIT_MAX_VERSION  12

/* How far the coprocessor has got. The stock kext calls AGXFirmware::
 * isGFXBooted() [KC], so this is the state that question reads. */
enum agx_asc_state {
    AGX_ASC_OFF = 0,        /* CPU_CONTROL.START clear */
    AGX_ASC_BOOTING,        /* started, HELLO sent, waiting for HELLO_ACK */
    AGX_ASC_EPMAP,          /* version agreed, publishing the endpoint map */
    AGX_ASC_RUNNING,        /* endpoints started; ready for traffic */
};

struct agx_asc {
    uint64_t base;               /* window base PA (AGX_ASC0_BASE or ASC1) */
    uint32_t cpu_control;
    enum agx_asc_state state;
    struct agx_fifo a2i;         /* what the AP wrote, waiting for us */
    struct agx_fifo i2a;         /* what we produced, waiting for the AP */
    uint32_t ep_started;         /* bitmap of endpoints the AP has started */
    uint32_t version;            /* agreed RTKit version, 0 until HELLO_ACK */
    uint32_t unknown_writes;     /* writes this model decoded nowhere */
};

/* --------------------------------------------------------------- UAT [M1N1] */

/* The GPU page tables are 16K-granule, three levels, 11 index bits each:
 *     L1 = va[46:36]   L2 = va[35:25]   L3 = va[24:14]     [M1N1 uat.c:604-617]
 * Same granule XNU uses for the CPU, which the hypervisor already cannot walk
 * natively -- but the GPU side is not walked by this machine's MMU at all, so
 * unlike shadow/mmu.c there is nothing to re-translate. These tables are data. */
#define AGX_UAT_PAGE_SHIFT  14
#define AGX_UAT_PAGE_SIZE   (1ULL << AGX_UAT_PAGE_SHIFT)
#define AGX_UAT_INDEX_BITS  11
#define AGX_UAT_L1_SHIFT    36
#define AGX_UAT_L2_SHIFT    25
#define AGX_UAT_L3_SHIFT    14

#define AGX_UAT_PTE_ADDR_MASK   0x0000fffffffff000ULL
#define AGX_UAT_VALID_LEAF_BITS 0x0080000000000400ULL
#define AGX_UAT_TTBR_ADDR_MASK  0x000003ffffffc000ULL

/* The GMMU context table: 64 slots of {TTBR0, TTBR1}, 16 bytes each, which
 * SET_CTX_ID writes and REMOVE_CTX_ID invalidates. [M1N1 uat.c:1378-1449] */
#define AGX_UAT_MAX_CTX     64
#define AGX_UAT_CTX_STRIDE  16
#define AGX_UAT_CTX_NONE    0xffffU

/* Byte offsets inside the state object XNU passes as regs[0]. The handle is a
 * pointer to XNU's own memory and the monitor writes back into it, so these
 * are part of the ABI, not bookkeeping. [M1N1 uat.c:15-27] */
#define AGX_UAT_STATE_ROOT0         0x08
#define AGX_UAT_STATE_ROOT1         0x10
#define AGX_UAT_STATE_CTX_ID        0x18
#define AGX_UAT_STATE_OPTIONS       0x40
#define AGX_UAT_STATE_FLUSH_LEVEL   0x44

/* The 14 endpoints of SPTM domain 0, table 7, as the kernelcache's own stubs
 * enumerate them. 0..12 carry the names m1n1-j700/src/sptm/private.h gives
 * them; 13 has a stub in mac17p and no name anywhere, and is not guessed at. */
#define AGX_UAT_FN_INIT_STATE             0
#define AGX_UAT_FN_DESTROY_STATE          1
#define AGX_UAT_FN_MAP_TABLE              2
#define AGX_UAT_FN_UNMAP_TABLE            3
#define AGX_UAT_FN_MAP_BEGIN              4
#define AGX_UAT_FN_MAP_CONTINUE           5
#define AGX_UAT_FN_PREP_FW_UNMAP_BEGIN    6
#define AGX_UAT_FN_PREP_FW_UNMAP_CONTINUE 7
#define AGX_UAT_FN_UNMAP_BEGIN            8
#define AGX_UAT_FN_UNMAP_CONTINUE         9
#define AGX_UAT_FN_SET_CTX_ID             10
#define AGX_UAT_FN_REMOVE_CTX_ID          11
#define AGX_UAT_FN_GET_INFO               12
#define AGX_UAT_FN_UNNAMED_13             13
#define AGX_UAT_ENDPOINTS                 14

#define AGX_UAT_MAX_STATES 32

struct agx_uat_state {
    uint64_t handle;        /* XNU's state object PA; 0 means the slot is free */
    uint64_t root0_pa;
    uint64_t root1_pa;
    uint64_t options;
    uint16_t ctx_id;        /* AGX_UAT_CTX_NONE until SET_CTX_ID */
    uint8_t type;
    uint8_t used;
};

struct agx_uat {
    struct agx_mem mem;
    uint64_t ctx_table_pa;              /* the 64-slot GMMU context table */
    struct agx_uat_state slot[AGX_UAT_MAX_STATES];
    uint64_t calls[AGX_UAT_ENDPOINTS];  /* per-endpoint counters */
    uint64_t refused;                   /* calls rejected on validation */
    uint64_t unhandled;                 /* calls to endpoints not modelled */
    uint32_t tlbi_asid;                 /* ASID-scoped invalidations requested */
    uint32_t tlbi_all;                  /* global invalidations requested */
};

/* ------------------------------------------------------------ the whole device */

struct agx_device {
    struct agx_asc asc[2];
    struct agx_uat uat;
    uint64_t mmio_reads, mmio_writes;
    uint64_t mmio_undecoded;            /* accesses in range that decode nowhere */
};

void agx_init(struct agx_device *dev, const struct agx_mem *mem);

/* MMIO. `size` is 4 or 8; anything else is refused rather than widened.
 * Returns 0 if the access was decoded, -1 if the address is ours but no
 * register lives there, and -2 if the address is not ours at all. A read that
 * returns -1 still writes 0 to *out, because that is what an unclaimed Apple
 * MMIO window does, but it is counted so the count can be looked at. */
int agx_mmio_read(struct agx_device *dev, uint64_t pa, unsigned size, uint64_t *out);
int agx_mmio_write(struct agx_device *dev, uint64_t pa, unsigned size, uint64_t value);

/* --------------------------------------------------------------- ASC / RTKit */

void agx_asc_init(struct agx_asc *asc, uint64_t base);

/* Run the coprocessor: drain whatever the AP put in the A2I mailbox and
 * produce the replies RTKit requires. Returns how many messages it consumed.
 * Nothing here is timed; the model advances only when this is called. */
int agx_asc_step(struct agx_asc *asc);

int agx_asc_booted(const struct agx_asc *asc);

/* FIFO primitives, exposed because the tests drive them directly. */
int agx_fifo_push(struct agx_fifo *f, const struct agx_msg *m);
int agx_fifo_pop(struct agx_fifo *f, struct agx_msg *m);

/* ----------------------------------------------------------------- UAT calls */

void agx_uat_init(struct agx_uat *uat, const struct agx_mem *mem);

/* Index into the table at `level` (1, 2 or 3) for `va`. */
uint32_t agx_uat_index(uint32_t level, uint64_t va);

/* The leaf descriptor SPTM installs for `pa` under `options`, for a state of
 * `type`. Bit-for-bit the expression in m1n1-j700's uat_leaf_pte(). */
uint64_t agx_uat_leaf_pte(uint8_t type, uint64_t pa, uint64_t options);

/* The TTBR value SET_CTX_ID writes into the context table. */
uint64_t agx_uat_ttbr(uint64_t root_pa, uint32_t ctx_id);

/* Walk `va` through the 16K tables rooted at `root_pa`, in software.
 * Returns 0 and sets *pte_out to the leaf (0 if unmapped), or -1 if a table
 * could not be read -- which is not the same as unmapped. */
int agx_uat_walk(struct agx_uat *uat, uint64_t root_pa, uint64_t va, uint64_t *pte_out);

/* Dispatch one SPTM domain-0 table-7 call. `regs` is x0..x4 as the stub
 * marshalled them; regs[0] is the handle for every endpoint except INIT_STATE.
 * Returns 0 if the endpoint is modelled (with *rc_out set to what XNU is told),
 * and -1 if it is not -- the caller must then decide, loudly, what to do. */
int agx_uat_call(struct agx_uat *uat, uint32_t endpoint, uint64_t *regs, uint64_t *rc_out);

const char *agx_uat_endpoint_name(uint32_t endpoint);

/* ------------------------------------------------------------------ honesty */

/* Behaviours known to exist and deliberately not modelled, in the shape
 * emuasi/device uses: a NULL-terminated list every test run prints, so a green
 * result reads as "no known regressions", never as "matches hardware".
 * Removing an entry needs evidence, not an argument. */
const char *const *agx_unmodelled(void);
