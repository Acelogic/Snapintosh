/* SPDX-License-Identifier: MIT */
/* Portions (constants and expressions marked [M1N1]) from m1n1, https://github.com/AsahiLinux/m1n1:
 * Copyright The Asahi Linux Contributors, MIT. */
/* The GPU page tables, and the 14 SPTM calls XNU manages them with. See agx.h.
 *
 * This is the half of AGX that has a deadline before anything renders. XNU
 * reaches the GPU MMU through SPTM domain 0, table 7, and those calls arrive at
 * EL2 as soon as the AGX kexts probe -- whether or not a GPU exists behind
 * them. Refusing them is a choice about what XNU is told, not a way to avoid
 * the question.
 *
 * The geometry, the descriptor encodings and the context-table layout are
 * m1n1-j700/src/sptm/uat.c's, which was reverse-engineered against this same
 * SoC. What is NOT taken from there is its side effects: that tree runs on real
 * Apple silicon and does cache maintenance for a real coprocessor, issues real
 * GMMU TLBIs, and reaches memory through an EL2 IOMMU alias. Here those become
 * counters and callbacks, so the table arithmetic can be tested on its own.
 */
#include "agx.h"

/* ------------------------------------------------------------- descriptors */

uint32_t agx_uat_index(uint32_t level, uint64_t va)
{
    uint32_t shift;

    switch (level) {
    case 1: shift = AGX_UAT_L1_SHIFT; break;
    case 2: shift = AGX_UAT_L2_SHIFT; break;
    case 3: shift = AGX_UAT_L3_SHIFT; break;
    default: return 0;
    }
    return (uint32_t)((va >> shift) & ((1ULL << AGX_UAT_INDEX_BITS) - 1));
}

/* options -> MAIR-ish attribute index. The permutation is not derivable; it is
 * the table m1n1-j700 recovered, and 0xff marks a combination real SPTM does
 * not produce (folded to 0 below, as it does). */
static const uint8_t uat_attr_table[16] = {
    0, 8, 9, 10, 4, 1, 0xff, 0xff,
    5, 0xff, 2, 0xff, 6, 7, 0xff, 3,
};

uint64_t agx_uat_leaf_pte(uint8_t type, uint64_t pa, uint64_t options)
{
    uint64_t idx = ((options >> 8) & 2ULL) |
                   ((options & 3ULL) << 2) |
                   ((options >> 8) & 1ULL);
    uint64_t attr = uat_attr_table[idx & 0xf];
    uint64_t perm = 3ULL;
    /* nG is set unless the state is one of the global types. `type & 10` is
     * bits 1 and 3 together, not a value comparison. */
    uint64_t os_ng = ((type & 10U) != 0) ? 0 : 0x800ULL;

    if (attr == 0xff)
        attr = 0;
    if (options & 8ULL)
        perm = 0xbULL;
    if (options & 4ULL)
        perm = 7ULL;

    return os_ng |
           ((attr & 3ULL) << 53) |
           (pa & AGX_UAT_PTE_ADDR_MASK) |
           perm |
           (((attr >> 2) & 3ULL) << 6) |
           AGX_UAT_VALID_LEAF_BITS;
}

uint64_t agx_uat_ttbr(uint64_t root_pa, uint32_t ctx_id)
{
    return (root_pa & AGX_UAT_TTBR_ADDR_MASK) |
           ((uint64_t)(ctx_id & 0xffff) << 48) | 1ULL;
}

/* ------------------------------------------------------------------ memory */

static int mem_read(struct agx_uat *uat, uint64_t pa, uint64_t *out)
{
    if (!uat->mem.read64)
        return -1;
    return uat->mem.read64(uat->mem.ctx, pa, out);
}

static int mem_write(struct agx_uat *uat, uint64_t pa, uint64_t value)
{
    if (!uat->mem.write64)
        return -1;
    return uat->mem.write64(uat->mem.ctx, pa, value);
}

/* A plausible physical address: 16K-aligned and not in the low page. The point
 * is to refuse sentinels and small integers that travel through the same
 * argument slots, not to validate against a real memory map. */
static int looks_like_pa(uint64_t pa)
{
    return pa >= AGX_UAT_PAGE_SIZE && (pa & (AGX_UAT_PAGE_SIZE - 1)) == 0;
}

int agx_uat_walk(struct agx_uat *uat, uint64_t root_pa, uint64_t va, uint64_t *pte_out)
{
    uint64_t table = root_pa;

    *pte_out = 0;
    if (!looks_like_pa(root_pa))
        return -1;

    for (uint32_t level = 1; level <= 3; level++) {
        uint64_t entry;
        uint64_t slot = table + 8ULL * agx_uat_index(level, va);

        if (mem_read(uat, slot, &entry) != 0)
            return -1;
        if ((entry & 1ULL) == 0)
            return 0;                       /* unmapped, and that is an answer */
        if (level == 3) {
            *pte_out = entry;
            return 0;
        }
        table = entry & AGX_UAT_PTE_ADDR_MASK;
        if (!looks_like_pa(table))
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------- state slots */

void agx_uat_init(struct agx_uat *uat, const struct agx_mem *mem)
{
    for (unsigned i = 0; i < sizeof(*uat); i++)
        ((unsigned char *)uat)[i] = 0;
    if (mem)
        uat->mem = *mem;
    for (unsigned i = 0; i < AGX_UAT_MAX_STATES; i++)
        uat->slot[i].ctx_id = AGX_UAT_CTX_NONE;
}

static struct agx_uat_state *find(struct agx_uat *uat, uint64_t handle)
{
    if (!handle)
        return 0;
    for (unsigned i = 0; i < AGX_UAT_MAX_STATES; i++)
        if (uat->slot[i].used && uat->slot[i].handle == handle)
            return &uat->slot[i];
    return 0;
}

static struct agx_uat_state *alloc(struct agx_uat *uat, uint64_t handle)
{
    struct agx_uat_state *s = find(uat, handle);

    if (s)
        return s;
    for (unsigned i = 0; i < AGX_UAT_MAX_STATES; i++) {
        if (uat->slot[i].used)
            continue;
        s = &uat->slot[i];
        s->handle = handle;
        s->root0_pa = 0;
        s->root1_pa = 0;
        s->options = 0;
        s->ctx_id = AGX_UAT_CTX_NONE;
        s->type = 0;
        s->used = 1;
        return s;
    }
    return 0;      /* out of slots: the caller refuses, it does not overwrite */
}

/* ---------------------------------------------------------------- endpoints */

/* INIT_STATE. regs[0] is the handle -- a pointer to XNU's own state object --
 * and the monitor publishes the roots back into it at the documented offsets.
 * That write-back is the part that cannot be skipped: XNU reads those fields. */
static uint64_t ep_init_state(struct agx_uat *uat, uint64_t *regs)
{
    struct agx_uat_state *s;
    uint64_t handle = regs[0];

    if (!looks_like_pa(handle)) {
        uat->refused++;
        return 0;
    }
    s = alloc(uat, handle);
    if (!s) {
        uat->refused++;
        return 0;
    }
    s->root0_pa = regs[1];
    s->root1_pa = regs[2];
    s->type = (uint8_t)regs[3];
    s->options = regs[4];

    if (mem_write(uat, handle + AGX_UAT_STATE_ROOT0, s->root0_pa) != 0 ||
        mem_write(uat, handle + AGX_UAT_STATE_ROOT1, s->root1_pa) != 0) {
        s->used = 0;
        uat->refused++;
        return 0;
    }
    return 0;
}

static uint64_t ep_destroy_state(struct agx_uat *uat, uint64_t *regs)
{
    struct agx_uat_state *s = find(uat, regs[0]);

    if (!s) {
        uat->refused++;
        return 0;
    }
    /* Refusing to destroy a state that is still bound to a context is the
     * behaviour m1n1-j700 records; dropping it here would leave the GMMU
     * pointed at an address space nothing owns any more. */
    if (s->ctx_id != AGX_UAT_CTX_NONE) {
        uat->refused++;
        return 0;
    }
    s->used = 0;
    s->handle = 0;
    return 0;
}

/* SET_CTX_ID. Publishes {TTBR0, TTBR1} into slot `ctx` of the context table
 * and asks for a global invalidation. Real SPTM requires the slot to be
 * *invalid* rather than zero, because REMOVE_CTX_ID clears only the valid bit
 * and leaves the old payload -- requiring zero rejects the normal reuse
 * sequence. That check is reproduced. */
static uint64_t ep_set_ctx_id(struct agx_uat *uat, uint64_t *regs)
{
    struct agx_uat_state *s = find(uat, regs[0]);
    uint64_t ctx = regs[1];
    uint64_t base, root1, live0, live1;

    if (!s || ctx >= AGX_UAT_MAX_CTX || s->ctx_id != AGX_UAT_CTX_NONE ||
        !uat->ctx_table_pa) {
        uat->refused++;
        return 0;
    }
    /* Type selects which root the upper half uses. Types this model has no
     * evidence for are refused rather than defaulted. */
    if (s->type == 1)
        root1 = s->root0_pa;
    else if (s->type == 4)
        root1 = s->root1_pa;
    else {
        uat->refused++;
        return 0;
    }
    if (!looks_like_pa(s->root0_pa) || !looks_like_pa(root1)) {
        uat->refused++;
        return 0;
    }

    base = uat->ctx_table_pa + ctx * AGX_UAT_CTX_STRIDE;
    if (mem_read(uat, base, &live0) != 0 || mem_read(uat, base + 8, &live1) != 0) {
        uat->refused++;
        return 0;
    }
    if ((live0 & 1ULL) != 0 || (live1 & 1ULL) != 0) {
        uat->refused++;
        return 0;
    }
    if (mem_write(uat, base, agx_uat_ttbr(s->root0_pa, (uint32_t)ctx)) != 0 ||
        mem_write(uat, base + 8, agx_uat_ttbr(root1, (uint32_t)ctx)) != 0) {
        uat->refused++;
        return 0;
    }
    s->ctx_id = (uint16_t)ctx;
    uat->tlbi_all++;
    return 0;
}

static uint64_t ep_remove_ctx_id(struct agx_uat *uat, uint64_t *regs)
{
    struct agx_uat_state *s = find(uat, regs[0]);
    uint64_t base, v;

    if (!s || s->ctx_id == AGX_UAT_CTX_NONE) {
        uat->refused++;
        return 0;
    }
    if (uat->ctx_table_pa) {
        base = uat->ctx_table_pa + (uint64_t)s->ctx_id * AGX_UAT_CTX_STRIDE;
        /* Clear VALID only. The payload stays, and SET_CTX_ID above depends
         * on that being what it finds. */
        if (mem_read(uat, base, &v) == 0)
            mem_write(uat, base, v & ~1ULL);
        if (mem_read(uat, base + 8, &v) == 0)
            mem_write(uat, base + 8, v & ~1ULL);
    }
    s->ctx_id = AGX_UAT_CTX_NONE;
    uat->tlbi_all++;
    return 0;
}

/* MAP_TABLE / UNMAP_TABLE install and remove one table descriptor. The leaf
 * path (MAP_BEGIN and its CONTINUE) walks a segment list and is not modelled;
 * see agx_unmodelled(). */
static uint64_t ep_map_table(struct agx_uat *uat, uint64_t *regs)
{
    struct agx_uat_state *s = find(uat, regs[0]);
    uint64_t slot_pa = regs[1], value = regs[2];

    if (!s || !looks_like_pa(slot_pa & ~7ULL)) {
        uat->refused++;
        return 0;
    }
    if (mem_write(uat, slot_pa, value) != 0) {
        uat->refused++;
        return 0;
    }
    if (s->ctx_id != AGX_UAT_CTX_NONE)
        uat->tlbi_asid++;
    return 0;
}

static uint64_t ep_unmap_table(struct agx_uat *uat, uint64_t *regs)
{
    struct agx_uat_state *s = find(uat, regs[0]);
    uint64_t slot_pa = regs[1];

    if (!s || !looks_like_pa(slot_pa & ~7ULL)) {
        uat->refused++;
        return 0;
    }
    if (mem_write(uat, slot_pa, 0) != 0) {
        uat->refused++;
        return 0;
    }
    if (s->ctx_id != AGX_UAT_CTX_NONE)
        uat->tlbi_asid++;
    return 0;
}

int agx_uat_call(struct agx_uat *uat, uint32_t endpoint, uint64_t *regs, uint64_t *rc_out)
{
    uint64_t rc = 0;

    if (endpoint >= AGX_UAT_ENDPOINTS) {
        uat->unhandled++;
        return -1;
    }
    uat->calls[endpoint]++;

    switch (endpoint) {
    case AGX_UAT_FN_INIT_STATE:    rc = ep_init_state(uat, regs);    break;
    case AGX_UAT_FN_DESTROY_STATE: rc = ep_destroy_state(uat, regs); break;
    case AGX_UAT_FN_MAP_TABLE:     rc = ep_map_table(uat, regs);     break;
    case AGX_UAT_FN_UNMAP_TABLE:   rc = ep_unmap_table(uat, regs);   break;
    case AGX_UAT_FN_SET_CTX_ID:    rc = ep_set_ctx_id(uat, regs);    break;
    case AGX_UAT_FN_REMOVE_CTX_ID: rc = ep_remove_ctx_id(uat, regs); break;
    default:
        /* MAP_BEGIN/CONTINUE, the two PREP_FW_UNMAP halves, UNMAP_BEGIN/
         * CONTINUE, GET_INFO, and the unnamed 13. Counted, then handed back
         * unhandled -- an endpoint that silently answers 0 is the failure mode
         * this whole arrangement exists to avoid. */
        uat->unhandled++;
        return -1;
    }

    if (rc_out)
        *rc_out = rc;
    return 0;
}

const char *agx_uat_endpoint_name(uint32_t endpoint)
{
    static const char *const names[AGX_UAT_ENDPOINTS] = {
        "INIT_STATE", "DESTROY_STATE", "MAP_TABLE", "UNMAP_TABLE",
        "MAP_BEGIN", "MAP_CONTINUE", "PREP_FW_UNMAP_BEGIN",
        "PREP_FW_UNMAP_CONTINUE", "UNMAP_BEGIN", "UNMAP_CONTINUE",
        "SET_CTX_ID", "REMOVE_CTX_ID", "GET_INFO", "<unnamed 13>",
    };
    return endpoint < AGX_UAT_ENDPOINTS ? names[endpoint] : "<out of range>";
}
