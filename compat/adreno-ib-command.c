/* SPDX-License-Identifier: MIT */
/* ADRENO_KCMD_IB kext core. Contract, policy and the list of what is deliberately not enforced: adreno-ib-command.h.
 * Every table comes from generated headers: AdrenoA8xxRegs.h (Mesa XML: registers, fields, enums, PM4 headers)
 * and adreno-ib-tables.h (q1n1: CP_PROTECT ranges). No register number is typed here. */
#define A8XX_REGS_TABLES 1
#include "../gpu/adreno-kext/include/AdrenoA8xxRegs.h"
#include "adreno-ib-command.h"
#include "adreno-ib-tables.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the kernel-command wire format is little endian and relocation records are read in place"
#endif

#define NONE ADRENO_IB_RELOC_NO_HI
#define KIND(k) (1u << (k))
#define READ_KINDS (KIND(ADRENO_IB_RELOC_RESOURCE) | KIND(ADRENO_IB_RELOC_PACKAGE) | KIND(ADRENO_IB_RELOC_ZERO))
#define RING_LIMIT ADRENO_RING_DWORDS(ADRENO_RING_BUFSZ)

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static int bit_get(const uint64_t *map, uint64_t i) { return (int)((map[i >> 6] >> (i & 63)) & 1u); }
static void bit_set(uint64_t *map, uint64_t i) { map[i >> 6] |= 1ull << (i & 63); }
static void bit_clear(uint64_t *map, uint64_t i) { map[i >> 6] &= ~(1ull << (i & 63)); }

/* The source is shared with user space: every byte is loaded exactly once and only the copy is parsed. */
static void copy_in(uint8_t *to, const void *from, uint64_t bytes)
{
    if (!(((uintptr_t)to | (uintptr_t)from | bytes) & 3)) {
        const volatile uint32_t *source = (const volatile uint32_t *)from;
        uint32_t *copy = (uint32_t *)(void *)to;
        for (uint64_t i = 0; i < bytes / 4; i++) copy[i] = source[i];
        return;
    }
    const volatile uint8_t *source = (const volatile uint8_t *)from;
    for (uint64_t i = 0; i < bytes; i++) to[i] = source[i];
}

static int fail(struct adreno_ib_work *w, int error, uint64_t at)
{
    w->last_error = error;
    w->error_at = (uint32_t)at;
    return error;
}

/* ---- address fields -------------------------------------------------------------------------------------------- */
struct field {
    uint32_t lo_address;   /* lo bits that hold address bits: a null field has none of them set */
    uint32_t lo_other;     /* lo bits below the alignment that another field of the same dword may use */
    uint32_t hi_address;   /* hi bits that hold address bits */
    uint8_t hi_bits, align, kinds, write;
};

/* Policy of the 64-bit address registers (adreno-ib-command.h). Unknown base: 0 (tables_init then fails closed). */
static int register_field(uint32_t base, struct field *f, int *textures)
{
    *f = (struct field){0xffffffffu, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64, ADRENO_IB_ALIGN_LOG2_TEXTURE,
                        KIND(ADRENO_IB_RELOC_RESOURCE), 0};
    *textures = 0;
    switch (base) {
    case A8XX_REG_RB_MRT_BASE: case A8XX_REG_RB_A2D_DEST_BUFFER_BASE: case A8XX_REG_RB_DEPTH_BUFFER_BASE:
    case A8XX_REG_GRAS_LRZ_BUFFER_BASE: case A8XX_REG_GRAS_LRZ_FAST_CLEAR_BUFFER_BASE:
    case A8XX_REG_SP_VS_PVT_MEM_BASE: case A8XX_REG_SP_PS_PVT_MEM_BASE: case A8XX_REG_SP_CS_PVT_MEM_BASE:
        f->write = 1;                  /* the GPU writes through these: RESOURCE with WRITE access only */
        return 1;
    case A8XX_REG_RB_COLOR_FLAG_BUFFER_ADDR:   /* Mesa writes the RT base here even without UBWC (design 5.1) */
    case A8XX_REG_TPL1_A2D_SRC_TEXTURE_BASE: case A8XX_REG_TPL1_A2D_SRC_TEXTURE_FLAG_BASE:
        return 1;
    case A8XX_REG_VFD_VERTEX_BUFFER_BASE:
        f->align = ADRENO_IB_ALIGN_LOG2_VERTEX;
        f->kinds |= KIND(ADRENO_IB_RELOC_PACKAGE);
        return 1;
    case A8XX_REG_SP_VS_BASE: case A8XX_REG_SP_PS_BASE: case A8XX_REG_SP_CS_BASE:
        f->align = ADRENO_IB_ALIGN_LOG2_SHADER;
        f->kinds |= KIND(ADRENO_IB_RELOC_PACKAGE);
        return 1;
    case A8XX_REG_SP_PS_SAMPLER_BASE: case A8XX_REG_SP_CS_SAMPLER_BASE:
        f->align = ADRENO_IB_ALIGN_LOG2_SAMPLER;
        f->kinds = KIND(ADRENO_IB_RELOC_PACKAGE);
        return 1;
    case A8XX_REG_SP_PS_TEXMEMOBJ_BASE: case A8XX_REG_SP_CS_TEXMEMOBJ_BASE:
        f->kinds = KIND(ADRENO_IB_RELOC_PACKAGE);
        *textures = 1;
        return 1;
    case A8XX_REG_SP_CS_UAV_BASE:
        f->kinds = KIND(ADRENO_IB_RELOC_PACKAGE);
        *textures = 2;                 /* descriptor table is read; image bases inside it require WRITE */
        return 1;
    case A8XX_REG_SP_GFX_BINDLESS_BASE_DESCRIPTOR:
        f->lo_address = (uint32_t)A8XX_REG_SP_GFX_BINDLESS_BASE_DESCRIPTOR__ADDR__MASK;
        f->lo_other = (uint32_t)A8XX_REG_SP_GFX_BINDLESS_BASE_DESCRIPTOR__DESC_SIZE__MASK;
        f->kinds = KIND(ADRENO_IB_RELOC_ZERO);      /* empty sets: descriptors elsewhere would be unchecked */
        return 1;
    case A8XX_REG_TPL1_GFX_BORDER_COLOR_BASE: case A8XX_REG_TPL1_CS_BORDER_COLOR_BASE:
        f->kinds = KIND(ADRENO_IB_RELOC_ZERO) | KIND(ADRENO_IB_RELOC_PACKAGE);
        return 1;
    }
    return 0;
}

static const struct a8xx_reg_info *address_row(const struct adreno_ib_tables *t, uint32_t reg, uint32_t *half)
{
    for (uint32_t n = 0; n < t->address_rows; n++) {
        const struct a8xx_reg_info *r = &a8xx_ib_regs[t->address_row[n]];
        if (reg < r->offset) continue;
        uint32_t delta = reg - r->offset, stride = r->count > 1 ? r->stride : 2;
        if (delta / stride < r->count && delta % stride < 2) {
            *half = delta % stride;
            return r;
        }
    }
    return 0;
}

int adreno_ib_tables_init(struct adreno_ib_tables *t)
{
    if (!t) return ADRENO_IB_E_FORMAT;
    for (uint32_t i = 0; i < ADRENO_IB_REG_LIMIT / 64; i++) t->allowed[i] = t->address[i] = 0;
    t->address_rows = t->allowed_offsets = 0;
    uint32_t known = 0;
    for (uint32_t row = 0; row < A8XX_REGS_IB_COUNT; row++) {
        const struct a8xx_reg_info *r = &a8xx_ib_regs[row];
        uint32_t halves = r->bits == 64 ? 2 : 1;
        if (!r->count || (r->bits != 32 && r->bits != 64) || (r->count > 1 && r->stride < halves))
            return ADRENO_IB_E_FORMAT;
        if (r->flags & A8XX_REG_FLAG_ADDRESS) {
            struct field f;
            int textures;
            if (r->bits != 64 || t->address_rows >= ADRENO_IB_ADDRESS_ROWS || !register_field(r->offset, &f, &textures))
                return ADRENO_IB_E_FORMAT;
            /* Every register Mesa marks GPU-written needs WRITE here, except the documented flag-buffer case. */
            if (!!(r->flags & A8XX_REG_FLAG_WADDRESS) != (f.write || r->offset == A8XX_REG_RB_COLOR_FLAG_BUFFER_ADDR))
                return ADRENO_IB_E_FORMAT;
            t->address_row[t->address_rows++] = (uint16_t)row;
        }
        for (uint32_t i = 0; i < r->count; i++)
            for (uint32_t h = 0; h < halves; h++) {
                uint64_t offset = r->offset + (uint64_t)i * r->stride + h;
                if (offset >= ADRENO_IB_REG_LIMIT) return ADRENO_IB_E_FORMAT;
                if (!bit_get(t->allowed, offset)) { bit_set(t->allowed, offset); known++; }
                if (r->flags & A8XX_REG_FLAG_ADDRESS) bit_set(t->address, offset);
            }
    }
    if (known != ADRENO_IB_KNOWN_OFFSETS) return ADRENO_IB_E_FORMAT;   /* the two generators no longer agree */
    uint32_t removed = 0;
    for (uint32_t p = 0; p < ADRENO_IB_PROTECT_COUNT; p++) {
        uint64_t first = ADRENO_IB_PROTECT_REG(adreno_ib_protect[p]);
        uint64_t last = first + ADRENO_IB_PROTECT_LEN(adreno_ib_protect[p]);
        if (ADRENO_IB_PROTECT_LAST_SPAN_INF && p + 1 == ADRENO_IB_PROTECT_COUNT) last = ADRENO_IB_REG_LIMIT - 1;
        for (uint64_t o = first; o <= last && o < ADRENO_IB_REG_LIMIT; o++)
            if (bit_get(t->allowed, o)) { bit_clear(t->allowed, o); removed++; }
    }
    if (removed != ADRENO_IB_KNOWN_PROTECTED) return ADRENO_IB_E_FORMAT;
    t->allowed_offsets = known - removed;
    return 0;
}

int adreno_ib_work_init(struct adreno_ib_work *w, const struct adreno_ib_tables *tables, uint8_t *arena,
                        uint64_t arena_gpu, uint64_t arena_bytes, struct adreno_ib_reloc *relocs, uint16_t *order,
                        uint8_t *used, uint32_t reloc_capacity, uint64_t *targets)
{
    if (!w) return ADRENO_LIST_E_ARGUMENT;
    *w = (struct adreno_ib_work){0};
    if (!tables || !tables->allowed_offsets || !arena || !relocs || !order || !used || !targets)
        return ADRENO_LIST_E_ARGUMENT;
    if (((uintptr_t)arena & 63) || (arena_gpu & 0x3fff) || arena_bytes < ADRENO_IB_PACKAGE_AT + ADRENO_IB_MAX_PACKAGE ||
        arena_gpu < ADRENO_WINDOW_BASE || arena_gpu >= ADRENO_WINDOW_END || arena_bytes > ADRENO_WINDOW_END - arena_gpu ||
        !reloc_capacity || reloc_capacity > ADRENO_IB_MAX_RELOCS)
        return ADRENO_IB_E_CAPACITY;
#if ADRENO_VA_WIDE
    /* agents/gpu-va-wide V11: the zero page and the package stay below 4 GiB, where lo-only PACKAGE/ZERO
     * relocations (adreno-submit.h NO_HI) still resolve. A higher arena leaves IB off; FENCE/FILL32 go on. */
    if (arena_gpu >= ADRENO_LOW_WINDOW_END || arena_bytes > ADRENO_LOW_WINDOW_END - arena_gpu)
        return ADRENO_IB_E_CAPACITY;
#endif
    for (uint32_t i = 0; i < ADRENO_IB_ZERO_BYTES; i++) arena[i] = 0;
    *w = (struct adreno_ib_work){.arena = arena, .arena_gpu = arena_gpu, .arena_bytes = arena_bytes,
        .relocs = relocs, .order = order, .used = used, .reloc_capacity = reloc_capacity,
        .state = ADRENO_IB_STATE_READY, .targets = targets, .tables = tables};
    return 0;
}

static void stage_fields(struct adreno_ib_work *w, const struct adreno_ib_command *c)
{
    w->command = *c;
    w->package = w->arena + ADRENO_IB_PACKAGE_AT;
    w->package_gpu = w->arena_gpu + ADRENO_IB_PACKAGE_AT;
    w->data_offset = adreno_ib_data_offset(c->ib_dwords);
    w->package_bytes = adreno_ib_package_bytes(c->ib_dwords, c->data_bytes);
}

int adreno_ib_stage(struct adreno_ib_work *w, const void *command, uint64_t available)
{
    if (!w || !command) return ADRENO_LIST_E_ARGUMENT;
    if (!(w->state & ADRENO_IB_STATE_READY) || (w->state & ADRENO_IB_STATE_UNCERTAIN))
        return ADRENO_SUBMIT_E_INACTIVE;   /* never rewrite an arena the CP may still fetch */
    w->package_bytes = 0;                  /* nothing is staged until every check below passed */
    w->command.reloc_count = 0;
    if (available < sizeof(struct adreno_ib_command)) return fail(w, ADRENO_IB_E_FORMAT, 0);
    struct adreno_ib_command c;
    copy_in((uint8_t *)&c, command, sizeof c);
    if (c.header.type != ADRENO_KCMD_IB) return fail(w, ADRENO_SUBMIT_E_COMMAND, 0);
    if (c.version != ADRENO_IB_COMMAND_VERSION || c.flags || c.reserved0 || c.reserved1[0] || c.reserved1[1] ||
        !c.ib_dwords || c.ib_dwords > ADRENO_IB_MAX_DWORDS || c.data_bytes > ADRENO_IB_MAX_DATA ||
        c.data_bytes % ADRENO_IB_ALIGN || c.reloc_count > ADRENO_IB_MAX_RELOCS ||
        c.header.size != adreno_ib_command_bytes(c.ib_dwords, c.data_bytes, c.reloc_count) ||
        c.header.size > available)
        return fail(w, ADRENO_IB_E_FORMAT, 0);
    uint64_t package = adreno_ib_package_bytes(c.ib_dwords, c.data_bytes);
    if (c.reloc_count > w->reloc_capacity || ADRENO_IB_PACKAGE_AT + package > w->arena_bytes ||
        package / 4 > (uint64_t)ADRENO_IB_TARGET_WORDS * 64)
        return fail(w, ADRENO_IB_E_CAPACITY, 0);
    stage_fields(w, &c);
    w->package_bytes = 0;
    copy_in(w->package, (const uint8_t *)command + sizeof c, package);
    copy_in((uint8_t *)w->relocs, (const uint8_t *)command + sizeof c + package,
            (uint64_t)c.reloc_count * sizeof(struct adreno_ib_reloc));
    for (uint64_t at = 4ull * c.ib_dwords; at < w->data_offset; at++)
        if (w->package[at]) return fail(w, ADRENO_IB_E_FORMAT, at);   /* the padding is zero by contract */
    w->package_bytes = package;
    return 0;
}

/* ---- relocation -------------------------------------------------------------------------------------------------- */
static int placed(uint32_t at, const struct adreno_ib_work *w)
{
    return !(at & 3) && (uint64_t)at + 4 <= w->package_bytes &&
           !(at >= 4ull * w->command.ib_dwords && at < w->data_offset);
}

static void sift(uint16_t *a, const struct adreno_ib_reloc *r, uint32_t root, uint32_t end)
{
    for (;;) {
        uint32_t child = 2 * root + 1, top = root;
        if (child >= end) return;
        if (r[a[top]].lo < r[a[child]].lo) top = child;
        if (child + 1 < end && r[a[top]].lo < r[a[child + 1]].lo) top = child + 1;
        if (top == root) return;
        uint16_t t = a[root]; a[root] = a[top]; a[top] = t;
        root = top;
    }
}
static void sort_by_lo(uint16_t *a, const struct adreno_ib_reloc *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) a[i] = (uint16_t)i;
    if (n < 2) return;
    for (uint32_t s = n / 2; s-- > 0;) sift(a, r, s, n);
    for (uint32_t end = n - 1; end > 0; end--) {
        uint16_t t = a[0]; a[0] = a[end]; a[end] = t;
        sift(a, r, 0, end);
    }
}
/* The relocation whose low half targets package byte offset `at`, or -1. */
static int32_t find_lo(const struct adreno_ib_work *w, uint32_t at)
{
    uint32_t low = 0, high = w->command.reloc_count;
    while (low < high) {
        uint32_t mid = low + (high - low) / 2, lo = w->relocs[w->order[mid]].lo;
        if (lo == at) return (int32_t)w->order[mid];
        if (lo < at) low = mid + 1; else high = mid;
    }
    return -1;
}
static int target(const struct adreno_ib_work *w, uint32_t at) { return bit_get(w->targets, at >> 2); }

int adreno_ib_relocate(struct adreno_ib_work *w,
                       int (*resolve)(void *, uint32_t, unsigned, uint64_t, uint64_t, uint64_t *), void *context)
{
    if (!w || !resolve) return ADRENO_LIST_E_ARGUMENT;
    if (!w->package_bytes) return fail(w, ADRENO_IB_E_FORMAT, 0);
    uint8_t *p = w->package;
    const uint64_t package = w->package_bytes;
    const uint32_t n = w->command.reloc_count;
    for (uint64_t i = 0; i < (package / 4 + 63) / 64; i++) w->targets[i] = 0;
    for (uint32_t i = 0; i < n; i++) {
        const struct adreno_ib_reloc *r = &w->relocs[i];
        const int high = r->hi != NONE;
        w->used[i] = 0;
        if (r->kind < ADRENO_IB_RELOC_RESOURCE || r->kind > ADRENO_IB_RELOC_ZERO || !r->access ||
            (r->access & ~(ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE)) ||
            (r->kind != ADRENO_IB_RELOC_RESOURCE && r->access != ADRENO_IB_ACCESS_READ) ||
            (r->kind == ADRENO_IB_RELOC_RESOURCE) != (r->resource_id != 0) ||
            r->align_log2 > ADRENO_IB_RELOC_MAX_ALIGN_LOG2 || r->hi_bits > 32 || (high && !r->hi_bits) ||
            !r->length || r->length > UINT64_MAX - r->offset ||
            !placed(r->lo, w) || (high && (!placed(r->hi, w) || r->hi == r->lo)))
            return fail(w, ADRENO_IB_E_RELOC, i);
        /* No package dword may receive two relocation halves. */
        if (target(w, r->lo) || (high && target(w, r->hi))) return fail(w, ADRENO_IB_E_RELOC, i);
        bit_set(w->targets, r->lo >> 2);
        if (high) bit_set(w->targets, r->hi >> 2);
        const uint32_t align_mask = (1u << r->align_log2) - 1u;
        const uint32_t hi_mask = !high ? 0 : r->hi_bits == 32 ? 0xffffffffu : (1u << r->hi_bits) - 1u;
        if ((rd32(p + r->lo) & ~align_mask) || (high && (rd32(p + r->hi) & hi_mask)))
            return fail(w, ADRENO_IB_E_RELOC, i);   /* the placeholder carries address bits */
        uint64_t address = 0;
        switch (r->kind) {
        case ADRENO_IB_RELOC_RESOURCE:
            if (resolve(context, r->resource_id, r->access, r->offset, r->length, &address) ||
                address < ADRENO_WINDOW_BASE || address >= ADRENO_WINDOW_END || r->length > ADRENO_WINDOW_END - address)
                return fail(w, ADRENO_IB_E_RELOC, i);
            break;
        case ADRENO_IB_RELOC_PACKAGE:
            if (r->offset > package || r->length > package - r->offset) return fail(w, ADRENO_IB_E_RELOC, i);
            address = w->package_gpu + r->offset;
            break;
        default:
            if (r->offset > ADRENO_IB_ZERO_BYTES || r->length > ADRENO_IB_ZERO_BYTES - r->offset)
                return fail(w, ADRENO_IB_E_RELOC, i);
            address = w->arena_gpu + r->offset;
            break;
        }
        if ((address & align_mask) || (high ? r->hi_bits < 32 && ((address >> 32) >> r->hi_bits) : address >> 32))
            return fail(w, ADRENO_IB_E_RELOC, i);
        wr32(p + r->lo, rd32(p + r->lo) | (uint32_t)address);
        if (high) wr32(p + r->hi, rd32(p + r->hi) | ((uint32_t)(address >> 32) & hi_mask));
    }
    sort_by_lo(w->order, w->relocs, n);
    return 0;
}

/* ---- validation -------------------------------------------------------------------------------------------------- */
/* An address field whose dwords are at package offsets lo/hi (hi may be NONE): null (no address bits and no
 * relocation half on either dword), or exactly the relocation whose halves are lo and hi. *reloc: index or -1. */
static int match_field(struct adreno_ib_work *w, uint32_t lo, uint32_t hi, const struct field *f, int32_t *reloc)
{
    const uint8_t *p = w->package;
    int32_t i = find_lo(w, lo);
    *reloc = -1;
    if (i < 0) {
        if ((rd32(p + lo) & f->lo_address) || target(w, lo) ||
            (hi != NONE && ((rd32(p + hi) & f->hi_address) || target(w, hi))))
            return fail(w, ADRENO_IB_E_ADDRESS, lo);
        return 0;
    }
    const struct adreno_ib_reloc *r = &w->relocs[i];
    if (r->hi != hi || (hi != NONE && r->hi_bits != f->hi_bits) || r->align_log2 < f->align ||
        !(f->kinds & KIND(r->kind)) || (f->write && !(r->access & ADRENO_IB_ACCESS_WRITE)) ||
        (rd32(p + lo) & ((1u << r->align_log2) - 1u) & ~f->lo_other))
        return fail(w, ADRENO_IB_E_ADDRESS, lo);
    w->used[i] |= (uint8_t)(1u | (hi != NONE ? 2u : 0u));
    *reloc = i;
    return 0;
}

/* A T# array in the package data area: every descriptor's BASE, FLAG/U and V address pairs are null or relocated
 * (BASE_HI width), and no other descriptor dword carries a relocation half (design R3, defence in depth). */
static int check_textures(struct adreno_ib_work *w, int32_t i, uint64_t count, uint32_t at)
{
    const struct adreno_ib_reloc *r = &w->relocs[i];
    if (r->kind != ADRENO_IB_RELOC_PACKAGE || r->offset < w->data_offset) return fail(w, ADRENO_IB_E_ADDRESS, at);
    if (count > r->length / 64) return fail(w, ADRENO_IB_E_BOUNDS, at);
    for (uint64_t k = 0; k < count; k++) {
        const uint32_t base = (uint32_t)(r->offset + 64 * k);
        for (uint32_t d = 0; d < 16; d++) {
            if (d == A8XX_DESC_A8XX_TEX_MEMOBJ_0 || d == A8XX_DESC_A8XX_TEX_MEMOBJ_4 || d == A8XX_DESC_A8XX_TEX_MEMOBJ_8) {
                const struct field f = {
                    d == A8XX_DESC_A8XX_TEX_MEMOBJ_0 ? 0xffffffffu : A8XX_DESC_A8XX_TEX_MEMOBJ_4__FLAG_LO__MASK,
                    d == A8XX_DESC_A8XX_TEX_MEMOBJ_0 ? 0 : ~A8XX_DESC_A8XX_TEX_MEMOBJ_4__FLAG_LO__MASK,
                    A8XX_DESC_A8XX_TEX_MEMOBJ_1__BASE_HI__MASK, ADRENO_IB_HI_BITS_DESC, ADRENO_IB_ALIGN_LOG2_TEXTURE,
                    READ_KINDS, 0};
                int32_t j;
                int e = match_field(w, base + 4 * d, base + 4 * d + 4, &f, &j);
                if (e) return e;
                d++;   /* the high half belongs to the pair */
                continue;
            }
            if (target(w, base + 4 * d)) return fail(w, ADRENO_IB_E_RELOC, base + 4 * d);
        }
    }
    return 0;
}

/* Native CS storage contract (docs/USERSPACE-GRAPHICS-20261019.md): 1..ADRENO_IB_CS_STORAGE_MAX slots, each a zero
 * hole or a linear, single-layer 2D RGBA32F/RGBA16F/RGBA8 (WZYX) or BGRA8 (WXYZ) image with identity swizzle (MPS's
 * image integral: hole + RGBA32F; CoreImage: one BGRA8 or RGBA16F image). A table relocation is PACKAGE/READ; every
 * live image BASE is RESOURCE/WRITE. */
#define ADRENO_IB_CS_STORAGE_MAX 8u
#define ADRENO_IB_CS_TEXTURE_MAX 8u
static int check_storage_images(struct adreno_ib_work *w, int32_t i, uint64_t count, uint32_t at)
{
    const struct adreno_ib_reloc *table = &w->relocs[i];
    if (table->kind != ADRENO_IB_RELOC_PACKAGE || table->offset < w->data_offset)
        return fail(w, ADRENO_IB_E_ADDRESS, at);
    if (!count || count > ADRENO_IB_CS_STORAGE_MAX || count > table->length / 64)
        return fail(w, ADRENO_IB_E_BOUNDS, at);
    for (uint64_t k = 0; k < count; k++) {
        const uint32_t base = (uint32_t)(table->offset + 64 * k);
        uint32_t d[16], nonzero = 0;
        for (unsigned n = 0; n < 16; n++) { d[n] = rd32(w->package + base + 4 * n); nonzero |= d[n]; }
        if (!nonzero) {
            for (unsigned n = 0; n < 16; n++)
                if (target(w, base + 4 * n)) return fail(w, ADRENO_IB_E_RELOC, base + 4 * n);
            continue;
        }
        const struct field image = {A8XX_DESC_A8XX_TEX_MEMOBJ_0__BASE_LO__MASK, 0,
            A8XX_DESC_A8XX_TEX_MEMOBJ_1__BASE_HI__MASK, ADRENO_IB_HI_BITS_DESC,
            ADRENO_IB_ALIGN_LOG2_TEXTURE, KIND(ADRENO_IB_RELOC_RESOURCE), 1};
        int32_t image_reloc;
        int e = match_field(w, base, base + 4, &image, &image_reloc);
        if (e) return e;
        if (image_reloc < 0) return fail(w, ADRENO_IB_E_ADDRESS, base);
        for (unsigned n = 2; n < 16; n++)
            if (target(w, base + 4 * n)) return fail(w, ADRENO_IB_E_RELOC, base + 4 * n);
#define DESC_GET(n, field) ((d[n] & A8XX_DESC_A8XX_TEX_MEMOBJ_##n##__##field##__MASK) >> \
                           A8XX_DESC_A8XX_TEX_MEMOBJ_##n##__##field##__SHIFT)
        const uint32_t width = DESC_GET(2, WIDTH), height = DESC_GET(2, HEIGHT);
        const uint64_t pitch_bits = DESC_GET(6, TEX_LINE_OFFSET), pitch = pitch_bits / 8;
        const uint64_t bytes = pitch * height;
        static const struct { uint32_t fmt, swap, cpp; } formats[] = {
            {A8XX_E_FMT6_32_32_32_32_FLOAT, A8XX_E_WZYX, 16}, {A8XX_E_FMT6_16_16_16_16_FLOAT, A8XX_E_WZYX, 8},
            {A8XX_E_FMT6_8_8_8_8_UNORM, A8XX_E_WZYX, 4}, {A8XX_E_FMT6_8_8_8_8_UNORM, A8XX_E_WXYZ, 4}};
        const uint32_t identity = A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWIZ_X(A8XX_E_A8XX_SWIZ_X) |
            A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWIZ_Y(A8XX_E_A8XX_SWIZ_Y) |
            A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWIZ_Z(A8XX_E_A8XX_SWIZ_Z) |
            A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWIZ_W(A8XX_E_A8XX_SWIZ_W);
        uint32_t cpp = 0;
        for (unsigned f = 0; f < sizeof formats / sizeof formats[0]; f++)
            if (d[3] == (A8XX_DESC_A8XX_TEX_MEMOBJ_3__FMT(formats[f].fmt) |
                         A8XX_DESC_A8XX_TEX_MEMOBJ_3__SWAP(formats[f].swap) | identity))
                cpp = formats[f].cpp;
        const uint32_t type = A8XX_DESC_A8XX_TEX_MEMOBJ_1__TYPE(A8XX_E_A6XX_TEX_2D) |
                              A8XX_DESC_A8XX_TEX_MEMOBJ_1__DEPTH(1);
        if ((d[0] & ~A8XX_DESC_A8XX_TEX_MEMOBJ_0__BASE_LO__MASK) ||
            (d[1] & ~A8XX_DESC_A8XX_TEX_MEMOBJ_1__BASE_HI__MASK) != type ||
            !width || width > 16384 || !height || height > 16384 || DESC_GET(2, SAMPLES) != A8XX_E_MSAA_ONE ||
            !cpp || d[4] || d[5] || !pitch || pitch_bits % 8 || pitch % 64 ||
            pitch < (uint64_t)width * cpp || DESC_GET(6, MIPLVLS) || DESC_GET(6, MIN_LINE_OFFSET) > 2 ||
            pitch % (64u << DESC_GET(6, MIN_LINE_OFFSET)) ||
            d[7] != A8XX_DESC_A8XX_TEX_MEMOBJ_7__ARRAY_SLICE_OFFSET((bytes + 4095) & ~4095ull))
            return fail(w, ADRENO_IB_E_PACKET, base);
        for (unsigned n = 8; n < 16; n++)
            if (d[n]) return fail(w, ADRENO_IB_E_PACKET, base + 4 * n);
        if (bytes > w->relocs[image_reloc].length) return fail(w, ADRENO_IB_E_BOUNDS, base);
#undef DESC_GET
    }
    return 0;
}

static void compute_register(struct adreno_ib_work *w, uint32_t reg, uint32_t value)
{
    unsigned index;
    if (reg >= A8XX_REG_SP_CS_NDRANGE_0 && reg <= A8XX_REG_SP_CS_NDRANGE_6) {
        index = reg - A8XX_REG_SP_CS_NDRANGE_0;
        w->cs_ndrange[index] = value; w->cs_seen |= 1u << index;
    } else if (reg == A8XX_REG_SP_CS_NDRANGE_7) {
        w->cs_ndrange[7] = value; w->cs_seen |= 1u << 7;
    } else if (reg >= A8XX_REG_SP_CS_KERNEL_GROUP_X && reg <= A8XX_REG_SP_CS_KERNEL_GROUP_Z) {
        index = reg - A8XX_REG_SP_CS_KERNEL_GROUP_X;
        w->cs_groups[index] = value; w->cs_seen |= 1u << (8 + index);
    }
}

/* One register write: `reg` takes the package dword at `at`. next_reg/next_at describe the packet's next write
 * (next_at NONE if there is none); *pair is set when that write was validated as this address's high half. */
static int reg_write(struct adreno_ib_work *w, uint32_t reg, uint32_t at, uint32_t next_reg, uint32_t next_at, int *pair)
{
    const struct adreno_ib_tables *t = w->tables;
    *pair = 0;
    if (reg >= ADRENO_IB_REG_LIMIT || !bit_get(t->allowed, reg)) return fail(w, ADRENO_IB_E_REGISTER, at);
    compute_register(w, reg, rd32(w->package + at));
    if (!bit_get(t->address, reg)) return 0;
    uint32_t half = 0;
    const struct a8xx_reg_info *row = address_row(t, reg, &half);
    struct field f;
    int textures;
    if (!row || !register_field(row->offset, &f, &textures)) return fail(w, ADRENO_IB_E_REGISTER, at);
    if (half) {   /* a high half that no relocated low half claimed: it must be null */
        if (rd32(w->package + at) || target(w, at)) return fail(w, ADRENO_IB_E_ADDRESS, at);
        return 0;
    }
    const uint32_t hi = next_at != NONE && next_reg == reg + 1 ? next_at : NONE;
    int32_t i;
    int e = match_field(w, at, hi, &f, &i);
    if (e) return e;
    if (i < 0) return 0;   /* null: a following high-half write is checked on its own */
    if (hi == NONE || next_reg >= ADRENO_IB_REG_LIMIT || !bit_get(t->allowed, next_reg))
        return fail(w, ADRENO_IB_E_ADDRESS, at);   /* a relocated register is written whole, in one packet */
    *pair = 1;
    if (textures) {
        const struct adreno_ib_reloc *r = &w->relocs[i];
        if (r->length % 64) return fail(w, ADRENO_IB_E_BOUNDS, at);
        return textures == 2 ? check_storage_images(w, i, r->length / 64, at) :
                               check_textures(w, i, r->length / 64, at);
    }
    return 0;
}

static int bunch(struct adreno_ib_work *w, uint32_t at, uint32_t count, int noncontext)
{
    const uint8_t *p = w->package;
    uint32_t first = 0;
    if (noncontext) {
        if (count < 2 || rd32(p + at) != 1 || rd32(p + at + 4)) return fail(w, ADRENO_IB_E_PACKET, at - 4);
        first = 2;
    }
    if (count < first + 2 || (count - first) % 2) return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint32_t pairs = (count - first) / 2;
    for (uint32_t k = 0; k < pairs; k++) {
        const uint32_t reg_at = at + 4 * (first + 2 * k);
        uint32_t next_reg = 0, next_at = NONE;
        if (k + 1 < pairs) { next_reg = rd32(p + reg_at + 8); next_at = reg_at + 12; }
        int pair;
        int e = reg_write(w, rd32(p + reg_at), reg_at + 4, next_reg, next_at, &pair);
        if (e) return e;
        k += (uint32_t)pair;
    }
    return 0;
}

static int load_state(struct adreno_ib_work *w, uint32_t op, uint32_t at, uint32_t count)
{
    const uint8_t *p = w->package;
    if (count < 3) return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint32_t w0 = rd32(p + at);
    const uint32_t type = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__STATE_TYPE__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__STATE_TYPE__SHIFT;
    const uint32_t src = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__STATE_SRC__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__STATE_SRC__SHIFT;
    const uint32_t block = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__STATE_BLOCK__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__STATE_BLOCK__SHIFT;
    const uint32_t units = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__NUM_UNIT__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__NUM_UNIT__SHIFT;
    const uint32_t ext_lo = at + 4 * A8XX_PKT_CP_LOAD_STATE6_1, ext_hi = at + 4 * A8XX_PKT_CP_LOAD_STATE6_2;
    if (type == A8XX_E_ST6_UBO && src == A8XX_E_SS6_DIRECT) {
        const int shader_block = op == A8XX_E_CP_LOAD_STATE6_GEOM ? block == A8XX_E_SB6_VS_SHADER :
                                 (block == A8XX_E_SB6_FS_SHADER || block == A8XX_E_SB6_CS_SHADER);
        if (!shader_block ||
            count != 3 + 2 * units || rd32(p + ext_lo) || rd32(p + ext_hi) || target(w, ext_lo) || target(w, ext_hi))
            return fail(w, ADRENO_IB_E_PACKET, at - 4);
        if (block == A8XX_E_SB6_CS_SHADER) {
            uint32_t dst = (w0 & A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF__MASK) >> A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF__SHIFT;
            if (!units || units > 2 || dst > 2 - units) return fail(w, ADRENO_IB_E_PACKET, at);
        }
        const struct field ubo = {0xffffffffu, 0, A8XX_DESC_A6XX_UBO_1__BASE_HI__MASK, ADRENO_IB_HI_BITS_DESC,
                                  ADRENO_IB_ALIGN_LOG2_UBO, KIND(ADRENO_IB_RELOC_RESOURCE) | KIND(ADRENO_IB_RELOC_PACKAGE), 0};
        for (uint32_t k = 0; k < units; k++) {
            const uint32_t lo = at + 12 + 8 * k, hi = lo + 4;
            int32_t i;
            int e = match_field(w, lo, hi, &ubo, &i);
            if (e) return e;
            if (i < 0) {   /* an unused slot is the all-zero descriptor (a sized null UBO would fault the SMMU) */
                if (rd32(p + hi)) return fail(w, ADRENO_IB_E_ADDRESS, hi);
                continue;
            }
            const uint64_t size = (uint64_t)((rd32(p + hi) & A8XX_DESC_A6XX_UBO_1__SIZE__MASK) >>
                                             A8XX_DESC_A6XX_UBO_1__SIZE__SHIFT) * 16;
            if (size > w->relocs[i].length) return fail(w, ADRENO_IB_E_BOUNDS, lo);
        }
        return 0;
    }
    const int cs_uav = block == A8XX_E_SB6_CS_SHADER && type == A8XX_E_ST6_UAV;
    const int texture_load = (block == A8XX_E_SB6_FS_TEX || block == A8XX_E_SB6_CS_TEX) &&
                             (type == A8XX_E_ST6_SHADER || type == A8XX_E_ST6_CONSTANTS);
    if (src == A8XX_E_SS6_INDIRECT && op == A8XX_E_CP_LOAD_STATE6_FRAG && (texture_load || cs_uav)) {
        if (count != 3) return fail(w, ADRENO_IB_E_PACKET, at - 4);
        /* CS samplers: one unit. CS T#s: 1..ADRENO_IB_CS_TEXTURE_MAX units (CoreImage's T#1 with a null T#0), each
         * checked by check_textures below. */
        if (block == A8XX_E_SB6_CS_TEX &&
            (!units || units > (type == A8XX_E_ST6_CONSTANTS ? ADRENO_IB_CS_TEXTURE_MAX : 1u) ||
             (w0 & A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF__MASK)))
            return fail(w, ADRENO_IB_E_PACKET, at);
        const struct field ext = {A8XX_PKT_CP_LOAD_STATE6_1__EXT_SRC_ADDR__MASK, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64,
                                  ADRENO_IB_ALIGN_LOG2_LOAD_STATE, KIND(ADRENO_IB_RELOC_PACKAGE), 0};
        int32_t i;
        int e = match_field(w, ext_lo, ext_hi, &ext, &i);
        if (e) return e;
        if (i < 0) return fail(w, ADRENO_IB_E_ADDRESS, ext_lo);   /* an indirect load needs a source */
        if (cs_uav) {
            if (w0 & A8XX_PKT_CP_LOAD_STATE6_0__DST_OFF__MASK) return fail(w, ADRENO_IB_E_PACKET, at);
            return check_storage_images(w, i, units, ext_lo);
        }
        if (type == A8XX_E_ST6_CONSTANTS) return check_textures(w, i, units, ext_lo);
        if ((uint64_t)units * 16 > w->relocs[i].length) return fail(w, ADRENO_IB_E_BOUNDS, ext_lo);
        return 0;
    }
    return fail(w, ADRENO_IB_E_PACKET, at - 4);
}

static int draw(struct adreno_ib_work *w, uint32_t at, uint32_t count)
{
    const uint8_t *p = w->package;
    if (!count) return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint32_t d0 = rd32(p + at);
    const uint32_t prim = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PRIM_TYPE__MASK) >> A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PRIM_TYPE__SHIFT;
    const uint32_t source = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__SOURCE_SELECT__MASK) >>
                            A8XX_PKT_CP_DRAW_INDX_OFFSET_0__SOURCE_SELECT__SHIFT;
    const uint32_t vis = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__VIS_CULL__MASK) >> A8XX_PKT_CP_DRAW_INDX_OFFSET_0__VIS_CULL__SHIFT;
    const uint32_t size = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__INDEX_SIZE__MASK) >> A8XX_PKT_CP_DRAW_INDX_OFFSET_0__INDEX_SIZE__SHIFT;
    const uint32_t patch = (d0 & A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PATCH_TYPE__MASK) >> A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PATCH_TYPE__SHIFT;
    const uint32_t known = A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PRIM_TYPE__MASK | A8XX_PKT_CP_DRAW_INDX_OFFSET_0__SOURCE_SELECT__MASK |
                           A8XX_PKT_CP_DRAW_INDX_OFFSET_0__VIS_CULL__MASK | A8XX_PKT_CP_DRAW_INDX_OFFSET_0__INDEX_SIZE__MASK |
                           A8XX_PKT_CP_DRAW_INDX_OFFSET_0__PATCH_TYPE__MASK;   /* GS/TESS enables stay clear */
    const int prim_ok = prim == A8XX_E_DI_PT_TRILIST || prim == A8XX_E_DI_PT_TRISTRIP || prim == A8XX_E_DI_PT_TRIFAN ||
                        prim == A8XX_E_DI_PT_LINELIST || prim == A8XX_E_DI_PT_LINESTRIP || prim == A8XX_E_DI_PT_POINTLIST;
    if ((d0 & ~known) || !prim_ok || vis > A8XX_E_USE_VISIBILITY || patch != A8XX_E_TESS_QUADS)
        return fail(w, ADRENO_IB_E_PACKET, at - 4);
    if (count == 3)
        return source == A8XX_E_DI_SRC_SEL_AUTO_INDEX && size == A8XX_E_INDEX4_SIZE_8_BIT ? 0 :
               fail(w, ADRENO_IB_E_PACKET, at - 4);
    if (count != 7 || source != A8XX_E_DI_SRC_SEL_DMA ||
        (size != A8XX_E_INDEX4_SIZE_16_BIT && size != A8XX_E_INDEX4_SIZE_32_BIT))
        return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const struct field index = {0xffffffffu, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64,
                                size == A8XX_E_INDEX4_SIZE_16_BIT ? ADRENO_IB_ALIGN_LOG2_INDEX16 : 2,
                                KIND(ADRENO_IB_RELOC_RESOURCE) | KIND(ADRENO_IB_RELOC_PACKAGE), 0};
    const uint32_t base = at + 4 * A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_INDX_BASE;
    int32_t i;
    int e = match_field(w, base, base + 4, &index, &i);
    if (e) return e;
    if (i < 0) return fail(w, ADRENO_IB_E_ADDRESS, base);
    const uint64_t indices = rd32(p + at + 4 * A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_6);
    if (indices * (size == A8XX_E_INDEX4_SIZE_16_BIT ? 2u : 4u) > w->relocs[i].length)
        return fail(w, ADRENO_IB_E_BOUNDS, at + 4 * A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_6);
    return 0;
}

/* CP_MEMCPY is an ordered resource copy, never an arbitrary physical write. */
static int memory_copy(struct adreno_ib_work *w, uint32_t at, uint32_t count)
{
    if (count != 5) return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint64_t bytes = (uint64_t)rd32(w->package + at) * 4;
    if (!bytes || target(w, at)) return fail(w, ADRENO_IB_E_PACKET, at);
    const struct field source = {0xffffffffu, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64, 2,
                                  KIND(ADRENO_IB_RELOC_RESOURCE), 0};
    const struct field destination = {0xffffffffu, 0, 0xffffffffu, ADRENO_IB_HI_BITS_REG64, 2,
                                       KIND(ADRENO_IB_RELOC_RESOURCE), 1};
    int32_t src, dst;
    int e = match_field(w, at + 4, at + 8, &source, &src);
    if (e) return e;
    e = match_field(w, at + 12, at + 16, &destination, &dst);
    if (e) return e;
    if (src < 0 || dst < 0 || !(w->relocs[src].access & ADRENO_IB_ACCESS_READ))
        return fail(w, ADRENO_IB_E_ADDRESS, at);
    if (bytes > w->relocs[src].length || bytes > w->relocs[dst].length)
        return fail(w, ADRENO_IB_E_BOUNDS, at);
    const uint64_t src_address = (uint64_t)rd32(w->package + at + 4) |
                                (uint64_t)rd32(w->package + at + 8) << 32;
    const uint64_t dst_address = (uint64_t)rd32(w->package + at + 12) |
                                (uint64_t)rd32(w->package + at + 16) << 32;
    if (src_address > UINT64_MAX - bytes || dst_address > UINT64_MAX - bytes ||
        (src_address < dst_address + bytes && dst_address < src_address + bytes))
        return fail(w, ADRENO_IB_E_BOUNDS, at);
    return 0;
}

static int event_allowed(uint32_t event)
{
    switch (event) {
    case A8XX_E_CCU_CLEAN_COLOR: case A8XX_E_CCU_CLEAN_DEPTH: case A8XX_E_CCU_INVALIDATE_COLOR:
    case A8XX_E_CCU_INVALIDATE_DEPTH: case A8XX_E_CACHE_CLEAN: case A8XX_E_CACHE_INVALIDATE7:
    case A8XX_E_LRZ_CACHE_FLUSH: case A8XX_E_DUMMY_EVENT: case A8XX_E_SUBPASS_FENCE: case A8XX_E_DEBUG_LABEL:
        return 1;
    }
    return 0;
}

static int compute_dispatch(struct adreno_ib_work *w, uint32_t at, uint32_t count)
{
    if (count != 4 || rd32(w->package + at) || w->cs_seen != 0x7ffu)
        return fail(w, ADRENO_IB_E_PACKET, at - 4);
    const uint32_t d = w->cs_ndrange[0];
    const uint32_t local[3] = {
        ((d & A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEX__MASK) >> A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEX__SHIFT) + 1,
        ((d & A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEY__MASK) >> A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEY__SHIFT) + 1,
        ((d & A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEZ__MASK) >> A8XX_REG_SP_CS_NDRANGE_0__LOCALSIZEZ__SHIFT) + 1};
    const uint32_t dim = (d & A8XX_REG_SP_CS_NDRANGE_0__KERNELDIM__MASK) >> A8XX_REG_SP_CS_NDRANGE_0__KERNELDIM__SHIFT;
    const uint32_t last = A8XX_REG_SP_CS_NDRANGE_7__LOCALSIZEX(local[0] - 1) |
                         A8XX_REG_SP_CS_NDRANGE_7__LOCALSIZEY(local[1] - 1) |
                         A8XX_REG_SP_CS_NDRANGE_7__LOCALSIZEZ(local[2] - 1);
    if (!dim || dim > 3 || (uint64_t)local[0] * local[1] * local[2] > 1024 || w->cs_ndrange[7] != last)
        return fail(w, ADRENO_IB_E_PACKET, at - 4);
    for (unsigned axis = 0; axis < 3; axis++) {
        uint32_t groups = rd32(w->package + at + 4 * (axis + 1));
        uint64_t global = (uint64_t)groups * local[axis];
        if (!groups || groups != w->cs_groups[axis] || global > UINT32_MAX ||
            global != w->cs_ndrange[1 + 2 * axis] || w->cs_ndrange[2 + 2 * axis] ||
            (axis >= dim && (groups != 1 || local[axis] != 1)))
            return fail(w, ADRENO_IB_E_PACKET, at + 4 * (axis + 1));
    }
    w->cs_seen = 0;                   /* every later dispatch must provide a fresh full geometry */
    return 0;
}

static int packet7(struct adreno_ib_work *w, uint32_t op, uint32_t at, uint32_t count)
{
    const uint8_t *p = w->package;
    const uint32_t v = count ? rd32(p + at) : 0;
    int ok = 0;
    switch (op) {
    case A8XX_E_CP_NOP: return 0;   /* skipped by the CP; a relocation inside it is never consumed */
    case A8XX_E_CP_WAIT_FOR_IDLE: case A8XX_E_CP_CCHE_INVALIDATE:
    case A8XX_E_CP_WAIT_MEM_WRITES: ok = !count; break;
    case A8XX_E_CP_SET_MODE: ok = count == 1 && v <= 1; break;
    case A8XX_E_CP_THREAD_CONTROL:
        ok = count == 1 && (v & A8XX_PKT_CP_THREAD_CONTROL_0__THREAD__MASK) &&
             !(v & ~(A8XX_PKT_CP_THREAD_CONTROL_0__THREAD__MASK | A8XX_PKT_CP_THREAD_CONTROL_0__CONCURRENT_BIN_DISABLE__MASK |
                     A8XX_PKT_CP_THREAD_CONTROL_0__SYNC_THREADS__MASK));
        break;
    case A8XX_E_CP_SET_MARKER:
        ok = count == 1 && (v == A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_DIRECT_RENDER) ||
                            v == A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_BLIT2DSCALE) ||
                            v == A8XX_PKT_A8XX_CP_SET_MARKER_0__MODE(A8XX_E_RM6_COMPUTE));
        break;
    case A8XX_E_CP_SKIP_IB2_ENABLE_GLOBAL: case A8XX_E_CP_SKIP_IB2_ENABLE_LOCAL: case A8XX_E_CP_SET_VISIBILITY_OVERRIDE:
        ok = count == 1 && v <= 1;
        break;
    case A8XX_E_CP_EVENT_WRITE7:   /* the event alone: no memory write, no IRQ, no sample counts */
        ok = count == 1 && !(v & ~A8XX_PKT_CP_EVENT_WRITE7_0__EVENT__MASK) &&
             event_allowed((v & A8XX_PKT_CP_EVENT_WRITE7_0__EVENT__MASK) >> A8XX_PKT_CP_EVENT_WRITE7_0__EVENT__SHIFT);
        break;
    case A8XX_E_CP_SET_DRAW_STATE:   /* only "disable all groups": a group would run an unvalidated IB */
        ok = count == 3 && v == A8XX_PKT_CP_SET_DRAW_STATE__0__DISABLE_ALL_GROUPS__MASK && !rd32(p + at + 4) &&
             !rd32(p + at + 8);
        break;
    case A8XX_E_CP_BLIT: ok = count == 1 && v == A8XX_PKT_CP_BLIT_0__OP(A8XX_E_BLIT_OP_SCALE); break;
    case A8XX_E_CP_CONTEXT_REG_BUNCH: return bunch(w, at, count, 0);
    case A8XX_E_CP_NON_CONTEXT_REG_BUNCH: return bunch(w, at, count, 1);
    case A8XX_E_CP_LOAD_STATE6_GEOM: case A8XX_E_CP_LOAD_STATE6_FRAG: return load_state(w, op, at, count);
    case A8XX_E_CP_DRAW_INDX_OFFSET: return draw(w, at, count);
    case A8XX_E_CP_EXEC_CS: return compute_dispatch(w, at, count);
    case A8XX_E_CP_MEMCPY: return memory_copy(w, at, count);
    }
    return ok ? 0 : fail(w, ADRENO_IB_E_PACKET, at - 4);
}

int adreno_ib_validate(struct adreno_ib_work *w)
{
    if (!w || !w->tables) return ADRENO_LIST_E_ARGUMENT;
    if (!w->package_bytes) return fail(w, ADRENO_IB_E_FORMAT, 0);
    const uint8_t *p = w->package;
    const uint32_t n = w->command.ib_dwords;
    w->cs_seen = 0;
    for (uint32_t i = 0; i < w->command.reloc_count; i++) w->used[i] = 0;
    for (uint32_t at = 0; at < n;) {
        const uint32_t h = rd32(p + 4ull * at), payload = at + 1;
        if ((h & 0xf0000000u) == A8XX_E_CP_TYPE4_PKT) {
            const uint32_t count = h & A8XX_PKT4_COUNT_MASK, reg = (h >> 8) & A8XX_PKT4_REG_MASK;
            if (h != a8xx_pkt4_hdr(reg, count) || !count || count > n - payload)
                return fail(w, ADRENO_IB_E_PACKET, 4ull * at);
            for (uint32_t k = 0; k < count; k++) {
                int pair;
                int e = reg_write(w, reg + k, 4 * (payload + k), reg + k + 1,
                                  k + 1 < count ? 4 * (payload + k + 1) : NONE, &pair);
                if (e) return e;
                k += (uint32_t)pair;
            }
            at = payload + count;
            continue;
        }
        if ((h & 0xf0000000u) == A8XX_E_CP_TYPE7_PKT) {
            const uint32_t count = h & A8XX_PKT7_COUNT_MASK, op = (h >> 16) & A8XX_PKT7_OPCODE_MASK;
            if (h != a8xx_pkt7_hdr(op, count) || count > n - payload) return fail(w, ADRENO_IB_E_PACKET, 4ull * at);
            int e = packet7(w, op, 4 * payload, count);
            if (e) return e;
            at = payload + count;
            continue;
        }
        return fail(w, ADRENO_IB_E_PACKET, 4ull * at);
    }
    /* Every relocation half inside the IB must have been claimed by an address field above. */
    const uint64_t ib = 4ull * n;
    for (uint32_t i = 0; i < w->command.reloc_count; i++) {
        const struct adreno_ib_reloc *r = &w->relocs[i];
        if ((r->lo < ib && !(w->used[i] & 1)) || (r->hi != NONE && r->hi < ib && !(w->used[i] & 2)))
            return fail(w, ADRENO_IB_E_RELOC, i);
    }
    return 0;
}

/* ---- submission ------------------------------------------------------------------------------------------------- */
int adreno_ib_resource_range(const struct adreno_resource *r, uint64_t offset, uint64_t bytes, uint64_t *address)
{
    if (!r || !address) return ADRENO_RESOURCE_E_STATE;
    *address = 0;
    if (r->flags != (ADRENO_RESOURCE_RESERVED | ADRENO_RESOURCE_PINNED) || !r->length || !r->logical_length ||
        r->logical_length > r->length || r->mapped_length != r->length)
        return ADRENO_RESOURCE_E_STATE;
    if (!bytes || offset > r->logical_length || bytes > r->logical_length - offset ||
        r->address < ADRENO_WINDOW_BASE || r->address >= ADRENO_WINDOW_END || r->length > ADRENO_WINDOW_END - r->address)
        return ADRENO_RESOURCE_E_RANGE;
    *address = r->address + offset;
    return 0;
}

int adreno_ib_classify(const struct adreno_ib_reply *r)
{
    if (!r) return ADRENO_SUBMIT_E_UNCERTAIN;
    if (!r->status) return r->marker && r->wptr < RING_LIMIT ? 0 : ADRENO_SUBMIT_E_UNCERTAIN;
    if (r->marker) return ADRENO_SUBMIT_E_UNCERTAIN;   /* a failure never carries a completion marker */
    switch (r->status) {
    case ADRENO_IB_E_GPU_ERROR: return ADRENO_IB_E_GPU_ERROR;
#if ADRENO_GPU_RECOVER
    case ADRENO_IB_E_RESET: case ADRENO_IB_E_RESET_FAULT: return (int)r->status;
#endif
    case ADRENO_E_PARAMS: case ADRENO_E_WINDOW: case ADRENO_E_TARGET: case ADRENO_E_CX: case ADRENO_E_GX:
    case ADRENO_E_HALT: case ADRENO_E_CB0: case ADRENO_E_FAULT: case ADRENO_E_SQE: case ADRENO_E_RING:
    case ADRENO_IB_E_BUSY: case ADRENO_IB_E_STICKY:
        return ADRENO_SUBMIT_E_INACTIVE;   /* adreno-guest.h: refused before any ring write */
    }
    return ADRENO_SUBMIT_E_UNCERTAIN;      /* ADRENO_IB_E_UNCERTAIN and anything undocumented */
}

struct resolver {
    const struct adreno_resource_list *list;
    int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *);
    void *context;
};
/* Admit a RESOURCE relocation: the ID is in this command buffer's prepared list (repeated IDs share one resource
 * and preparation), WRITE needs Write usage, READ needs Read or Sample usage; then the kext's range check. */
static int resolve_entry(void *c, uint32_t id, unsigned access, uint64_t offset, uint64_t length, uint64_t *address)
{
    const struct resolver *rs = c;
    const struct adreno_resource_entry *selected = 0;
    unsigned usage = 0;
    for (uint64_t i = 0; i < rs->list->count; i++) {
        const struct adreno_resource_entry *e = &rs->list->entries[i];
        if (e->id != id) continue;
        if (!e->resource || !e->preparation || e->reserved ||
            (selected && (e->resource != selected->resource || e->preparation != selected->preparation)))
            return -1;
        selected = e;
        usage |= e->usage;
    }
    if (!selected || ((access & ADRENO_IB_ACCESS_WRITE) && !(usage & ADRENO_USAGE_WRITE)) ||
        ((access & ADRENO_IB_ACCESS_READ) && !(usage & (ADRENO_USAGE_READ | ADRENO_USAGE_SAMPLE))))
        return -1;
    *address = 0;
    return rs->resolve(rs->context, selected->resource, selected->preparation, offset, length, address) ? -1 : 0;
}

#if !ADRENO_PIPELINE
struct ring_call {
    struct adreno_ib_work *w;
    int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *);
    void *context;
    int outcome;
};
static int ring_package(void *c)
{
    struct ring_call *call = c;
    struct adreno_ib_work *w = call->w;
    struct adreno_ib_reply reply = {ADRENO_IB_E_UNCERTAIN, 0, 0, 0};
    int e = call->ring(call->context, w->package_gpu, w->command.ib_dwords, w->package_bytes, &reply);
    w->reply = reply;
    call->outcome = e ? ADRENO_SUBMIT_E_UNCERTAIN : adreno_ib_classify(&reply);
    /* GPU_ERROR: retired and idle, so the list's FROM_DEVICE still runs and the list is not frozen. */
#if ADRENO_GPU_RECOVER
    if (call->outcome == ADRENO_IB_E_RESET || call->outcome == ADRENO_IB_E_RESET_FAULT) return 0;   /* as GPU_ERROR */
#endif
    return call->outcome == ADRENO_IB_E_GPU_ERROR ? 0 : call->outcome;
}
#endif

#if ADRENO_PIPELINE
/* --pipeline: adreno_ib_submit below, split at the doorbell (adreno-ib-command.h). Same checks, order and results. */
int adreno_ib_submit_begin(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                           const void *command, uint64_t available,
                           int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *), void *context,
                           struct adreno_ib_pending *p)
{
    if (!w || !list || !ops || !command || !resolve || !p) return ADRENO_LIST_E_ARGUMENT;
    p->armed = 0; p->marker = 0;
    if (!(w->state & ADRENO_IB_STATE_READY) || (w->state & (ADRENO_IB_STATE_DISABLED | ADRENO_IB_STATE_UNCERTAIN)))
        return ADRENO_SUBMIT_E_INACTIVE;
    if (list->ready & ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready != (ADRENO_LIST_READY | ADRENO_LIST_PREPARED) || list->prepared_count != list->count ||
        (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    const struct resolver rs = {list, resolve, context};
    int e = adreno_ib_stage(w, command, available);
    if (!e) e = adreno_ib_relocate(w, resolve_entry, (void *)&rs);
    if (!e) e = adreno_ib_validate(w);
    if (e) { w->refused++; return e; }
    e = adreno_resource_list_begin(list, ops, &p->list);
    if (e) return fail(w, e, 0);   /* list/cache refusal before the doorbell */
    p->armed = 1;
    return 0;
}
int adreno_ib_submit_finish(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                            struct adreno_ib_pending *p, const struct adreno_ib_reply *final, int transport_error)
{
    if (!w || !list || !ops || !p || !p->armed || !final) return ADRENO_LIST_E_ARGUMENT;
    p->armed = 0; p->marker = 0;
    w->reply = *final;
    const int outcome = transport_error ? ADRENO_SUBMIT_E_UNCERTAIN : adreno_ib_classify(final);
    /* GPU_ERROR: retired and idle, so the list's FROM_DEVICE still runs and the list is not frozen. */
#if ADRENO_GPU_RECOVER
    const int reset = outcome == ADRENO_IB_E_RESET || outcome == ADRENO_IB_E_RESET_FAULT;   /* the same (R14) */
    const int e = adreno_resource_list_end(list, ops, &p->list, outcome == ADRENO_IB_E_GPU_ERROR || reset ? 0 : outcome);
#else
    const int e = adreno_resource_list_end(list, ops, &p->list, outcome == ADRENO_IB_E_GPU_ERROR ? 0 : outcome);
#endif
    if (e == ADRENO_SUBMIT_E_UNCERTAIN || e == ADRENO_LIST_E_VISIBILITY) {
        w->state |= ADRENO_IB_STATE_UNCERTAIN;   /* the arena keeps this package until reset */
        w->uncertain++;
        return fail(w, e, 0);
    }
    if (e == ADRENO_SUBMIT_E_INACTIVE && outcome == ADRENO_SUBMIT_E_INACTIVE) {
        w->refused++;
        if (w->reply.status == ADRENO_IB_E_STICKY) w->state |= ADRENO_IB_STATE_DISABLED;  /* only a reset clears it */
        return fail(w, (int)w->reply.status, 0);
    }
    if (e) return fail(w, e, 0);
    if (outcome == ADRENO_IB_E_GPU_ERROR) {
        w->gpu_errors++;
        w->state |= ADRENO_IB_STATE_DISABLED;
        return fail(w, ADRENO_IB_E_GPU_ERROR, 0);
    }
#if ADRENO_GPU_RECOVER
    if (reset) { w->resets++; return fail(w, outcome, 0); }   /* this IB failed; the GPU and the work stay usable */
#endif
    w->submitted++;
    return 0;
}
int adreno_ib_submit_ring(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                          struct adreno_ib_pending *p, int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *),
                          void *context)
{
    if (!w || !list || !ops || !p || !p->armed || !ring) return ADRENO_LIST_E_ARGUMENT;
    struct adreno_ib_reply reply = {ADRENO_IB_E_UNCERTAIN, 0, 0, 0};
    const int transport = ring(context, w->package_gpu, w->command.ib_dwords, w->package_bytes, &reply);
    if (!transport && reply.status == ADRENO_IB_PENDING) {
        if (reply.marker && !(reply.marker >> 32)) {   /* in flight: the caller polls for the final reply */
            w->reply = reply;
            p->marker = reply.marker;
            return ADRENO_IB_IN_FLIGHT;
        }
        reply.status = ADRENO_IB_E_UNCERTAIN;          /* rung, without a marker to poll (async-ib A9) */
        reply.marker = 0;
    }
    return adreno_ib_submit_finish(w, list, ops, p, &reply, transport);
}
int adreno_ib_submit(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                     const void *command, uint64_t available,
                     int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *),
                     int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *), void *context)
{
    if (!w || !list || !ops || !command || !resolve || !ring) return ADRENO_LIST_E_ARGUMENT;
    struct adreno_ib_pending p;
    int e = adreno_ib_submit_begin(w, list, ops, command, available, resolve, context, &p);
    if (e) return e;
    e = adreno_ib_submit_ring(w, list, ops, &p, ring, context);
    if (e == ADRENO_IB_IN_FLIGHT) {                    /* a synchronous caller's ring answered PENDING: not final */
        const struct adreno_ib_reply uncertain = {ADRENO_IB_E_UNCERTAIN, 0, w->reply.ticks, w->reply.wptr};
        e = adreno_ib_submit_finish(w, list, ops, &p, &uncertain, 0);
    }
    return e;
}
#else
int adreno_ib_submit(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                     const void *command, uint64_t available,
                     int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *),
                     int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *), void *context)
{
    if (!w || !list || !ops || !command || !resolve || !ring) return ADRENO_LIST_E_ARGUMENT;
    if (!(w->state & ADRENO_IB_STATE_READY) || (w->state & (ADRENO_IB_STATE_DISABLED | ADRENO_IB_STATE_UNCERTAIN)))
        return ADRENO_SUBMIT_E_INACTIVE;
    if (list->ready & ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready != (ADRENO_LIST_READY | ADRENO_LIST_PREPARED) || list->prepared_count != list->count ||
        (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    const struct resolver rs = {list, resolve, context};
    int e = adreno_ib_stage(w, command, available);
    if (!e) e = adreno_ib_relocate(w, resolve_entry, (void *)&rs);
    if (!e) e = adreno_ib_validate(w);
    if (e) { w->refused++; return e; }
    struct ring_call call = {w, ring, context, 0};
    e = adreno_resource_list_submit(list, ops, ring_package, &call);
    if (e == ADRENO_SUBMIT_E_UNCERTAIN || e == ADRENO_LIST_E_VISIBILITY) {
        w->state |= ADRENO_IB_STATE_UNCERTAIN;   /* the arena keeps this package until reset */
        w->uncertain++;
        return fail(w, e, 0);
    }
    if (e == ADRENO_SUBMIT_E_INACTIVE && call.outcome == ADRENO_SUBMIT_E_INACTIVE) {
        w->refused++;
        if (w->reply.status == ADRENO_IB_E_STICKY) w->state |= ADRENO_IB_STATE_DISABLED;  /* only a reset clears it */
        return fail(w, (int)w->reply.status, 0);
    }
    if (e) return fail(w, e, 0);   /* list/cache refusal before the doorbell */
    if (call.outcome == ADRENO_IB_E_GPU_ERROR) {
        w->gpu_errors++;
        w->state |= ADRENO_IB_STATE_DISABLED;
        return fail(w, ADRENO_IB_E_GPU_ERROR, 0);
    }
#if ADRENO_GPU_RECOVER
    if (call.outcome == ADRENO_IB_E_RESET || call.outcome == ADRENO_IB_E_RESET_FAULT) {   /* R14 */
        w->resets++;
        return fail(w, call.outcome, 0);
    }
#endif
    w->submitted++;
    return 0;
}
#endif

int adreno_ib_probe(struct adreno_ib_work *w, uint64_t *package_gpu, uint64_t *ib_dwords, uint64_t *package_bytes)
{
    if (!w || !package_gpu || !ib_dwords || !package_bytes) return ADRENO_LIST_E_ARGUMENT;
    if (!(w->state & ADRENO_IB_STATE_READY) || (w->state & ADRENO_IB_STATE_UNCERTAIN)) return ADRENO_SUBMIT_E_INACTIVE;
    struct adreno_ib_command c = {{ADRENO_KCMD_IB, (uint32_t)adreno_ib_command_bytes(1, 0, 0)},
                                  ADRENO_IB_COMMAND_VERSION, 0, 1, 0, 0, 0, {0, 0}};
    stage_fields(w, &c);
    for (uint64_t i = 0; i < w->package_bytes; i++) w->package[i] = 0;
    wr32(w->package, a8xx_pkt7_hdr(A8XX_E_CP_NOP, 0));
    w->targets[0] = 0;
    int e = adreno_ib_validate(w);
    if (e) return e;
    *package_gpu = w->package_gpu;
    *ib_dwords = w->command.ib_dwords;
    *package_bytes = w->package_bytes;
    return 0;
}

int adreno_fence_classify(int64_t status, uint64_t reply, uint32_t value, uint32_t observed)
{
    if (!status) return reply == value && observed == value ? 0 : ADRENO_SUBMIT_E_UNCERTAIN;
    if (reply || observed != (uint32_t)~value) return ADRENO_SUBMIT_E_UNCERTAIN;
    switch (status) {
    case ADRENO_E_PARAMS: case ADRENO_E_TARGET: case ADRENO_E_CX: case ADRENO_E_GX: case ADRENO_E_SQE:
        return ADRENO_SUBMIT_E_INACTIVE;
    }
    return ADRENO_SUBMIT_E_UNCERTAIN;
}

int adreno_submit_gated(uint8_t *latch, int (*work)(void *), void *context)
{
    if (!latch || !work) return ADRENO_LIST_E_ARGUMENT;
    if (*latch) return ADRENO_SUBMIT_E_INACTIVE;
    int result = work(context);
    if (result == ADRENO_SUBMIT_E_UNCERTAIN || result == ADRENO_LIST_E_VISIBILITY) *latch = 1;
    return result;
}

int adreno_kernel_command(const void *command, uint64_t available, const struct adreno_kernel_ops *ops)
{
    if (!ops || !ops->fence) return ADRENO_SUBMIT_E_FORMAT;
    int result = adreno_submit_command(command, available, ops->fence, ops->context);
    if (result != ADRENO_SUBMIT_E_COMMAND) return result;
    struct adreno_fill32_request fill;
    result = adreno_fill32_decode(command, available, &fill);
    if (!result) return ops->fill ? ops->fill(ops->context, &fill) : ADRENO_SUBMIT_E_INACTIVE;
    if (result != ADRENO_SUBMIT_E_COMMAND) return result;
    uint8_t type[4];
    copy_in(type, command, sizeof type);
    if (rd32(type) != ADRENO_KCMD_IB) return ADRENO_SUBMIT_E_COMMAND;
    return ops->ib ? ops->ib(ops->context, command, available) : ADRENO_SUBMIT_E_INACTIVE;
}
