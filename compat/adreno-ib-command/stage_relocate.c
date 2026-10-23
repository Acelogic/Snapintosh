/* SPDX-License-Identifier: MIT */
/* Register access helpers, field tables, staging and relocation.
 * Part of compat/adreno-ib-command.c's translation unit, included in order; not compiled on its own. */
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

