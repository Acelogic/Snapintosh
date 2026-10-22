/* SPDX-License-Identifier: MIT */
#include "adreno-resource.h"
#include "adreno.h"

#define PAGE 0x4000UL
#define LEAF_SPAN (1UL << 25)
#define RUN_PAGES 64UL /* t8110dart_map sends the SPTM 64-page lists */

static int valid(const struct adreno_resource *r, const struct adreno_resource_ops *o)
{
    return r && o && o->reserve && o->free && o->pin && o->unpin &&
        o->physical && o->insert && o->clear && !(r->flags & ADRENO_RESOURCE_FAILED);
}
static int failed(struct adreno_resource *r, int error)
{
    r->flags |= ADRENO_RESOURCE_FAILED;
    return error;
}

int adreno_resource_cache(const struct adreno_resource *r, unsigned direction,
                         int (*maintain)(void *, uint64_t, uint64_t, unsigned), void *context)
{
    if (!r || direction>ADRENO_CACHE_FROM_DEVICE || (direction && !maintain) ||
        r->flags!=(ADRENO_RESOURCE_RESERVED|ADRENO_RESOURCE_PINNED) ||
        r->mapped_length!=r->length) return ADRENO_RESOURCE_E_STATE;
    if (!r->logical_length || ((r->address|r->logical_length)&63) ||
        r->logical_length>r->length || r->address<ADRENO_WINDOW_BASE ||
        r->address>=ADRENO_WINDOW_END || r->length>ADRENO_WINDOW_END-r->address)
        return ADRENO_RESOURCE_E_RANGE;
    if (!direction) return 0;
    for (uint64_t offset=0;offset<r->logical_length;) {
        uint64_t bytes=r->logical_length-offset;
        if (bytes>ADRENO_CACHE_MAX_BYTES) bytes=ADRENO_CACHE_MAX_BYTES;
        if (maintain(context,r->address+offset,bytes,direction)) return ADRENO_RESOURCE_E_CACHE;
        offset+=bytes;
    }
    return 0;
}
#if ADRENO_CACHE_SPARSE
int adreno_resource_cache_range(const struct adreno_resource *r, unsigned direction, uint64_t offset, uint64_t bytes,
                                int (*maintain)(void *, uint64_t, uint64_t, unsigned), void *context)
{
    int e=adreno_resource_cache(r,0,0,0);           /* state, alignment and window rules of the whole extent */
    if (e) return e;
    if (direction>ADRENO_CACHE_FROM_DEVICE || (direction && !maintain)) return ADRENO_RESOURCE_E_STATE;
    if (!bytes || offset>=r->logical_length || bytes>r->logical_length-offset) return ADRENO_RESOURCE_E_RANGE;
    if (!direction) return 0;
    const uint64_t end=(offset+bytes+63)&~63UL;     /* <= logical_length, a multiple of 64 */
    for (uint64_t at=offset&~63UL;at<end;) {
        uint64_t n=end-at;
        if (n>ADRENO_CACHE_MAX_BYTES) n=ADRENO_CACHE_MAX_BYTES;
        if (maintain(context,r->address+at,n,direction)) return ADRENO_RESOURCE_E_CACHE;
        at+=n;
    }
    return 0;
}
#endif

int adreno_resource_reserve(struct adreno_resource *r, const struct adreno_resource_ops *o,
                             uint64_t length)
{
    if (!valid(r, o) || r->flags || r->address) return ADRENO_RESOURCE_E_STATE;
    if (!length || length > ADRENO_WINDOW_END - ADRENO_WINDOW_BASE) return ADRENO_RESOURCE_E_RANGE;
    uint64_t span = (length + PAGE - 1) & ~(PAGE - 1), address = 0, actual = 0;
    int e = o->reserve(o->ctx, span, &address, &actual);
    if (e) {
        if (address || actual) {
            r->address = address; r->length = actual;
            return failed(r, ADRENO_RESOURCE_E_RESERVE);
        }
        return ADRENO_RESOURCE_E_RESERVE;
    }
    r->address = address; r->length = actual; r->logical_length = length;
    r->flags = ADRENO_RESOURCE_RESERVED;
    if (!address || !actual) return failed(r, ADRENO_RESOURCE_E_RANGE);
    if ((address & (PAGE - 1)) || address < ADRENO_WINDOW_BASE || address >= ADRENO_WINDOW_END ||
        actual != span || actual > ADRENO_WINDOW_END - address) {
        /* Native final free requires populated PTEs. An inadmissible VA
         * cannot be populated here, so preserve its uncertain reservation. */
        return failed(r, ADRENO_RESOURCE_E_RANGE);
    }
    return 0;
}

static uint64_t physical_page(const struct adreno_resource *r,
                              const struct adreno_resource_ops *o, uint64_t offset)
{
    uint64_t length = 0, pa = o->physical(o->ctx, offset, &length);
    uint64_t need = r->logical_length - offset;
    if (need > PAGE) need = PAGE;
    if (!pa || (pa & (PAGE - 1)) || pa > (1UL << 48) - PAGE || length < need) return 0;
    return pa;
}

/* One run: physically contiguous pages, at most RUN_PAGES, inside one 32 MiB leaf
 * table. IODARTMapper::iovmInsert maps page i of an insert to pa + i * PAGE. */
static uint64_t run_bytes(const struct adreno_resource *r, const struct adreno_resource_ops *o,
                          uint64_t offset, uint64_t pa)
{
    uint64_t va = r->address + offset, limit = LEAF_SPAN - (va & (LEAF_SPAN - 1)), bytes = PAGE;
    if (limit > r->length - offset) limit = r->length - offset;
    if (limit > RUN_PAGES * PAGE) limit = RUN_PAGES * PAGE;
    while (bytes < limit && physical_page(r, o, offset + bytes) == pa + bytes) bytes += PAGE;
    return bytes;
}

static void uncharge(struct adreno_residency *res, uint64_t length, uint64_t *counter)
{
    if (!res) return;
    __atomic_fetch_sub(&res->bytes, length, __ATOMIC_RELAXED);
    __atomic_fetch_add(counter, 1, __ATOMIC_RELAXED);
}

static int release(struct adreno_resource *r, const struct adreno_resource_ops *o,
                   struct adreno_residency *res);

static int commit(struct adreno_resource *r, const struct adreno_resource_ops *o, unsigned options)
{
    if (!valid(r, o) || !(r->flags & ADRENO_RESOURCE_RESERVED)) return ADRENO_RESOURCE_E_STATE;
    if (r->flags & ADRENO_RESOURCE_PINNED)
        return r->mapped_length == r->length ? 0 : ADRENO_RESOURCE_E_STATE;
    if (o->pin(o->ctx)) return ADRENO_RESOURCE_E_PIN;
    r->flags |= ADRENO_RESOURCE_PINNED;
    int e = ADRENO_RESOURCE_E_SEGMENT;
    /* Pinning fixes the descriptor's physical pages. Admit the complete logical
     * range before publishing any PTE; the prepared tail page is mapped whole. */
    for (uint64_t offset = 0; offset < r->length; offset += PAGE)
        if (!physical_page(r, o, offset)) goto unwind;
    for (uint64_t offset = 0; offset < r->length;) {
        uint64_t pa = physical_page(r, o, offset);
        if (!pa) { e = ADRENO_RESOURCE_E_SEGMENT; goto unwind; }
        uint64_t bytes = (options & ADRENO_COMMIT_RUNS) ? run_bytes(r, o, offset, pa) : PAGE;
        r->mapped_length = offset + bytes; /* include a possibly partial failed insertion */
        if (o->insert(o->ctx, r->address, offset, pa, bytes)) {
            e = ADRENO_RESOURCE_E_INSERT; goto unwind;
        }
        offset += bytes;
    }
    return 0;
unwind:;
    int cleanup = release(r, o, 0);
    return cleanup ? cleanup : e;
}

static int release(struct adreno_resource *r, const struct adreno_resource_ops *o,
                   struct adreno_residency *res)
{
    if (!valid(r, o)) return ADRENO_RESOURCE_E_STATE;
    if (!(r->flags & ADRENO_RESOURCE_PINNED)) return 0;
    for (uint64_t offset = 0; offset < r->mapped_length;) {
        uint64_t va = r->address + offset, bytes = LEAF_SPAN - (va & (LEAF_SPAN - 1));
        if (bytes > r->mapped_length - offset) bytes = r->mapped_length - offset;
        if (o->clear(o->ctx, va, bytes)) return failed(r, ADRENO_RESOURCE_E_CLEAR);
        offset += bytes;
    }
    r->mapped_length = 0;
    if (o->unpin(o->ctx)) return failed(r, ADRENO_RESOURCE_E_UNPIN);
    r->flags &= ~ADRENO_RESOURCE_PINNED;
    /* Only a completed release uncharges. The failures above freeze a RESIDENT
     * mapping with its charge: its pages may still be wired. */
    if (r->flags & ADRENO_RESOURCE_RESIDENT) {
        r->flags &= ~ADRENO_RESOURCE_RESIDENT;
        if (res) uncharge(res, r->length, &res->evicted);
    }
    return 0;
}

static int free_resource(struct adreno_resource *r, const struct adreno_resource_ops *o,
                         struct adreno_residency *res, unsigned options)
{
    if (!valid(r, o)) return ADRENO_RESOURCE_E_STATE;
    if (r->flags & ADRENO_RESOURCE_RESERVED) {
        /* Native IOGPU finalize may have unwired this map. Native DART final
         * free uses strict unmap, so it needs complete PTEs and pinned backing
         * even when that requires a temporary recommit at the retained VA.
         * A RESIDENT mapping already has both. */
        int e = commit(r, o, options);
        if (e) return failed(r, e);
        if (o->free(o->ctx, r->address, r->length))
            return failed(r, ADRENO_RESOURCE_E_FREE);
        r->flags &= ~ADRENO_RESOURCE_RESERVED;
        r->mapped_length = 0;
        /* The free callback includes native unmap and mirror invalidation.
         * Keep the descriptor pinned until both have completed. */
        if (o->unpin(o->ctx)) return failed(r, ADRENO_RESOURCE_E_UNPIN);
        r->flags &= ~ADRENO_RESOURCE_PINNED;
    }
    if ((r->flags & ADRENO_RESOURCE_RESIDENT) && res) {
        __atomic_fetch_sub(&res->bytes, r->length, __ATOMIC_RELAXED);
    }
    *r = (struct adreno_resource){0};
    return 0;
}

int adreno_resource_commit(struct adreno_resource *r, const struct adreno_resource_ops *o)
{
    return commit(r, o, 0);
}

int adreno_resource_release(struct adreno_resource *r, const struct adreno_resource_ops *o)
{
    return release(r, o, 0);
}

int adreno_resource_free(struct adreno_resource *r, const struct adreno_resource_ops *o)
{
    return free_resource(r, o, 0, 0);
}

int adreno_resource_free_with(struct adreno_resource *r, const struct adreno_resource_ops *o,
                              struct adreno_residency *res, unsigned options)
{
    return free_resource(r, o, res, options);
}

int adreno_resource_unwire(struct adreno_resource *r, const struct adreno_resource_ops *o,
                           struct adreno_residency *res, int keep)
{
    if (!valid(r, o)) return ADRENO_RESOURCE_E_STATE;
    if (keep && res && res->budget && r->length && r->mapped_length == r->length &&
        r->flags == (ADRENO_RESOURCE_RESERVED | ADRENO_RESOURCE_PINNED)) {
        /* Charge first; a concurrent unwire may see a transient excess and refuse. */
        uint64_t prior = __atomic_fetch_add(&res->bytes, r->length, __ATOMIC_RELAXED);
        if (prior <= res->budget && r->length <= res->budget - prior) {
            r->flags |= ADRENO_RESOURCE_RESIDENT;
            __atomic_fetch_add(&res->retained, 1, __ATOMIC_RELAXED);
            return 0;
        }
        uncharge(res, r->length, &res->refused);
    }
    return release(r, o, res);
}

#if ADRENO_RESOURCE_POOL
#define POOL_BUMP(p, field) do { if (p) __atomic_fetch_add(&(p)->field, 1, __ATOMIC_RELAXED); } while (0)
static void pool_lock(struct adreno_va_pool *p) { if (p->lock) p->lock(p->lock_ctx); }
static void pool_unlock(struct adreno_va_pool *p) { if (p->unlock) p->unlock(p->lock_ctx); }
#if ADRENO_POOL_ARENA
/* K6: an entry of the arena class: exactly arena_span and takeable (a parked collision is general). */
static int arena_entry(const struct adreno_va_pool *p, uint64_t span, unsigned flags)
{
    return p->arena_span && span == p->arena_span && !(flags & ADRENO_VA_POOL_SUSPECT);
}
#endif

/* The oldest entry of exactly this span (D4) that is not a parked collision (V3); removed (D10). */
static int pool_take(struct adreno_va_pool *p, uint64_t span, uint64_t *address)
{
    if (!p) return 0;
    pool_lock(p);
    unsigned best = ADRENO_VA_POOL_SLOTS;
    for (unsigned i = 0; i < p->count; i++)
        if (p->span[i] == span && !(p->flags[i] & ADRENO_VA_POOL_SUSPECT) &&
            (best == ADRENO_VA_POOL_SLOTS || p->order[i] < p->order[best])) best = i;
    int found = best < ADRENO_VA_POOL_SLOTS;
    if (found) {
        unsigned last = --p->count;
        *address = p->address[best];
        p->bytes -= p->span[best];
#if ADRENO_POOL_ARENA
        p->arena_count -= (uint64_t)arena_entry(p, p->span[best], p->flags[best]);
#endif
        p->address[best] = p->address[last]; p->span[best] = p->span[last];
        p->order[best] = p->order[last]; p->flags[best] = p->flags[last];
        POOL_BUMP(p, takes);
    }
    pool_unlock(p);
    return found;
}
/* Admission within the slot, per-span, byte and span limits (D5); 0 when admitted. */
static int pool_put(struct adreno_va_pool *p, uint64_t address, uint64_t span, unsigned flags)
{
    if (!p || !span || span > p->max_span) return -1;
    pool_lock(p);
#if ADRENO_VA_RECLAIM
    /* G6, G9: while the DART is short, a released reservation goes back to it (the strict path, filled) instead of
     * waiting here; a parked collision is still parked (G1: the DART would hand it out again). */
    if (p->pressure && !(flags & ADRENO_VA_POOL_SUSPECT)) {
        p->pressure--;
        POOL_BUMP(p, refused);
        POOL_BUMP(p, pressure_refused);
        pool_unlock(p);
        return -1;
    }
#endif
    unsigned same = 0;
#if ADRENO_POOL_ARENA
    /* K5-K7: an arena against the class limit alone; anything else against batch 8's rules over the general
     * entries (the class's entries, and their bytes, left out). */
    int arena = arena_entry(p, span, flags), ok;
    if (arena) {
        ok = p->count < ADRENO_VA_POOL_SLOTS && p->arena_count < p->arena_limit &&
             p->arena_limit <= ADRENO_VA_POOL_ARENA_ENTRIES;
    } else {
        uint64_t general = p->bytes - p->arena_count * p->arena_span;
        for (unsigned i = 0; i < p->count; i++)
            same += p->span[i] == span && !arena_entry(p, p->span[i], p->flags[i]);
        ok = p->count - p->arena_count < ADRENO_VA_POOL_GENERAL && same < ADRENO_VA_POOL_PER_SPAN &&
             general <= p->limit_bytes && span <= p->limit_bytes - general;
    }
#else
    for (unsigned i = 0; i < p->count; i++) same += p->span[i] == span;
    int ok = p->count < ADRENO_VA_POOL_SLOTS && same < ADRENO_VA_POOL_PER_SPAN && p->bytes <= p->limit_bytes &&
             span <= p->limit_bytes - p->bytes;
#endif
    if (ok) {
        unsigned i = p->count++;
        p->address[i] = address; p->span[i] = span; p->order[i] = p->next++; p->flags[i] = flags;
        p->bytes += span;
#if ADRENO_POOL_ARENA
        p->arena_count += (uint64_t)arena;
#endif
        POOL_BUMP(p, puts);
        if (flags & ADRENO_VA_POOL_SUSPECT) POOL_BUMP(p, suspects);
    } else {
        POOL_BUMP(p, refused);
    }
    pool_unlock(p);
    return ok ? 0 : -1;
}

int adreno_resource_adopt(struct adreno_resource *r, uint64_t length, uint64_t address, uint64_t span)
{
    if (!r || r->flags || r->address) return ADRENO_RESOURCE_E_STATE;
    if (!length || length > ADRENO_WINDOW_END - ADRENO_WINDOW_BASE) return ADRENO_RESOURCE_E_RANGE;
    if (span != ((length + PAGE - 1) & ~(PAGE - 1)) || !address || (address & (PAGE - 1)) ||
        address < ADRENO_WINDOW_BASE || address >= ADRENO_WINDOW_END || span > ADRENO_WINDOW_END - address)
        return ADRENO_RESOURCE_E_RANGE;
    *r = (struct adreno_resource){address, span, length, 0, ADRENO_RESOURCE_RESERVED};
    return 0;
}

#if ADRENO_VA_RECLAIM
static int filler_ok(const struct adreno_va_filler *f)
{
    return f && f->insert && f->free && f->pa && !(f->pa & (PAGE - 1)) && f->bytes >= PAGE &&
           !(f->bytes & (PAGE - 1)) && f->bytes <= RUN_PAGES * PAGE;
}
/* G2, G3: a reservation without a leaf gets the filler's read-only leaves over its whole span (runs within one 32 MiB
 * leaf table and the filler), then the strict native free. A failed insert never reaches the free. */
static int fill_free(const struct adreno_va_filler *f, uint64_t address, uint64_t span)
{
    for (uint64_t offset = 0; offset < span;) {
        uint64_t va = address + offset, bytes = LEAF_SPAN - (va & (LEAF_SPAN - 1));
        if (bytes > span - offset) bytes = span - offset;
        if (bytes > f->bytes) bytes = f->bytes;
        if (f->insert(f->ctx, address, offset, f->pa, bytes)) return ADRENO_RESOURCE_E_INSERT;
        offset += bytes;
    }
    return f->free(f->ctx, address, span) ? ADRENO_RESOURCE_E_FREE : 0;
}
static void count_lost(struct adreno_va_pool *p, uint64_t bytes)
{
    POOL_BUMP(p, lost);
    __atomic_fetch_add(&p->lost_bytes, bytes, __ATOMIC_RELAXED);
}
/* G5: the strict free of an unpinned reservation without its backing. A failure freezes r, as before. */
static int filled_free(struct adreno_resource *r, struct adreno_va_pool *p)
{
    int e = fill_free(p->filler, r->address, r->length);
    if (e) {
        count_lost(p, r->length);
        return failed(r, e);
    }
    POOL_BUMP(p, filled);
    *r = (struct adreno_resource){0};
    return 0;
}
/* G1: one entry out of the pool under its lock, never a parked collision: with fit, the smallest whose span alone
 * holds fit (oldest first among equals); without, the oldest. 0 when there is none. */
static int pool_remove(struct adreno_va_pool *p, uint64_t fit, uint64_t *address, uint64_t *span)
{
    pool_lock(p);
    unsigned best = ADRENO_VA_POOL_SLOTS;
    for (unsigned i = 0; i < p->count; i++) {
        if ((p->flags[i] & ADRENO_VA_POOL_SUSPECT) || (fit && p->span[i] < fit)) continue;
        if (best == ADRENO_VA_POOL_SLOTS || (fit && p->span[i] < p->span[best]) ||
            ((!fit || p->span[i] == p->span[best]) && p->order[i] < p->order[best])) best = i;
    }
    int found = best < ADRENO_VA_POOL_SLOTS;
    if (found) {
        unsigned last = --p->count;
        *address = p->address[best]; *span = p->span[best];
        p->bytes -= p->span[best];
#if ADRENO_POOL_ARENA
        const uint64_t arena = (uint64_t)arena_entry(p, p->span[best], p->flags[best]);
        p->arena_count -= arena;                                 /* K7 for a drained entry */
#endif
        p->address[best] = p->address[last]; p->span[best] = p->span[last];
        p->order[best] = p->order[last]; p->flags[best] = p->flags[last];
    }
    pool_unlock(p);
    return found;
}
/* G6, G17: give the DART back the entry that alone fits span, then the oldest, until max(span, the floor) bytes;
 * each through a filled strict free outside the pool lock (G8). Returns the bytes given back. */
static uint64_t pool_drain(struct adreno_va_pool *p, uint64_t span)
{
    const uint64_t goal = span > ADRENO_VA_DRAIN_FLOOR ? span : ADRENO_VA_DRAIN_FLOOR;
    uint64_t given = 0, address = 0, length = 0;
    int fit = pool_remove(p, span, &address, &length);
    while (fit || (given < goal && pool_remove(p, 0, &address, &length))) {
        fit = 0;
        __atomic_fetch_add(&p->recommit_pages, length / PAGE, __ATOMIC_RELAXED);
        if (fill_free(p->filler, address, length)) {
            count_lost(p, length);                               /* G2: never freed, never pooled again */
            continue;
        }
        POOL_BUMP(p, drained);
        __atomic_fetch_add(&p->drained_bytes, length, __ATOMIC_RELAXED);
        given += length;
    }
    return given;
}
/* G6, G7: the DART refused a fresh reservation. Pressure first (later puts go back to the DART), then at most
 * ADRENO_VA_RECLAIM_ROUNDS drains, each followed by one more reserve; stops when the pool has nothing to give. */
static int reclaim(struct adreno_resource *r, const struct adreno_resource_ops *o, uint64_t length,
                   struct adreno_va_pool *p)
{
    int e = ADRENO_RESOURCE_E_RESERVE;
    if (!p) return e;
    POOL_BUMP(p, exhausted);
    if (!filler_ok(p->filler)) return e;                        /* G12: as without the define */
    const uint64_t span = (length + PAGE - 1) & ~(PAGE - 1);
    pool_lock(p);
    p->pressure = ADRENO_VA_PRESSURE_PUTS;
    pool_unlock(p);
    for (unsigned round = 0; round < ADRENO_VA_RECLAIM_ROUNDS && pool_drain(p, span); round++) {
        e = adreno_resource_reserve(r, o, length);
        if (e != ADRENO_RESOURCE_E_RESERVE || r->flags) break;
    }
    if (e) POOL_BUMP(p, reclaim_failed);
    else POOL_BUMP(p, reclaimed);
    return e;
}
#endif

/* The native side has let go of r's range (or never held it). Empty it and pool it, else free it strictly. */
static int settle(struct adreno_resource *r, const struct adreno_resource_ops *o, struct adreno_residency *res,
                  unsigned options, struct adreno_va_pool *pool, unsigned flags)
{
    if (!valid(r, o)) return ADRENO_RESOURCE_E_STATE;            /* frozen earlier: retained (D7) */
    if (!(r->flags & ADRENO_RESOURCE_RESERVED)) {
        if (r->flags) return ADRENO_RESOURCE_E_STATE;
        *r = (struct adreno_resource){0};
        return 0;
    }
    if (pool && r->length <= pool->max_span) {
        uint64_t address = r->address, span = r->length, logical = r->logical_length;
        /* D1: clear every leaf (holes admitted) and unpin, uncharging a RESIDENT mapping; nothing when the
         * reservation was never committed or already released. A failure freezes r (FAILED, pinned). */
        int e = release(r, o, res);
        if (e) return e;
        *r = (struct adreno_resource){0};
        if (!pool_put(pool, address, span, flags)) return 0;
        /* Refused: the strict path, as before the pool (D2). */
        *r = (struct adreno_resource){address, span, logical, 0, ADRENO_RESOURCE_RESERVED};
    }
    if (pool) {
        POOL_BUMP(pool, strict);
        if (!(r->flags & ADRENO_RESOURCE_PINNED))
            __atomic_fetch_add(&pool->recommit_pages, r->length / PAGE, __ATOMIC_RELAXED);
#if ADRENO_VA_RECLAIM
        /* G3, G5: released (or never committed), so no leaf: the filler stands in for the backing. */
        if (filler_ok(pool->filler) && !(r->flags & ADRENO_RESOURCE_PINNED)) return filled_free(r, pool);
#endif
    }
    return free_resource(r, o, res, options);
}

int adreno_resource_retire(struct adreno_resource *r, const struct adreno_resource_ops *o,
                           struct adreno_residency *res, unsigned options, struct adreno_va_pool *pool,
                           adreno_unbind_fn unbind, void *ctx)
{
    if (!r || !o) return ADRENO_RESOURCE_E_STATE;
    if (unbind) unbind(ctx);                                     /* V1: the CB0 range first */
    return settle(r, o, res, options, pool, 0);
}

int adreno_resource_bind(struct adreno_resource *r, const struct adreno_resource_ops *o, uint64_t length,
                         struct adreno_va_pool *pool, adreno_bind_fn bind, adreno_unbind_fn unbind, void *ctx,
                         struct adreno_residency *res, unsigned options)
{
    if (!valid(r, o) || !bind || r->flags || r->address) return ADRENO_RESOURCE_E_STATE;
    if (!length || length > ADRENO_WINDOW_END - ADRENO_WINDOW_BASE) return ADRENO_RESOURCE_E_RANGE;
    uint64_t span = (length + PAGE - 1) & ~(PAGE - 1);
    for (unsigned attempt = 0; attempt < ADRENO_BIND_ATTEMPTS; attempt++) {
        uint64_t address = 0;
        int e = attempt == 0 && pool_take(pool, span, &address) ? adreno_resource_adopt(r, length, address, span)
                                                                : adreno_resource_reserve(r, o, length);
#if ADRENO_VA_RECLAIM
        if (e == ADRENO_RESOURCE_E_RESERVE && !r->flags) e = reclaim(r, o, length, pool);
#endif
        if (e) return e;
        /* The bind may commit into r (add_mapping on wired memory) before it returns. */
        int b = bind(ctx, r->address, length);
        if (!b) return 0;
        if (b != 1) {
            /* V4: natively allocated but not admitted: CB0 first, then the reservation; no retry. */
            POOL_BUMP(pool, unbound);
            int f = adreno_resource_retire(r, o, res, options, pool, unbind, ctx);
            return f ? f : ADRENO_RESOURCE_E_BIND;
        }
        /* V3, V6: refused before the native allocation, so add_mapping did not run and r is empty. Park
         * it (never handed out again) and reserve a fresh range; the DART cannot return the parked one. */
        POOL_BUMP(pool, collisions);
        int f = settle(r, o, res, options, pool, ADRENO_VA_POOL_SUSPECT);
        if (f) return f;
        if (attempt + 1 < ADRENO_BIND_ATTEMPTS) POOL_BUMP(pool, retried);
    }
    POOL_BUMP(pool, gave_up);
    return ADRENO_RESOURCE_E_BIND;
}
#endif

int adreno_resource_rewire(struct adreno_resource *r, const struct adreno_resource_ops *o,
                           struct adreno_residency *res, int same, unsigned options)
{
    if (!valid(r, o)) return ADRENO_RESOURCE_E_STATE;
    if (r->flags & ADRENO_RESOURCE_RESIDENT) {
        if (same) {
            if (r->flags != (ADRENO_RESOURCE_RESERVED | ADRENO_RESOURCE_PINNED | ADRENO_RESOURCE_RESIDENT) ||
                r->mapped_length != r->length) return ADRENO_RESOURCE_E_STATE;
            r->flags &= ~ADRENO_RESOURCE_RESIDENT;
            uncharge(res, r->length, res ? &res->reused : 0);
            return 0;
        }
        /* Stale backing: clear, invalidate and unpin before pinning the new one. */
        int e = release(r, o, res);
        if (e) return e;
    } else if (!same) {
        return ADRENO_RESOURCE_E_STATE;
    }
    return commit(r, o, options);
}
