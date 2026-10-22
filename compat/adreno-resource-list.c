/* SPDX-License-Identifier: MIT */
#include "adreno-resource-list.h"
#include "adreno-submit.h"
#include "adreno-guest.h"

static uint16_t read16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1]<<8); }
static uint32_t read32(const uint8_t *p)
{ return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }

int adreno_resource_list_measure(const void *input, uint64_t available,
                                 uint64_t *bytes, uint64_t *capacity)
{
    if (!input || !bytes || !capacity) return ADRENO_LIST_E_ARGUMENT;
    *bytes=0; *capacity=0;
    if (available<32) return ADRENO_LIST_E_FORMAT;
    uint32_t groups=read32((const uint8_t *)input+28);
    if (groups>ADRENO_LIST_MAX_GROUPS || groups>(available-32)/64)
        return ADRENO_LIST_E_FORMAT;
    *bytes=32+(uint64_t)groups*64;
    *capacity=(uint64_t)groups*6;
    return 0;
}

void adreno_resource_list_freeze(struct adreno_resource_list *list)
{
    if (list && list->ready) list->ready|=ADRENO_LIST_FROZEN;
}
#if ADRENO_CACHE_SPARSE
/* Epochs for lists and list submissions: unique, never 0 (FAILURE-MODES.md C1c). Zero-initialized: no data. */
static uint64_t cache_epochs, cache_counts[ADRENO_CACHE_COUNTERS];
static uint64_t next_epoch(void) { return __atomic_add_fetch(&cache_epochs,1,__ATOMIC_RELAXED); }
static void count(unsigned which, uint64_t n) { if (n) __atomic_fetch_add(&cache_counts[which],n,__ATOMIC_RELAXED); }
void adreno_cache_sparse_counters(uint64_t v[ADRENO_CACHE_COUNTERS])
{
    for (unsigned i=0;i<ADRENO_CACHE_COUNTERS;i++) v[i]=__atomic_load_n(&cache_counts[i],__ATOMIC_RELAXED);
}
static struct adreno_cache_mark *mark_of(const struct adreno_resource_list *list,
                                         const struct adreno_resource_list_ops *ops, void *preparation)
{
    return list->cache && list->cache->mark ? list->cache->mark(ops->context,preparation) : 0;
}
static int sync_scope(const struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                      void *preparation, unsigned direction, const struct adreno_cache_scope *scope)
{
    return list->cache && list->cache->sync_range ?
        list->cache->sync_range(ops->context,preparation,direction,scope->offset,scope->bytes) :
        ops->sync(ops->context,preparation,direction);
}
#if ADRENO_PIPELINE
/* --pipeline: submit_scope below, split at its work call (adreno-resource-list.h). Same checks, order and results. */
int adreno_resource_list_begin_scope(struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                                     const struct adreno_cache_scope *scope, struct adreno_list_pending *p)
{
    if (!list || !ops || !ops->sync || !scope || !p || scope->kind>ADRENO_CACHE_SCOPE_RANGE)
        return ADRENO_LIST_E_ARGUMENT;
    p->armed=0;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready!=(ADRENO_LIST_READY|ADRENO_LIST_PREPARED) ||
        list->prepared_count!=list->count || (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    for (uint64_t i=0;i<list->count;i++)
        if (ops->sync(ops->context,list->entries[i].preparation,0)) return ADRENO_LIST_E_CACHE;
    void *target=0;
    unsigned target_usage=0;
    if (scope->kind==ADRENO_CACHE_SCOPE_RANGE) {
        for (uint64_t i=0;i<list->count;i++)
            if (list->entries[i].preparation==scope->preparation) {
                target=list->entries[i].preparation;
                target_usage|=list->entries[i].usage;
            }
        if (!target) return ADRENO_LIST_E_ARGUMENT;
    }
    const uint64_t submission=next_epoch();
    count(ADRENO_CACHE_N_ALL+scope->kind,1);
    if (scope->kind==ADRENO_CACHE_SCOPE_ALL) {
        for (uint64_t i=0;i<list->count;i++) {
            void *preparation=list->entries[i].preparation;
            struct adreno_cache_mark *m=mark_of(list,ops,preparation);
            if (m && __atomic_load_n(&m->cleaned,__ATOMIC_RELAXED)==list->epoch) {
                count(ADRENO_CACHE_N_TO_SKIPPED,1);
                continue;
            }
            if (ops->sync(ops->context,preparation,ADRENO_CACHE_TO_DEVICE)) return ADRENO_LIST_E_CACHE;
            if (m) __atomic_store_n(&m->cleaned,list->epoch,__ATOMIC_RELAXED);
            count(ADRENO_CACHE_N_TO,1);
        }
    } else if (scope->kind==ADRENO_CACHE_SCOPE_RANGE) {
        if (sync_scope(list,ops,target,ADRENO_CACHE_TO_DEVICE,scope)) return ADRENO_LIST_E_CACHE;
        count(ADRENO_CACHE_N_TO_SKIPPED,list->count-1);
    } else {
        count(ADRENO_CACHE_N_TO_SKIPPED,list->count);
    }
    p->submission=submission; p->kind=scope->kind; p->target=target; p->target_usage=target_usage;
    p->offset=scope->offset; p->bytes=scope->bytes; p->armed=1;
    return 0;
}
int adreno_resource_list_begin(struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                               struct adreno_list_pending *p)
{
    const struct adreno_cache_scope all={ADRENO_CACHE_SCOPE_ALL,0,0,0};
    return adreno_resource_list_begin_scope(list,ops,&all,p);
}
int adreno_resource_list_end(struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                             struct adreno_list_pending *p, int result)
{
    if (!list || !ops || !ops->sync || !p || !p->armed) return ADRENO_LIST_E_ARGUMENT;
    p->armed=0;
    if (result) {
        if (result==ADRENO_SUBMIT_E_INACTIVE) return result;
        adreno_resource_list_freeze(list);
        return ADRENO_SUBMIT_E_UNCERTAIN;
    }
    if (p->kind==ADRENO_CACHE_SCOPE_ALL) {
        for (uint64_t i=0;i<list->count;i++) {
            if (!(list->entries[i].usage&2u)) continue;
            void *preparation=list->entries[i].preparation;
            struct adreno_cache_mark *m=mark_of(list,ops,preparation);
            if (m && __atomic_load_n(&m->invalidated,__ATOMIC_RELAXED)==p->submission) {
                count(ADRENO_CACHE_N_FROM_SKIPPED,1);
                continue;
            }
            if (ops->sync(ops->context,preparation,ADRENO_CACHE_FROM_DEVICE)) {
                adreno_resource_list_freeze(list);
                return ADRENO_LIST_E_VISIBILITY;
            }
            if (m) __atomic_store_n(&m->invalidated,p->submission,__ATOMIC_RELAXED);
            count(ADRENO_CACHE_N_FROM,1);
        }
    } else if (p->kind==ADRENO_CACHE_SCOPE_RANGE && (p->target_usage&2u)) {
        const struct adreno_cache_scope scope={ADRENO_CACHE_SCOPE_RANGE,p->target,p->offset,p->bytes};
        if (sync_scope(list,ops,(void *)(uintptr_t)p->target,ADRENO_CACHE_FROM_DEVICE,&scope)) {
            adreno_resource_list_freeze(list);
            return ADRENO_LIST_E_VISIBILITY;
        }
        count(ADRENO_CACHE_N_FROM,1);
    }
    return 0;
}
int adreno_resource_list_submit_scope(struct adreno_resource_list *list,
                                      const struct adreno_resource_list_ops *ops,
                                      int (*submit)(void *), void *context,
                                      const struct adreno_cache_scope *scope)
{
    if (!list || !ops || !ops->sync || !submit || !scope || scope->kind>ADRENO_CACHE_SCOPE_RANGE)
        return ADRENO_LIST_E_ARGUMENT;
    struct adreno_list_pending p;
    int result=adreno_resource_list_begin_scope(list,ops,scope,&p);
    if (result) return result;
    return adreno_resource_list_end(list,ops,&p,submit(context));
}
#else
int adreno_resource_list_submit_scope(struct adreno_resource_list *list,
                                      const struct adreno_resource_list_ops *ops,
                                      int (*submit)(void *), void *context,
                                      const struct adreno_cache_scope *scope)
{
    if (!list || !ops || !ops->sync || !submit || !scope || scope->kind>ADRENO_CACHE_SCOPE_RANGE)
        return ADRENO_LIST_E_ARGUMENT;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready!=(ADRENO_LIST_READY|ADRENO_LIST_PREPARED) ||
        list->prepared_count!=list->count || (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    /* Check every logical extent before touching any resource's CPU cache (C9: a fence still refuses a lost map). */
    for (uint64_t i=0;i<list->count;i++)
        if (ops->sync(ops->context,list->entries[i].preparation,0)) return ADRENO_LIST_E_CACHE;
    void *target=0;
    unsigned target_usage=0;
    if (scope->kind==ADRENO_CACHE_SCOPE_RANGE) {
        for (uint64_t i=0;i<list->count;i++)
            if (list->entries[i].preparation==scope->preparation) {
                target=list->entries[i].preparation;
                target_usage|=list->entries[i].usage;
            }
        if (!target) return ADRENO_LIST_E_ARGUMENT;
    }
    const uint64_t submission=next_epoch();
    count(ADRENO_CACHE_N_ALL+scope->kind,1);
    /* TO_DEVICE. ALL: each map once per list; a whole clean marks it (C1). RANGE: the target's range, unmarked. */
    if (scope->kind==ADRENO_CACHE_SCOPE_ALL) {
        for (uint64_t i=0;i<list->count;i++) {
            void *preparation=list->entries[i].preparation;
            struct adreno_cache_mark *m=mark_of(list,ops,preparation);
            if (m && __atomic_load_n(&m->cleaned,__ATOMIC_RELAXED)==list->epoch) {
                count(ADRENO_CACHE_N_TO_SKIPPED,1);
                continue;
            }
            if (ops->sync(ops->context,preparation,ADRENO_CACHE_TO_DEVICE)) return ADRENO_LIST_E_CACHE;
            if (m) __atomic_store_n(&m->cleaned,list->epoch,__ATOMIC_RELAXED);
            count(ADRENO_CACHE_N_TO,1);
        }
    } else if (scope->kind==ADRENO_CACHE_SCOPE_RANGE) {
        if (sync_scope(list,ops,target,ADRENO_CACHE_TO_DEVICE,scope)) return ADRENO_LIST_E_CACHE;
        count(ADRENO_CACHE_N_TO_SKIPPED,list->count-1);
    } else {
        count(ADRENO_CACHE_N_TO_SKIPPED,list->count);
    }
    int result=submit(context);
    if (result) {
        if (result==ADRENO_SUBMIT_E_INACTIVE) return result;
        adreno_resource_list_freeze(list);
        return ADRENO_SUBMIT_E_UNCERTAIN;
    }
    /* FROM_DEVICE after retirement, only where this command let the GPU write (C2, C3: every range invalidated here
     * was cleaned in this list before the doorbell). ALL: each Write map once per submission (C7). */
    if (scope->kind==ADRENO_CACHE_SCOPE_ALL) {
        for (uint64_t i=0;i<list->count;i++) {
            if (!(list->entries[i].usage&2u)) continue;
            void *preparation=list->entries[i].preparation;
            struct adreno_cache_mark *m=mark_of(list,ops,preparation);
            if (m && __atomic_load_n(&m->invalidated,__ATOMIC_RELAXED)==submission) {
                count(ADRENO_CACHE_N_FROM_SKIPPED,1);
                continue;
            }
            if (ops->sync(ops->context,preparation,ADRENO_CACHE_FROM_DEVICE)) {
                adreno_resource_list_freeze(list);
                return ADRENO_LIST_E_VISIBILITY;
            }
            if (m) __atomic_store_n(&m->invalidated,submission,__ATOMIC_RELAXED);
            count(ADRENO_CACHE_N_FROM,1);
        }
    } else if (scope->kind==ADRENO_CACHE_SCOPE_RANGE && (target_usage&2u)) {
        if (sync_scope(list,ops,target,ADRENO_CACHE_FROM_DEVICE,scope)) {
            adreno_resource_list_freeze(list);
            return ADRENO_LIST_E_VISIBILITY;
        }
        count(ADRENO_CACHE_N_FROM,1);
    }
    return 0;
}
#endif
int adreno_resource_list_submit(struct adreno_resource_list *list,
                                const struct adreno_resource_list_ops *ops,
                                int (*submit)(void *), void *context)
{
    const struct adreno_cache_scope all={ADRENO_CACHE_SCOPE_ALL,0,0,0};
    return adreno_resource_list_submit_scope(list,ops,submit,context,&all);
}
#if ADRENO_PIPELINE
int adreno_resource_list_validate(struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops)
{
    if (!list || !ops || !ops->sync) return ADRENO_LIST_E_ARGUMENT;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready!=(ADRENO_LIST_READY|ADRENO_LIST_PREPARED) ||
        list->prepared_count!=list->count || (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    for (uint64_t i=0;i<list->count;i++)
        if (ops->sync(ops->context,list->entries[i].preparation,0)) return ADRENO_LIST_E_CACHE;
    return 0;
}
#endif
#elif ADRENO_PIPELINE
/* --pipeline: adreno_resource_list_submit split at its work call (adreno-resource-list.h). Same checks, order and
 * results as the unsplit function below. */
int adreno_resource_list_begin(struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                               struct adreno_list_pending *p)
{
    if (!list || !ops || !ops->sync || !p) return ADRENO_LIST_E_ARGUMENT;
    p->armed=0;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready!=(ADRENO_LIST_READY|ADRENO_LIST_PREPARED) ||
        list->prepared_count!=list->count || (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    for (unsigned direction=0;direction<=ADRENO_CACHE_TO_DEVICE;direction++)
        for (uint64_t i=0;i<list->count;i++)
            if (ops->sync(ops->context,list->entries[i].preparation,direction))
                return ADRENO_LIST_E_CACHE;
    p->submission=0; p->kind=0; p->target=0; p->target_usage=0; p->offset=0; p->bytes=0; p->armed=1;
    return 0;
}
int adreno_resource_list_end(struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                             struct adreno_list_pending *p, int result)
{
    if (!list || !ops || !ops->sync || !p || !p->armed) return ADRENO_LIST_E_ARGUMENT;
    p->armed=0;
    if (result) {
        if (result==ADRENO_SUBMIT_E_INACTIVE) return result;
        adreno_resource_list_freeze(list);
        return ADRENO_SUBMIT_E_UNCERTAIN;
    }
    for (uint64_t i=0;i<list->count;i++)
        if ((list->entries[i].usage&2u) &&
            ops->sync(ops->context,list->entries[i].preparation,ADRENO_CACHE_FROM_DEVICE)) {
            adreno_resource_list_freeze(list);
            return ADRENO_LIST_E_VISIBILITY;
        }
    return 0;
}
int adreno_resource_list_validate(struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops)
{
    if (!list || !ops || !ops->sync) return ADRENO_LIST_E_ARGUMENT;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready!=(ADRENO_LIST_READY|ADRENO_LIST_PREPARED) ||
        list->prepared_count!=list->count || (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    for (uint64_t i=0;i<list->count;i++)
        if (ops->sync(ops->context,list->entries[i].preparation,0)) return ADRENO_LIST_E_CACHE;
    return 0;
}
int adreno_resource_list_submit(struct adreno_resource_list *list,
                                const struct adreno_resource_list_ops *ops,
                                int (*submit)(void *), void *context)
{
    if (!list || !ops || !ops->sync || !submit) return ADRENO_LIST_E_ARGUMENT;
    struct adreno_list_pending p;
    int result=adreno_resource_list_begin(list,ops,&p);
    if (result) return result;
    return adreno_resource_list_end(list,ops,&p,submit(context));
}
#else
int adreno_resource_list_submit(struct adreno_resource_list *list,
                                const struct adreno_resource_list_ops *ops,
                                int (*submit)(void *), void *context)
{
    if (!list || !ops || !ops->sync || !submit) return ADRENO_LIST_E_ARGUMENT;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready!=(ADRENO_LIST_READY|ADRENO_LIST_PREPARED) ||
        list->prepared_count!=list->count || (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    /* Check every logical extent before touching any resource's CPU cache. */
    for (unsigned direction=0;direction<=ADRENO_CACHE_TO_DEVICE;direction++)
        for (uint64_t i=0;i<list->count;i++)
            if (ops->sync(ops->context,list->entries[i].preparation,direction))
                return ADRENO_LIST_E_CACHE;
    int result=submit(context);
    if (result) {
        if (result==ADRENO_SUBMIT_E_INACTIVE) return result;
        adreno_resource_list_freeze(list);
        return ADRENO_SUBMIT_E_UNCERTAIN;
    }
    /* FROM_DEVICE only invalidates: run it only where the GPU may have written (MTLResourceUsageWrite, 2).
     * On a read-only entry it would discard concurrent CPU stores, and the monitor refuses it on a
     * GPU-read-only leaf (design 3.5, R4). TO_DEVICE above stays on every entry. */
    for (uint64_t i=0;i<list->count;i++)
        if ((list->entries[i].usage&2u) &&
            ops->sync(ops->context,list->entries[i].preparation,ADRENO_CACHE_FROM_DEVICE)) {
            adreno_resource_list_freeze(list);
            return ADRENO_LIST_E_VISIBILITY;
        }
    return 0;
}
#endif
int adreno_resource_list_complete(struct adreno_resource_list *list,
                                  const struct adreno_resource_list_ops *ops)
{
    if (!list) return ADRENO_LIST_E_ARGUMENT;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->prepared_count && (!ops || !ops->complete)) return ADRENO_LIST_E_ARGUMENT;
    while (list->prepared_count) {
        struct adreno_resource_entry *entry=&list->entries[--list->prepared_count];
        ops->complete(ops->context,entry->preparation);
        entry->preparation=0;
    }
    list->ready&=~ADRENO_LIST_PREPARED;
    return 0;
}
int adreno_resource_list_prepare(struct adreno_resource_list *list,
                                 const struct adreno_resource_list_ops *ops)
{
    if (!list || !list->ready || !ops || !ops->prepare || !ops->complete)
        return ADRENO_LIST_E_ARGUMENT;
    if ((list->ready&(ADRENO_LIST_PREPARED|ADRENO_LIST_FROZEN)) || list->prepared_count)
        return ADRENO_LIST_E_BUSY;
    for (uint64_t i=0;i<list->count;i++) {
        struct adreno_resource_entry *entry=&list->entries[i];
        entry->preparation=0;
        int result=ops->prepare(ops->context,entry->resource,&entry->preparation);
        if ((!result)!=!!entry->preparation) {
            if (entry->preparation) list->prepared_count++;
            adreno_resource_list_freeze(list);
            return ADRENO_LIST_E_STATE;
        }
        if (result) {
            adreno_resource_list_complete(list,ops);
            return ADRENO_LIST_E_PREPARE;
        }
        list->prepared_count++;
    }
    list->ready|=ADRENO_LIST_PREPARED;
#if ADRENO_CACHE_SPARSE
    list->epoch=next_epoch();          /* a new ownership interval: no map counts as cleaned in it yet */
#endif
    return 0;
}
int adreno_resource_list_release(struct adreno_resource_list *list,
                                 const struct adreno_resource_list_ops *ops)
{
    if (!list) return ADRENO_LIST_E_ARGUMENT;
    if (!list->ready) return 0;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (!ops || !ops->release) return ADRENO_LIST_E_ARGUMENT;
    int result=adreno_resource_list_complete(list,ops);
    if (result) return result;
    while (list->count) {
        struct adreno_resource_entry *entry=&list->entries[--list->count];
        ops->release(ops->context,entry->resource);
        entry->resource=0;
    }
    list->entries=0; list->ready=0;
    return 0;
}

int adreno_resource_list_acquire(struct adreno_resource_list *list, const void *input,
    uint64_t available, void *snapshot, uint64_t snapshot_capacity,
    struct adreno_resource_entry *entries, uint64_t entry_capacity,
    const struct adreno_resource_list_ops *ops)
{
    if (!list) return ADRENO_LIST_E_ARGUMENT;
    if (list->ready) return ADRENO_LIST_E_BUSY;
    if (!snapshot || snapshot==input || !ops || !ops->retain || !ops->release)
        return ADRENO_LIST_E_ARGUMENT;
    uint64_t bytes=0,maximum=0;
    int result=adreno_resource_list_measure(input,available,&bytes,&maximum);
    if (result) return result;
    if (bytes>snapshot_capacity) return ADRENO_LIST_E_CAPACITY;
    /* The source can change while copied. Only the bounded copy is parsed. */
    const volatile uint8_t *source=input;
    uint8_t *copy=snapshot;
    for (uint64_t i=0;i<bytes;i++) copy[i]=source[i];
    result=adreno_resource_list_measure(copy,bytes,&bytes,&maximum);
    if (result) return result;
    uint32_t groups=read32(copy+28);
    uint64_t count=0;
    for (uint32_t g=0;g<groups;g++) {
        const uint8_t *group=copy+32+(uint64_t)g*64;
        uint16_t n=read16(group+62);
        if (n>6) return ADRENO_LIST_E_FORMAT;
        count+=n;
        for (uint16_t i=0;i<n;i++)
            if (!read32(group+i*4)) return ADRENO_LIST_E_FORMAT;
    }
    if (count>entry_capacity) return ADRENO_LIST_E_CAPACITY;
    if (count && !entries) return ADRENO_LIST_E_ARGUMENT;
    list->entries=entries; list->count=0; list->prepared_count=0; list->ready=ADRENO_LIST_READY;
    for (uint32_t g=0;g<groups;g++) {
        const uint8_t *group=copy+32+(uint64_t)g*64;
        uint16_t n=read16(group+62);
        for (uint16_t i=0;i<n;i++) {
            uint32_t id=read32(group+i*4);
            void *resource=ops->retain(ops->context,id);
            if (!resource) {
                adreno_resource_list_release(list,ops);
                return ADRENO_LIST_E_RESOURCE;
            }
            list->entries[list->count++]=(struct adreno_resource_entry){id,read16(group+48+i*2),0,resource,0};
        }
    }
    return 0;
}
