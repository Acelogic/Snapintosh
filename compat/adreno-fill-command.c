/* SPDX-License-Identifier: MIT */
#include "adreno-fill-command.h"

static uint32_t read32(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint64_t read64(const uint8_t *p)
{ return (uint64_t)read32(p)|(uint64_t)read32(p+4)<<32; }
static int valid_request(const struct adreno_fill32_request *r)
{
    return r && r->resource_id && r->bytes && r->bytes<=ADRENO_FILL32_MAX_BYTES &&
        !((r->offset|r->bytes)&3) && r->offset<=UINT64_MAX-r->bytes;
}
int adreno_fill32_decode(const void *command,uint64_t available,struct adreno_fill32_request *out)
{
    if (!command || !out || available<32) return ADRENO_SUBMIT_E_FORMAT;
    uint8_t copy[32];
    const volatile uint8_t *source=command;
    for (unsigned i=0;i<sizeof copy;i++) copy[i]=source[i];
    if (read32(copy)!=ADRENO_KCMD_FILL32) return ADRENO_SUBMIT_E_COMMAND;
    if (read32(copy+4)!=sizeof copy) return ADRENO_SUBMIT_E_FORMAT;
    struct adreno_fill32_request request={read32(copy+8),read32(copy+12),
                                        read64(copy+16),read64(copy+24)};
    if (!valid_request(&request)) return ADRENO_SUBMIT_E_FORMAT;
    *out=request;
    return 0;
}
int adreno_fill32_resource_range(const struct adreno_resource *r,uint64_t offset,
                                 uint64_t bytes,uint64_t *address)
{
    if (!r || !address) return ADRENO_RESOURCE_E_STATE;
    *address=0;
    if (r->flags!=(ADRENO_RESOURCE_RESERVED|ADRENO_RESOURCE_PINNED) ||
        !r->length || !r->logical_length || r->logical_length>r->length ||
        r->mapped_length!=r->length) return ADRENO_RESOURCE_E_STATE;
    if (!bytes || bytes>ADRENO_FILL32_MAX_BYTES || ((offset|bytes|r->address)&3) ||
        offset>r->logical_length || bytes>r->logical_length-offset ||
        r->address<ADRENO_WINDOW_BASE || r->address>=ADRENO_WINDOW_END ||
        r->length>ADRENO_WINDOW_END-r->address) return ADRENO_RESOURCE_E_RANGE;
    *address=r->address+offset;
    return 0;
}
struct fill_work {
    int (*transfer)(void *,uint64_t,uint64_t,uint32_t);
    void *context;
    uint64_t address,bytes;
    uint32_t pattern;
};
static int perform(void *context)
{
    struct fill_work *work=context;
    int result=work->transfer(work->context,work->address,work->bytes,work->pattern);
    if (!result) return 0;
    return result==ADRENO_FILL32_E_UNCERTAIN ? ADRENO_SUBMIT_E_UNCERTAIN : ADRENO_SUBMIT_E_INACTIVE;
}
int adreno_fill32_submit(struct adreno_resource_list *list,const struct adreno_resource_list_ops *ops,
    const struct adreno_fill32_request *request,
    int (*resolve)(void *,void *,void *,uint64_t,uint64_t,uint64_t *),
    int (*transfer)(void *,uint64_t,uint64_t,uint32_t),void *context)
{
    if (!list || !ops || !resolve || !transfer || !valid_request(request))
        return ADRENO_LIST_E_ARGUMENT;
    if (list->ready&ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready!=(ADRENO_LIST_READY|ADRENO_LIST_PREPARED) ||
        list->count>ADRENO_LIST_MAX_GROUPS*6UL || list->prepared_count!=list->count ||
        (list->count && !list->entries)) return ADRENO_LIST_E_STATE;
    const struct adreno_resource_entry *selected=0;
    unsigned usage=0;
    for (uint64_t i=0;i<list->count;i++) {
        const struct adreno_resource_entry *e=&list->entries[i];
        if (!e->resource || !e->preparation || e->reserved) return ADRENO_LIST_E_STATE;
        if (e->id!=request->resource_id) continue;
        if (selected && (e->resource!=selected->resource || e->preparation!=selected->preparation))
            return ADRENO_LIST_E_RESOURCE;
        selected=e; usage|=e->usage;
    }
    if (!selected || !(usage&2u)) return ADRENO_LIST_E_RESOURCE;
    uint64_t address=0;
    int result=resolve(context,selected->resource,selected->preparation,
                       request->offset,request->bytes,&address);
    if (result) return result;
    if ((address&3) || address<ADRENO_WINDOW_BASE || address>=ADRENO_WINDOW_END ||
        request->bytes>ADRENO_WINDOW_END-address) return ADRENO_RESOURCE_E_RANGE;
    struct fill_work work={transfer,context,address,request->bytes,request->pattern};
#if ADRENO_CACHE_SPARSE
    /* The fill writes only [offset, offset + bytes) of this entry's map (FAILURE-MODES.md C13). */
    const struct adreno_cache_scope scope={ADRENO_CACHE_SCOPE_RANGE,selected->preparation,request->offset,
                                           request->bytes};
    return adreno_resource_list_submit_scope(list,ops,perform,&work,&scope);
#else
    return adreno_resource_list_submit(list,ops,perform,&work);
#endif
}
