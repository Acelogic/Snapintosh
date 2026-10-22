/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
#include "monitor-arena.h"

/* Monitor-owned pages only. Owner0 is permanent; 1..254 are reclaimable
 * allocation domains. The caller serializes access and proves a domain has
 * no hardware/software users, including stale TLB entries, before release. */
#define TABLE_POOL_MAX MONITOR_ARENA_PAGES
_Static_assert(TABLE_POOL_MAX <= UINT16_MAX, "table-pool links must represent the sentinel");
#define TABLE_POOL_FREE 255u
struct table_pool {
    uint8_t owner[TABLE_POOL_MAX];
    uint16_t next[TABLE_POOL_MAX];
    uint32_t head, count;
    uint64_t reused, released, releases;
};
static inline int table_pool_take(struct table_pool *p,uint32_t *used,
                                 uint32_t capacity,unsigned owner)
{
    if(!p || !used || capacity>TABLE_POOL_MAX || *used>capacity ||
       owner>=TABLE_POOL_FREE || p->count>*used)return -1;
    uint32_t index;
    if(p->count) {
        index=p->head;
        if(index>=*used || p->owner[index]!=TABLE_POOL_FREE ||
           (p->count>1 && (p->next[index]>=*used || p->next[index]==index ||
                          p->owner[p->next[index]]!=TABLE_POOL_FREE)))return -1;
        p->head=p->next[index];p->count--;p->reused++;
    } else {
        if(*used==capacity)return -1;
        index=*used;
        if(p->owner[index])return -1;
        (*used)++;
    }
    p->owner[index]=(uint8_t)owner;
    return (int)index;
}
/* Give back one page of a domain (a freed shared-region group page); the
 * same caller obligations as table_pool_release. */
static inline int table_pool_release_one(struct table_pool *p,uint32_t used,uint32_t index,
                                         unsigned owner)
{
    if(!p || used>TABLE_POOL_MAX || index>=used || !owner || owner>=TABLE_POOL_FREE ||
       p->owner[index]!=owner || p->count>=used)return -1;
    p->owner[index]=TABLE_POOL_FREE;p->next[index]=(uint16_t)p->head;
    p->head=index;p->count++;p->released++;
    return 0;
}
static inline int table_pool_release(struct table_pool *p,uint32_t used,unsigned owner)
{
    if(!p || used>TABLE_POOL_MAX || !owner || owner>=TABLE_POOL_FREE || p->count>used)
        return -1;
    int count=0;
    for(uint32_t i=0;i<used;i++)if(p->owner[i]==owner) {
        p->owner[i]=TABLE_POOL_FREE;p->next[i]=(uint16_t)p->head;
        p->head=i;p->count++;count++;
    }
    p->released+=(unsigned)count;p->releases++;
    return count;
}
