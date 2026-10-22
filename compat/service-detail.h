/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>

/* Per-CPU nested timing inside an already acquired runtime service lock.
 * Inclusive buckets overlap. Self time removes instrumented children; the
 * sum of all self time must equal completed outer intervals. */
#define SERVICE_DETAIL_DEPTH 8u
#define SERVICE_DETAIL_CALL_BASE 16u
#define SERVICE_DETAIL_CALL_COUNT 128u
#define SERVICE_DETAIL_BUCKETS (SERVICE_DETAIL_CALL_BASE+SERVICE_DETAIL_CALL_COUNT)
enum service_detail_kind {
    DETAIL_KERNEL_REFRESH, DETAIL_KERNEL_PPERM,
    DETAIL_USER_REFRESH, DETAIL_USER_SYNC, DETAIL_OTHER_CALL,
    /* The canonical user-view proof of UPERM writes and TPRO PPERM changes. */
    DETAIL_USER_VIEW_PROOF
};
struct service_detail_bucket {
    uint64_t calls,inclusive_ticks,self_ticks,max_ticks,failed;
};
struct service_detail_frame { uint64_t bucket,start,children; };
struct service_detail {
    uint64_t errors,depth,max_depth,begins,ends,outer_ticks;
    struct service_detail_frame stack[SERVICE_DETAIL_DEPTH];
    struct service_detail_bucket buckets[SERVICE_DETAIL_BUCKETS];
};
static inline unsigned service_detail_call_bucket(uint64_t x16)
{
    return x16<SERVICE_DETAIL_CALL_COUNT ? SERVICE_DETAIL_CALL_BASE+(unsigned)x16 :
                                         DETAIL_OTHER_CALL;
}
static inline int service_detail_begin(struct service_detail *p,unsigned bucket,uint64_t now)
{
    if(bucket>=SERVICE_DETAIL_BUCKETS || p->depth>=SERVICE_DETAIL_DEPTH) {
        p->errors++;return 0;
    }
    p->stack[p->depth++]=(struct service_detail_frame){bucket,now,0};
    if(p->depth>p->max_depth)p->max_depth=p->depth;
    p->begins++;p->buckets[bucket].calls++;return 1;
}
static inline void service_detail_end(struct service_detail *p,unsigned bucket,
                                      uint64_t now,int success)
{
    if(bucket>=SERVICE_DETAIL_BUCKETS || !p->depth || p->depth>SERVICE_DETAIL_DEPTH ||
       p->stack[p->depth-1].bucket!=bucket) {p->errors++;return;}
    struct service_detail_frame f=p->stack[--p->depth];
    uint64_t elapsed=now-f.start;
    if(f.children>elapsed) {p->errors++;return;}
    struct service_detail_bucket *b=&p->buckets[bucket];
    b->inclusive_ticks+=elapsed;b->self_ticks+=elapsed-f.children;
    if(elapsed>b->max_ticks)b->max_ticks=elapsed;
    b->failed+=!success;p->ends++;
    if(p->depth)p->stack[p->depth-1].children+=elapsed;
    else p->outer_ticks+=elapsed;
}
