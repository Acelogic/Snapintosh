/* SPDX-License-Identifier: MIT */
#pragma once
#include "sprr-view.h"

/* Optional class-proof optimization. Caller holds the
 * service lock and uses the existing table-memo notifications BEFORE every
 * store, mapped transaction, allocator zeroing and reuse. Initialize this cache
 * alongside its generation source; never restart one without the other.
 *
 * Only L3 content is summarized. Every structural edge and every mapping
 * callback is still visited, including aliases, cycles and count limits. This
 * permits a surrounding whole-tree proof to retain its complete coverage map.
 */
struct sprr_class_leaf_entry {
    uint64_t generation;
    uint32_t pages;
    uint16_t classes,reserved;
};
struct sprr_class_leaf_stats {
    uint64_t calls,hits,scans,verified,mismatches,resets,poisoned;
    uint64_t base,pages,clock;
};
struct sprr_class_leaf_cache {
    struct sprr_class_leaf_stats stats;
    struct sprr_class_leaf_entry entry[SPRR_TABLE_MEMO_PAGES];
};
struct sprr_class_leaf_walk {
    struct sprr_class_leaf_cache *cache;
    const struct sprr_table_memo *source;
    sprr_table_reader read_table;
    struct sprr_class_walk_stats *walk;
    unsigned verify;
};
static inline int sprr_class_leaf_scan(const volatile uint64_t *w,
    struct sprr_class_leaf_entry *result,struct sprr_class_walk_stats *walk)
{
    for(unsigned i=0;i<512;i++) {
        if(!(i&7)) {
            uint64_t any=w[i]|w[i+1]|w[i+2]|w[i+3]|w[i+4]|w[i+5]|w[i+6]|w[i+7];
            walk->groups++;
            if(!any) {walk->empty_groups++;i+=7;continue;}
        }
        uint64_t d=w[i];if(!d)continue;
        if((d&3)!=3)return 0;
        result->pages++;result->classes|=(uint16_t)(1u<<sprr_pte_class(d));
    }
    return 1;
}
static inline int sprr_class_leaf_inspect(const struct shadow *s,uint64_t table,
    unsigned level,uint64_t path[4],uint64_t forbidden,struct sprr_view_classes *v,
    struct sprr_class_leaf_walk *r)
{
    if(!table || (table&4095) || ++v->tables>SPRR_CLASS_WALK_TABLES)return 0;
    for(unsigned n=0;n<level;n++)if(path[n]==table)return 0;
    path[level]=table;
    const volatile uint64_t *w=r->read_table(s->ctx,table);
    if(!w || ((uintptr_t)w&7))return 0;
    r->walk->tables++;
    if(level==3) {
        struct sprr_class_leaf_entry *saved=0,result={0};uint64_t generation=0;
        const struct sprr_table_memo *m=r->source;
        if(table>=m->base && (table-m->base)/4096<m->pages) {
            uint64_t page=(table-m->base)/4096,token=m->page[page];
            if((token&SPRR_TABLE_MEMO_POOL) && (token>>16)) {
                generation=token>>16;saved=&r->cache->entry[page];
            }
        }
        int hit=saved && saved->generation==generation;
        if(hit)r->cache->stats.hits++;
        if(!hit || r->verify) {
            r->cache->stats.scans++;
            int valid=sprr_class_leaf_scan(w,&result,r->walk);
            if(hit) {
                r->cache->stats.verified++;
                if(!valid || result.pages!=saved->pages || result.classes!=saved->classes) {
                    r->cache->stats.mismatches++;r->cache->stats.poisoned=1;return 0;
                }
            }
            if(!valid)return 0;
            if(saved) {result.generation=generation;*saved=result;}
        } else result=*saved;
        if(forbidden&result.classes)return 0;
        v->pages+=result.pages;v->classes|=result.classes;return 1;
    }
    for(unsigned i=0;i<512;i++) {
        if(!(i&7)) {
            uint64_t any=w[i]|w[i+1]|w[i+2]|w[i+3]|w[i+4]|w[i+5]|w[i+6]|w[i+7];
            r->walk->groups++;
            if(!any) {r->walk->empty_groups++;i+=7;continue;}
        }
        uint64_t d=w[i];if(!d)continue;
        if(!(d&1) || (!level && i>=256))return 0;
        if((d&3)==3) {
            if((d&~PT_OA_MASK)!=3 ||
               !sprr_class_leaf_inspect(s,d&PT_OA_MASK,level+1,path,forbidden,v,r))return 0;
        } else {
            if(!level || (d&3)!=1)return 0;
            uint64_t size=mmu_level_size(12,level),bit=1UL<<sprr_pte_class(d);
            if(((d&PT_OA_MASK)&(size-1)) || (forbidden&bit))return 0;
            v->pages+=size/4096;v->classes|=bit;
        }
    }
    return 1;
}
static inline int sprr_class_leaf_check(struct sprr_class_leaf_cache *cache,
    const struct shadow *s,uint64_t forbidden,const struct sprr_table_memo *source,
    struct sprr_view_classes *out,sprr_table_reader read_table,
    struct sprr_class_walk_stats *walk)
{
    if(!cache || cache->stats.poisoned || !s || s->txsz!=17 || !out || !read_table ||
       !walk || (forbidden&~0xffffUL))return 0;
    cache->stats.calls++;
    if(!sprr_table_memo_usable(source))
        return sprr_views_check_classes_mapped(s,forbidden,out,read_table,walk);
    if(cache->stats.base!=source->base || cache->stats.pages!=source->pages || cache->stats.clock>source->clock) {
        for(unsigned i=0;i<SPRR_TABLE_MEMO_PAGES;i++)cache->entry[i].generation=0;
        cache->stats.base=source->base;cache->stats.pages=source->pages;cache->stats.resets++;
    }
    cache->stats.clock=source->clock;
    struct sprr_class_walk_stats k={0};struct sprr_view_classes v={0};uint64_t path[4];
    struct sprr_class_leaf_walk r={cache,source,read_table,&k,
        (cache->stats.calls%SPRR_TABLE_MEMO_SAMPLE)==0 || !!source->force};
    if(!sprr_class_leaf_inspect(s,s->root,0,path,forbidden,&v,&r))return 0;
    walk->tables+=k.tables;walk->groups+=k.groups;walk->empty_groups+=k.empty_groups;
    *out=v;return 1;
}
