/* SPDX-License-Identifier: MIT */
#include "sptm-slide.h"
#include "sptm-access.h"
#include "../shadow/mmu.h"

#define PAGE 0x4000UL
#define MASK 0x0000ffffffffc000UL
#define VAMASK ((1UL<<47)-1)

/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static uint64_t get(volatile uint8_t *p,unsigned n)
{ if(n==8)return sptm_get64(p); uint64_t v=0; for(unsigned i=0;i<n;i++) v|=(uint64_t)p[i]<<(8*i); return v; }
static void put(volatile uint8_t *p,uint64_t v,unsigned n)
{ if(n==8) {sptm_put64(p,v);return;} for(unsigned i=0;i<n;i++) p[i]=(uint8_t)(v>>(8*i)); }
static void copy_state(struct sptm_slide_state *dst,const struct sptm_slide_state *src)
{
    volatile uint8_t *d=(volatile uint8_t *)dst;
    const volatile uint8_t *s=(const volatile uint8_t *)src;
    for(unsigned i=0;i<sizeof(*dst);i++) d[i]=s[i];
}
static int range(uint64_t base,uint64_t size)
{ return size && base<=UINT64_MAX-size; }
static int overlap(uint64_t a,uint64_t an,uint64_t b,uint64_t bn)
{ return a<b+bn && b<a+an; }

/* A table must have one role and one VA prefix across BOTH walks. This
 * rejects DAG aliases as well as cycles before the commit pass: otherwise
 * clearing a source leaf could overwrite a later destination or ancestor. */
struct walk_seen { uint64_t pa, prefix; unsigned role; };
struct walk_guard { unsigned count; struct walk_seen seen[128]; };
static int unique_table(struct walk_guard *g,uint64_t pa,uint64_t va,
                        unsigned granule,unsigned level,unsigned first)
{
    uint64_t prefix=level==first ? 0 :
        (va&VAMASK)/mmu_level_size(granule,level-1);
    unsigned role=granule*4+level;
    for(unsigned i=0;i<g->count;i++) if(g->seen[i].pa==pa)
        return g->seen[i].prefix==prefix && g->seen[i].role==role;
    if(g->count==128) return 0;
    g->seen[g->count++]=(struct walk_seen){pa,prefix,role};
    return 1;
}

static enum sptm_result guest_slot(const struct sptm_memory *m,
    const struct sptm_slide_config *c,uint64_t root,uint64_t va,
    volatile uint8_t **out,uint64_t *pa,struct walk_guard *guard)
{
    uint64_t table=root,seen[3];
    for(unsigned level=1;level<=3;level++) {
        if ((table&(PAGE-1)) || table<c->table_low || table>c->table_high-PAGE)
            return SPTM_BAD_TABLE;
        if(!unique_table(guard,table,va,14,level,1)) return SPTM_BAD_TABLE;
        for(unsigned i=0;i<level-1;i++) if(seen[i]==table) return SPTM_BAD_TABLE;
        seen[level-1]=table;
        volatile uint8_t *p=m->map(m->ctx,table,PAGE);
        if(!p) return SPTM_MEMORY_UNAVAILABLE;
        uint64_t offset=8UL*mmu_index(14,level,va);
        if(level==3) { *out=p+offset; *pa=table+offset; return SPTM_OK; }
        uint64_t d=get(p+offset,8);
        if((d&3)!=3 || (d&~(MASK|3UL))) return SPTM_BAD_TABLE;
        table=d&MASK;
    }
    return SPTM_BAD_TABLE;
}

static enum sptm_result shadow_slot(const struct sptm_update_backend *b,
    uint64_t va,volatile uint8_t **out,struct walk_guard *guard)
{
    uint64_t table=b->shadow_root,seen[4];
    for(unsigned level=0;level<=3;level++) {
        if(table&0xfff) return SPTM_BAD_TABLE;
        if(!unique_table(guard,table,va,12,level,0)) return SPTM_BAD_TABLE;
        for(unsigned i=0;i<level;i++) if(seen[i]==table) return SPTM_BAD_TABLE;
        seen[level]=table;
        volatile uint8_t *p=b->map_shadow(b->ctx,table,0x1000);
        if(!p) return SPTM_SHADOW_FAILED;
        p+=8UL*mmu_index(12,level,va);
        if(level==3) { *out=p; return SPTM_OK; }
        uint64_t d=get(p,8);
        if((d&3)!=3 || (d&~(PT_OA_MASK|3UL))) return SPTM_BAD_TABLE;
        table=d&PT_OA_MASK;
    }
    return SPTM_BAD_TABLE;
}

static enum sptm_result validate_config(const struct sptm_memory *m,
    const struct sptm_update_backend *b,const struct sptm_slide_config *c)
{
    if(!m || !m->map || !m->publish || !b || !b->map_shadow || !c ||
       !c->count || c->count>SPTM_SLIDE_INPUTS || c->begin<0xffff800000000000UL ||
       c->begin>=c->end || (c->end-c->begin)>0x4000000 ||
       ((c->begin|c->end|c->table_low|c->table_high|b->kernel_root)&(PAGE-1)) ||
       c->table_low>=c->table_high || c->table_high>m->alloc_low ||
       c->table_low<m->frame_low || (c->map_pa&0xfff) ||
       !range(c->map_pa,0x1000) || c->map_pa<m->frame_low ||
       c->map_pa+0x1000>m->alloc_low ||
       overlap(c->map_pa,0x1000,c->table_low,c->table_high-c->table_low))
        return SPTM_BAD_CONFIG;
    for(unsigned i=0;i<c->count;i++) {
        struct sptm_slide_region r=c->regions[i];
        if(!r.pages || r.pages>0x40000 || r.va<0xffff800000000000UL ||
           ((r.va|r.pa)&(PAGE-1)) || !range(r.va,r.pages*PAGE) ||
           !range(r.pa,r.pages*PAGE) || r.pa<m->frame_low ||
           r.pa+r.pages*PAGE>m->alloc_low ||
           overlap(r.va,r.pages*PAGE,c->begin,c->end-c->begin) ||
           overlap(r.pa,r.pages*PAGE,c->table_low,c->table_high-c->table_low) ||
           overlap(r.pa,r.pages*PAGE,c->map_pa,0x1000)) return SPTM_BAD_CONFIG;
        for(unsigned j=0;j<i;j++) {
            struct sptm_slide_region q=c->regions[j];
            if(overlap(r.va,r.pages*PAGE,q.va,q.pages*PAGE) ||
               overlap(r.pa,r.pages*PAGE,q.pa,q.pages*PAGE)) return SPTM_BAD_CONFIG;
        }
    }
    return SPTM_OK;
}

enum sptm_result sptm_mac_slide_region(const struct sptm_memory *m,
    const struct sptm_update_backend *b,const struct sptm_slide_config *c,
    struct sptm_slide_state *s,uint64_t va,uint64_t count,int locked)
{
    enum sptm_result result=validate_config(m,b,c);
    if(result) return result;
    if(!s) return SPTM_BAD_CONFIG;
    if(locked) return SPTM_FRAME_BUSY;
    if(!count || count>0x3ffff || !range(va,count*PAGE) ||
       va<0xffff800000000000UL || (va&(PAGE-1))) return SPTM_BAD_ADDRESS;
    struct sptm_slide_state next;
    copy_state(&next,s);
    if(!next.count) {
        if(next.cursor || next.calls || next.pages) return SPTM_BAD_CONFIG;
        next.cursor=c->begin;next.count=c->count;
        for(unsigned i=0;i<c->count;i++) next.regions[i]=c->regions[i];
    }
    if(next.count>SPTM_SLIDE_REGIONS || next.cursor<c->begin || next.cursor>c->end ||
       (next.cursor&(PAGE-1)) || count*PAGE>c->end-next.cursor)
        return SPTM_BAD_CONFIG;
    uint64_t size=count*PAGE,dest=next.cursor,physical=0;
    unsigned found=SPTM_SLIDE_REGIONS;
    for(unsigned i=0;i<next.count;i++) {
        struct sptm_slide_region r=next.regions[i];
        if(va>=r.va && size<=r.pages*PAGE && va-r.va<=r.pages*PAGE-size) {
            found=i; physical=r.pa+va-r.va; break;
        }
    }
    if(found==SPTM_SLIDE_REGIONS || overlap(va,size,dest,size)) return SPTM_BAD_ADDRESS;
    struct sptm_slide_region original=next.regions[found];
    unsigned extra=(va>original.va)+(va+size<original.va+original.pages*PAGE);
    if(next.count+extra>SPTM_SLIDE_REGIONS) return SPTM_MEMORY_UNAVAILABLE;
    next.regions[found]=(struct sptm_slide_region){dest,physical,count};
    if(va>original.va) next.regions[next.count++]=(struct sptm_slide_region){
        original.va,original.pa,(va-original.va)/PAGE};
    if(va+size<original.va+original.pages*PAGE) next.regions[next.count++]=
        (struct sptm_slide_region){va+size,physical+size,
            (original.va+original.pages*PAGE-va-size)/PAGE};

    /* Build the replacement physical-to-virtual view off to the side. No
     * duplicate physical coverage: replace/split exactly one existing range. */
    volatile uint8_t *map=m->map(m->ctx,c->map_pa,0x1000);
    if(!map) return SPTM_MEMORY_UNAVAILABLE;
    uint64_t entries=get(map,4),out_count=0,last=0;
    struct sptm_slide_region out[SPTM_SLIDE_REGIONS];
    unsigned matches=0;
    if(!entries || entries>SPTM_SLIDE_REGIONS) return SPTM_BAD_CONFIG;
    for(unsigned i=0;i<entries;i++) {
        volatile uint8_t *p=map+0x10+24*i;
        uint64_t pa=get(p,8),to=get(p+8,8),pages=get(p+16,4),span=pages*PAGE;
        if(!range(pa,span) || !range(to,span) || ((pa|to)&(PAGE-1)) ||
           (i && pa<last)) return SPTM_BAD_CONFIG;
        last=pa+span;
        unsigned inside=physical>=pa && size<=span && physical-pa<=span-size;
        if(overlap(pa,span,physical,size) && !inside) return SPTM_BAD_CONFIG;
        unsigned additions=inside ? 1+(physical>pa)+(physical+size<pa+span) : 1;
        if(out_count+additions>SPTM_SLIDE_REGIONS) return SPTM_MEMORY_UNAVAILABLE;
        if(!inside) out[out_count++]=(struct sptm_slide_region){to,pa,pages};
        else {
            matches++;
            if(physical>pa) out[out_count++]=(struct sptm_slide_region){to,pa,(physical-pa)/PAGE};
            out[out_count++]=(struct sptm_slide_region){dest,physical,count};
            if(physical+size<pa+span) out[out_count++]=(struct sptm_slide_region){
                to+physical+size-pa,physical+size,(pa+span-physical-size)/PAGE};
        }
    }
    if(matches!=1) return SPTM_BAD_CONFIG;

    /* Pass 0 validates every source, destination and shadow before writes.
     * Tables were reserved by the loader/host: this path never allocates. */
    struct walk_guard guard;
    guard.count=0;
    for(unsigned pass=0;pass<2;pass++) for(uint64_t n=0;n<count;n++) {
        volatile uint8_t *src,*dst,*ss[4],*ds[4]; uint64_t sp,dp;
        result=guest_slot(m,c,b->kernel_root,va+n*PAGE,&src,&sp,&guard); if(result) return result;
        result=guest_slot(m,c,b->kernel_root,dest+n*PAGE,&dst,&dp,&guard); if(result) return result;
        uint64_t old=get(src,8),pa=physical+n*PAGE;
        if((old&3)!=3 || (old&MASK)!=pa || get(dst,8) || src==dst)
            return SPTM_BAD_TABLE;
        /* These bootstrap frames aren't allocator-owned data references.
         * The fresh alias is ordinary NX kernel-RW memory, not executable. */
        uint64_t value=pa|3UL|(old&(PT_LEAF_ATTRS&~0xc0UL))|(3UL<<53);
        for(unsigned j=0;j<4;j++) {
            result=shadow_slot(b,(va+n*PAGE+j*0x1000)&VAMASK,&ss[j],&guard);if(result)return result;
            result=shadow_slot(b,(dest+n*PAGE+j*0x1000)&VAMASK,&ds[j],&guard);if(result)return result;
            uint64_t expected=(pa+j*0x1000)|3UL|(old&(PT_LEAF_ATTRS|PT_LEAF_UPPER));
            if(get(ss[j],8)!=expected || get(ds[j],8) || ss[j]==ds[j]) return SPTM_SHADOW_FAILED;
        }
        if(pass) {
            put(src,0,8);put(dst,value,8);
            for(unsigned j=0;j<4;j++) {
                put(ss[j],0,8);put(ds[j],(value&~PT_OA_MASK)|(pa+j*0x1000),8);
            }
            m->publish(m->ctx,sp,8);m->publish(m->ctx,dp,8);
        }
    }
    for(unsigned i=0;i<SPTM_SLIDE_REGIONS;i++) {
        volatile uint8_t *p=map+0x10+24*i;
        struct sptm_slide_region r=i<out_count ? out[i] : (struct sptm_slide_region){0};
        put(p,r.pa,8);put(p+8,r.va,8);put(p+16,r.pages,4);put(p+20,0,4);
    }
    put(map,out_count,4);
    m->publish(m->ctx,c->map_pa,0x10+24*SPTM_SLIDE_REGIONS);
    next.cursor+=size;next.calls++;next.pages+=count;copy_state(s,&next);
    return SPTM_OK;
}
