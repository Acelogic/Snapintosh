/* SPDX-License-Identifier: MIT */
#include "native-view.h"
#include "../compat/sprr.h"

static int ready(const struct sprr_views *v,const struct shadow *s)
{
    return v && s && s->txsz==17 && s->root && !(s->root&4095) &&
        s->read && s->write && s->alloc && v->canonical_root==s->root &&
        v->count && v->count<=SPRR_VIEW_TABLES &&
        v->tables[0].source==s->root && !v->tables[0].level;
}
int native_views_find(const struct sprr_views *v,uint64_t table)
{
    if(!v || v->count>SPRR_VIEW_TABLES)return -1;
    for(unsigned n=0;n<v->count;n++)if(v->tables[n].source==table)return (int)n;
    return -1;
}
uint64_t native_views_root(const struct sprr_views *v,unsigned w)
{
    return v && v->count && v->count<=SPRR_VIEW_TABLES && w<NATIVE_VARIANTS ?
        v->tables[0].copy[w] : 0;
}
/* A page already serving as a source or as any copy. */
static int in_use(const struct sprr_views *v,uint64_t pa)
{
    for(unsigned n=0;n<v->count;n++) {
        if(v->tables[n].source==pa)return 1;
        for(unsigned c=0;c<SPRR_VIEW_CPUS;c++)if(v->tables[n].copy[c]==pa)return 1;
    }
    return 0;
}
/* Index of source's copies, adding them if missing; -1 on failure. */
static int add(struct sprr_views *v,const struct shadow *s,uint64_t source,unsigned level)
{
    int found=native_views_find(v,source);
    if(found>=0)return v->tables[found].level==level ? found : -1;
    if(v->count>=SPRR_VIEW_TABLES || !source || (source&4095) || level>3)return -1;
    uint64_t copy[NATIVE_VARIANTS];
    for(unsigned w=0;w<NATIVE_VARIANTS;w++) {
        uint64_t pa=shadow_alloc_page(s);
        if(!pa || (pa&4095) || pa==source || in_use(v,pa))return -1;
        for(unsigned k=0;k<w;k++)if(copy[k]==pa)return -1;
        copy[w]=pa;
    }
    struct sprr_view_table *t=&v->tables[v->count];
    t->source=source;t->level=level;
    for(unsigned c=0;c<SPRR_VIEW_CPUS;c++)t->copy[c]=c<NATIVE_VARIANTS ? copy[c] : 0;
    return (int)v->count++;
}
/* sprr-view.c's user entry_decode with "TPRO write" fixed to w. */
static int decode(const struct sprr_views *v,unsigned n,uint64_t d,unsigned index,
                  unsigned w,uint64_t umprr,uint64_t *out)
{
    const struct sprr_view_table *t=&v->tables[n];
    if(!t->level && index>=256 && (d&1))return 0;
    if(!(d&1)) {*out=d;return 1;}
    if(t->level<3 && (d&3)==3) {
        if((d&~PT_OA_MASK)!=3 || !(d&PT_OA_MASK))return 0;
        int child=native_views_find(v,d&PT_OA_MASK);
        if(child>=0) {
            if(v->tables[child].level!=t->level+1)return 0;
            d=v->tables[child].copy[w]|3;
        }
    } else {
        if(t->level!=3 || (d&3)!=3)return 0;
        if(sprr_pte_class(d)==9) {
            if((umprr&0xc0000)!=0x40000)return 0;
            /* Data reads at EL0 and EL1 in both states; bit36 grants writes;
             * never executable. PAN still sees an EL0-accessible page. */
            d=(d&~(PT_AP|PT_PXN|PT_UXN))|PT_PXN|PT_UXN|(1UL<<6);
            if(!w)d|=2UL<<6;
        } else if(!sprr_fixed_native_leaf(d))return 0;
    }
    *out=d;return 1;
}
static int translate(struct sprr_views *v,const struct shadow *s,unsigned n,uint64_t umprr)
{
    const struct sprr_view_table *t=&v->tables[n];
    for(unsigned i=0;i<512;i++) {
        uint64_t d;
        if(s->read(s->ctx,t->source+8UL*i,&d))return 0;
        for(unsigned w=0;w<NATIVE_VARIANTS;w++) {
            uint64_t out;
            if(!decode(v,n,d,i,w,umprr,&out) || s->write(s->ctx,t->copy[w]+8UL*i,out))return 0;
        }
    }
    return 1;
}
int native_views_init(struct sprr_views *v,const struct shadow *s,uint64_t umprr)
{
    if(!v || !s || v->count || v->canonical_root || s->txsz!=17 || !s->root ||
       (s->root&4095) || !s->read || !s->write || !s->alloc)return 0;
    if(add(v,s,s->root,0)!=0)return 0;
    v->canonical_root=s->root;
    return translate(v,s,0,umprr);
}
/* The canonical path to va: path[level] for levels 0..3. The level-3 entry
 * must be empty or a page; every higher entry a table pointer. */
static int canonical_path(const struct sprr_views *v,const struct shadow *s,uint64_t va,
                          uint64_t path[4])
{
    uint64_t table=s->root;
    for(unsigned level=0;level<4;level++) {
        if(!table || (table&4095))return 0;
        for(unsigned k=0;k<level;k++)if(path[k]==table)return 0;
        int n=native_views_find(v,table);
        if(n>=0 && v->tables[n].level!=level)return 0;
        for(unsigned k=0;k<v->count;k++)
            for(unsigned c=0;c<SPRR_VIEW_CPUS;c++)if(v->tables[k].copy[c]==table)return 0;
        path[level]=table;
        uint64_t pte;
        if(s->read(s->ctx,table+8UL*mmu_index(12,level,va),&pte))return 0;
        if(level==3) {if(pte && (pte&3)!=3)return 0;}
        else {
            if((pte&~PT_OA_MASK)!=3 || !(pte&PT_OA_MASK))return 0;
            table=pte&PT_OA_MASK;
        }
    }
    return 1;
}
int native_views_prepare_leaf(struct sprr_views *v,const struct shadow *s,uint64_t va,
                              uint64_t umprr)
{
    uint64_t path[4];int existed[4],index[4];
    if(!ready(v,s) || va>=(1UL<<47) || (va&4095) || !canonical_path(v,s,va,path))return 0;
    unsigned missing=0;
    for(unsigned level=0;level<4;level++) {
        existed[level]=native_views_find(v,path[level])>=0;
        missing+=!existed[level];
    }
    if(!missing)return 1;
    /* Copies are made from the top of the path down; a table with copies
     * always has copied ancestors, so the new tables are a suffix. */
    for(unsigned level=1;level<4;level++)if(existed[level] && !existed[level-1])return 0;
    for(unsigned level=0;level<4;level++)
        if((index[level]=add(v,s,path[level],level))<0)return 0;
    /* Fill the new, still unreachable copies, then link them with one store
     * per variant into the lowest existing ancestor's copies. */
    for(unsigned level=4;level--;)
        if(!existed[level] && !translate(v,s,(unsigned)index[level],umprr))return 0;
    for(unsigned level=0;level<3;level++) {
        if(!existed[level] || existed[level+1])continue;
        unsigned i=mmu_index(12,level,va);uint64_t d;
        if(s->read(s->ctx,path[level]+8UL*i,&d))return 0;
        for(unsigned w=0;w<NATIVE_VARIANTS;w++) {
            uint64_t out;
            if(!decode(v,(unsigned)index[level],d,i,w,umprr,&out) ||
               s->write(s->ctx,v->tables[index[level]].copy[w]+8UL*i,out))return 0;
        }
    }
    return 2;
}
int native_views_admit(const struct sprr_views *v,uint64_t pa,uint64_t value,uint64_t umprr)
{
    if(!v || (pa&7))return 0;
    int n=native_views_find(v,pa&~UINT64_C(4095));
    if(n<0)return !(value&1) || sprr_pte_class(value)!=9;
    uint64_t out;
    for(unsigned w=0;w<NATIVE_VARIANTS;w++)
        if(!decode(v,(unsigned)n,value,(unsigned)((pa&4095)/8),w,umprr,&out))return 0;
    return 1;
}
int native_views_store(struct sprr_views *v,const struct shadow *s,uint64_t pa,uint64_t value,
                       uint64_t umprr)
{
    if(!v || !s || !native_views_admit(v,pa,value,umprr))return 0;
    int n=native_views_find(v,pa&~UINT64_C(4095));
    /* A table without copies is walked by both variants as it is. */
    if(n<0)return 1;
    unsigned i=(unsigned)((pa&4095)/8);
    for(unsigned w=0;w<NATIVE_VARIANTS;w++) {
        uint64_t out;
        if(!decode(v,(unsigned)n,value,i,w,umprr,&out) ||
           s->write(s->ctx,v->tables[n].copy[w]+8UL*i,out))return 0;
    }
    return 1;
}
/* Every class 9 leaf under table: call mark() with its path. */
static int discover(struct sprr_views *v,const struct shadow *s,uint64_t table,unsigned level,
                    uint64_t base,uint64_t path[4],unsigned *tables,
                    int (*mark)(struct sprr_views *,const struct shadow *,const uint64_t *,uint64_t))
{
    if(!table || (table&4095) || ++*tables>8192)return 0;
    for(unsigned k=0;k<level;k++)if(path[k]==table)return 0;
    path[level]=table;
    uint64_t span=mmu_level_size(12,level);
    for(unsigned i=0;i<512;i++) {
        uint64_t d;
        if(s->read(s->ctx,table+8UL*i,&d))return 0;
        if(!(d&1))continue;
        if(!level && i>=256)return 0;
        if(level<3 && (d&3)==3) {
            if((d&~PT_OA_MASK)!=3 ||
               !discover(v,s,d&PT_OA_MASK,level+1,base+i*span,path,tables,mark))return 0;
        } else if(sprr_pte_class(d)==9 && (level!=3 || !mark(v,s,path,base+i*span)))return 0;
    }
    return 1;
}
static int mark_path(struct sprr_views *v,const struct shadow *s,const uint64_t *path,uint64_t va)
{
    (void)va;
    for(unsigned level=0;level<4;level++)if(add(v,s,path[level],level)<0)return 0;
    return 1;
}
int native_views_sync(struct sprr_views *v,const struct shadow *s,uint64_t umprr)
{
    if(!v || !s)return 0;
    if(!v->count && !native_views_init(v,s,umprr))return 0;
    uint64_t path[4];unsigned tables=0;
    if(!ready(v,s) || !discover(v,s,s->root,0,0,path,&tables,mark_path))return 0;
    for(unsigned n=0;n<v->count;n++)if(!translate(v,s,n,umprr))return 0;
    return 1;
}
static int covered(struct sprr_views *v,const struct shadow *s,const uint64_t *path,uint64_t va)
{
    (void)s;(void)va;
    for(unsigned level=0;level<4;level++) {
        int n=native_views_find(v,path[level]);
        if(n<0 || v->tables[n].level!=level)return 0;
    }
    return 1;
}
int native_views_exact(const struct sprr_views *v,const struct shadow *s,uint64_t umprr)
{
    if(!ready(v,s))return 0;
    for(unsigned n=0;n<v->count;n++) {
        const struct sprr_view_table *t=&v->tables[n];
        if(!t->source || (t->source&4095) || t->level>3 || (n && native_views_find(v,t->source)!=(int)n))
            return 0;
        for(unsigned c=0;c<SPRR_VIEW_CPUS;c++) {
            uint64_t pa=t->copy[c];
            if(c>=NATIVE_VARIANTS) {if(pa)return 0;continue;}
            if(!pa || (pa&4095) || native_views_find(v,pa)>=0)return 0;
            for(unsigned k=0;k<v->count;k++)
                for(unsigned e=0;e<NATIVE_VARIANTS;e++)
                    if((k!=n || e!=c) && v->tables[k].copy[e]==pa)return 0;
        }
        for(unsigned i=0;i<512;i++) {
            uint64_t d,copy;
            if(s->read(s->ctx,t->source+8UL*i,&d))return 0;
            for(unsigned w=0;w<NATIVE_VARIANTS;w++) {
                uint64_t want;
                if(!decode(v,n,d,i,w,umprr,&want) ||
                   s->read(s->ctx,t->copy[w]+8UL*i,&copy) || copy!=want)return 0;
            }
        }
    }
    return 1;
}
int native_views_verify(const struct sprr_views *v,const struct shadow *s,uint64_t umprr)
{
    uint64_t path[4];unsigned tables=0;
    return native_views_exact(v,s,umprr) &&
        discover((struct sprr_views *)v,s,s->root,0,0,path,&tables,covered);
}
