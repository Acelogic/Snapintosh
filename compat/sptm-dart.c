/* SPDX-License-Identifier: MIT */
#include "sptm-dart.h"
#include "sptm-access.h"
#include "sptm-refs.h"
#ifndef SNAP_DART_MEMO
#define SNAP_DART_MEMO 0
#endif
#if SNAP_DART_MEMO
#include "sptm-dart-memo.h"
#endif

#define TABLE_ADDRESS 0x3ffffffc00UL
#define PA_LIMIT (1UL<<36)
/* SEP (20) and the Adreno virtual DART (SPTM_DART_ADRENO) end below the
 * 0x4400000-page threshold, so their streams use TCR 1: a two-level table. */
static unsigned first_level(uint64_t id) { return id==20 || id==SPTM_DART_ADRENO ? 1 : 0; }
static int iova_range(uint64_t id,uint64_t sid,uint64_t iova,uint64_t size)
{
    if (id==20) return dart_sep_iova_range((unsigned)sid,iova,size);
    uint64_t low=id==SPTM_DART_ADRENO ? SPTM_DART_ADRENO_BASE : 1UL<<40;
    uint64_t end=id==SPTM_DART_ADRENO ? SPTM_DART_ADRENO_END : 1UL<<42;
    return size && iova>=low && iova<end && size<=end-iova;
}
static int root_slot(uint64_t id,uint64_t sid,unsigned index)
{
    /* A partially covered first/last table is valid. Leaf bounds are checked
     * against the complete declared window before each MAP/UNMAP/DMA call.
     * The Adreno window [1 GiB, 4 GiB) is level-1 slots 32..127 ([1 GiB,
     * 16 GiB) with ADRENO_VA_WIDE: slots 32..511). */
    if (id==20) return index<(sid ? 40U : 128U);
    return id==SPTM_DART_ADRENO ? index>=32 && index<(unsigned)(SPTM_DART_ADRENO_END>>25) :
           index>=16 && index<64;
}
struct iommu_frame {
    uint64_t pa, meta_pa;
    volatile uint8_t *meta, *page;
    unsigned refs;
};
/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static uint64_t load64(volatile uint8_t *p) {return sptm_get64(p);}
static void store64(volatile uint8_t *p,uint64_t value) {sptm_put64(p,value);}
static enum sptm_result frame(const struct sptm_memory *m,uint64_t pa,
    unsigned id,unsigned sid,unsigned level,struct iommu_frame *out)
{
    if ((pa&0x3fff) || !sptm_managed_frame(m,pa))
        return SPTM_BAD_ADDRESS;
    out->pa=pa;out->meta_pa=m->frame_map_pa+((pa-m->frame_low)>>14)*16;
    out->meta=m->map(m->ctx,out->meta_pa,16);
    if (!out->meta) return SPTM_MEMORY_UNAVAILABLE;
    volatile uint8_t *e=out->meta;
    if (e[2]!=SPTM_MAC_IOMMU || e[6]!=5 || e[8]!=id || e[9]!=sid || e[10]!=level)
        return SPTM_TYPE_MISMATCH;
    if (e[0] || e[1]) return SPTM_FRAME_BUSY;
    if (e[3] || e[7] || e[11] || e[12] || e[13] || e[14] || e[15])
        return SPTM_BAD_REFERENCE;
    out->refs=(unsigned)e[4]|((unsigned)e[5]<<8);
    out->page=m->map(m->ctx,pa,0x4000);
    return out->page ? SPTM_OK : SPTM_MEMORY_UNAVAILABLE;
}
static void publish_refs(const struct sptm_memory *m,struct iommu_frame *f,unsigned count)
{
    f->meta[4]=(uint8_t)count;f->meta[5]=(uint8_t)(count>>8);
    m->publish(m->ctx,f->meta_pa,16);
}
static enum sptm_result configuration(const struct sptm_memory *m,
    struct dart_state *s,uint64_t id,uint64_t sid)
{
    if (!m || !m->map || !m->publish || !s || !sptm_sep_firmware_valid(m) ||
        ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
        (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
        m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
        m->alloc_high>m->frame_high || m->alloc_high>PA_LIMIT)
        return SPTM_BAD_CONFIG;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if (m->frame_map_pa>UINT64_MAX-map_size ||
        (m->frame_map_pa<m->alloc_high && m->frame_map_pa+map_size>m->alloc_low))
        return SPTM_BAD_CONFIG;
    if (id>=32 || sid>=2) return SPTM_UNSUPPORTED_OPTIONS;
    uint32_t bit=1U<<(unsigned)id;
    if (s->initialized_ids!=bit || s->powered_ids!=bit || s->tcr[sid]!=(first_level(id) ? 1U : 9U))
        return SPTM_BAD_CONFIG;
    return SPTM_OK;
}
#if SNAP_DART_MEMO
/* The per-table check every walk below repeats, as one function: each live
 * descriptor well-formed for its level, and refs == entries + 1. */
static enum sptm_result scan_table(const struct sptm_memory *m,const struct iommu_frame *t,
    uint64_t id,uint64_t sid,unsigned level,unsigned root_level)
{
    unsigned entries=0;
    for (unsigned i=0;i<2048;i++) {
        uint64_t v=load64(t->page+8*i);
        if (!v) continue;
        uint64_t allowed=TABLE_ADDRESS|1UL;
        if (level==2) allowed|=0xffffff000000000cUL;
        if (!(v&1) || (v&~allowed) ||
            (level==2 ? !sptm_dart_data_frame(m,id,sid,(v&TABLE_ADDRESS)<<4) :
                        !sptm_managed_frame(m,(v&TABLE_ADDRESS)<<4)) ||
            (level==root_level && !root_slot(id,sid,i)) ||
            (level==2 && (v>>52)>((v>>40)&0xfff))) return SPTM_BAD_TABLE;
        entries++;
    }
    return t->refs!=entries+1 ? SPTM_BAD_REFERENCE : SPTM_OK;
}
/* scan_table, answered from compat/sptm-dart-memo.h when the table passed it
 * with these refs and nothing published has touched the table since; every
 * SPTM_DART_MEMO_SAMPLE-th hit is scanned too and must agree. */
static enum sptm_result table_verdict(const struct sptm_memory *m,const struct iommu_frame *t,
    uint64_t id,uint64_t sid,unsigned level,unsigned root_level)
{
    struct sptm_dart_memo *memo=m->dart_memo;
    if (!memo || !sptm_dart_memo_ready(memo,m)) return scan_table(m,t,id,sid,level,root_level);
    memo->stats.lookups++;
    enum sptm_result r;
    struct sptm_dart_memo_entry *e=sptm_dart_memo_lookup(memo,t->pa,(unsigned)id,(unsigned)sid,level,t->refs);
    if (e) {
        memo->stats.hits++;
        if (++e->hits<SPTM_DART_MEMO_SAMPLE) return SPTM_OK;
        e->hits=0;memo->stats.sampled++;
        r=scan_table(m,t,id,sid,level,root_level);
        if (r) {memo->stats.mismatches++;sptm_dart_memo_forget(memo,t->pa);}
        return r;
    }
    memo->stats.misses++;
    r=scan_table(m,t,id,sid,level,root_level);
    if (!r) sptm_dart_memo_record(memo,t->pa,(unsigned)id,(unsigned)sid,level,t->refs,0);
    return r;
}
/* After a MAP or UNMAP commit: the leaf table passed the walk, the commit only
 * added checked leaves or removed leaves, and its refs are now `refs`. */
static void table_committed(const struct sptm_memory *m,const struct iommu_frame *t,
    uint64_t id,uint64_t sid,unsigned refs,uint32_t hits)
{
    if (m->dart_memo && sptm_dart_memo_ready(m->dart_memo,m))
        sptm_dart_memo_record(m->dart_memo,t->pa,(unsigned)id,(unsigned)sid,2,refs,hits);
}
#endif
enum sptm_result sptm_dart_map_table(const struct sptm_memory *m,
    struct dart_state *s,uint64_t id,uint64_t sid,uint64_t iova,uint64_t level,uint64_t pa)
{
    if (!m || !m->map || !m->publish || !s || !sptm_sep_firmware_valid(m) ||
        ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
        (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
        m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
        m->alloc_high>m->frame_high || m->alloc_high>PA_LIMIT)
        return SPTM_BAD_CONFIG;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if (m->frame_map_pa>UINT64_MAX-map_size ||
        (m->frame_map_pa<m->alloc_high && m->frame_map_pa+map_size>m->alloc_low))
        return SPTM_BAD_CONFIG;
    if (id>=32 || sid>=2 || level>2 || level<first_level(id)) return SPTM_UNSUPPORTED_OPTIONS;
    if ((iova&0x3fff) || !iova_range(id,sid,iova,1)) return SPTM_BAD_ADDRESS;
    uint32_t bit=1U<<(unsigned)id;
    if (s->initialized_ids!=bit || s->powered_ids!=bit || s->tcr[sid]!=(first_level(id) ? 1U : 9U))
        return SPTM_BAD_CONFIG;
    struct iommu_frame child,parent;
    enum sptm_result r=frame(m,pa,(unsigned)id,(unsigned)sid,(unsigned)level,&child);
    if (r) return r;
    if (child.refs) return SPTM_FRAME_BUSY;
    for (unsigned i=0;i<0x4000;i++) if (child.page[i]) return SPTM_BAD_TABLE;
    for (unsigned i=0;i<DART_STREAMS;i++)
        if ((s->ttbr[i]&1) && ((uint64_t)(s->ttbr[i]&0x3ffffffcU)<<12)==pa)
            return SPTM_FRAME_BUSY;

    volatile uint8_t *slot=0;
    uint64_t slot_pa=0;
    unsigned first=first_level(id);
    if (level==first) {
        if (s->ttbr[sid]) return SPTM_TABLE_EXISTS;
        if ((s->protect&1) || (s->enabled[sid/32]&(1U<<(sid%32))))
            return SPTM_FRAME_BUSY;
    } else {
        uint32_t ttbr=s->ttbr[sid];
        if (!ttbr) return SPTM_TABLE_MISSING;
        if (!(ttbr&1) || (ttbr&~0x3ffffffdU)) return SPTM_BAD_TABLE;
        uint64_t current=(uint64_t)(ttbr&0x3ffffffcU)<<12,seen[2];
        for (unsigned l=first;l<level;l++) {
            if (current==pa) return SPTM_BAD_TABLE;
            for (unsigned i=first;i<l;i++) if (seen[i]==current) return SPTM_BAD_TABLE;
            seen[l]=current;
            r=frame(m,current,(unsigned)id,(unsigned)sid,l,&parent);
            if (r) return r;
            /* Each table has one incoming reference plus its child entries.
             * Do not repair a mismatched count or accept malformed siblings. */
#if SNAP_DART_MEMO
            r=table_verdict(m,&parent,id,sid,l,first);
            if (r) return r;
#else
            unsigned entries=0;
            for (unsigned i=0;i<2048;i++) {
                uint64_t v=load64(parent.page+8*i);
                if (!v) continue;
                if (!(v&1) || (v&~(TABLE_ADDRESS|1UL)) ||
                    !sptm_managed_frame(m,(v&TABLE_ADDRESS)<<4) ||
                    (l==first && !root_slot(id,sid,i)))
                    return SPTM_BAD_TABLE;
                entries++;
            }
            if (parent.refs!=entries+1) return SPTM_BAD_REFERENCE;
#endif
            unsigned index=(unsigned)((iova>>(36-11*l))&2047);
            slot=parent.page+8*index;slot_pa=parent.pa+8*index;
            uint64_t v=load64(slot);
            if (l+1==level) {
                if (v) return SPTM_TABLE_EXISTS;
            } else {
                if (!v) return SPTM_TABLE_MISSING;
                current=(v&TABLE_ADDRESS)<<4;
            }
        }
    }
    /* 270d7f38..84: publish ownership before the descriptor/TTBR. No
     * operation below can fail; the guest service lock excludes concurrent DMA
     * producer and this DART walks current memory without cached entries. */
    m->publish(m->ctx,child.pa,0x4000);
    publish_refs(m,&child,1);
    if (level!=first) {
        publish_refs(m,&parent,parent.refs+1);
        store64(slot,((pa>>4)&TABLE_ADDRESS)|1);
        m->publish(m->ctx,slot_pa,8);
    } else {
        /* 270d7714 programs TTBR only; enable is a separate service. */
        s->ttbr[sid]=(uint32_t)(pa>>12)|1;
    }
    return SPTM_OK;
}

static enum sptm_result data_frame(const struct sptm_memory *m,uint64_t pa,
                                 uint64_t id,uint64_t sid,int list,volatile uint8_t **metadata)
{
    if ((pa&0x3fff) || (list ? !sptm_managed_frame(m,pa) : !sptm_dart_data_frame(m,id,sid,pa)))
        return SPTM_BAD_ADDRESS;
    volatile uint8_t *e=m->map(m->ctx,m->frame_map_pa+((pa-m->frame_low)>>14)*16,16);
    if (!e) return SPTM_MEMORY_UNAVAILABLE;
    /* Pinned descriptors: DEFAULT permits data DMA; DEFAULT and
     * KERNEL_RESTRICTED permit page-list reads (+0x34). No other owned
     * class-3 type implemented here permits DMA (+0x28/+0x30). */
    if (e[2]!=11 && !(list && e[2]==35)) return SPTM_TYPE_MISMATCH;
    if (e[0] || e[1]) return SPTM_FRAME_BUSY;
    if (e[3] || e[4] || e[5] || e[6] || e[7]) return SPTM_BAD_REFERENCE;
    if (load64(e+8)&0x8000000080000000UL) return SPTM_BAD_REFERENCE;
    *metadata=e;
    return SPTM_OK;
}
static uint64_t leaf_descriptor(uint64_t pa,uint64_t iova,uint64_t end,uint64_t options)
{
    uint64_t begin=iova&0x3fff,bytes=0x4000-begin;
    if (bytes>end-iova) bytes=end-iova;
    return (pa>>4)|1|((options&2)<<1)|((options&1)<<3)|
        ((begin>>2)<<52)|(((begin+bytes-1)>>2)<<40);
}
enum sptm_result sptm_dart_dma_translate(const struct sptm_memory *m,struct dart_state *s,
    uint64_t id,uint64_t sid,uint64_t iova,uint64_t size,int write,uint64_t *physical)
{
    enum sptm_result r=configuration(m,s,id,sid);
    if (r) return r;
    if (!physical || (write!=0 && write!=1)) return SPTM_BAD_CONFIG;
    if (!iova_range(id,sid,iova,size) || size>0x4000-(iova&0x3fff))
        return SPTM_BAD_ADDRESS;
    if (!(s->enabled[sid/32]&(1U<<(sid%32)))) return SPTM_BAD_CONFIG;
    uint32_t ttbr=s->ttbr[sid];
    if (!ttbr) return SPTM_TABLE_MISSING;
    if (!(ttbr&1) || (ttbr&~0x3ffffffdU)) return SPTM_BAD_TABLE;
    uint64_t current=(uint64_t)(ttbr&0x3ffffffcU)<<12,seen[3],leaf=0;
    unsigned first=first_level(id);
    for (unsigned level=first;level<3;level++) {
        for (unsigned i=first;i<level;i++) if (seen[i]==current) return SPTM_BAD_TABLE;
        seen[level]=current;
        struct iommu_frame table;
        r=frame(m,current,(unsigned)id,(unsigned)sid,level,&table);if (r) return r;
#if SNAP_DART_MEMO
        r=table_verdict(m,&table,id,sid,level,first);if (r) return r;
#else
        unsigned entries=0;
        for (unsigned i=0;i<2048;i++) {
            uint64_t v=load64(table.page+8*i);if (!v) continue;
            uint64_t allowed=TABLE_ADDRESS|1UL;
            if (level==2) allowed|=0xffffff000000000cUL;
            if (!(v&1) || (v&~allowed) ||
                (level==2 ? !sptm_dart_data_frame(m,id,sid,(v&TABLE_ADDRESS)<<4) :
                            !sptm_managed_frame(m,(v&TABLE_ADDRESS)<<4)) ||
                (level==first && !root_slot(id,sid,i)) ||
                (level==2 && (v>>52)>((v>>40)&0xfff))) return SPTM_BAD_TABLE;
            entries++;
        }
        if (table.refs!=entries+1) return SPTM_BAD_REFERENCE;
#endif
        leaf=load64(table.page+8*((iova>>(36-11*level))&2047));
        if (!leaf) return SPTM_TABLE_MISSING;
        current=(leaf&TABLE_ADDRESS)<<4;
    }
    if (leaf&(write ? 4UL : 8UL)) return SPTM_UNSUPPORTED_OPTIONS;
    uint64_t offset=iova&0x3fff,begin=(leaf>>52)*4,end=(((leaf>>40)&0xfff)+1)*4;
    if (offset<begin || offset>=end || size>end-offset) return SPTM_BAD_ADDRESS;
    volatile uint8_t *meta;
    r=data_frame(m,current,id,sid,0,&meta);if (r) return r;
    unsigned off=(leaf&4) ? 8 : 12;
    if (!(meta[off]|meta[off+1]|meta[off+2]|meta[off+3])) return SPTM_BAD_REFERENCE;
    /* Check access to the whole final range before publishing the translation. */
    if (!m->map(m->ctx,current+offset,size)) return SPTM_MEMORY_UNAVAILABLE;
    *physical=current+offset;s->translations++;return SPTM_OK;
}
enum sptm_result sptm_sep_rom_buffer(const struct sptm_memory *m,struct dart_state *s,
    unsigned kind,uint64_t iova,uint64_t size)
{
    if(!m || !s || kind>1 || !sptm_sep_firmware_valid(m))return SPTM_BAD_CONFIG;
    if(!size || ((iova|size)&0x3fff) || !iova || iova>UINT64_MAX-size ||
       (!kind && (!m->sep_firmware_size || size!=m->sep_firmware_size)) ||
       (kind && size>0x100000))return SPTM_BAD_ADDRESS;
    uint64_t before=s->translations,pages=size>>14,seen[64];
    if(before>UINT64_MAX-pages*(kind ? 2 : 1))return SPTM_BAD_CONFIG;
    enum sptm_result result=SPTM_OK;
    for(uint64_t n=0;n<pages;n++) {
        uint64_t pa,write_pa;
        result=sptm_dart_dma_translate(m,s,20,0,iova+n*0x4000,0x4000,0,&pa);
        if(result)break;
        if(!kind) {
            if(pa!=m->sep_firmware_pa+n*0x4000){result=SPTM_BAD_ADDRESS;break;}
        } else {
            if(!sptm_managed_frame(m,pa)){result=SPTM_BAD_ADDRESS;break;}
            for(uint64_t j=0;j<n;j++)if(seen[j]==pa){result=SPTM_BAD_ADDRESS;break;}
            if(result)break;
            seen[n]=pa;
            result=sptm_dart_dma_translate(m,s,20,0,iova+n*0x4000,0x4000,1,&write_pa);
            if(result)break;
            if(write_pa!=pa){result=SPTM_BAD_ADDRESS;break;}
        }
    }
    if(result)s->translations=before;
    return result;
}

static enum sptm_result sep_service_buffers(const struct sptm_memory *m,struct dart_state *s,
    const struct sptm_sep_span *spans,unsigned count,uint64_t *physical,unsigned max_spans,unsigned capacity)
{
    if(!m || !s || !spans || !physical || !count || count>max_spans)return SPTM_BAD_CONFIG;
    uint64_t pages=0;
    for(unsigned i=0;i<count;i++) {
        uint64_t va=spans[i].iova,size=spans[i].size;
        if(!va || !size || ((va|size)&0x3fff) || size>7*0x4000 || va>UINT64_MAX-size)
            return SPTM_BAD_ADDRESS;
        for(unsigned j=0;j<i;j++)if(va<spans[j].iova+spans[j].size &&
            spans[j].iova<va+size)return SPTM_BAD_ADDRESS;
        pages+=size/0x4000;
    }
    if(pages>capacity || s->translations>UINT64_MAX-2*pages)return SPTM_BAD_CONFIG;
    uint64_t before=s->translations,seen[SPTM_SEP_ALL_PAGES]={0};unsigned n=0;
    enum sptm_result result=SPTM_OK;
    for(unsigned i=0;i<count && !result;i++)for(uint64_t off=0;off<spans[i].size;off+=0x4000) {
        uint64_t pa,write_pa;
        result=sptm_dart_dma_translate(m,s,20,0,spans[i].iova+off,0x4000,0,&pa);
        if(result)break;
        if(!sptm_managed_frame(m,pa)){result=SPTM_BAD_ADDRESS;break;}
        for(unsigned j=0;j<n;j++)if(seen[j]==pa){result=SPTM_BAD_ADDRESS;break;}
        if(result)break;
        if(spans[i].expected && pa!=spans[i].expected[off/0x4000]){result=SPTM_BAD_ADDRESS;break;}
        result=sptm_dart_dma_translate(m,s,20,0,spans[i].iova+off,0x4000,1,&write_pa);
        if(result)break;
        if(write_pa!=pa){result=SPTM_BAD_ADDRESS;break;}
        seen[n++]=pa;
    }
    if(result){s->translations=before;return result;}
    for(unsigned i=0;i<capacity;i++)physical[i]=seen[i];
    return SPTM_OK;
}
enum sptm_result sptm_sep_service_buffers(const struct sptm_memory *m,struct dart_state *s,
    const struct sptm_sep_span *spans,unsigned count,uint64_t physical[SPTM_SEP_SERVICE_PAGES])
{
    return sep_service_buffers(m,s,spans,count,physical,3,SPTM_SEP_SERVICE_PAGES);
}
enum sptm_result sptm_sep_endpoint_buffers(const struct sptm_memory *m,struct dart_state *s,
    const struct sptm_sep_span *spans,unsigned count,uint64_t physical[SPTM_SEP_ENDPOINT_PAGES])
{
    return sep_service_buffers(m,s,spans,count,physical,5,SPTM_SEP_ENDPOINT_PAGES);
}
enum sptm_result sptm_sep_all_buffers(const struct sptm_memory *m,struct dart_state *s,
    const struct sptm_sep_span *spans,unsigned count,uint64_t physical[SPTM_SEP_ALL_PAGES])
{
    return sep_service_buffers(m,s,spans,count,physical,7,SPTM_SEP_ALL_PAGES);
}

enum sptm_result sptm_dart_enable(const struct sptm_memory *m,struct dart_state *s,
                                uint64_t id,uint64_t sid)
{
    enum sptm_result r=configuration(m,s,id,sid);
    if (r) return r;
    uint32_t ttbr=s->ttbr[sid];
    if (ttbr) {
        if (!(ttbr&1) || (ttbr&~0x3ffffffdU)) return SPTM_BAD_TABLE;
        struct iommu_frame root;
        r=frame(m,(uint64_t)(ttbr&0x3ffffffcU)<<12,(unsigned)id,(unsigned)sid,first_level(id),&root);
        if (r) return r;
        /* TTBR is the root published by MAP_TABLE. Check its attachment
         * ownership before exposing it to a DMA producer; no repair. */
        unsigned children=0;
        for (unsigned i=0;i<2048;i++) {
            uint64_t v=load64(root.page+8*i);
            if (!v) continue;
            uint64_t pa=(v&TABLE_ADDRESS)<<4;
            if (!root_slot(id,sid,i) || !(v&1) || (v&~(TABLE_ADDRESS|1UL)) ||
                !sptm_managed_frame(m,pa) || pa==root.pa)
                return SPTM_BAD_TABLE;
            children++;
        }
        if (root.refs!=children+1) return SPTM_BAD_REFERENCE;
    }
    /* 270d02c4: W1S at 0xc00+4*(SID/32), followed by DSB. A zero TTBR
     * may be enabled too; the walker then faults on access as hardware does.
     * Repeated enables preserve all other streams and pending errors. */
    s->enabled[sid/32]|=1U<<(sid%32);
#if defined(__aarch64__)
    __asm__ volatile("dsb sy" ::: "memory");
#else
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#endif
    return SPTM_OK;
}
enum sptm_result sptm_dart_map(const struct sptm_memory *m,struct dart_state *s,
    uint64_t id,uint64_t sid,uint64_t iova,uint64_t list,uint64_t size,uint64_t options)
{
    enum sptm_result r=configuration(m,s,id,sid);
    if (r) return r;
    if (!m->refs) return SPTM_BAD_CONFIG;
    if (options>3) return SPTM_UNSUPPORTED_OPTIONS;
    if (!iova_range(id,sid,iova,size) || size>(1UL<<25) ||
        (id!=20 && size>=(1UL<<42)-iova) || size>(1UL<<25)-(iova&((1UL<<25)-1)))
        return SPTM_BAD_ADDRESS;
    unsigned count=(unsigned)(((iova&0x3fff)+size+0x3fff)>>14);
    if ((list&7) || (list&0x3fff)+count*8>0x4000) return SPTM_BAD_ADDRESS;
    volatile uint8_t *meta,*pages;
    r=data_frame(m,list&~0x3fffUL,id,sid,1,&meta);
    if (r) return r;
    pages=m->map(m->ctx,list,count*8);
    if (!pages) return SPTM_MEMORY_UNAVAILABLE;
    uint32_t ttbr=s->ttbr[sid];
    if (!ttbr) return SPTM_TABLE_MISSING;
    if (!(ttbr&1) || (ttbr&~0x3ffffffdU)) return SPTM_BAD_TABLE;
    uint64_t current=(uint64_t)(ttbr&0x3ffffffcU)<<12,seen[3];
    struct iommu_frame table;
    unsigned root_level=first_level(id);
    for (unsigned level=root_level;level<3;level++) {
        for (unsigned i=root_level;i<level;i++) if (current==seen[i]) return SPTM_BAD_TABLE;
        seen[level]=current;
        r=frame(m,current,(unsigned)id,(unsigned)sid,level,&table);
        if (r) return r;
#if SNAP_DART_MEMO
        r=table_verdict(m,&table,id,sid,level,root_level);
        if (r) return r;
#else
        unsigned entries=0;
        for (unsigned i=0;i<2048;i++) {
            uint64_t v=load64(table.page+8*i);
            if (!v) continue;
            uint64_t allowed=TABLE_ADDRESS|1UL;
            if (level==2) allowed|=0xffffff000000000cUL;
            if (!(v&1) || (v&~allowed) ||
                (level==2 ? !sptm_dart_data_frame(m,id,sid,(v&TABLE_ADDRESS)<<4) :
                            !sptm_managed_frame(m,(v&TABLE_ADDRESS)<<4)) ||
                (level==root_level && !root_slot(id,sid,i)) ||
                (level==2 && (v>>52)>((v>>40)&0xfff))) return SPTM_BAD_TABLE;
            entries++;
        }
        if (table.refs!=entries+1) return SPTM_BAD_REFERENCE;
#endif
        if (level<2) {
            uint64_t next=load64(table.page+8*((iova>>(36-11*level))&2047));
            if (!next) return SPTM_TABLE_MISSING;
            current=(next&TABLE_ADDRESS)<<4;
        }
    }
#if SNAP_DART_MEMO
    uint32_t memo_hits=m->dart_memo ? sptm_dart_memo_hits(m->dart_memo,table.pa) : 0;
#endif
    sptm_refs_begin(m->refs);
    unsigned first=(unsigned)((iova>>14)&2047),added=0;
    uint64_t cursor=iova,end=iova+size;
    for (unsigned i=0;i<count;i++) {
        uint64_t pa=load64(pages+8*i),old=load64(table.page+8*(first+i));
        r=data_frame(m,pa,id,sid,0,&meta);
        if (r) return r;
        uint64_t next=leaf_descriptor(pa,cursor,end,options);
        if (old && old!=next) return SPTM_TABLE_EXISTS;
        if (!old) {
            r=sptm_refs_dart_stream(m,id,sid,pa,!!(next&4),0);
            if (r) return r;
            added++;
        } else {
            unsigned off=(next&4) ? 8 : 12;
            if (!(meta[off]|meta[off+1]|meta[off+2]|meta[off+3])) return SPTM_BAD_REFERENCE;
        }
        cursor=(cursor&~0x3fffUL)+0x4000;
    }
    r=sptm_refs_validate(m);
    if (r) return r;
    /* The guest service lock also covers the synchronous AES DMA producer. The mapped
     * list stays valid and cannot alias a typed IOMMU table or metadata.
     * All admission completes before these infallible publications. */
    sptm_refs_commit(m);
    if (added) publish_refs(m,&table,table.refs+added);
    cursor=iova;
    for (unsigned i=0;i<count;i++) {
        volatile uint8_t *slot=table.page+8*(first+i);
        uint64_t next=leaf_descriptor(load64(pages+8*i),cursor,end,options);
        if (!load64(slot)) {
            store64(slot,next);
            m->publish(m->ctx,table.pa+8*(first+i),8);
        }
        cursor=(cursor&~0x3fffUL)+0x4000;
    }
#if SNAP_DART_MEMO
    table_committed(m,&table,id,sid,table.refs+added,memo_hits);
#endif
    return SPTM_OK;
}

enum sptm_result sptm_dart_unmap(const struct sptm_memory *m,struct dart_state *s,
    uint64_t id,uint64_t sid,uint64_t iova,uint64_t size,uint64_t options)
{
    enum sptm_result r=configuration(m,s,id,sid);
    if (r) return r;
    if (!m->refs) return SPTM_BAD_CONFIG;
    /* 26A428 SPTM 270d4f04: option bit1 permits a missing leaf. Bit0
     * selects a separate platform policy; it is not admitted here. */
    if (options!=0 && options!=2) return SPTM_UNSUPPORTED_OPTIONS;
    if (!iova_range(id,sid,iova,size) || size>(1UL<<25) ||
        (id!=20 && size>=(1UL<<42)-iova) || size>(1UL<<25)-(iova&((1UL<<25)-1)))
        return SPTM_BAD_ADDRESS;
    uint32_t ttbr=s->ttbr[sid];
    if (!ttbr) return SPTM_TABLE_MISSING;
    if (!(ttbr&1) || (ttbr&~0x3ffffffdU)) return SPTM_BAD_TABLE;
    uint64_t current=(uint64_t)(ttbr&0x3ffffffcU)<<12,seen[3];
    struct iommu_frame table;
    unsigned root_level=first_level(id);
    for (unsigned level=root_level;level<3;level++) {
        for (unsigned i=root_level;i<level;i++) if (current==seen[i]) return SPTM_BAD_TABLE;
        seen[level]=current;
        r=frame(m,current,(unsigned)id,(unsigned)sid,level,&table);if (r) return r;
#if SNAP_DART_MEMO
        r=table_verdict(m,&table,id,sid,level,root_level);if (r) return r;
#else
        unsigned entries=0;
        for (unsigned i=0;i<2048;i++) {
            uint64_t v=load64(table.page+8*i);if (!v) continue;
            uint64_t allowed=TABLE_ADDRESS|1UL;
            if (level==2) allowed|=0xffffff000000000cUL;
            if (!(v&1) || (v&~allowed) ||
                (level==2 ? !sptm_dart_data_frame(m,id,sid,(v&TABLE_ADDRESS)<<4) :
                            !sptm_managed_frame(m,(v&TABLE_ADDRESS)<<4)) ||
                (level==root_level && !root_slot(id,sid,i)) ||
                (level==2 && (v>>52)>((v>>40)&0xfff))) return SPTM_BAD_TABLE;
            entries++;
        }
        if (table.refs!=entries+1) return SPTM_BAD_REFERENCE;
#endif
        if (level<2) {
            uint64_t next=load64(table.page+8*((iova>>(36-11*level))&2047));
            if (!next) return SPTM_TABLE_MISSING;
            current=(next&TABLE_ADDRESS)<<4;
        }
    }
#if SNAP_DART_MEMO
    uint32_t memo_hits=m->dart_memo ? sptm_dart_memo_hits(m->dart_memo,table.pa) : 0;
#endif
    sptm_refs_begin(m->refs);
    unsigned first=(unsigned)((iova>>14)&2047);
    unsigned count=(unsigned)(((iova&0x3fff)+size+0x3fff)>>14),removed=0;
    for (unsigned i=0;i<count;i++) {
        uint64_t v=load64(table.page+8*(first+i));
        if (!v) {if (options&2) continue;return SPTM_TABLE_MISSING;}
        uint64_t pa=(v&TABLE_ADDRESS)<<4;volatile uint8_t *meta;
        r=data_frame(m,pa,id,sid,0,&meta);if (r) return r;
        r=sptm_refs_dart_stream(m,id,sid,pa,!!(v&4),1);if (r) return r;
        removed++;
    }
    r=sptm_refs_validate(m);if (r) return r;
    /* Native 270d4ee4 clears leaves; 270d4fa0..4fc8 orders/invalidate;
     * 270d4fe4..4fec drops data references. No fallible operation follows
     * admission. Service serialization excludes the synchronous AES producer. */
    for (unsigned i=0;i<count;i++) {
        volatile uint8_t *slot=table.page+8*(first+i);
        if (load64(slot)) {store64(slot,0);m->publish(m->ctx,table.pa+8*(first+i),8);}
    }
#if defined(__aarch64__)
    __asm__ volatile("dsb sy" ::: "memory");
#else
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#endif
    /* The software DART walker has no cached translations or asynchronous
     * DMA to drain. Every later producer must perform a fresh owned walk. */
    s->flushes++;
    sptm_refs_commit(m);
    if (removed) publish_refs(m,&table,table.refs-removed);
#if SNAP_DART_MEMO
    table_committed(m,&table,id,sid,table.refs-removed,memo_hits);
#endif
    return SPTM_OK;
}

uint64_t sptm_dart_leaf(const struct sptm_memory *m,const struct dart_state *s,
    uint64_t id,uint64_t sid,uint64_t iova)
{
    if (!m || !m->map || !s || sid>=2 || !(s->ttbr[sid]&1)) return 0;
    uint64_t table=(uint64_t)(s->ttbr[sid]&0x3ffffffcU)<<12,v=0;
    for (unsigned level=first_level(id);level<3;level++) {
        volatile uint8_t *page=m->map(m->ctx,table,0x4000);
        if (!page) return 0;
        v=load64(page+8*((iova>>(36-11*level))&2047));
        if (!(v&1)) return 0;
        table=(v&TABLE_ADDRESS)<<4;
    }
    return v;
}
