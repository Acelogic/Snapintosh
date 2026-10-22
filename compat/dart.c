/* SPDX-License-Identifier: MIT */
#include "dart.h"

#define PA_LIMIT (1UL<<36)
#define VA_LIMIT (1UL<<44)
#define PTE_ADDRESS 0x0000003ffffffc00UL
#define ERROR_FLAG (1U<<31)

/* Pinned j700 normal SEP stream windows. The native SPTM uses a level1
 * root for these biased IOVAs; the 1 TiB tag is outside both table indices. */
int dart_sep_iova_range(unsigned sid,uint64_t iova,uint64_t size)
{
    if (sid>1 || !size) return 0;
    uint64_t low=sid ? 0x10000000000UL : 0x10000004000UL;
    uint64_t end=sid ? 0x10050000000UL : 0x100ffff4000UL;
    return iova>=low && iova<end && size<=end-iova;
}

void dart_init(struct dart_state *s)
{
    if (!s) return;
    volatile uint8_t *p=(volatile uint8_t *)s;
    for (unsigned i=0; i<sizeof(*s); i++) p[i]=0;
}

static uint32_t stream_mask(unsigned streams, unsigned bank)
{
    unsigned start=bank*32;
    if (start>=streams) return 0;
    return streams-start>=32 ? UINT32_MAX : (1U<<(streams-start))-1;
}

int dart_irq_pending(const struct dart_state *s)
{
    return s && (s->error & ERROR_FLAG) && (s->error & ~s->error_mask & 0x20007fffU);
}

enum dart_result dart_access(struct dart_state *s, unsigned streams,
    uint64_t off, unsigned width, int write, uint64_t *value)
{
    if (!s || !value || !streams || streams>DART_STREAMS) return DART_BAD_CONFIG;
    if (width!=4 || (off&3)) return DART_BAD_WIDTH;
    if (write && *value>UINT32_MAX) return DART_BAD_VALUE;
    uint32_t v=(uint32_t)*value;
    if (off<0x10) {
        if (write) return DART_READ_ONLY;
        /* 16 KiB pages with subpage protection, zero cached translations,
         * full bypass, 36-bit PA / 44-bit VA, v2 register layout. */
        const uint32_t params[]={0x8e000000,1,(36U<<24)|(44U<<16)|(2U<<8),
                                 (streams<<16)|streams};
        *value=params[off/4];
        return DART_OK;
    }
    if (off==0x80) {
        if (!write) { *value=s->tlb_op; return DART_OK; }
        unsigned op=(v>>8)&7, sid=v&255;
        if ((v & ~0x8000f7ffU) || (op!=0 && op!=1 && op!=4) ||
            (op==1 && sid>=streams) || (op!=1 && sid) ||
            ((v&(1U<<14)) && s->tlb_start>s->tlb_end)) return DART_BAD_VALUE;
        /* Every walk reads current guest tables and completes synchronously.
         * There is no cached entry or in-flight translation left to drain. */
        s->tlb_op=v & ~ERROR_FLAG;
        s->flushes++;
        return DART_OK;
    }
    if (off==0x98 || off==0xa0) {
        uint32_t *reg=off==0x98 ? &s->tlb_start : &s->tlb_end;
        if (write) { if (v&3) return DART_BAD_VALUE; *reg=v; }
        else *value=*reg;
        return DART_OK;
    }
    if (off==0x100) {
        if (write) { if (v&ERROR_FLAG) s->error=0; }
        else *value=s->error;
        return DART_OK;
    }
    if (off==0x104) {
        if (write) s->error_mask=v;
        else *value=s->error_mask;
        return DART_OK;
    }
    if (off==0x170 || off==0x174) {
        if (write) return DART_READ_ONLY;
        *value=(uint32_t)(s->error_address>>(off==0x174 ? 32 : 0));
        return DART_OK;
    }
    if (off>=0x1c0 && off<0x1e0) {
        unsigned bank=(unsigned)(off-0x1c0)/4;
        if (write) s->error_streams[bank]&=~v;
        else *value=s->error_streams[bank];
        return DART_OK;
    }
    if (off==0x200 || off==0x204 || off==0x208) {
        if (!write) { *value=off==0x208 ? s->protect_lock : s->protect; return DART_OK; }
        if (v&~0x1fU) return DART_BAD_VALUE;
        if (off==0x200) s->protect|=v;
        else if (off==0x204) s->protect&=~(v&~s->protect_lock);
        else s->protect_lock|=v;
        return DART_OK;
    }
    /* This uncached virtual DART has no TLIMIT allocation or saved cache
     * diagnostics. POWERUP's initial values are all zero. */
    if (off==0x210 || off==0x228 || off==0x22c) {
        if (write) return off==0x210 && !v ? DART_OK : DART_READ_ONLY;
        *value=0;
        return DART_OK;
    }
    if (off>=0xc00 && off<0xc40) {
        unsigned bank=(unsigned)(off&0x1f)/4;
        if (!write) *value=s->enabled[bank];
        else if (off<0xc20) s->enabled[bank]|=v&stream_mask(streams,bank);
        else s->enabled[bank]&=~v;
        return DART_OK;
    }
    if (off>=0x1000 && off<0x1800) {
        unsigned sid=(unsigned)(off&0x3ff)/4;
        if (sid>=streams) return DART_UNKNOWN_REGISTER;
        uint32_t *reg=off<0x1400 ? &s->tcr[sid] : &s->ttbr[sid];
        if (!write) { *value=*reg; return DART_OK; }
        if (s->protect&1) return DART_BAD_VALUE;
        if (off<0x1400) {
            /* Remapping and other unaudited modes remain refused. */
            if ((v&~15U) || (v&3)==3) return DART_BAD_VALUE;
        } else if ((v&~0x3ffffffdU) || ((uint64_t)(v&0x3ffffffcU)<<12)>=PA_LIMIT)
            return DART_BAD_VALUE;
        *reg=v;
        return DART_OK;
    }
    return DART_UNKNOWN_REGISTER;
}

static enum dart_result fault(struct dart_state *s,unsigned sid,uint64_t iova,
                             int write,uint32_t code)
{
    s->faults++;
    s->error_streams[sid/32]|=1U<<(sid%32);
    if (!(s->error&ERROR_FLAG)) {
        s->error=ERROR_FLAG | (write ? 1U<<28 : 0) | (sid<<20) | code;
        s->error_address=iova;
    } else s->error|=1U<<19;
    return DART_FAULT;
}

enum dart_result dart_translate(struct dart_state *s,unsigned streams,
    const struct dart_memory *m,unsigned sid,uint64_t iova,uint64_t size,
    int write,uint64_t *physical)
{
    if (!s || !m || !m->read64 || !m->allow || !physical || !streams ||
        streams>DART_STREAMS || sid>=streams || !size || size>0x4000 ||
        (iova&0x3fff)>0x4000-size || (write!=0 && write!=1)) return DART_BAD_CONFIG;
    if (iova>=VA_LIMIT || size>VA_LIMIT-iova)
        return fault(s,sid,iova,write,1U<<6);
    uint32_t tcr=s->tcr[sid];
    if (!(s->enabled[sid/32]&(1U<<(sid%32))) || !(tcr&3) || (tcr&3)==3)
        return fault(s,sid,iova,write,1U);
    uint64_t pa;
    if (tcr&2) pa=iova;
    else {
        if (!(s->ttbr[sid]&1)) return fault(s,sid,iova,write,1U);
        if (!(tcr&8)) {
            int sep=s->initialized_ids==(1U<<20) && s->powered_ids==(1U<<20);
            if (sep ? !dart_sep_iova_range(sid,iova,size) : iova>=(1UL<<36))
                return fault(s,sid,iova,write,1U<<6);
        }
        pa=(uint64_t)(s->ttbr[sid]&0x3ffffffcU)<<12;
        uint64_t seen[3]; unsigned count=0;
        for (unsigned shift=tcr&8 ? 36 : 25; ; shift-=11) {
            for (unsigned j=0; j<count; j++)
                if (seen[j]==pa) return fault(s,sid,iova,write,1U<<7);
            seen[count++]=pa;
            uint64_t pte;
            if (pa>=PA_LIMIT || 0x4000>PA_LIMIT-pa || !m->allow(m->ctx,pa,0x4000,0) ||
                m->read64(m->ctx,pa+8*((iova>>shift)&2047),&pte))
                return fault(s,sid,iova,write,1U<<7);
            if (!(pte&1)) return fault(s,sid,iova,write,1U<<(shift==14 ? 3 : shift==25 ? 2 : 1));
            pa=(pte&PTE_ADDRESS)<<4;
            if (shift==14) {
                if (pte & (write ? 4U : 8U)) return fault(s,sid,iova,write,1U<<(write ? 4 : 5));
                uint64_t begin=((pte>>52)&0xfff)*4, end=(((pte>>40)&0xfff)+1)*4;
                uint64_t offset=iova&0x3fff;
                if (offset<begin || offset>=end || size>end-offset)
                    return fault(s,sid,iova,write,1U<<29);
                pa+=offset;
                break;
            }
        }
    }
    if (pa>=PA_LIMIT || size>PA_LIMIT-pa || !m->allow(m->ctx,pa,size,write))
        return fault(s,sid,iova,write,1U<<6);
    *physical=pa;
    s->translations++;
    return DART_OK;
}
