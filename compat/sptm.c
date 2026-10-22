/* SPDX-License-Identifier: MIT */
#include "sptm.h"
#include "sptm-access.h"
#include "sptm-root-memo.h"
#if SNAP_ROOT_INDEX
#include "root-index.h"
#endif

/* Apple's RETYPE gate (...270f8524..8550): the OLD type descriptor's
 * transition bitmap at +0x40 must contain the new type, else sptm_retype
 * panics (violation 0x19). Low words for types 0..47 of the pinned image;
 * pinned by tools/replay-sptm-matrix.py. XNU_DEFAULT uses SPTM_UNTYPED's
 * all-ones word only before a lockdown flag the monitor has long passed. */
int sptm_mac_apple_retype(uint64_t old_type,uint64_t new_type)
{
    static const uint64_t words[48]={
        [11]=0x8000042ee3f7c802UL,[14]=0x800,[15]=0x800,[16]=0x800,[17]=0x800,
        [18]=0x80800,[19]=0x800,[20]=0x800,[21]=0x800,[24]=0x800,[25]=0x800,
        [32]=0x800,[33]=0x800,[34]=0x800,[35]=0x800000800UL,[37]=0x800,[41]=0x800,
        [42]=0x1802000000000000UL};
    return old_type<48 && new_type<64 && ((words[old_type]>>new_type)&1);
}

static int page_table_type(uint64_t type)
{
    return type == SPTM_MAC_PAGE_TABLE || type == SPTM_MAC_PAGE_TABLE_SHARED || type == SPTM_MAC_PAGE_TABLE_ROZONE ||
           type == SPTM_MAC_PAGE_TABLE_COMMPAGE;
}
/* The transitions this monitor implements, each with its own contract. */
enum {RETYPE_FROM_DEFAULT=1,RETYPE_RELEASE_DATA=2,RETYPE_RELEASE_TABLE=4,
      RETYPE_RELEASE_ROOT=8,RETYPE_SHARE_ROOT=16,RETYPE_RELEASE_SHARED=32};
static unsigned retype_kind(uint64_t old_type,uint64_t new_type)
{
    /* XNU pmap_txm_transfer_page first removes aliases, then retypes even
     * DEFAULT to DEFAULT. Apple's bit11 is set and its ordinary data
     * destructor/reset/constructor still run; never bypass lock/ref checks.
     * Pinned lifecycle replay: tools/replay-default-retype.py. */
    if(old_type==SPTM_MAC_DEFAULT && new_type==SPTM_MAC_DEFAULT)
        return RETYPE_RELEASE_DATA;
    if (old_type == SPTM_MAC_DEFAULT &&
        (page_table_type(new_type) || new_type == SPTM_MAC_KERNEL_RESTRICTED ||
         new_type == SPTM_MAC_ROZONE || new_type == SPTM_MAC_USER_ROOT_TABLE ||
         new_type == SPTM_MAC_COMMPAGE_RW || new_type == SPTM_MAC_COMMPAGE_RO ||
         new_type == SPTM_MAC_COMMPAGE_RX || new_type == SPTM_MAC_IOMMU ||
         new_type == SPTM_MAC_USER_EXEC || new_type == SPTM_MAC_USER_TPRO ||
         new_type == SPTM_MAC_TXM_DEFAULT))
        return RETYPE_FROM_DEFAULT;
    if (new_type == SPTM_MAC_DEFAULT) {
        if (old_type == SPTM_MAC_KERNEL_RESTRICTED || old_type == SPTM_MAC_ROZONE ||
            old_type == SPTM_MAC_USER_EXEC || old_type == SPTM_MAC_USER_TPRO)
            return RETYPE_RELEASE_DATA;
        /* Type22's Apple bitmap is empty: ROZONE tables are never released. */
        if (old_type==SPTM_MAC_PAGE_TABLE || old_type==SPTM_MAC_PAGE_TABLE_SHARED)
            return RETYPE_RELEASE_TABLE;
        if (old_type == SPTM_MAC_USER_ROOT_TABLE) return RETYPE_RELEASE_ROOT;
        if (old_type == SPTM_MAC_SHARED_ROOT_TABLE) return RETYPE_RELEASE_SHARED;
    }
    if (old_type == SPTM_MAC_USER_ROOT_TABLE && new_type == SPTM_MAC_SHARED_ROOT_TABLE)
        return RETYPE_SHARE_ROOT;
    return 0;
}
int sptm_mac_retype_supported(uint64_t old_type,uint64_t new_type)
{
    return retype_kind(old_type,new_type) && sptm_mac_apple_retype(old_type,new_type);
}

int sptm_mac_shared_slot_valid(const struct sptm_shared_slot *s,unsigned format)
{
    if(!s || format>1 || !s->root)return 0;
    if(s->state==1)return !s->start && !s->size;
    uint64_t mask=(format ? 0x1000UL : 0x4000UL)-1;
    return s->state==3 && s->size && s->size<=(1UL<<36) &&
        !((s->start|s->size)&mask) && s->start<(1UL<<47) && s->size<=(1UL<<47)-s->start;
}

uint64_t sptm_published_pointer(const struct sptm_aperture *a,
                                const struct sptm_moved *moved, uint64_t pa,
                                uint64_t size)
{
    if (moved && moved->regions && size && moved->count<=64)
        for (uint64_t i=0;i<moved->count;i++) {
            const struct sptm_slide_region *r=&moved->regions[i];
            uint64_t span=r->pages*0x4000;
            if (r->va<moved->low || r->va>=moved->high || !r->pages ||
                r->pages>(UINT64_MAX>>14) || span>UINT64_MAX-r->pa ||
                pa<r->pa || pa-r->pa>=span) continue;
            return size<=span-(pa-r->pa) ? r->va+(pa-r->pa) : 0;
        }
    return sptm_aperture_pointer(a,pa,size);
}

uint64_t sptm_aperture_pointer(const struct sptm_aperture *a, uint64_t pa,
                               uint64_t size)
{
    if (!a || !size || !a->size || a->size > UINT64_MAX-a->pa ||
        a->size > UINT64_MAX-a->va || pa<a->pa || pa-a->pa>=a->size ||
        size>a->size-(pa-a->pa)) return 0;
    return a->va+(pa-a->pa);
}

enum sptm_result sptm_mac_kernel_map_leaf(const struct sptm_aperture *a,
    const struct sptm_moved *moved, uint64_t slot_pa, uint64_t old,
    uint64_t requested, struct sptm_kernel_leaf *out)
{
    if (!out || (slot_pa&7) || (requested&3)!=3) return SPTM_BAD_CONFIG;
    uint64_t pointer=sptm_published_pointer(a,moved,slot_pa,8);
    if (!pointer) return SPTM_BAD_ADDRESS;
    int valid=(old&3)==3;
    /* ...f92e8 masks bits 12..47 of the old descriptor, ...f8fbc the new. */
    int conflict=valid && ((old^requested)&0x0000fffffffff000UL);
    *out=(struct sptm_kernel_leaf){.old=old,.pointer=pointer,.install=!conflict,
        .status=conflict ? SPTM_MAC_MAP_CONFLICT :
                valid ? sptm_mac_map_page_status(old,requested) : 0};
    return SPTM_OK;
}

/* 8-byte fields: one single-copy-atomic access (compat/sptm-access.h, v67). */
static uint64_t load64(volatile uint8_t *p) {return sptm_get64(p);}
static void store64(volatile uint8_t *p, uint64_t value) {sptm_put64(p, value);}

enum sptm_result sptm_mac_map_table(const struct sptm_memory *m, uint64_t root,
                                   uint64_t va, uint64_t level, uint64_t tte)
{
    const uint64_t pa_mask = 0x0000ffffffffc000UL;
    uint64_t child = tte & pa_mask;
    if (!m || !m->map || !m->publish || !sptm_boot_memory_valid(m) || level < 1 || level > 2 ||
        (root & 0x3fff) || (tte & ~pa_mask) != 3 ||
        va < 0xffff800000000000UL || (va&0x3fff) ||
        !sptm_managed_frame(m,child) ||
        (m->frame_map_pa & 15))
        return SPTM_BAD_TABLE;
    uint64_t index = (child - m->frame_low) >> 14;
    if (index > (UINT64_MAX - m->frame_map_pa - 15) / 16)
        return SPTM_BAD_CONFIG;
    uint64_t entry_pa = m->frame_map_pa + index * 16;
    volatile uint8_t *entry = m->map(m->ctx, entry_pa, 16);
    if (!entry) return SPTM_MEMORY_UNAVAILABLE;
    if (!(entry[2]==SPTM_MAC_PAGE_TABLE || entry[2]==SPTM_MAC_PAGE_TABLE_ROZONE) ||
        entry[4] != level + 1)
        return SPTM_TYPE_MISMATCH;
    if (entry[0] || entry[1] || entry[6] || entry[7] || entry[8] || entry[9])
        return SPTM_FRAME_BUSY;
    volatile uint8_t *child_page = m->map(m->ctx, child, SPTM_MAC_FRAME_SIZE);
    if (!child_page) return SPTM_MEMORY_UNAVAILABLE;
    for (unsigned i = 0; i < SPTM_MAC_FRAME_SIZE; i++)
        if (child_page[i]) return SPTM_BAD_TABLE;

    uint64_t parent = root,seen[2];
    volatile uint8_t *slot = 0;
    uint64_t slot_pa = 0;
    for (unsigned l = 1; l <= level; l++) {
        if (parent == child || (parent & 0x3fff)) return SPTM_BAD_TABLE;
        for(unsigned n=0;n<l-1;n++) if(seen[n]==parent) return SPTM_BAD_TABLE;
        seen[l-1]=parent;
        volatile uint8_t *table = m->map(m->ctx, parent, SPTM_MAC_FRAME_SIZE);
        if (!table) return SPTM_MEMORY_UNAVAILABLE;
        uint64_t offset = ((va >> (14 + (3 - l) * 11)) & 0x7ff) * 8;
        slot = table + offset;
        slot_pa = parent + offset;
        uint64_t current = load64(slot);
        if (l == level) {
            if (current & 1) return SPTM_TABLE_EXISTS;
            if (current) return SPTM_BAD_TABLE;
        } else {
            if (!(current & 1)) return SPTM_TABLE_MISSING;
            if ((current & 3) != 3 || (current & ~(pa_mask|3UL))) return SPTM_BAD_TABLE;
            parent = current & pa_mask;
        }
    }
    entry[6] = 1;            /* one parent references this table */
    m->publish(m->ctx, entry_pa, 16);
    store64(slot, tte);
    m->publish(m->ctx, slot_pa, 8);
    return SPTM_OK;
}

enum sptm_result sptm_txm_retype_check(const struct sptm_memory *m,uint64_t pa,
                               uint64_t old_type,uint64_t new_type)
{
    /* Native domain2 ownership and retained-count contract:
     * tools/replay-txm-donation.py --txm-ownership. Domain1 cannot perform
     * these operations; keep this entry absent from the public dispatcher. */
    if(!((old_type==SPTM_MAC_TXM_DEFAULT && new_type==SPTM_MAC_TXM_OWNED) ||
         (old_type==SPTM_MAC_TXM_OWNED && new_type==SPTM_MAC_DEFAULT)))
        return SPTM_UNSUPPORTED_RETYPE;
    const uint64_t mask=SPTM_MAC_FRAME_SIZE-1;
    if(!m || !m->map || !m->publish || !m->retype_txm_owned || !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&mask) ||
       (m->frame_map_pa&(SPTM_MAC_ENTRY_SIZE-1)) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low || m->alloc_high>m->frame_high)
        return SPTM_BAD_CONFIG;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*SPTM_MAC_ENTRY_SIZE;
    if(m->frame_map_pa>UINT64_MAX-map_size ||
       (m->frame_map_pa<m->alloc_high && m->frame_map_pa+map_size>m->alloc_low))
        return SPTM_BAD_CONFIG;
    if((pa&mask) || !sptm_managed_frame(m,pa))return SPTM_BAD_ADDRESS;
    uint64_t at=m->frame_map_pa+((pa-m->frame_low)>>14)*SPTM_MAC_ENTRY_SIZE;
    volatile uint8_t *entry=m->map(m->ctx,at,SPTM_MAC_ENTRY_SIZE);
    if(!entry)return SPTM_MEMORY_UNAVAILABLE;
    if(entry[2]!=old_type)return SPTM_TYPE_MISMATCH;
    /* Donation admits only these clean flags and bounded RO references.
     * Refuse unqualified private state instead of discarding live counts. */
    for(unsigned i=0;i<16;i++)
        if(i!=2 && (i<8 || i>=12) && entry[i])return SPTM_FRAME_BUSY;
    if(entry[11]&0x80)return SPTM_FRAME_BUSY;
    if(!m->map(m->ctx,pa,SPTM_MAC_FRAME_SIZE))return SPTM_MEMORY_UNAVAILABLE;
    return SPTM_OK;
}

enum sptm_result sptm_txm_retype(const struct sptm_memory *m,uint64_t pa,
                               uint64_t old_type,uint64_t new_type)
{
    enum sptm_result r=sptm_txm_retype_check(m,pa,old_type,new_type);
    if(r)return r;
    uint64_t at=m->frame_map_pa+((pa-m->frame_low)>>14)*SPTM_MAC_ENTRY_SIZE;
    volatile uint8_t *entry=m->map(m->ctx,at,SPTM_MAC_ENTRY_SIZE);
    if(!entry)return SPTM_MEMORY_UNAVAILABLE;
    if(!m->retype_txm_owned(m->ctx,pa,old_type,new_type))return SPTM_SHADOW_FAILED;
    sptm_root_memo_retype(m->root_memo,entry);
    /* Both native leaf callbacks preserve the page and read-only count. */
    entry[2]=(uint8_t)new_type;
    m->publish(m->ctx,at,SPTM_MAC_ENTRY_SIZE);
    return SPTM_OK;
}

enum sptm_result sptm_mac_retype(const struct sptm_memory *m, uint64_t pa,
                               uint64_t old_type, uint64_t new_type,
                               uint64_t options)
{
    const uint64_t mask = SPTM_MAC_FRAME_SIZE - 1;
    if (!m || !m->map || !m->publish || !sptm_boot_memory_valid(m) ||
        ((m->frame_low | m->frame_high | m->alloc_low | m->alloc_high) & mask) ||
        (m->frame_map_pa & (SPTM_MAC_ENTRY_SIZE - 1)) ||
        m->frame_low >= m->frame_high || m->alloc_low >= m->alloc_high ||
        m->alloc_low < m->frame_low || m->alloc_high > m->frame_high)
        return SPTM_BAD_CONFIG;
    uint64_t map_size = ((m->frame_high - m->frame_low) >> 14) * SPTM_MAC_ENTRY_SIZE;
    if (m->frame_map_pa > UINT64_MAX - map_size ||
        (m->frame_map_pa < m->alloc_high &&
         m->frame_map_pa + map_size > m->alloc_low))
        return SPTM_BAD_CONFIG;
    if ((pa & mask) || !sptm_managed_frame(m,pa))
        return SPTM_BAD_ADDRESS;
    unsigned kind=retype_kind(old_type,new_type);
    int new_root = new_type == SPTM_MAC_USER_ROOT_TABLE;
    int new_iommu = new_type == SPTM_MAC_IOMMU;
    int exec_transition=old_type==SPTM_MAC_USER_EXEC || new_type==SPTM_MAC_USER_EXEC;
    int tpro_transition=old_type==SPTM_MAC_USER_TPRO || new_type==SPTM_MAC_USER_TPRO;
    int txm_donation=old_type==SPTM_MAC_DEFAULT && new_type==SPTM_MAC_TXM_DEFAULT;
    int release_table = !!(kind&RETYPE_RELEASE_TABLE);
    int release_root = !!(kind&RETYPE_RELEASE_ROOT);
    int share_root = !!(kind&RETYPE_SHARE_ROOT);
    int release_shared = !!(kind&RETYPE_RELEASE_SHARED);
    /* Never admit a transition Apple's matrix refuses. */
    if (!sptm_mac_retype_supported(old_type,new_type)) return SPTM_UNSUPPORTED_RETYPE;
    if (release_root && !m->retire_user_root) return SPTM_BAD_CONFIG;
    if(exec_transition && !m->retype_user_exec)return SPTM_BAD_CONFIG;
    if(tpro_transition && !m->retype_user_tpro)return SPTM_BAD_CONFIG;
    if(txm_donation && !m->retype_txm_default)return SPTM_BAD_CONFIG;
    if ((share_root && !m->share_user_root) ||
        (release_shared && !m->retire_shared_root)) return SPTM_BAD_CONFIG;
    if((share_root || release_shared) && !m->shared_regions)return SPTM_BAD_CONFIG;
    uint64_t asid = (options >> 32) & 0xffff;
    /* Measured SPTM ...ebb3c constructor: format [7:0], flags [31:16],
     * ASID [47:32]. It stores supported controls unchanged, including PA off.
     * Reuse geometry validation; do not force CONFIGURE_ROOT's initial flags. */
    uint64_t flags=(options>>16)&0xffff;
    struct sptm_user_geometry geometry;
    if (new_root ? (!asid || (options & ~0x0000ffffffff0001UL) ||
                    !sptm_mac_user_geometry((unsigned)(options&0xff),(unsigned)flags,&geometry)) :
        share_root ? ((options&0xff)>1) :
        new_iommu ? ((options & ~0x00ffffff000000ffUL) || (options & 0xff)!=5) :
        new_type==SPTM_MAC_PAGE_TABLE_SHARED ? ((options&0xff)>3) :
        options > (page_table_type(new_type) ? 3UL : 0UL))
        return SPTM_UNSUPPORTED_OPTIONS;
    if(new_type==SPTM_MAC_PAGE_TABLE_COMMPAGE && options!=3)
        return SPTM_UNSUPPORTED_OPTIONS;
    if (new_iommu) {
        if (!m->admit_iommu) return SPTM_BAD_CONFIG;
        if (!m->admit_iommu(m->ctx, (unsigned)(options&0xff),
                            (unsigned)((options>>32)&0xff),
                            (unsigned)((options>>40)&0xff),
                            (unsigned)((options>>48)&0xff)))
            return SPTM_UNSUPPORTED_OPTIONS;
    }

    uint64_t entry_pa = m->frame_map_pa + ((pa - m->frame_low) >> 14) * 16;
    volatile uint8_t *entry = m->map(m->ctx, entry_pa, SPTM_MAC_ENTRY_SIZE);
    if (!entry) return SPTM_MEMORY_UNAVAILABLE;
    if (entry[2] != old_type) return SPTM_TYPE_MISMATCH;
    /* The bootstrap path has no in-flight operations or counted data
     * references. Reject recycling/live-frame semantics we do not implement. */
    if (entry[0] || entry[1]) return SPTM_FRAME_BUSY;
    unsigned shared_slot=SPTM_MAC_SHARED_ROOT_LIMIT;
    volatile uint8_t *bound_meta=0;uint64_t bound_meta_pa=0;
    if (release_root || share_root) {
        asid = (uint64_t)entry[4] | (uint64_t)entry[5] << 8;
        if (!asid || (share_root && entry[8]!=0xff) ||
            !sptm_mac_user_binding_valid(m,entry) || entry[9] ||
            !sptm_mac_user_geometry(entry[12],entry[10],&geometry) ||
            entry[11] || entry[13] || entry[14] || entry[15])
            return SPTM_BAD_TABLE;
        if (entry[6] || entry[7]) return SPTM_FRAME_BUSY;
        if(entry[8]!=0xff) {
            uint64_t parent=m->shared_regions->slots[entry[8]].root;
            bound_meta_pa=m->frame_map_pa+((parent-m->frame_low)>>14)*16;
            bound_meta=m->map(m->ctx,bound_meta_pa,16);
            if(!bound_meta)return SPTM_MEMORY_UNAVAILABLE;
        }
    } else if (release_shared) {
        shared_slot=entry[8];
        if (shared_slot>=SPTM_MAC_SHARED_ROOT_LIMIT || entry[9] ||
            entry[10] || entry[11] || entry[12]>1 || entry[13] || entry[14] || entry[15])
            return SPTM_BAD_TABLE;
        if (entry[4] || entry[5] || entry[6] || entry[7]) return SPTM_FRAME_BUSY;
    } else if (release_table) {
        /* Destructor precondition at SPTM ...eb020: both u16 reference
         * counts must be zero. Level is not in-flight state for this class. */
        if (entry[4] > 3) return SPTM_BAD_TABLE;
        if (entry[6] || entry[7]) return SPTM_FRAME_BUSY;
    } else if (entry[4] & 3) return SPTM_FRAME_BUSY;
    if (!release_root && !share_root && !release_shared)
        for (unsigned i = (exec_transition || txm_donation) ? 12 : 8; i < 16; i++)
            if (entry[i]) return SPTM_FRAME_BUSY;
    if(exec_transition && (entry[3] || entry[4] || entry[5] || entry[6] || entry[7] ||
                           (entry[11]&0x80)))return SPTM_FRAME_BUSY;
    /* XNU_USER_TPRO has no preserved references. The reached unaliased
     * constructor/destructor state has no private flags either. */
    if(tpro_transition && (entry[3] || entry[4] || entry[5] || entry[6] || entry[7]))
        return SPTM_FRAME_BUSY;
    /* Apple's DEFAULT destructor permits retained RO counts for destination42.
     * Keep the reached clean private flags and bounded nonnegative count;
     * writable references were rejected above. Payload is never cleared. */
    if(txm_donation && (entry[3] || entry[4] || entry[5] || entry[6] || entry[7] ||
                        (entry[11]&0x80)))return SPTM_FRAME_BUSY;
    volatile uint8_t *page = m->map(m->ctx, pa, SPTM_MAC_FRAME_SIZE);
    if (!page) return SPTM_MEMORY_UNAVAILABLE;
    if (new_root) {
        /* One authority for allocated ASIDs: the shared typed frame map.
         * Duplicate allocation is refused until the old root is retired. */
        volatile uint8_t *all = m->map(m->ctx, m->frame_map_pa, map_size);
        if (!all) return SPTM_MEMORY_UNAVAILABLE;
#if SNAP_ROOT_INDEX
        /* compat/root-index.h: the listed records, re-read as the scan reads
         * them; -1 scans every record as before. */
        uint64_t listed[SPTM_ROOT_INDEX_LIST];
        int count=sptm_root_index_candidates(m->root_index,m,SPTM_ROOT_KEY_USER(asid),0,listed);
        for (int k = 0; k < count; k++) {
            volatile uint8_t *f = all + ((listed[k] - m->frame_low) >> 14) * 16;
            if (f[2] == SPTM_MAC_USER_ROOT_TABLE && ((uint64_t)f[4] | ((uint64_t)f[5] << 8)) == asid)
                return SPTM_FRAME_BUSY;
        }
        if (count < 0)
#endif
        for (uint64_t off = 0; off < map_size; off += 16)
            if (all[off+2] == SPTM_MAC_USER_ROOT_TABLE &&
                ((uint64_t)all[off+4] | ((uint64_t)all[off+5] << 8)) == asid)
                return SPTM_FRAME_BUSY;
    }
    if (share_root || release_shared) {
        /* The typed frame map is also the authority for shared slots, just
         * as it is for ASIDs. mac-v1 has slots 0..254; 255 means no nesting.
         * Refuse duplicate/corrupt identities before touching translations. */
        volatile uint8_t *all=m->map(m->ctx,m->frame_map_pa,map_size);
        if (!all) return SPTM_MEMORY_UNAVAILABLE;
        uint8_t used[SPTM_MAC_SHARED_ROOT_LIMIT]={0};
        for(uint64_t off=0;off<map_size;off+=16) {
            if(all[off+2]!=SPTM_MAC_SHARED_ROOT_TABLE)continue;
            unsigned slot=all[off+8];
            if(slot>=SPTM_MAC_SHARED_ROOT_LIMIT || used[slot])return SPTM_BAD_TABLE;
            const struct sptm_shared_slot *s=&m->shared_regions->slots[slot];
            uint64_t owner=m->frame_low+(off/16)*SPTM_MAC_FRAME_SIZE;
            if(s->root!=owner || !sptm_mac_shared_slot_valid(s,all[off+12]))return SPTM_BAD_TABLE;
            used[slot]=1;
        }
        for(unsigned slot=0;slot<SPTM_MAC_SHARED_ROOT_LIMIT;slot++) {
            const struct sptm_shared_slot *s=&m->shared_regions->slots[slot];
            if(!used[slot] && (s->state || s->start || s->size || s->root))return SPTM_BAD_TABLE;
        }
        if(share_root) {
            for(shared_slot=0;shared_slot<SPTM_MAC_SHARED_ROOT_LIMIT;shared_slot++)
                if(!used[shared_slot])break;
            if(shared_slot==SPTM_MAC_SHARED_ROOT_LIMIT)return SPTM_MEMORY_UNAVAILABLE;
        }
        /* Native retype preserves the payload (descriptor permissions zero).
         * A valid entry with zero references is inconsistent ownership;
         * invalid software bits are retained, not silently cleared. */
        for(unsigned off=0;off<SPTM_MAC_FRAME_SIZE;off+=8)
            if(load64(page+off)&1)return SPTM_BAD_TABLE;
    }
    if (release_table || release_root) {
        /* The real destructor clears the page. Restrict recycling to already
         * empty, never-attached tables until table removal is implemented. */
#if SNAP_SPTM_FINE_RETYPE
        /* compat/fine-lock.h: the same test a word at a time (2,048 loads,
         * not 16,384); any nonzero byte is a nonzero word. */
        for (uint64_t i = 0; i < SPTM_MAC_FRAME_SIZE; i += 8)
            if (sptm_get64(page + i)) return SPTM_BAD_TABLE;
#else
        for (uint64_t i = 0; i < SPTM_MAC_FRAME_SIZE; i++)
            if (page[i]) return SPTM_BAD_TABLE;
#endif
    }
    /* SPTM ...eb558/eb880 retires the ASID and its translations. The host
     * also owns TXM registration and active-root tracking, so it must approve
     * retirement before the shared type or ASID can change. */
    if (release_root && !m->retire_user_root(m->ctx, pa, (uint16_t)asid))
        return SPTM_FRAME_BUSY;
    if (share_root && !m->share_user_root(m->ctx,pa,(uint16_t)asid,(uint8_t)shared_slot))
        return SPTM_FRAME_BUSY;
    if (release_shared && !m->retire_shared_root(m->ctx,pa,(uint8_t)shared_slot))
        return SPTM_FRAME_BUSY;
    if(bound_meta) {
        /* ...eb924..960 releases the SPTM reference at ASID retirement,
         * after TXM36 has already removed its separate object reference. */
        unsigned refs=(unsigned)bound_meta[4]|(unsigned)bound_meta[5]<<8;
        --refs;bound_meta[4]=(uint8_t)refs;bound_meta[5]=(uint8_t)(refs>>8);
        m->publish(m->ctx,bound_meta_pa+4,2);
    }
    if(share_root)
        m->shared_regions->slots[shared_slot]=(struct sptm_shared_slot){.state=1,.root=pa};
    if(release_shared)
        m->shared_regions->slots[shared_slot]=(struct sptm_shared_slot){0};

    if(old_type==SPTM_MAC_ROZONE || new_type==SPTM_MAC_ROZONE) {
        if(!m->retype_rozone)return SPTM_BAD_CONFIG;
        if(!m->retype_rozone(m->ctx,pa,old_type,new_type))return SPTM_SHADOW_FAILED;
    }
    if(exec_transition && !m->retype_user_exec(m->ctx,pa,old_type,new_type))
        return SPTM_SHADOW_FAILED;
    if(tpro_transition && !m->retype_user_tpro(m->ctx,pa,old_type,new_type))
        return SPTM_SHADOW_FAILED;
    if(txm_donation && !m->retype_txm_default(m->ctx,pa,old_type,new_type))
        return SPTM_SHADOW_FAILED;
    /* No failure below. The record still holds the old type and counts:
     * exec and TXM donation keep read-only references (checks above). */
    sptm_root_memo_retype(m->root_memo,entry);
#if SNAP_ROOT_INDEX
    /* compat/root-index.h: the key this record loses and the one it gains. */
    sptm_root_index_retype(m->root_index,pa,sptm_root_index_key(entry),
        new_root ? SPTM_ROOT_KEY_USER(asid) : share_root ? SPTM_ROOT_KEY_SHARED(shared_slot) : 0);
#endif
    /* XNU expects freshly retyped table frames to contain no descriptors.
     * Publish the whole page before changing the type visible to its direct
     * frame-map readers. Preserve unrelated entry state. */
    if (page_table_type(new_type) || new_root) {
#if SNAP_SPTM_FINE_RETYPE
        /* A word at a time: the same zero page, an eighth of the stores. */
        for (uint64_t i = 0; i < SPTM_MAC_FRAME_SIZE; i += 8) sptm_put64(page + i, 0);
#else
        for (uint64_t i = 0; i < SPTM_MAC_FRAME_SIZE; i++) page[i] = 0;
#endif
        m->publish(m->ctx, pa, SPTM_MAC_FRAME_SIZE);
    }
    /* Types 25,29..31,35 are data: their constructor at 0xfffffff0270ebf7c
     * in the audited SPTM is a no-op. Preserve every byte of its payload.
     * The common path ...f8614..8744 uses the outgoing type's preserve mask:
     * DEFAULT retains bytes8..11 (validated zero); USER_ROOT retains only
     * its ASID bytes, which retirement clears or shared conversion replaces.
     * Clearing this interval produces the supported post-transition state. */
    for (unsigned i = 4; i < SPTM_MAC_ENTRY_SIZE; i++)
        if(!(exec_transition || txm_donation) || i<8 || i>=12)entry[i] = 0;
    /* PAGE_TABLE's constructor stores the level byte at entry+4. */
    if (page_table_type(new_type)) entry[4] = (uint8_t)options;
    if (new_iommu) {
        /* 26A428 SPTM 270eaeb8 and class-5 constructor 270d8b28:
         * u16 references at +4, class at +6, device/SID/level at +8/+9/+10.
         * Neither constructor clears payload; no descriptor is attached. */
        entry[6] = (uint8_t)options;
        entry[8] = (uint8_t)(options>>32);
        entry[9] = (uint8_t)(options>>40);
        entry[10] = (uint8_t)(options>>48);
    }
    if (new_root) {
        entry[4] = (uint8_t)asid; entry[5] = (uint8_t)(asid >> 8);
        entry[8] = 0xff; /* no nested root */
        entry[10] = (uint8_t)flags;
        entry[12] = (uint8_t)(options&1); /* keep granule separate from 16K frame size */
    }
    if (share_root) {
        /* ...ebc48..ebd08: +4 is now a nesting count, not an ASID.
         * TXM retains the object handle, rekeyed as (slot, class=1). */
        entry[8]=(uint8_t)shared_slot;
        entry[12]=(uint8_t)options;
    }
    entry[2] = (uint8_t)new_type;
    m->publish(m->ctx, entry_pa, SPTM_MAC_ENTRY_SIZE);
    if (new_root && m->created_user_root)
        m->created_user_root(m->ctx, pa, (uint16_t)asid, (unsigned)(options&1), (unsigned)flags);
    return SPTM_OK;
}

int sptm_mac_user_binding_valid(const struct sptm_memory *m,volatile uint8_t *f)
{
    if(!m || !m->map || !f || f[9])return 0;
    if(f[8]==0xff)return 1;
    if(!m->shared_regions)return 0;
    const struct sptm_shared_slot *s=&m->shared_regions->slots[f[8]];
    if(s->state!=3 || !sptm_mac_shared_slot_valid(s,f[12]) ||
       !sptm_managed_frame(m,s->root))return 0;
    volatile uint8_t *p=m->map(m->ctx,m->frame_map_pa+((s->root-m->frame_low)>>14)*16,16);
    return p && !p[0] && !p[1] && p[2]==SPTM_MAC_SHARED_ROOT_TABLE &&
        (p[4]|p[5]) && ((unsigned)p[4]|(unsigned)p[5]<<8)<=0xfff9 &&
        p[8]==f[8] && !p[9] && !p[10] && !p[11] && p[12]==f[12] &&
        !p[13] && !p[14] && !p[15];
}

enum sptm_result sptm_mac_set_shared_region(const struct sptm_memory *m,
    uint64_t user_root,uint64_t shared_root)
{
    if(!m || !m->map || !m->publish || !m->bind_shared_root || !m->shared_regions ||
       !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high)return SPTM_BAD_CONFIG;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if(m->frame_map_pa>UINT64_MAX-map_size ||
       (m->frame_map_pa<m->alloc_high && m->frame_map_pa+map_size>m->alloc_low))return SPTM_BAD_CONFIG;
    if(user_root==shared_root || !sptm_managed_frame(m,user_root) ||
       !sptm_managed_frame(m,shared_root))return SPTM_BAD_ADDRESS;
    uint64_t upa=m->frame_map_pa+((user_root-m->frame_low)>>14)*16;
    uint64_t ppa=m->frame_map_pa+((shared_root-m->frame_low)>>14)*16;
    volatile uint8_t *u=m->map(m->ctx,upa,16),*p=m->map(m->ctx,ppa,16);
    if(!u || !p)return SPTM_MEMORY_UNAVAILABLE;
    if(u[2]!=SPTM_MAC_USER_ROOT_TABLE || p[2]!=SPTM_MAC_SHARED_ROOT_TABLE)return SPTM_TYPE_MISMATCH;
    if(u[0] || u[1] || p[0] || p[1])return SPTM_FRAME_BUSY;
    struct sptm_user_geometry g;
    unsigned asid=(unsigned)u[4]|(unsigned)u[5]<<8,refs=(unsigned)p[4]|(unsigned)p[5]<<8;
    if(!asid || u[9] || u[11] || u[13] || u[14] || u[15] ||
       !sptm_mac_user_geometry(u[12],u[10],&g) || p[8]==255 || p[9] || p[10] ||
       p[11] || p[12]!=u[12] || p[13] || p[14] || p[15])return SPTM_BAD_TABLE;
    if(u[8]!=255)return SPTM_FRAME_BUSY;
    if(refs>=0xfff9)return SPTM_BAD_REFERENCE;
    const struct sptm_shared_slot *s=&m->shared_regions->slots[p[8]];
    if(s->root!=shared_root || !sptm_mac_shared_slot_valid(s,p[12]))return SPTM_BAD_TABLE;
    if(s->state!=3)return SPTM_FRAME_BUSY;
    if(!m->bind_shared_root(m->ctx,user_root,(uint16_t)asid,shared_root,p[8],s->start,s->size))
        return SPTM_FRAME_BUSY;
    /* Native ...fed10 CASB assigns the slot, and ...fed68 increments the
     * shared root's u16 reference. Our service token serializes both with
     * the internal TXM operation. No PTE or translation changes occur. */
    u[8]=p[8];refs++;p[4]=(uint8_t)refs;p[5]=(uint8_t)(refs>>8);
    m->publish(m->ctx,upa+8,1);m->publish(m->ctx,ppa+4,2);
    return SPTM_OK;
}

enum sptm_result sptm_mac_configure_root(const struct sptm_memory *m,
    uint64_t root,uint64_t value,uint64_t mask)
{
    if(!m || !m->map || !m->publish || !m->configure_user_root || !m->root_configuration ||
       !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&0x3fff) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high)return SPTM_BAD_CONFIG;
    uint64_t size=((m->frame_high-m->frame_low)>>14)*16;
    if(m->frame_map_pa>UINT64_MAX-size ||
       (m->frame_map_pa<m->alloc_high && m->frame_map_pa+size>m->alloc_low))return SPTM_BAD_CONFIG;
    /* Native ...10020c..21c checks these low16 bits and CASH stores a u16.
     * Other allowed modifiers have separate effects and stay unsupported. */
    value=(uint16_t)value;mask=(uint16_t)mask;
    if(((value|mask)&0xfea4) ||
       (mask&~(SPTM_MAC_ROOT_FLAG_UMPRR18|SPTM_MAC_ROOT_FLAG_ADDRESS_PAUTH|
               SPTM_MAC_ROOT_FLAG_UMPRR11)))
        return SPTM_UNSUPPORTED_OPTIONS;
    if(!sptm_managed_frame(m,root))return SPTM_BAD_ADDRESS;
    uint64_t pa=m->frame_map_pa+((root-m->frame_low)>>14)*16;
    volatile uint8_t *f=m->map(m->ctx,pa,16);
    if(!f)return SPTM_MEMORY_UNAVAILABLE;
    if(f[2]!=SPTM_MAC_USER_ROOT_TABLE)return SPTM_TYPE_MISMATCH;
    if(f[0] || f[1])return SPTM_FRAME_BUSY;
    struct sptm_user_geometry g;unsigned before=(unsigned)f[10]|(unsigned)f[11]<<8;
    if(!(f[4]|f[5]) || !sptm_mac_user_geometry(f[12],before,&g) ||
       f[13] || f[14] || f[15] || !sptm_mac_user_binding_valid(m,f))return SPTM_BAD_TABLE;
    if(((unsigned)f[6]|(unsigned)f[7]<<8)>g.root_groups+6)return SPTM_BAD_REFERENCE;
    unsigned after=(before&~(unsigned)mask)|((unsigned)value&(unsigned)mask);
    struct sptm_root_configuration *c=m->root_configuration;
    if(c->calls==UINT64_MAX || (before!=after && c->changes==UINT64_MAX))return SPTM_BAD_CONFIG;
    if(before!=after && !m->configure_user_root(m->ctx,root,(uint16_t)before,(uint16_t)after))
        return SPTM_FRAME_BUSY;
    f[10]=(uint8_t)after;f[11]=(uint8_t)(after>>8);
    m->publish(m->ctx,pa+10,2);
    c->calls++;c->changes+=before!=after;c->root=root;c->value=value;c->mask=mask;
    c->before=before;c->after=after;
    return SPTM_OK;
}

enum sptm_result sptm_mac_configure_sharedregion(const struct sptm_memory *m,
    uint64_t root,uint64_t start,uint64_t page_count)
{
    const uint64_t mask=SPTM_MAC_FRAME_SIZE-1;
    if(!m || !m->map || !m->shared_regions || !sptm_boot_memory_valid(m) ||
       ((m->frame_low|m->frame_high|m->alloc_low|m->alloc_high)&mask) ||
       (m->frame_map_pa&15) || m->frame_low>=m->frame_high ||
       m->alloc_low>=m->alloc_high || m->alloc_low<m->frame_low ||
       m->alloc_high>m->frame_high)return SPTM_BAD_CONFIG;
    uint64_t map_size=((m->frame_high-m->frame_low)>>14)*16;
    if(m->frame_map_pa>UINT64_MAX-map_size ||
       (m->frame_map_pa<m->alloc_high && m->frame_map_pa+map_size>m->alloc_low))
        return SPTM_BAD_CONFIG;
    if(!sptm_managed_frame(m,root))return SPTM_BAD_ADDRESS;
    uint64_t meta_pa=m->frame_map_pa+((root-m->frame_low)>>14)*16;
    volatile uint8_t *f=m->map(m->ctx,meta_pa,16);
    if(!f)return SPTM_MEMORY_UNAVAILABLE;
    if(f[2]!=SPTM_MAC_SHARED_ROOT_TABLE && f[2]!=SPTM_MAC_USER_ROOT_TABLE)
        return SPTM_TYPE_MISMATCH;
    if(f[0] || f[1])return SPTM_FRAME_BUSY;
    if(f[8]>=SPTM_MAC_SHARED_ROOT_LIMIT || f[9] || f[11] || f[12]>1 ||
       f[13] || f[14] || f[15])return SPTM_BAD_TABLE;
    if(f[2]==SPTM_MAC_SHARED_ROOT_TABLE ? f[10]!=0 :
       (!(f[4]|f[5]) || !sptm_mac_user_runtime_flags_valid(f[10]) ||
        ((f[10]&SPTM_MAC_ROOT_FLAG_X86_COMMPAGE) && f[12]!=1)))return SPTM_BAD_TABLE;
    struct sptm_shared_slot *s=&m->shared_regions->slots[f[8]];
    if(!sptm_mac_shared_slot_valid(s,f[12]) || !sptm_managed_frame(m,s->root))return SPTM_BAD_TABLE;
    if(f[2]==SPTM_MAC_SHARED_ROOT_TABLE && s->root!=root)return SPTM_TYPE_MISMATCH;
    if(f[2]==SPTM_MAC_USER_ROOT_TABLE && s->root==root)return SPTM_TYPE_MISMATCH;
    if(s->root!=root) {
        /* Native class1 handling can resolve through a nested user root.
         * Require the recorded shared parent and matching format. Binding
         * creation belongs to SET_SHARED_REGION, before NEST attaches PTEs. */
        uint64_t parent_pa=m->frame_map_pa+((s->root-m->frame_low)>>14)*16;
        volatile uint8_t *parent=m->map(m->ctx,parent_pa,16);
        if(!parent)return SPTM_MEMORY_UNAVAILABLE;
        if(parent[0] || parent[1] || parent[2]!=SPTM_MAC_SHARED_ROOT_TABLE ||
           parent[8]!=f[8] || parent[9] || parent[10] || parent[11] ||
           parent[12]!=f[12] || parent[13] || parent[14] || parent[15] ||
           !(parent[4]|parent[5]))return SPTM_BAD_TABLE;
    }
    if(s->state!=1)return SPTM_FRAME_BUSY;
    /* ...fcf98 zero-extends w1. Geometry0/1 both have a 47-bit VA limit;
     * this helper does not use an ordinary root's ARM64_32 flag to shrink it. */
    uint64_t pages=(uint32_t)page_count,page_size=f[12] ? 0x1000UL : 0x4000UL;
    if(!pages || pages>(1UL<<36)/page_size || (start&(page_size-1)) ||
       start>=(1UL<<47) || pages*page_size>(1UL<<47)-start)return SPTM_BAD_ADDRESS;
    if(m->shared_regions->configurations==UINT64_MAX)return SPTM_BAD_CONFIG;
    s->start=start;s->size=pages*page_size;s->state=3;
    m->shared_regions->configurations++;
    return SPTM_OK;
}
