/* SPDX-License-Identifier: MIT */
/* SNAP_ROOT_VALIDATE_MEMO: cache-hit SWITCH_ROOT validation reusing level-3
 * verdicts (compat/sptm-root-memo.h), exercised through the real SWITCH_ROOT,
 * SPTM operations and publish callback with the default 1-in-64 reference
 * walk. Build (from the repository root):
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *      -Icompat -Ishadow tools/test-root-validate-memo.c compat/sptm-root.c \
 *      compat/sptm-user.c compat/sptm.c compat/sptm-refs.c compat/sptm-unmap.c \
 *      compat/sptm-update.c compat/txm.c compat/sptm-papt.c compat/sptm-slide.c \
 *      shadow/shadow.c shadow/mmu.c shadow/sprr-view.c -o build/test-root-validate-memo
 * 1) Hits return the full walk's verdict and state; one lookup per level-3
 *    table; a build never uses the memo; the same table is shared by roots of
 *    equal flags and kept apart for different flags.
 * 2) A published store retires exactly the touched table, so a published
 *    policy violation is refused on the next switch; a table's reference-count
 *    write keeps its verdict.
 * 3) Retyping a mapped frame (USER_EXEC, TXM donation) advances the epoch and
 *    the next switch refuses; without the retype hook it would not. Unmapped
 *    TPRO retypes keep verdicts; every other retype of a mapped frame is
 *    refused by SPTM itself.
 * 4) A wrap of the stored 32-bit epoch clears all entries.
 * 5) A freed level-3 frame loses its verdict at the type change and is
 *    rescanned when reused as a table.
 * 6) An unpublished violation survives at most 63 hits; the sampled reference
 *    walk then refuses (terminal, counted) and nothing is installed.
 * 7) The witness drops exactly what an independent overlap rule predicts, on
 *    both its small-range and bounded large-range paths.
 * 8) Random published SPTM sequences: memo and full walk always agree. */
#define SPTM_ROOT_SUITE root_switch_suite
#include "test-sptm-root.c"
#include "sptm-root-memo.h"
int root_switch_suite(void);
#if defined(SPTM_ROOT_VALIDATE_SAMPLE) && SPTM_ROOT_VALIDATE_SAMPLE!=63
#error "build with the monitor's default 1-in-64 sampling"
#endif
#define VA2 0x800000000UL                   /* same level-2 table as VA */
#define L3P (BASE+0x1c000)                  /* ordinary (type20) level-3 */
#define D(n) (BASE+0x20000+(uint64_t)(n)*0x4000) /* DEFAULT data, n<4 */
#define ROOT2 (BASE+0x30000)
#define L2B (BASE+0x34000)
#define ROOT3 (BASE+0x38000)
#define L2C (BASE+0x3c000)
#define RO_SH 0x0060000000000fc3UL          /* user RO, NX, inner shareable */
#define RO_NS 0x0060000000000cc3UL          /* the same, non-shareable */
#define RW_SH 0x0060000000000f43UL
#define USER_EXEC_OK 0x0020000000000fc3UL   /* DEFAULT policy refuses (UXN clear) */
static struct sptm_root_memo memo;
static struct sptm_root_validate_stats vstats;
static int witness_off;
static void witness(void *ctx,uint64_t pa,uint64_t n)
{if(!witness_off)sptm_root_memo_publish(&memo,FM,BASE,BASE+SIZE,map,ctx,pa,n);}
static int allow(void *ctx,uint64_t pa,uint64_t old,uint64_t next)
{(void)ctx;(void)pa;(void)old;(void)next;return 1;}
static unsigned l3_tables;
static struct sptm_memory setup(unsigned format)
{
    memset(&memo,0,sizeof memo);memset(&vstats,0,sizeof vstats);witness_off=0;
    publish_observer=witness;fixture_root_memo=&memo;
    reset_host();
    struct sptm_memory m=reset_geometry(31,2,VA,format);uint64_t result;
    m.retype_user_exec=allow;m.retype_txm_default=allow;m.retype_user_tpro=allow;
    root_backend.validate=&vstats;root_backend.memo=&memo;
    check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,"commpage leaf");
    l3_tables=format ? 4 : 1;
    if(!format) {
        check(sptm_mac_retype(&m,L3P,11,20,3)==SPTM_OK,"ordinary level-3 constructor");
        check(sptm_mac_map_user_table(&m,ROOT,VA2,2,L3P|3)==SPTM_OK,"ordinary level-3 link");
        for(unsigned n=0;n<3;n++)
            check(sptm_mac_map_user_page(&m,&backend,ROOT,VA2+n*0x4000UL,D(n)|(n ? RO_SH : RO_NS),
                  1,0,&result)==SPTM_OK,"read-only DEFAULT leaves");
        l3_tables++;
    }
    return m;
}
static uint64_t slot2(unsigned k) {return L3P+8UL*mmu_index(14,3,VA2+k*0x4000UL);}
/* One cache-hit switch into ROOT on `cpu`, once as a memo-free byte walk and
 * once memo-assisted from identical guest, shadow and root state. The CPU is
 * returned to the kernel root afterwards, so ROOT stays cached and inactive. */
static uint8_t ram_in[SIZE],ram_ref[SIZE],host_in[sizeof host],host_ref[sizeof host];
static enum sptm_result both(struct sptm_memory *m,struct sptm_root_state *s,unsigned cpu,
                             uint64_t root,enum sptm_result *reference)
{
    memcpy(ram_in,ram,SIZE);memcpy(host_in,host,sizeof host);
    struct sptm_root_state s_in=*s,s_ref;uint64_t next_in=next_host,next_ref;
    unsigned b_in=builds,i_in=installs,b_ref,i_ref;uint64_t inst_in[6][4],inst_ref[6][4];
    memcpy(inst_in,installed,sizeof installed);
    root_backend.validate=0;root_backend.memo=0;current_cpu=cpu;
    *reference=sptm_mac_switch_root(m,s,&root_backend,cpu,root,0,0);
    memcpy(ram_ref,ram,SIZE);memcpy(host_ref,host,sizeof host);s_ref=*s;next_ref=next_host;
    b_ref=builds;i_ref=installs;memcpy(inst_ref,installed,sizeof installed);
    memcpy(ram,ram_in,SIZE);memcpy(host,host_in,sizeof host);*s=s_in;next_host=next_in;
    builds=b_in;installs=i_in;memcpy(installed,inst_in,sizeof installed);
    root_backend.validate=&vstats;root_backend.memo=&memo;current_cpu=cpu;
    enum sptm_result got=sptm_mac_switch_root(m,s,&root_backend,cpu,root,0,0);
    if(got==*reference)
        check(!memcmp(ram,ram_ref,SIZE) && !memcmp(host,host_ref,sizeof host) &&
              !memcmp(s,&s_ref,sizeof *s) && next_host==next_ref && builds==b_ref &&
              installs==i_ref && !memcmp(installed,inst_ref,sizeof installed),
              "memo-assisted switch leaves the full walk's guest, shadow and root state");
    if(got==SPTM_OK)check(activate(m,s,cpu,BASE)==SPTM_OK,"return to the kernel root");
    return got;
}
static enum sptm_result agreed(struct sptm_memory *m,struct sptm_root_state *s,unsigned cpu)
{
    enum sptm_result reference,got=both(m,s,cpu,ROOT,&reference);
    check(got==reference,"memo-assisted verdict equals the full walk");
    return got;
}
/* Keep the next validation off the 1-in-64 reference schedule. */
static void unsampled_next(struct sptm_memory *m,struct sptm_root_state *s)
{if(!((vstats.validations+1)&63))check(agreed(m,s,5)==SPTM_OK,"schedule spacer switch");}
static void warm(struct sptm_memory *m,struct sptm_root_state *s)
{
    check(activate(m,s,0,ROOT)==SPTM_OK && activate(m,s,0,BASE)==SPTM_OK,"build and leave");
    check(!memo.stats.calls && !memo.stats.misses,"a build never consults the memo");
    check(agreed(m,s,1)==SPTM_OK && memo.stats.misses==l3_tables && memo.stats.records==l3_tables,
          "first hit scans and records every level-3 table");
}
static void test_hits(void)
{
    for(unsigned format=0;format<2;format++) {
        struct sptm_memory m=setup(format);struct sptm_root_state s={0};
        warm(&m,&s);
        uint64_t installs0=installs;
        for(unsigned i=0;i<200;i++)check(agreed(&m,&s,i%6)==SPTM_OK,"cache hit");
        check(memo.stats.calls==201 && memo.stats.hits==200UL*l3_tables &&
              memo.stats.misses==l3_tables && !memo.stats.invalidations,"hits answer every level-3 table");
        check(builds==1 && installs==installs0+200*2,"one build; each hit installs the cached shadow");
        check(memo.stats.sampled==vstats.sampled && vstats.sampled==vstats.validations/64 &&
              memo.stats.sampled>=3 && !vstats.mismatches && !memo.stats.mismatches,
              "every 64th validation re-walked without the memo and agreed");
        check(activate(&m,&s,2,ROOT)==SPTM_OK,"hit installs");
        mapping(installed[2][0],VA,DATA,1);
        if(!format)mapping(installed[2][0],VA2+0x4000,D(1),1);
        check(activate(&m,&s,2,BASE)==SPTM_OK,"leave");
    }
    /* Key: one commpage table attached to three roots. Equal flags share the
     * verdict; different flags (UMPRR11) do not. */
    struct sptm_memory m=setup(0);struct sptm_root_state s={0};uint64_t result;
    warm(&m,&s);
    for(unsigned r=0;r<2;r++) {
        uint64_t root=r ? ROOT3 : ROOT2,l2=r ? L2C : L2B;unsigned flags=r ? 3 : 2;
        check(sptm_mac_retype(&m,root,11,18,((uint64_t)(3+r)<<32)|((uint64_t)flags<<16))==SPTM_OK &&
              sptm_mac_retype(&m,l2,11,20,2)==SPTM_OK &&
              sptm_mac_map_user_table(&m,root,VA,1,l2|3)==SPTM_OK,"second root and level-2");
        uint64_t drops=memo.stats.invalidations,links=get(meta(L3)+6,2);
        check(sptm_mac_map_user_table(&m,root,VA,2,L3|3)==SPTM_OK && get(meta(L3)+6,2)==links+1,
              "commpage table attached to another root");
        check(memo.stats.invalidations==drops,"a link-count write keeps the table's verdict");
        check(activate(&m,&s,3,root)==SPTM_OK && activate(&m,&s,3,BASE)==SPTM_OK,"build other root");
        uint64_t hits=memo.stats.hits,misses=memo.stats.misses;enum sptm_result reference;
        check(both(&m,&s,4,root,&reference)==SPTM_OK && reference==SPTM_OK,"other root hit");
        check(r ? memo.stats.misses==misses+1 && memo.stats.hits==hits :
                  memo.stats.hits==hits+1 && memo.stats.misses==misses,
              r ? "different flags scan the shared table again" : "equal flags reuse the table's verdict");
        (void)result;
    }
}
static void test_published(void)
{
    struct sptm_memory m=setup(0);struct sptm_root_state s={0};
    warm(&m,&s);
    /* A store that is published retires the table, so a policy violation is
     * seen on the very next switch (not only by sampling). */
    uint64_t at=slot2(3),drops=memo.stats.invalidations;
    unsampled_next(&m,&s);
    put(at,D(3)|USER_EXEC_OK,8);m.publish(m.ctx,at,8);
    check(memo.stats.invalidations==drops+1,"published store drops exactly the touched table");
    uint64_t sampled=vstats.sampled;
    check(agreed(&m,&s,0)==SPTM_BAD_TABLE && vstats.sampled==sampled && !memo.stats.mismatches,
          "published violation refused by the rescan, not by sampling");
    put(at,0,8);m.publish(m.ctx,at,8);
    check(agreed(&m,&s,0)==SPTM_OK,"restored table accepted again");
    /* Real SPTM writes: map, update-free unmap and a table record type change. */
    uint64_t result;drops=memo.stats.invalidations;
    check(sptm_mac_map_user_page(&m,&backend,ROOT,VA2+3*0x4000UL,D(3)|RW_SH,1,0,&result)==SPTM_OK,
          "MAP_PAGE");
    check(memo.stats.invalidations==drops+1,"MAP_PAGE drops the level-3 verdict");
    check(agreed(&m,&s,0)==SPTM_OK,"rescanned after MAP_PAGE");
    drops=memo.stats.invalidations;
    check(sptm_mac_unmap_user_region(&m,&backend,ROOT,VA2+3*0x4000UL,1,0,BASE)==SPTM_OK,"UNMAP_REGION");
    check(memo.stats.invalidations==drops+1,"UNMAP_REGION drops the level-3 verdict");
    check(agreed(&m,&s,0)==SPTM_OK,"rescanned after UNMAP_REGION");
}
static void test_retype(void)
{
    /* USER_EXEC: the non-shareable RO leaf is admitted for DEFAULT only. */
    for(unsigned hook=0;hook<2;hook++) {
        struct sptm_memory m=setup(0);struct sptm_root_state s={0};
        warm(&m,&s);unsampled_next(&m,&s);
        uint64_t bumps=memo.stats.epoch_bumps;
        if(!hook)m.root_memo=0;
        check(get(meta(D(0))+8,4)==1 && sptm_mac_retype(&m,D(0),11,14,0)==SPTM_OK,
              "mapped read-only frame retyped USER_EXEC with its reference");
        m.root_memo=&memo;
        enum sptm_result reference,got=both(&m,&s,0,ROOT,&reference);
        check(reference==SPTM_BAD_TABLE,"full walk refuses the non-shareable USER_EXEC leaf");
        if(hook)check(got==SPTM_BAD_TABLE && memo.stats.epoch_bumps==bumps+1 && !memo.stats.mismatches,
                      "the retype advanced the epoch and the next switch refused");
        else check(got==SPTM_OK && memo.stats.epoch_bumps==bumps,
                   "control: without the retype hook the stale verdict would be used");
    }
    {
        struct sptm_memory m=setup(0);struct sptm_root_state s={0};
        warm(&m,&s);
        uint64_t bumps=memo.stats.epoch_bumps;
        check(sptm_mac_retype(&m,D(1),11,SPTM_MAC_TXM_DEFAULT,0)==SPTM_OK,"mapped frame donated to TXM");
        check(memo.stats.epoch_bumps==bumps+1 && agreed(&m,&s,0)==SPTM_BAD_TABLE,
              "donation of a mapped frame retires verdicts; the leaf is refused");
    }
    {
        /* TPRO: only unmapped frames change type; neither case retires. */
        struct sptm_memory m=setup(0);struct sptm_root_state s={0};
        warm(&m,&s);
        uint64_t bumps=memo.stats.epoch_bumps,misses=memo.stats.misses;
        check(sptm_mac_retype(&m,D(3),11,SPTM_MAC_USER_TPRO,0)==SPTM_OK,"unmapped frame to TPRO");
        memcpy(before,ram,SIZE);
        check(sptm_mac_retype(&m,D(2),11,SPTM_MAC_USER_TPRO,0)==SPTM_FRAME_BUSY &&
              !memcmp(before,ram,SIZE),"mapped frame refused TPRO without any store");
        check(sptm_mac_retype(&m,D(3),SPTM_MAC_USER_TPRO,11,0)==SPTM_OK,"unmapped TPRO released");
        check(memo.stats.epoch_bumps==bumps && agreed(&m,&s,0)==SPTM_OK && memo.stats.misses==misses,
              "unmapped TPRO retypes keep every verdict");
    }
    {
        /* The retype hook bumps only for counted frames. Every transition
         * that succeeds for an unmapped DEFAULT frame is refused for a mapped
         * one, except USER_EXEC and TXM donation (both bump, above). */
        struct sptm_memory m=setup(0);unsigned admitted=0;
        const uint64_t options[]={0,1,2,3,(9UL<<32)|(2UL<<16),5};
        for(unsigned type=0;type<64;type++)for(unsigned o=0;o<6;o++) {
            memcpy(before,ram,SIZE);
            enum sptm_result free_frame=sptm_mac_retype(&m,D(3),11,type,options[o]);
            memcpy(ram,before,SIZE);
            if(free_frame!=SPTM_OK)continue;
            admitted++;
            enum sptm_result mapped=sptm_mac_retype(&m,D(2),11,type,options[o]);
            if(type==SPTM_MAC_USER_EXEC || type==SPTM_MAC_TXM_DEFAULT)
                check(mapped==SPTM_OK,"read-only references survive USER_EXEC/TXM donation");
            else check(mapped!=SPTM_OK && !memcmp(before,ram,SIZE),"mapped frame keeps its type");
            memcpy(ram,before,SIZE);
        }
        check(admitted>=8,"unmapped DEFAULT frame reached several transitions");
        /* Every type a user leaf may name has a mapping policy (the hook's filter). */
        struct sptm_user_geometry g;check(sptm_mac_user_geometry(0,2|8,&g),"geometry");
        /* RO/RW NX data, RX exec, TPRO class9, commpage RO/NX and RX. */
        const uint64_t attrs[]={RO_SH,RW_SH,USER_EXEC_OK,0x0020000000000f83UL,
                                0x00600000000007c3UL,0x00200000000007c3UL};
        const unsigned tables[]={SPTM_MAC_PAGE_TABLE,SPTM_MAC_PAGE_TABLE_SHARED,SPTM_MAC_PAGE_TABLE_COMMPAGE};
        unsigned admitted_types=0;
        for(unsigned type=0;type<256;type++) {
            int any=0;
            for(unsigned t=0;t<3;t++)for(unsigned a=0;a<6;a++)
                any|=sptm_mac_user_leaf_policy(2|8,tables[t],type,VA,D(0)|attrs[a],&g)==SPTM_OK;
            if(any){admitted_types++;check(sptm_mac_type_policy(type)!=0,"admitted type has a mapping policy");}
        }
        check(admitted_types==7,"policy sweep admitted DEFAULT, IO, USER_EXEC, TPRO and three commpage types");
    }
}
static void test_epoch_wrap(void)
{
    struct sptm_memory m=setup(0);struct sptm_root_state s={0};
    warm(&m,&s);
    const struct sptm_root_memo_entry *old=0;
    for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++)
        if(memo.entry[i].table==L3P && !memo.entry[i].epoch)old=&memo.entry[i];
    check(old!=0,"ordinary table verdict recorded at epoch 0");
    check(sptm_mac_retype(&m,D(0),11,14,0)==SPTM_OK && memo.epoch==1,"mapped retype: epoch 1");
    check(agreed(&m,&s,0)==SPTM_BAD_TABLE,"refused at epoch 1");
    check(old->table==L3P && old->epoch==0,"the epoch-0 verdict is still stored (stale)");
    memo.epoch=UINT32_MAX;   /* as after 2^32-2 further mapped-frame retypes */
    uint64_t flushes=memo.stats.flushes;
    check(sptm_mac_retype(&m,D(1),11,SPTM_MAC_TXM_DEFAULT,0)==SPTM_OK && (uint32_t)memo.epoch==0,
          "the next mapped retype wraps the stored epoch to 0");
    check(memo.stats.flushes==flushes+1 && !memo.live && !old->table,"wrap cleared every entry");
    check(agreed(&m,&s,0)==SPTM_BAD_TABLE,"no epoch-0 verdict answers after the wrap");
}
static void test_recycle(void)
{
    struct sptm_memory m=setup(0);struct sptm_root_state s={0};
    warm(&m,&s);
    check(sptm_mac_unmap_user_region(&m,&backend,ROOT,VA2,3,1,BASE)==SPTM_OK,"empty the table");
    check(agreed(&m,&s,0)==SPTM_OK,"empty table scanned and recorded");
    uint64_t drops=memo.stats.invalidations;
    check(sptm_mac_unmap_user_table(&m,&backend,ROOT,VA2,2)==SPTM_OK && !get(meta(L3P)+6,2),"detach");
    check(memo.stats.invalidations==drops,"detach changes only the table's link count");
    check(agreed(&m,&s,0)==SPTM_OK,"root without the table");
    check(sptm_mac_retype(&m,L3P,20,11,0)==SPTM_OK,"free the level-3 frame");
    check(memo.stats.invalidations==drops+1,"its verdict is dropped at the type change");
    for(unsigned i=0;i<2048;i++)put(L3P+8UL*i,D(3)|USER_EXEC_OK,8); /* ordinary memory now */
    check(sptm_mac_retype(&m,L3P,11,20,3)==SPTM_OK && !get(L3P,8),"reuse as a level-3 table (zeroed)");
    uint64_t result;
    check(sptm_mac_map_user_table(&m,ROOT,VA2,2,L3P|3)==SPTM_OK &&
          sptm_mac_map_user_page(&m,&backend,ROOT,VA2+5*0x4000UL,D(2)|RO_SH,1,0,&result)==SPTM_OK,
          "relink and map");
    uint64_t misses=memo.stats.misses;
    check(agreed(&m,&s,0)==SPTM_OK && memo.stats.misses==misses+1,"reused table is rescanned");
}
static void test_unpublished(void)
{
    struct sptm_memory m=setup(0);struct sptm_root_state s={0};
    warm(&m,&s);unsampled_next(&m,&s);
    put(slot2(3),D(3)|USER_EXEC_OK,8);  /* no publish: outside the contract */
    unsigned stale=0;enum sptm_result r;uint64_t shadow=s.cache[0].shadow;
    while((r=activate(&m,&s,1,ROOT))==SPTM_OK && stale<200) {
        stale++;mapping(installed[1][0],VA2+3*0x4000UL,0,0);
        check(installed[1][0]==shadow,"stale verdict only reuses the cached shadow");
        check(activate(&m,&s,1,BASE)==SPTM_OK,"leave");
    }
    check(r==SPTM_BAD_TABLE && stale>=1 && stale<=63,"sampled reference walk refuses within 64 switches");
    check(vstats.mismatches==1 && memo.stats.mismatches==1,"the disagreement is counted (terminal)");
    check(!s.active[1] && installed[1][0]==HOST,"nothing installed by the refused switch");
}
static void test_witness_ranges(void)
{
    /* Independent rule: an entry goes iff its frame overlaps the range, or
     * its frame record overlaps the range and bytes0..5 differ. Records here
     * all match except frame 7's, so only overlap and that frame matter. */
    static const uint64_t fl=BASE,fh=BASE+1024*0x4000UL;
    for(unsigned trial=0;trial<4000;trial++) {
        memset(&memo,0,sizeof memo);
        for(unsigned i=0;i<40;i++) {
            uint64_t f=fl+(uint64_t)(i ? reclaim_rnd(1024) : 7)*0x4000;
            volatile uint8_t *rec=map(0,FM+((f-fl)>>14)*16,16);
            uint64_t now=sptm_root_memo_record_bytes(rec);
            if(((f-fl)>>14)==7)now^=0x10000;   /* stale snapshot for frame 7 */
            sptm_root_memo_store(&memo,f+(reclaim_rnd(2) ? 0 : 0x1000),i,2,14,now);
        }
        uint64_t pa,size;
        switch(reclaim_rnd(3)) {
        case 0:pa=fl+reclaim_rnd(1024)*0x4000UL+reclaim_rnd(0x4000);size=1+reclaim_rnd(0x40000);break;
        case 1:pa=FM+reclaim_rnd(256);size=1+reclaim_rnd(0x4000);break;          /* records */
        default:pa=fl+reclaim_rnd(64)*0x4000UL;size=(1+reclaim_rnd(1024))*0x4000UL;break; /* large */
        }
        struct sptm_root_memo_entry kept[SPTM_ROOT_MEMO_ENTRIES];memcpy(kept,memo.entry,sizeof kept);
        uint64_t live=memo.live;
        sptm_root_memo_publish(&memo,FM,fl,fh,map,0,pa,size);
        unsigned dropped=0;
        for(unsigned i=0;i<SPTM_ROOT_MEMO_ENTRIES;i++) {
            const struct sptm_root_memo_entry *e=&kept[i];if(!e->table)continue;
            uint64_t f=e->table&~0x3fffUL,at=FM+((f-fl)>>14)*16;
            int expect=(f+0x3fff>=pa && f<=pa+size-1) ||
                       (at+15>=pa && at<=pa+size-1 && ((f-fl)>>14)==7);
            check(expect ? !memo.entry[i].table : !memcmp(&memo.entry[i],e,sizeof *e),
                  "witness drops exactly the overlapping or changed entries");
            dropped+=expect;
        }
        check(memo.live==live-dropped && memo.stats.invalidations==dropped,"live and drop counts agree");
    }
}
static void test_random(void)
{
    struct sptm_memory m=setup(0);struct sptm_root_state s={0};
    warm(&m,&s);
    const uint64_t attrs[]={RO_SH,RO_NS,RW_SH};
    const unsigned types[][2]={{11,14},{14,11},{11,17},{17,11}};
    unsigned accepted=0,refused=0;
    for(unsigned step=0;step<3000;step++) {
        unsigned k=reclaim_rnd(8),n=reclaim_rnd(4);uint64_t result;
        switch(reclaim_rnd(5)) {
        case 0:sptm_mac_map_user_page(&m,&backend,ROOT,VA2+k*0x4000UL,D(n)|attrs[reclaim_rnd(3)],
                                      1,0,&result);break;
        case 1:sptm_mac_unmap_user_region(&m,&backend,ROOT,VA2+k*0x4000UL,1+reclaim_rnd(3),
                                          reclaim_rnd(2),BASE);break;
        case 2:{unsigned t=reclaim_rnd(4);sptm_mac_retype(&m,D(n),types[t][0],types[t][1],0);break;}
        /* A published non-SPTM store into a free slot, or its removal: an
         * unmanaged frame is refused by every walk whatever the retypes (a
         * counted frame could not be named without SPTM's reference). */
        case 3:
            if(!get(slot2(k),8)) {put(slot2(k),BASE|RO_SH,8);m.publish(m.ctx,slot2(k),8);}
            break;
        default:
            for(unsigned j=0;j<8;j++)if(get(slot2(j),8)==(BASE|RO_SH)) {
                put(slot2(j),0,8);m.publish(m.ctx,slot2(j),8);
            }
            break;
        }
        enum sptm_result r=agreed(&m,&s,reclaim_rnd(6));
        if(r==SPTM_OK)accepted++;else refused++;
    }
    check(accepted>300 && refused>300,"random sequence exercised acceptance and refusal");
    check(!memo.stats.mismatches && !vstats.mismatches && memo.stats.hits>0 &&
          memo.stats.invalidations>0 && memo.stats.epoch_bumps>0,"random sequence used and retired verdicts");
    printf("random: %u accepted, %u refused; memo calls %llu hits %llu misses %llu drops %llu bumps %llu sampled %llu\n",
           accepted,refused,(unsigned long long)memo.stats.calls,(unsigned long long)memo.stats.hits,
           (unsigned long long)memo.stats.misses,(unsigned long long)memo.stats.invalidations,
           (unsigned long long)memo.stats.epoch_bumps,(unsigned long long)memo.stats.sampled);
}
int main(void)
{
    test_hits();
    test_published();
    test_retype();
    test_epoch_wrap();
    test_recycle();
    test_unpublished();
    test_witness_ranges();
    test_random();
    publish_observer=0;fixture_root_memo=0;root_backend.memo=0;root_backend.validate=0;
    printf("Root validation memo: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}
