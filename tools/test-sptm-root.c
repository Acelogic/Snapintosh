/* SPDX-License-Identifier: MIT */
/* Reuse the independently tested typed-table/ownership fixtures. */
#define main inactive_user_tests
#include "test-sptm-user.c"
#undef main
#include "sptm-root.h"
#include "sptm-root-memo.h"
#include "native-writer.h"
#define HOST 0x10000000UL
static uint8_t host[0x200000];
static uint64_t next_host,host_limit,installed[6][4];
static unsigned current_cpu,builds,installs;
static int admission_enabled;
static struct native_writer_mapping writer_mapping;
static int admit_user(void *ctx,uint64_t va,uint64_t pa,uint64_t size,
                      uint64_t low,uint64_t upper)
{
    (void)ctx;
    return native_writer_mapping_admit(&writer_mapping,NATIVE_WRITER_USER,
                                      va,pa,size,low,upper);
}
static int host_read(void *ctx,uint64_t pa,uint64_t *value)
{
    (void)ctx;
    if(pa<HOST || pa>HOST+sizeof(host)-8 || (pa&7))return -1;
    memcpy(value,host+(pa-HOST),8);return 0;
}
static int host_write(void *ctx,uint64_t pa,uint64_t value)
{
    (void)ctx;
    if(pa<HOST || pa>HOST+sizeof(host)-8 || (pa&7))return -1;
    memcpy(host+(pa-HOST),&value,8);return 0;
}
static uint64_t host_alloc(void *ctx)
{
    (void)ctx;
    if(next_host>=host_limit)return 0;
    uint64_t pa=HOST+next_host;next_host+=0x1000;
    memset(host+(pa-HOST),0,0x1000);return pa;
}
static int build(void *ctx,const struct sptm_memory *m,uint64_t root,
    unsigned format,unsigned flags,uint64_t previous,uint64_t *out,uint64_t *leaves)
{
    (void)ctx;builds++;
    struct shadow s={.txsz=17,.root=previous ? previous : host_alloc(0),
        .alloc=host_alloc,.read=host_read,.write=host_write,
        .admit=admission_enabled ? admit_user:0};
    if(!sptm_root_build_shadow(m,&s,root,format,flags,leaves))return 0;
    *out=s.root;return 1;
}
static void install(void *ctx,uint64_t shadow,uint64_t root,uint64_t asid,unsigned format)
{
    (void)ctx;installs++;
    installed[current_cpu][0]=shadow;installed[current_cpu][1]=root;
    installed[current_cpu][2]=asid;installed[current_cpu][3]=format;
}
static struct sptm_root_backend root_backend={.kernel_root=BASE,.kernel_shadow=HOST,
    .build=build,.install=install};
static enum sptm_result activate(const struct sptm_memory *m,struct sptm_root_state *s,
                                 unsigned cpu,uint64_t root)
{
    current_cpu=cpu;
    return sptm_mac_switch_root(m,s,&root_backend,cpu,root,0,0);
}
static void reset_host(void)
{
    memset(host,0,sizeof(host));memset(installed,0,sizeof(installed));
    next_host=0x1000;host_limit=sizeof(host);builds=installs=0;
    admission_enabled=0;
}
static void mapping(uint64_t root,uint64_t va,uint64_t pa,int valid)
{
    struct mmu_config cfg={12,17,root};struct mmu_leaf leaf;
    check(!mmu_walk(&cfg,va,host_read,0,&leaf),"independent hardware-shadow walk");
    check(leaf.valid==valid,"hardware-shadow presence matches source");
    if(valid)check(leaf.pa==pa && (leaf.descriptor&PT_AP)==PT_AP &&
        (leaf.descriptor&PT_PXN),"translated PA and user permissions preserved");
}
static void test_writer_alias_activation(void)
{
    for(unsigned format=0;format<2;format++)for(unsigned deny=0;deny<2;deny++) {
        reset_host();struct sptm_root_state s={0};uint64_t result;
        struct sptm_memory m=reset_geometry(31,2,VA,format);
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,
              "prepare native executable user mapping for admission test");
        admission_enabled=1;
        writer_mapping=(struct native_writer_mapping){{DATA+(deny ? 0:0x8000),
                                                        DATA+(deny ? 0x1000:0xc000)}};
        memcpy(before,ram,sizeof(ram));
        enum sptm_result r=activate(&m,&s,0,ROOT);
        if(deny) {
            check(r==SPTM_MEMORY_UNAVAILABLE,"reject executable writer alias during root build");
            check(!installs && !s.active[0] && !s.cache[0].valid,
                  "rejected alias cannot install or cache an executable root");
            check(!memcmp(before,ram,sizeof(ram)),"rejected root preserves native metadata and mappings");
        } else {
            check(r==SPTM_OK && installs==1,"unrelated executable mapping still activates");
            mapping(installed[0][0],VA,DATA,1);
        }
    }
    admission_enabled=0;
}
/* probes/xnuboot.c user_root_build's slot rule, verbatim: the build owns the
 * slot whose shadow is `previous`, or else the first slot with no shadow that
 * names no root (or this root). Arena reclaim zeroes whole entries, so this
 * must still agree with the entry sptm_mac_switch_root fills. */
static unsigned rule_slot,rule_calls;
static const struct sptm_root_state *rule_state;
static int rule_build(void *ctx,const struct sptm_memory *m,uint64_t root,
    unsigned format,unsigned flags,uint64_t previous,uint64_t *out,uint64_t *leaves)
{
    rule_slot=SPTM_ROOT_CACHE;rule_calls++;
    for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
        const struct sptm_root_cached *e=&rule_state->cache[i];
        if((previous && e->shadow==previous) ||
           (!previous && !e->shadow && (!e->root || e->root==root))) {rule_slot=i;break;}
    }
    if(rule_slot==SPTM_ROOT_CACHE || rule_state->cache[rule_slot].valid)return 0;
    return build(ctx,m,root,format,flags,0,out,leaves);
}
static uint64_t reclaim_rng=0x9e3779b97f4a7c15UL;
static unsigned reclaim_rnd(unsigned n){reclaim_rng^=reclaim_rng<<13;reclaim_rng^=reclaim_rng>>7;reclaim_rng^=reclaim_rng<<17;return (unsigned)(reclaim_rng%n);}
/* Native-table audit mode: the hook is asked only on cache hits. A skipped hit
 * walks nothing and does not use the walk's root reference identity; the
 * reference bound and the root header still apply; a sampled hit (the hook
 * answers 0) walks and refuses exactly as before; a build always walks. */
static unsigned skip_asks,skip_answer;
static int skip_hits(void *ctx) {(void)ctx;skip_asks++;return (int)skip_answer;}
static void test_hit_audit(void)
{
    reset_host();struct sptm_root_state s={0};uint64_t result;
    struct sptm_memory m=reset(31);
    struct sptm_root_validate_stats vs={0};
    /* Retained verdicts assist only the hits that are walked. */
    static struct sptm_root_memo hit_memo;memset(&hit_memo,0,sizeof hit_memo);
    struct sptm_root_backend b=root_backend;b.validate=&vs;b.skip_hit_validation=skip_hits;
    b.memo=&hit_memo;
    skip_asks=0;skip_answer=1;
    check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,"hit audit fixture map");
    current_cpu=0;
    check(sptm_mac_switch_root(&m,&s,&b,0,ROOT,0,0)==SPTM_OK && !skip_asks && vs.validations==1 &&
          builds==1,"a build walks without asking");
    current_cpu=1;
    check(sptm_mac_switch_root(&m,&s,&b,1,ROOT,0,0)==SPTM_OK && skip_asks==1 && vs.validations==1 &&
          builds==1 && installs==2,"a skipped hit walks nothing and installs the cached shadow");
    /* An identity the walk would refuse: one reference too many. */
    unsigned refs=(unsigned)get(meta(ROOT)+6,2);
    put(meta(ROOT)+6,refs+1,2);
    current_cpu=2;
    check(sptm_mac_switch_root(&m,&s,&b,2,ROOT,0,0)==SPTM_OK && skip_asks==2 && vs.validations==1,
          "a skipped hit does not recompute the reference identity");
    check(!hit_memo.stats.calls,"skipped hits and builds make no memo-assisted validation");
    put(meta(ROOT)+6,get(meta(ROOT)+6,2)+1,2);skip_answer=0;
    current_cpu=3;
    check(sptm_mac_switch_root(&m,&s,&b,3,ROOT,0,0)==SPTM_BAD_REFERENCE && skip_asks==3 &&
          vs.validations==2,"a sampled hit walks and refuses the wrong identity");
    put(meta(ROOT)+6,get(meta(ROOT)+6,2)-2,2);
    check(sptm_mac_switch_root(&m,&s,&b,3,ROOT,0,0)==SPTM_OK && vs.validations==3,
          "the restored identity passes a sampled walk");
    check(hit_memo.stats.calls==2,"each walked hit is one memo-assisted validation");
    skip_answer=1;uint64_t saved=get(meta(ROOT)+6,2);
    put(meta(ROOT)+6,0x80b,2);current_cpu=4;
    check(sptm_mac_switch_root(&m,&s,&b,4,ROOT,0,0)==SPTM_BAD_REFERENCE,
          "the reference bound holds on a skipped hit");
    put(meta(ROOT)+6,saved,2);
    put(meta(ROOT)+12,2,1);
    check(sptm_mac_switch_root(&m,&s,&b,4,ROOT,0,0)==SPTM_BAD_TABLE,"the root header holds on a skipped hit");
    check(hit_memo.stats.calls==2 && !hit_memo.stats.mismatches,"skipped hits leave the memo untouched");
}
static void test_arena_reclaim(void)
{
    uint64_t stamp[SPTM_ROOT_CACHE];
    /* Pick order: retired-with-shadow, then named invalid, then the oldest
     * valid root; never an active root or an excluded slot. */
    {
        struct sptm_root_state s={0};
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
            s.cache[i]=(struct sptm_root_cached){.root=0x1000000UL+i*0x4000,
                .shadow=0x2000000UL+i*0x1000,.asid=100+i,.valid=1};
            stamp[i]=1000+i;
        }
        s.builds=7;
        s.active[0]=s.cache[5].root;s.active[3]=s.cache[9].root;stamp[5]=stamp[9]=1;
        stamp[40]=2;
        check(sptm_root_reclaim_pick(&s,stamp,0)==40,"oldest inactive valid root is picked");
        check(sptm_root_reclaim_pick(&s,stamp,UINT64_C(1)<<40)==0,"next oldest when the oldest is excluded");
        s.cache[17].valid=0;
        check(sptm_root_reclaim_pick(&s,stamp,0)==17,"named invalid root before any valid one");
        s.cache[33].root=0;s.cache[33].valid=0;
        check(sptm_root_reclaim_pick(&s,stamp,0)==33,"retired slot still holding a shadow comes first");
        check(sptm_root_reclaim_pick(&s,stamp,UINT64_C(1)<<33)==17,"exclusion skips the retired slot");
        s.cache[33].shadow=0;
        check(sptm_root_reclaim_pick(&s,stamp,0)==17,"an empty never-used slot is not a candidate");
        check(sptm_root_reclaim_pick(&s,0,UINT64_C(1)<<17)==7,"without stamps valid roots go round robin from builds");
        s.cache[17].valid=1;
        uint64_t all=~UINT64_C(0);
        check(sptm_root_reclaim_pick(&s,stamp,all)==SPTM_ROOT_CACHE,"everything excluded: no candidate");
        struct sptm_root_state only={0};
        only.cache[2]=(struct sptm_root_cached){.root=0x1000000UL,.shadow=0x2000000UL,.asid=3,.valid=1};
        only.active[1]=0x1000000UL;
        check(sptm_root_reclaim_pick(&only,stamp,0)==SPTM_ROOT_CACHE,"an active root is never a candidate");
        check(sptm_root_reclaim_pick(0,stamp,0)==SPTM_ROOT_CACHE,"no state: no candidate");
        struct sptm_root_state saved=s;
        check(!sptm_root_reclaim_forget(&s,5) && !memcmp(&s,&saved,sizeof s),"active root cannot be forgotten");
        check(!sptm_root_reclaim_forget(&s,SPTM_ROOT_CACHE) && !memcmp(&s,&saved,sizeof s),"out-of-range slot refused");
        check(!sptm_root_reclaim_forget(0,1),"no state refused");
        uint64_t invalidations=s.invalidations;
        check(sptm_root_reclaim_forget(&s,40),"inactive root forgotten");
        const struct sptm_root_cached zero={0};
        check(!memcmp(&s.cache[40],&zero,sizeof zero),"forgotten slot equals a never-used slot");
        check(s.invalidations==invalidations+1,"forgetting a valid root counts as an invalidation");
        check(sptm_root_reclaim_pick(&s,stamp,0)==0,"a forgotten slot is never picked again");
        check(sptm_root_reclaim_forget(&s,33) && s.invalidations==invalidations+1,
              "forgetting an invalid slot is not a second invalidation");
    }
    /* A forgotten root switches back in through a fresh build. */
    {
        reset_host();struct sptm_root_state s={0};struct sptm_memory m=reset(31);uint64_t result;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,"reclaim fixture map");
        check(activate(&m,&s,0,ROOT)==SPTM_OK && activate(&m,&s,0,BASE)==SPTM_OK,"root cached then left");
        unsigned before=builds;
        check(sptm_root_reclaim_pick(&s,0,0)==0 && sptm_root_reclaim_forget(&s,0),"only cached root given back");
        check(activate(&m,&s,1,ROOT)==SPTM_OK && builds==before+1,"given-back root rebuilds on its next switch");
        check(s.cache[0].root==ROOT && s.cache[0].valid && installed[1][1]==ROOT,"rebuilt into the fresh slot");
        mapping(installed[1][0],VA,DATA,1);
        check(!sptm_root_reclaim_forget(&s,0),"now active: cannot be given back");
        check(activate(&m,&s,1,BASE)==SPTM_OK,"leave");
    }
    /* Randomized cache states mixing never-used, forgotten, retired, invalid
     * and valid slots (full caches included): the build's slot rule always
     * names the entry SWITCH_ROOT fills, so a zeroed slot can never make a
     * build release or reuse another slot's tables. */
    root_backend.build=rule_build;
    unsigned agreements=0;
    for(unsigned trial=0;trial<4000;trial++) {
        reset_host();struct sptm_root_state s={0};struct sptm_memory m=reset(31);uint64_t result;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,"rule fixture map");
        rule_state=&s;
        unsigned full=trial%4==0;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++) {
            unsigned kind=full ? 3+reclaim_rnd(2) : reclaim_rnd(5);
            struct sptm_root_cached *e=&s.cache[i];
            if(kind==0)continue; /* never used or forgotten */
            e->shadow=HOST+0x100000UL+i*0x1000UL;
            if(kind==1)continue; /* retired: shadow kept, no root */
            e->root=BASE+0x100000UL+i*0x4000UL;e->asid=200+i;e->valid=kind==4;
        }
        s.builds=reclaim_rnd(1000);
        if(!full && reclaim_rnd(3)==0) {
            /* This root already named, invalid, in a random slot. */
            unsigned i=reclaim_rnd(SPTM_ROOT_CACHE);
            s.cache[i]=(struct sptm_root_cached){.root=ROOT,.shadow=HOST+0x180000UL,.asid=2,.valid=0};
        }
        rule_calls=0;
        enum sptm_result r=activate(&m,&s,0,ROOT);
        unsigned filled=SPTM_ROOT_CACHE;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s.cache[i].root==ROOT && s.cache[i].valid)filled=i;
        check(r==SPTM_OK && rule_calls==1 && filled==rule_slot,"build slot rule agrees with the filled entry");
        agreements+=r==SPTM_OK && filled==rule_slot;
        check(activate(&m,&s,0,BASE)==SPTM_OK,"leave rule root");
    }
    check(agreements==4000,"every randomized cache state agreed");
    {
        /* Negative control: had a given-back slot kept its shadow address,
         * a later reissue of that page to another slot would make the build
         * rule name the wrong (valid) slot. forget() clears it for this. */
        reset_host();struct sptm_root_state s={0};struct sptm_memory m=reset(31);uint64_t result;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,"control fixture map");
        rule_state=&s;
        s.cache[0]=(struct sptm_root_cached){.root=BASE+0x100000UL,.shadow=HOST+0x100000UL,.asid=200,.valid=1};
        s.cache[1]=(struct sptm_root_cached){.root=BASE+0x104000UL,.shadow=HOST+0x101000UL,.asid=201,.valid=1};
        s.cache[2]=(struct sptm_root_cached){.shadow=HOST+0x101000UL};
        check(activate(&m,&s,0,ROOT)!=SPTM_OK,"a stale shadow token aliasing a live slot is refused");
        check(sptm_root_reclaim_forget(&s,2) && activate(&m,&s,0,ROOT)==SPTM_OK && s.cache[2].root==ROOT,
              "after forget the same state builds into the freed slot");
    }
    root_backend.build=build;rule_state=0;
}
/* test-root-validate-words.c reruns this suite under another name. */
#ifndef SPTM_ROOT_SUITE
#define SPTM_ROOT_SUITE main
#endif
int SPTM_ROOT_SUITE(void)
{
    const unsigned formats[]={0,0,1,1,1},flags[]={2,0x22,2,6,0x22};
    const uint64_t vas[]={VA,0xffffc000UL,VA,0x7fffffe00000UL,0xffffc000UL};
    for(unsigned no_pauth=0;no_pauth<2;no_pauth++)
    for(unsigned modifier=0;modifier<4;modifier++)for(unsigned test=0;test<5;test++) {
        reset_host();struct sptm_root_state s={0};uint64_t result;
        struct sptm_memory m=reset_geometry(31,flags[test],vas[test],formats[test]);
        put(meta(ROOT)+10,(flags[test]|(modifier&1?8:0)|(modifier&2?1:0))&~(no_pauth?2u:0u),2);
        uint64_t umprr=(modifier&1?0x40000:0)|(modifier&2?0x800:0);
        check(sptm_mac_map_user_page(&m,&backend,ROOT,vas[test],DATA|RX,1,0,&result)==SPTM_OK,
              "source commpage admitted by existing typed mapping service");
        unsigned links=(unsigned)get(meta(ROOT)+6,2);
        for(unsigned cpu=0;cpu<6;cpu++) {
            check(activate(&m,&s,cpu,ROOT)==SPTM_OK,"activate root on each CPU");
            check(s.active[cpu]==ROOT && installed[cpu][1]==ROOT &&
                  installed[cpu][2]==2 && installed[cpu][3]==formats[test],"per-CPU root/ASID/format installed");
            check(get(meta(ROOT)+6,2)==links+cpu+1,"CPU reference added to root metadata");
            check(sprr_fixed_state_valid(&s.sprr[cpu]) &&
                  s.sprr[cpu].umprr==umprr,
                  "activation retains per-CPU SPRR state and requested modifier");
            for(unsigned i=0;i<(formats[test] ? 1u : 4u);i++)
                mapping(installed[cpu][0],vas[test]+i*4096+123,DATA+i*4096+123,1);
            mapping(installed[cpu][0],BASE,0,0);
        }
        check(builds==1 && s.builds==1,"six CPUs reuse one coherent shadow");
        struct shadow fixed={.txsz=17,.root=s.cache[0].shadow,.read=host_read};
        struct sptm_fixed_view proof={0};
        check(sptm_root_fixed_view(&s.cache[0],&fixed,&m,&proof),"prove fixed user shadow before unused SPRR change");
        check(proof.tables==next_host/4096-1 && proof.pages==(formats[test] ? 1u : 4u) &&
              !(proof.classes&~0xac88UL),"proof counts every private table and leaf class");
        uint64_t table=fixed.root,pte=0;
        for(unsigned level=0;level<3;level++) {
            check(!host_read(0,table+8UL*mmu_index(12,level,vas[test]),&pte),"locate hardware leaf table");
            table=pte&PT_OA_MASK;
        }
        for(unsigned part=0;part<(formats[test] ? 1u : 4u);part++) {
            uint64_t loc=table+8UL*mmu_index(12,3,vas[test]+part*4096),old;
            check(!host_read(0,loc,&old),"read each constituent hardware leaf");
            for(unsigned bad=0;bad<5;bad++) {
                uint64_t changed=bad==0 ? (old&~(PT_AP|PT_UXN|PT_PXN))|(2UL<<6)|PT_PXN :
                    bad==1 ? old^4096 : bad==2 ? old^PT_AF : bad==3 ? 0 : old&~2UL;
                host_write(0,loc,changed);struct sptm_fixed_view before={7,8,9};proof=before;
                check(!sptm_root_fixed_view(&s.cache[0],&fixed,&m,&proof),"reject affected class, mismatch, missing leaf or malformed descriptor");
                check(!memcmp(&proof,&before,sizeof proof),"failed proof publishes no partial witness");
                host_write(0,loc,old);
            }
        }
        s.cache[0].leaves++;
        check(!sptm_root_fixed_view(&s.cache[0],&fixed,&m,&proof),"reject inconsistent cached leaf count");
        s.cache[0].leaves--;
        check(sptm_root_fixed_view(&s.cache[0],&fixed,&m,&proof),"restored source/shadow proof passes");
        check(!sptm_root_invalidate(&s,ROOT,0) && !sptm_root_invalidate(&s,ROOT,1),"active root cannot invalidate or retire");
        m.retire_user_root=retire;
        check(sptm_mac_retype(&m,ROOT,18,11,0)==SPTM_FRAME_BUSY,"active root cannot be freed");
        check(activate(&m,&s,0,ROOT)==SPTM_OK && get(meta(ROOT)+6,2)==links+6,
              "same-root switch preserves reference count");
        for(unsigned cpu=0;cpu<6;cpu++) {
            check(activate(&m,&s,cpu,BASE)==SPTM_OK,"switch CPU back to kernel regime");
            check(!s.active[cpu] && installed[cpu][0]==HOST && !installed[cpu][2],"kernel shadow restored without user ASID");
            check(get(meta(ROOT)+6,2)==links+5-cpu,"old CPU root reference released");
            check(sprr_fixed_state_valid(&s.sprr[cpu]) && !s.sprr[cpu].umprr,
                  "kernel return resets that CPU's SPRR modifier");
            for(unsigned other=cpu+1;other<6;other++)
                check(s.sprr[other].umprr==umprr,
                      "kernel return preserves another CPU's active modifier");
        }
        check(sptm_root_invalidate(&s,ROOT,0),"inactive mutation invalidates cached translations");
        uint64_t old_shadow=s.cache[0].shadow,old_alloc=next_host;
        check(activate(&m,&s,0,ROOT)==SPTM_OK && s.cache[0].shadow==old_shadow && next_host==old_alloc,
              "rebuild reuses private shadow table allocations");
        check(activate(&m,&s,0,BASE)==SPTM_OK && sptm_root_invalidate(&s,ROOT,1),"retire cached identity after last CPU leaves");
        /* Reassign the retained shadow to a32-bit root: old high mappings must disappear. */
        m=reset_geometry(31,0x22,0xffffc000,0);
        check(sptm_mac_map_user_page(&m,&backend,ROOT,0xffffc000,DATA|RX,1,0,&result)==SPTM_OK,"new32-bit commpage admitted");
        check(activate(&m,&s,0,ROOT)==SPTM_OK,"retired private storage can be reused");
        mapping(s.cache[0].shadow,0xffffc000,DATA,1);
        if(vas[test]!=0xffffc000)mapping(s.cache[0].shadow,vas[test],0,0);
    }
    {
        reset_host();struct sptm_root_state s={0};struct sptm_memory m=reset(31);
        const uint64_t other=BASE+0x20000;
        check(sptm_mac_retype(&m,other,11,18,(3UL<<32)|(2UL<<16))==SPTM_OK,"allocate second ASID");
        check(activate(&m,&s,0,ROOT)==SPTM_OK && activate(&m,&s,1,other)==SPTM_OK,"two independent user roots active");
        check(installed[0][2]==2 && installed[1][2]==3 && installed[0][0]!=installed[1][0],"ASIDs and private shadows stay distinct");
        check(activate(&m,&s,0,other)==SPTM_OK,"switch directly between user roots");
        check(get(meta(ROOT)+6,2)==1 && get(meta(other)+6,2)==2,"direct switch transfers CPU reference");
        check(activate(&m,&s,1,BASE)==SPTM_OK && get(meta(other)+6,2)==1,"one CPU can leave while another retains root");
        check(!sptm_root_invalidate(&s,other,1),"remaining CPU still prevents retirement");
    }
    {
        /* A full cache takes an inactive root's slot instead of refusing: an
         * already invalidated one first, then round robin, never a root a CPU
         * holds. The evicted root rebuilds from its guest tables when next
         * switched to. Placeholder roots fill slots the fixture has no RAM for;
         * eviction never reads a victim's metadata. */
        reset_host();struct sptm_root_state s={0};struct sptm_memory m=reset(31);uint64_t result;
        const uint64_t other=BASE+0x20000;uint64_t evictions=0;
        root_backend.evictions=&evictions;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,"eviction fixture map");
        check(sptm_mac_retype(&m,other,11,18,(3UL<<32)|(2UL<<16))==SPTM_OK,"eviction second root");
        check(activate(&m,&s,0,ROOT)==SPTM_OK && activate(&m,&s,0,BASE)==SPTM_OK,"root cached, then left");
        check(s.cache[0].root==ROOT && s.cache[0].valid,"first root in slot zero");
        for(unsigned i=1;i<SPTM_ROOT_CACHE;i++)
            s.cache[i]=(struct sptm_root_cached){.root=BASE+0x100000+i*0x4000UL,.asid=200+i,.valid=1};
        check(sptm_root_invalidate(&s,ROOT,0) && s.cache[0].root==ROOT && !s.cache[0].valid,
              "configure-style invalidation keeps the slot named");
        uint64_t invalidations=s.invalidations;
        check(activate(&m,&s,0,other)==SPTM_OK && evictions==1,"full cache evicts instead of refusing");
        check(s.cache[0].root==other && s.cache[0].valid && installed[0][1]==other,
              "invalidated slot is taken first");
        check(s.invalidations==invalidations+1,"eviction counts as an invalidation");
        for(unsigned i=1;i<SPTM_ROOT_CACHE;i++)
            check(s.cache[i].root==BASE+0x100000+i*0x4000UL && s.cache[i].valid,"other slots untouched");
        unsigned start=(unsigned)(s.builds%SPTM_ROOT_CACHE);
        s.active[1]=s.cache[start].root;
        check(activate(&m,&s,0,BASE)==SPTM_OK && activate(&m,&s,0,ROOT)==SPTM_OK && evictions==2,
              "evicted root switches back in");
        check(s.cache[start].root==s.active[1] && s.cache[start].valid,"root held by another CPU is never taken");
        unsigned slot=SPTM_ROOT_CACHE;
        for(unsigned i=0;i<SPTM_ROOT_CACHE;i++)if(s.cache[i].root==ROOT)slot=i;
        check(slot==start+1 && s.cache[slot].valid && installed[0][1]==ROOT,"next inactive slot rebuilt for it");
        mapping(s.cache[slot].shadow,VA,DATA,1);
        check(s.cache[0].root==other && s.cache[0].valid,"most recent root keeps its slot");
        s.active[1]=0;root_backend.evictions=0;
    }
    for(unsigned bad=0;bad<17;bad++) {
        reset_host();struct sptm_root_state s={0};
        struct sptm_memory m=reset(31);uint64_t result;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,"failure fixture map");
        uint64_t root=ROOT,set=0,clear=0;unsigned cpu=0;
        switch(bad) {
        case 0:root++;break;case 1:cpu=6;break;case 2:set=1;break;case 3:clear=2;break;
        case 4:put(meta(ROOT)+4,0,2);break;case 5:put(meta(ROOT)+8,0,2);break;
        case 6:put(meta(ROOT)+6,0,2);break;case 7:put(meta(ROOT)+12,2,1);break;
        case 8:put(meta(ROOT),1,1);break;case 9:put(meta(L2)+4,3,1);break;
        case 10:put(slot(VA),(BASE+SIZE)|RX,8);break;
        case 11:put(slot(VA),DATA|0x403,8);break;
        case 12:fail_pa=L3;break;case 13:host_limit=next_host;break;
        case 14:put(meta(DATA)+2,11,1);break;
        case 15:put(meta(ROOT)+10,10,2);put(slot(VA),DATA|0x0020000000000783UL,8);break;
        case 16:put(meta(ROOT)+10,1,2);put(slot(VA),DATA|0x0020000000000443UL,8);break;
        }
        memcpy(before,ram,sizeof(ram));
        check(sptm_mac_switch_root(&m,&s,&root_backend,cpu,root,set,clear)!=SPTM_OK,"malformed switch refused");
        check(!installs && !s.switches && !s.active[0],"failure cannot activate a root");
        check(!memcmp(before,ram,sizeof(ram)),"failure preserves all guest state");
        if(bad>=15)check(!builds && next_host==0x1000,
            "TPRO or selector5 leaf cannot enter an untranslated shadow even with its root modifier");
        check(!s.sprr[0].resets,"rejected activation cannot publish SPRR state");
    }
    test_writer_alias_activation();
    test_arena_reclaim();
    test_hit_audit();
    printf("Root switching: %u checks, %u failures (owned shadows, six CPUs, ASIDs, recycling, atomic refusal)\n",checks,failures);
    return failures ? 1 : 0;
}
