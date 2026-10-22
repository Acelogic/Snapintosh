/* SPDX-License-Identifier: MIT */
/* Run v47's TXM address-space lifecycle at process scale, through the real
 * SPTM retype/binding paths and compat/txm.c (compat/txm.h A1-A9).
 *
 * Built and run by tools/test-txm-aspace-wide.py, narrow and with
 * -DSNAP_TXM_ASPACE_WIDE=1, sanitized, together with mutants of compat/txm.c
 * that must make it fail. By hand:
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *      -Icompat -Ishadow tools/test-txm-aspace-churn.c compat/txm.c compat/sptm.c \
 *      compat/sptm-root.c compat/sptm-user.c compat/sptm-refs.c compat/sptm-unmap.c \
 *      compat/sptm-update.c shadow/mmu.c shadow/shadow.c [-DSNAP_TXM_ASPACE_WIDE=1]
 *
 * Failure modes this checks, written before the code:
 *  F1 A slot leak: some release path leaves a slot occupied, so TXM35 fails
 *     while fewer than TXM_ASPACE_LIMIT address spaces are alive. Every create
 *     below the limit must succeed through more than 5,000 creations.
 *  F2 Exhaustion off by one, or with side effects: the create that finds every
 *     slot live must return SPTM_MEMORY_UNAVAILABLE and change nothing.
 *  F3 RETYPE releasing a root TXM still holds (the "released by RETYPE without
 *     clearing the registry" case): refused, nothing changed.
 *  F4 Shared regions: a bound region must not be destroyed; unbinds must
 *     return every u32 (+0x68) and SPTM u16 reference; a freed slot must be
 *     reusable whatever class it held.
 *  F5 The v47 state (512 slots: 4 shared regions, 508 address spaces, the
 *     newest unbound, ASID 0x1551 the last issued) refuses ASID 0x1552 with
 *     the 8-page arena and admits it with the wide one, which then fills to
 *     exactly 4096.
 *  F6 A leaky lifecycle (TXM36 skipped) is visible: exhaustion arrives exactly
 *     at live + leaked == limit, and the leaked roots stay unretypable.
 *  F7 Slots past 511 (wide) behave like the first: handles, reuse at the
 *     limit, a full drain back to zero live slots. */
#include "sptm-root.h"
#include "sptm-user.h"
#include "txm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE 0x100000UL
#define PAGE 0x4000UL
#define MAP_PAGES 8u
#define STACK (BASE+MAP_PAGES*PAGE)
#define ARENA (STACK+PAGE)
#define ROOTS (ARENA+TXM_ASPACE_SIZE)
#define FRAMES (TXM_ASPACE_LIMIT+16u)
#define TOTAL (MAP_PAGES+1u+TXM_ASPACE_PAGES+FRAMES)
_Static_assert(TOTAL*16u<=MAP_PAGES*PAGE,"the frame map covers every frame");
#define REGIONS 4u
#define START 0x180000000UL
#define LENGTH 0xe40000000UL
#define V47_LAST_ASID 0x1551u

static uint8_t bytes[TOTAL*PAGE];
static struct txm_registry registry,saved_registry;
static struct sptm_shared_registry shared_regions,saved_regions;
static struct sptm_root_state roots;
static uint8_t saved_meta[MAP_PAGES*PAGE],saved_arena[TXM_ASPACE_SIZE];
static unsigned long checks;
static unsigned published;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)

static volatile uint8_t *map(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    return pa<BASE || pa-BASE>=sizeof(bytes) || size>sizeof(bytes)-(pa-BASE) ? NULL : bytes+(pa-BASE);
}
static void publish(void *ctx,uint64_t pa,uint64_t size){(void)ctx;(void)pa;(void)size;published++;}
static struct sptm_memory m;
static const struct txm_arena arena={ARENA,0xfffffe0100008000UL};
static const struct txm_service service={.stacks_pa=STACK,.stack_count=1};
static uint8_t *meta(uint64_t pa){return bytes+((pa-BASE)/PAGE)*16;}
static uint64_t get64(uint64_t pa){uint64_t v;memcpy(&v,bytes+(pa-BASE),8);return v;}
static uint32_t get32(uint64_t pa){uint32_t v;memcpy(&v,bytes+(pa-BASE),4);return v;}

/* probes/xnuboot.c's SPTM callbacks, against this registry. */
static int share(void *ctx,uint64_t pa,uint16_t asid,uint8_t slot)
{
    (void)ctx;struct txm_share_plan plan;
    if(txm_share_prepare(&m,&arena,&registry,pa,asid,slot,&plan))return 0;
    if(!sptm_root_invalidate(&roots,pa,1))return 0;
    txm_share_commit(&m,&registry,&plan);return 1;
}
static int retire_shared(void *ctx,uint64_t pa,uint8_t slot)
{
    (void)ctx;
    for(unsigned i=0;i<registry.count;i++)
        if(registry.root[i]==pa || (registry.root[i] && registry.shared[i] && registry.asid[i]==slot))return 0;
    return sptm_root_invalidate(&roots,pa,1);
}
static int retire_user(void *ctx,uint64_t pa,uint16_t asid)
{
    (void)ctx;
    for(unsigned i=0;i<registry.count;i++)
        if(registry.root[i]==pa || (!registry.shared[i] && registry.asid[i]==asid))return 0;
    return sptm_root_invalidate(&roots,pa,1);
}
static int bind(void *ctx,uint64_t user,uint16_t asid,uint64_t parent,uint8_t slot,uint64_t start,uint64_t size)
{
    (void)ctx;
    return !txm_bind_shared(&m,&arena,&registry,user,asid,parent,slot,start,size);
}

/* The model: what XNU believes is alive. */
struct space { uint64_t root,handle; unsigned asid; int region; };
static struct space live[FRAMES];
static unsigned nlive;
static uint64_t free_frames[FRAMES];
static unsigned nfree;
static uint64_t region_root[REGIONS],region_handle[REGIONS];
static unsigned region_users[REGIONS],nregions,next_asid,leaked;
static uint64_t creates,destroys,refusals;
static uint64_t rng=0x9e3779b97f4a7c15UL;
static uint64_t next_random(void){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}

static void reset(void)
{
    memset(bytes,0,sizeof(bytes));memset(&registry,0,sizeof(registry));
    memset(&roots,0,sizeof(roots));memset(&shared_regions,0,sizeof(shared_regions));
    m=(struct sptm_memory){.frame_map_pa=BASE,.frame_low=BASE,.frame_high=BASE+TOTAL*PAGE,
        .alloc_low=ROOTS,.alloc_high=BASE+TOTAL*PAGE,.map=map,.publish=publish,
        .share_user_root=share,.retire_shared_root=retire_shared,.retire_user_root=retire_user,
        .bind_shared_root=bind,.shared_regions=&shared_regions};
    nfree=0;
    for(unsigned i=FRAMES;i-->0;) {uint64_t pa=ROOTS+i*PAGE;meta(pa)[2]=11;free_frames[nfree++]=pa;}
    nlive=nregions=leaked=0;next_asid=1;creates=destroys=refusals=0;
    memset(region_users,0,sizeof(region_users));
}
static unsigned used(void){unsigned n=0;for(unsigned i=0;i<registry.count;i++)n+=!!registry.root[i];return n;}
static void snapshot(void)
{
    memcpy(saved_meta,bytes,sizeof(saved_meta));memcpy(saved_arena,bytes+(ARENA-BASE),sizeof(saved_arena));
    saved_registry=registry;saved_regions=shared_regions;published=0;
}
static void unchanged(void)
{
    CHECK(!published);CHECK(!memcmp(saved_meta,bytes,sizeof(saved_meta)));
    CHECK(!memcmp(saved_arena,bytes+(ARENA-BASE),sizeof(saved_arena)));
    CHECK(!memcmp(&saved_registry,&registry,sizeof(registry)));
    CHECK(!memcmp(&saved_regions,&shared_regions,sizeof(shared_regions)));
}
static unsigned slot_of(uint64_t handle){return (unsigned)((handle-arena.va)/TXM_ASPACE_STRIDE);}

/* pmap_create: SPTM root (RETYPE 11->18 with its ASID), then TXM35. */
static enum sptm_result create(unsigned asid,uint64_t *root,uint64_t *handle)
{
    CHECK(nfree>0 && asid && asid<=0xffff);
    uint64_t pa=free_frames[nfree-1];
    CHECK(sptm_mac_retype(&m,pa,11,18,((uint64_t)asid<<32)|(2UL<<16))==SPTM_OK);
    uint64_t args[8]={STACK,asid};
    enum sptm_result result=txm_aspace(&m,&service,&arena,&registry,35,args);
    if(result!=SPTM_OK) {CHECK(sptm_mac_retype(&m,pa,18,11,0)==SPTM_OK);return result;}
    nfree--;*root=pa;*handle=get64(STACK+0x3c20);
    CHECK(get64(STACK+0x3c18)==1 && *handle>=arena.va && *handle<arena.va+TXM_ASPACE_SIZE &&
          !((*handle-arena.va)%TXM_ASPACE_STRIDE));
    CHECK(registry.root[slot_of(*handle)]==pa && registry.asid[slot_of(*handle)]==asid);
    return SPTM_OK;
}
static void spawn(int region)
{
    unsigned full=used()==TXM_ASPACE_LIMIT;
    struct space s={0,0,next_asid,-1};
    if(full)snapshot();
    enum sptm_result result=create(next_asid,&s.root,&s.handle);
    if(full) {
        /* F2: refused exactly at the limit, with no side effect. */
        CHECK(result==SPTM_MEMORY_UNAVAILABLE);
        CHECK(!memcmp(&saved_registry,&registry,sizeof(registry)));
        CHECK(!memcmp(saved_arena,bytes+(ARENA-BASE),sizeof(saved_arena)));
        refusals++;return;
    }
    /* F1: below the limit a create never fails. */
    if(result!=SPTM_OK)fprintf(stderr,"slot leak: TXM35 %u with %u of %u slots live\n",result,used(),TXM_ASPACE_LIMIT);
    CHECK(result==SPTM_OK);
    next_asid++;creates++;
    if(region>=0) {
        CHECK(sptm_mac_set_shared_region(&m,s.root,region_root[region])==SPTM_OK);
        s.region=region;region_users[region]++;
    }
    live[nlive++]=s;
}
/* pmap_destroy: TXM36, then the root back to XNU_DEFAULT (RETYPE 18->11). */
static void destroy(unsigned index,int leak)
{
    CHECK(index<nlive);struct space s=live[index];
    live[index]=live[--nlive];
    if(leak) {leaked++;return;}   /* F6: XNU forgets TXM36; the root stays typed. */
    if(next_random()%61==0) {
        /* F3: the root may not go back while TXM still registers it. */
        snapshot();CHECK(sptm_mac_retype(&m,s.root,18,11,0)!=SPTM_OK);unchanged();
    }
    uint64_t args[8]={STACK,s.handle};
    CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_OK);
    CHECK(!registry.root[slot_of(s.handle)] && !registry.bound_shared[slot_of(s.handle)]);
    if(next_random()%67==0) {
        snapshot();CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_BAD_ADDRESS);unchanged();
    }
    CHECK(sptm_mac_retype(&m,s.root,18,11,0)==SPTM_OK);
    CHECK(meta(s.root)[2]==11);
    if(s.region>=0)region_users[s.region]--;
    free_frames[nfree++]=s.root;destroys++;
}
static void add_region(void)
{
    CHECK(nregions<REGIONS);
    uint64_t root,handle;unsigned asid=next_asid++;
    CHECK(create(asid,&root,&handle)==SPTM_OK);creates++;
    CHECK(sptm_mac_retype(&m,root,18,19,0)==SPTM_OK);
    CHECK(meta(root)[8]==nregions && registry.shared[slot_of(handle)] && registry.asid[slot_of(handle)]==nregions);
    uint64_t args[8]={STACK,handle,START,LENGTH};
    CHECK(txm_aspace(&m,&service,&arena,&registry,37,args)==SPTM_OK);
    CHECK(sptm_mac_configure_sharedregion(&m,root,START,LENGTH/PAGE)==SPTM_OK);
    region_root[nregions]=root;region_handle[nregions]=handle;nregions++;
}
static void remove_region(unsigned r)
{
    uint64_t args[8]={STACK,region_handle[r]};
    CHECK(region_users[r]==0);
    CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_OK);
    CHECK(sptm_mac_retype(&m,region_root[r],19,11,0)==SPTM_OK);
    free_frames[nfree++]=region_root[r];region_root[r]=0;
}
/* Model and registry agree on every slot, reference and frame type. */
static void verify(void)
{
    CHECK(registry.count<=TXM_ASPACE_LIMIT);
    CHECK(used()==nlive+nregions+leaked);
    unsigned bound=0;
    for(unsigned i=0;i<nlive;i++) {
        unsigned slot=slot_of(live[i].handle);
        CHECK(registry.root[slot]==live[i].root && registry.asid[slot]==live[i].asid && !registry.shared[slot]);
        CHECK(registry.bound_shared[slot]==(live[i].region<0 ? 0 : region_root[live[i].region]));
        CHECK(meta(live[i].root)[2]==18);
        bound+=live[i].region>=0;
    }
    for(unsigned r=0;r<nregions;r++) if(region_root[r]) {
        unsigned slot=slot_of(region_handle[r]);
        CHECK(registry.root[slot]==region_root[r] && registry.shared[slot]==1 && registry.asid[slot]==r);
        CHECK(get32(ARENA+slot*TXM_ASPACE_STRIDE+0x68)==region_users[r]);
        CHECK((unsigned)(meta(region_root[r])[4]|meta(region_root[r])[5]<<8)==region_users[r]);
    }
    if(!leaked)CHECK(registry.bindings-registry.unbindings==bound);
    for(unsigned i=0;i<nfree;i++)CHECK(meta(free_frames[i])[2]==11);
}
static int pick_region(void)
{
    unsigned x=(unsigned)(next_random()%1000);
    return x<994 ? 0 : (int)(1+x%3);
}

/* F5: the v47 shape. Four shared regions; a single-user phase whose shell
 * processes all exit (ASIDs to 815, two survivors); then multi-user boot and
 * login with fork/exec pairs (the fork map dies unbound, the exec map binds)
 * until ASID 0x1551, leaving 508 address spaces, the newest still unbound. */
static void v47_replay(void)
{
    reset();
    for(unsigned r=0;r<REGIONS;r++)add_region();
    while(next_asid<=815) {
        int keep=next_asid==6 || next_asid==8;
        spawn(next_asid==6 ? -1 : 0);
        if(!keep)destroy(nlive-1,0);
        if(creates%97==0)verify();
    }
    CHECK(nlive==2 && live[0].asid==6 && live[1].asid==8 && next_asid==816);
    /* Each pair's live target grows by under one, so nlive tracks it exactly
     * and is 506 when ASID 0x1550 is next. */
    while(next_asid+2<=V47_LAST_ASID-1) {
        spawn(-1);destroy(nlive-1,0);          /* the fork map, replaced by exec */
        spawn(pick_region());
        unsigned target=2+(unsigned)((uint64_t)(next_asid-816)*504/(V47_LAST_ASID-1-816));
        while(nlive>target)destroy(2+(unsigned)(next_random()%(nlive-2)),0);
        if(creates%97==0)verify();
    }
    CHECK(next_asid==V47_LAST_ASID-1 && nlive==506);
    spawn(pick_region());                      /* ASID 0x1550 */
    spawn(-1);                                 /* ASID 0x1551: created, not yet bound */
    verify();
    CHECK(nlive==508 && nregions==4 && used()==512 && registry.count==512);
    CHECK(live[nlive-1].asid==V47_LAST_ASID && live[nlive-1].region<0);
    unsigned unbound=0;for(unsigned i=0;i<nlive;i++)unbound+=live[i].region<0;
    CHECK(unbound==2 && registry.bindings-registry.unbindings==506);
    CHECK(creates>5000 && destroys>4400);
    printf("v47 replay: %llu creates, %llu destroys, %llu bindings, %llu unbindings, 512 slots live\n",
           (unsigned long long)creates,(unsigned long long)destroys,
           (unsigned long long)registry.bindings,(unsigned long long)registry.unbindings);
    /* The request that stopped v47: SPTM has typed the root, TXM35 follows. */
    uint64_t root,handle;
    if(TXM_ASPACE_LIMIT==512) {
        uint64_t pa=free_frames[nfree-1],args[8]={STACK,V47_LAST_ASID+1};
        CHECK(sptm_mac_retype(&m,pa,11,18,((uint64_t)(V47_LAST_ASID+1)<<32)|(2UL<<16))==SPTM_OK);
        snapshot();
        CHECK(txm_aspace(&m,&service,&arena,&registry,35,args)==SPTM_MEMORY_UNAVAILABLE);
        unchanged();CHECK(used()==512);
        CHECK(sptm_mac_retype(&m,pa,18,11,0)==SPTM_OK);
        printf("narrow arena: TXM35 ASID 0x1552 refused (SPTM_MEMORY_UNAVAILABLE), state unchanged\n");
    } else {
        enum sptm_result result=create(V47_LAST_ASID+1,&root,&handle);
        CHECK(result==SPTM_OK && slot_of(handle)==512);
        live[nlive++]=(struct space){root,handle,V47_LAST_ASID+1,-1};next_asid++;creates++;
        printf("wide arena: TXM35 ASID 0x1552 admitted in slot 512\n");
    }
    verify();
}
/* F2/F7: fill to the limit, churn at it, then drain everything. */
static void fill_churn_drain(void)
{
    while(used()<TXM_ASPACE_LIMIT)spawn(pick_region());
    verify();
    CHECK(registry.count==TXM_ASPACE_LIMIT && nlive==TXM_ASPACE_LIMIT-nregions);
    uint64_t refused=refusals;spawn(0);CHECK(refusals==refused+1);
    for(unsigned n=0;n<2000;n++) {
        destroy((unsigned)(next_random()%nlive),0);
        spawn(next_random()%5 ? pick_region() : -1);
        if(n%250==0) {verify();refused=refusals;spawn(0);CHECK(refusals==refused+1);}
    }
    verify();
    unsigned high=0;for(unsigned i=0;i<nlive;i++)if(slot_of(live[i].handle)>high)high=slot_of(live[i].handle);
    CHECK(high==TXM_ASPACE_LIMIT-1);
    printf("full arena: %u slots, 2000 destroy/create pairs at the limit, %llu refusals\n",
           TXM_ASPACE_LIMIT,(unsigned long long)refusals);
    /* F4: a bound region stays. */
    uint64_t args[8]={STACK,region_handle[0]};
    snapshot();CHECK(txm_aspace(&m,&service,&arena,&registry,36,args)==SPTM_FRAME_BUSY);unchanged();
    snapshot();CHECK(sptm_mac_retype(&m,region_root[0],19,11,0)!=SPTM_OK);unchanged();
    while(nlive)destroy(nlive-1,0);
    verify();
    for(unsigned r=0;r<nregions;r++)remove_region(r);
    CHECK(used()==0 && registry.count==TXM_ASPACE_LIMIT && registry.bindings==registry.unbindings);
    for(unsigned i=0;i<TXM_ASPACE_LIMIT;i++)
        CHECK(!registry.root[i] && !registry.asid[i] && !registry.shared[i] && !registry.bound_shared[i] &&
              !registry.region_start[i] && !registry.region_end[i]);
    for(unsigned i=0;i<TXM_ASPACE_SIZE;i++)CHECK(!bytes[ARENA-BASE+i]);
    CHECK(nfree==FRAMES);
    /* Every freed slot, ASID and shared-class slot is reusable afterwards. */
    nregions=0;add_region();region_users[0]=0;
    for(unsigned n=0;n<TXM_ASPACE_LIMIT-1;n++)spawn(n%2 ? 0 : -1);
    verify();CHECK(used()==TXM_ASPACE_LIMIT);
    refused=refusals;spawn(0);CHECK(refusals==refused+1);
}
/* F6: XNU skipping TXM36 for every eighth exit shows as orphan slots and an
 * early refusal, exactly when live + leaked fills the arena. */
static void leaky_lifecycle(void)
{
    reset();add_region();
    unsigned target=TXM_ASPACE_LIMIT/4,exits=0;
    for(;;) {
        if(used()==TXM_ASPACE_LIMIT) {
            CHECK(nlive+leaked+nregions==TXM_ASPACE_LIMIT && leaked>0);
            uint64_t refused=refusals;spawn(0);CHECK(refusals==refused+1);
            break;
        }
        spawn(0);
        if(nlive>target) {destroy((unsigned)(next_random()%nlive),++exits%8==0);}
    }
    CHECK(used()==nlive+leaked+nregions);
    verify();
    unsigned orphans=0;
    for(unsigned i=0;i<registry.count;i++) if(registry.root[i] && !registry.shared[i]) {
        int known=0;for(unsigned k=0;k<nlive;k++)known|=live[k].root==registry.root[i];
        if(!known && orphans++<64) {
            snapshot();CHECK(sptm_mac_retype(&m,registry.root[i],18,11,0)!=SPTM_OK);unchanged();
        }
    }
    CHECK(orphans==leaked);
    printf("leaky lifecycle: refused with %u live + %u leaked + %u shared, %u orphan roots stay registered\n",
           nlive,leaked,nregions,orphans);
}
int main(void)
{
    printf("arena: %u pages, %u slots\n",TXM_ASPACE_PAGES,TXM_ASPACE_LIMIT);
    CHECK(TXM_ASPACE_LIMIT==(SNAP_TXM_ASPACE_WIDE ? 4096u : 512u));
    v47_replay();
    fill_churn_drain();
    leaky_lifecycle();
    printf("PASS: %lu TXM address-space churn checks\n",checks);
    return 0;
}
