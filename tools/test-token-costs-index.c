/* SPDX-License-Identifier: MIT */
/* SNAP_ROOT_INDEX (compat/root-index.h) on the real retype/TXM fixtures
 * (test-sptm-shared-root.c). tools/test-token-costs.py builds this file with
 * and without the define and requires every "step" line (each operation's
 * result and a digest of the fixture memory and TXM registry) to match:
 * seeded random lifecycles of user and shared roots -- constructors with
 * colliding ASIDs, TXM35/36/37, sharing, releases -- with frame records
 * disturbed in ways the scan must still see (lock bytes, a bad binding, an
 * unexpected byte), so that every TXM error precedence is exercised. Lines
 * starting with '#' are the indexed build's own checks. */
#define main shared_root_main
#include "test-sptm-shared-root.c"
#undef main
#include "root-index.h"
#if SNAP_ROOT_INDEX
static struct sptm_root_index idx;
#endif
static uint64_t rng;
static uint64_t rnd(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
static uint64_t digest(void)
{
    uint64_t h=UINT64_C(0xcbf29ce484222325);
    for(size_t i=0;i<sizeof(bytes);i+=8) {uint64_t w;memcpy(&w,bytes+i,8);h=(h^w)*UINT64_C(0x100000001b3);}
    const uint8_t *r=(const uint8_t *)&registry;
    for(size_t i=0;i<sizeof(registry);i++)h=(h^r[i])*UINT64_C(0x100000001b3);
    const uint8_t *s=(const uint8_t *)&shared_regions;
    for(size_t i=0;i<sizeof(shared_regions);i++)h=(h^s[i])*UINT64_C(0x100000001b3);
    return h;
}
static unsigned steps;
static void step(const char *what,uint64_t a,int r)
{printf("step %u %s %llx r=%d digest=%016llx\n",steps++,what,(unsigned long long)a,r,(unsigned long long)digest());}
#define FRAMES 200u
static uint64_t frame_at(unsigned i) {return ROOT+(uint64_t)i*PAGE;}
static int find_slot(uint64_t pa)
{
    for(unsigned i=0;i<registry.count;i++)if(registry.root[i]==pa)return (int)i;
    return -1;
}
static uint64_t pick(unsigned type)
{
    for(unsigned tries=0;tries<64;tries++) {
        uint64_t pa=frame_at((unsigned)(rnd()%FRAMES));
        if(meta(pa)[2]==type)return pa;
    }
    return 0;
}
static void scenario(unsigned seed)
{
    rng=seed*UINT64_C(0x9e3779b97f4a7c15)+3;
    reset();
#if SNAP_ROOT_INDEX
    /* Odd seeds start without the index and build it from a populated map
     * at op 100 (R1). */
    memset(&idx,0,sizeof(idx));m.root_index=seed&1 ? 0 : &idx;
#endif
    uint64_t disturbed=0;uint8_t saved_byte=0;unsigned saved_at=0;
    for(unsigned op=0;op<300;op++) {
#if SNAP_ROOT_INDEX
        if(op==100)m.root_index=&idx;
#endif
        unsigned k=(unsigned)(rnd()%100);
        uint64_t stacks=service.stacks_pa;
        if(k<35) {                                         /* constructor, then TXM35 */
            uint64_t pa=pick(11);if(!pa)continue;
            unsigned asid=1+(unsigned)(rnd()%24),fmt=(unsigned)(rnd()%2),flags=rnd()%2 ? 2 : 0x22;
            int r=sptm_mac_retype(&m,pa,11,18,((uint64_t)asid<<32)|((uint64_t)flags<<16)|fmt);
            step("construct",pa,r);
            uint64_t args[8]={stacks,asid};
            if(rnd()%8)step("txm35",pa,txm_aspace(&m,&service,&arena,&registry,35,args));
        } else if(k<55) {                                  /* TXM36, then release */
            uint64_t pa=pick(18);if(!pa)continue;
            int s=find_slot(pa);
            if(s>=0) {
                uint64_t args[8]={stacks,arena.va+(uint64_t)s*256};
                step("txm36",pa,txm_aspace(&m,&service,&arena,&registry,36,args));
            }
            step("release",pa,sptm_mac_retype(&m,pa,18,11,0));
        } else if(k<65) {                                  /* share a user root */
            uint64_t pa=pick(18);if(!pa)continue;
            step("share",pa,sptm_mac_retype(&m,pa,18,19,(unsigned)(rnd()%2)));
        } else if(k<72) {                                  /* TXM37 on a shared root */
            uint64_t pa=pick(19);if(!pa)continue;
            int s=find_slot(pa);if(s<0)continue;
            uint64_t args[8]={stacks,arena.va+(uint64_t)s*256,0x180000000UL,0x40000000UL};
            step("txm37",pa,txm_aspace(&m,&service,&arena,&registry,37,args));
        } else if(k<80) {                                  /* unregister and release a shared root */
            uint64_t pa=pick(19);if(!pa)continue;
            int s=find_slot(pa);
            if(s>=0) {
                uint64_t args[8]={stacks,arena.va+(uint64_t)s*256};
                step("txm36s",pa,txm_aspace(&m,&service,&arena,&registry,36,args));
            }
            step("release-shared",pa,sptm_mac_retype(&m,pa,19,11,0));
        } else if(k<90) {                                  /* TXM36/35 on random slots */
            unsigned s=(unsigned)(rnd()%(registry.count+1));
            uint64_t args[8]={stacks,rnd()%3 ? arena.va+(uint64_t)s*256 : 1+(unsigned)(rnd()%24)};
            unsigned sel=args[1]<arena.va ? 35 : 36;
            step(sel==35 ? "txm35-any" : "txm36-any",s,txm_aspace(&m,&service,&arena,&registry,sel,args));
        } else {                                           /* disturb or restore one record byte */
            if(disturbed) {
                meta(disturbed)[saved_at]=saved_byte;disturbed=0;step("restore",0,0);
            } else {
                uint64_t pa=pick(rnd()%2 ? 18 : 19);if(!pa)continue;
                static const unsigned at[]={0,1,9,11,13,6};
                saved_at=at[rnd()%6];saved_byte=meta(pa)[saved_at];
                meta(pa)[saved_at]^=1;disturbed=pa;step("disturb",pa,(int)saved_at);
            }
        }
    }
#if SNAP_ROOT_INDEX
    /* R1/R2: the index holds exactly the map's root records. */
    unsigned roots=0;
    for(uint64_t pa=BASE;pa<m.frame_high;pa+=PAGE)roots+=sptm_root_index_key(meta(pa))!=0;
    if(idx.stats.built)CHECK(idx.stats.live==roots);
    CHECK(!idx.stats.mismatches && idx.stats.lookups+idx.stats.audits>0);
#endif
}
#if SNAP_ROOT_INDEX
/* R5: a table too small for the roots is refused and every lookup scans. */
static void capacity(void)
{
    reset();memset(&idx,0,sizeof(idx));m.root_index=&idx;
    for(unsigned i=0;i<SPTM_ROOT_INDEX_SLOTS/2+4 && i<FRAMES;i++)
        CHECK(!sptm_mac_retype(&m,frame_at(i),11,18,((uint64_t)(i+1)<<32)|(2u<<16)));
    uint64_t args[8]={service.stacks_pa,7};
    (void)txm_aspace(&m,&service,&arena,&registry,35,args);
    printf("# capacity: built=%llu full=%llu scans=%llu\n",(unsigned long long)idx.stats.built,
           (unsigned long long)idx.stats.full,(unsigned long long)idx.stats.scans);
}
/* R6: a key written behind the index (not through sptm_mac_retype) is
 * found by the audit when every lookup is audited: the scan's answer is used
 * and the index is dropped. */
static void audit(void)
{
    reset();memset(&idx,0,sizeof(idx));m.root_index=&idx;
    create(ROOT,9,0,2);
    meta(ROOT+PAGE)[2]=18;meta(ROOT+PAGE)[4]=5;          /* behind the index */
    uint64_t before=idx.stats.mismatches;
    int r=sptm_mac_retype(&m,ROOT+2*PAGE,11,18,((uint64_t)5<<32)|(2u<<16));
    if(SPTM_ROOT_INDEX_AUDIT==0)
        CHECK(r==SPTM_FRAME_BUSY && idx.stats.mismatches==before+1 && !idx.stats.built);
    printf("# audit: mismatches=%llu audits=%llu\n",(unsigned long long)idx.stats.mismatches,
           (unsigned long long)idx.stats.audits);
}
#endif
#if SNAP_ROOT_INDEX
/* Out-of-contract states (keys changed behind the index) that only add
 * stale entries, or duplicate keys the index knows: the indexed answer must
 * equal the scan's, because callers re-read every listed record, visit them
 * in address order and keep the scan's range (R2, R3, R4). */
static uint8_t probe_bytes[sizeof(bytes)];
static struct txm_registry probe_registry;
static struct sptm_shared_registry probe_regions;
static struct sptm_root_index probe_idx;
static int probe_txm(unsigned selector,uint64_t a1)
{uint64_t args[8]={service.stacks_pa,a1};return txm_aspace(&m,&service,&arena,&registry,selector,args);}
static int probe_construct(uint64_t pa,unsigned asid)
{return sptm_mac_retype(&m,pa,11,18,((uint64_t)asid<<32)|(2u<<16));}
/* op with the scan, then the same op from the same state with the index. */
static void probe(const char *what,int (*op)(uint64_t,unsigned),uint64_t a,unsigned b)
{
    memcpy(probe_bytes,bytes,sizeof(bytes));probe_registry=registry;probe_regions=shared_regions;probe_idx=idx;
    m.root_index=0;int scan=op(a,b);
    memcpy(bytes,probe_bytes,sizeof(bytes));registry=probe_registry;shared_regions=probe_regions;idx=probe_idx;
    m.root_index=&idx;int indexed=op(a,b);
    printf("# probe %s: scan %d, index %d\n",what,scan,indexed);
    CHECK(scan==indexed);
}
static int op_txm36_slot(uint64_t slot,unsigned unused) {(void)unused;return probe_txm(36,arena.va+slot*256);}
static int op_txm35(uint64_t asid,unsigned unused) {(void)unused;return probe_txm(35,asid);}
static int op_construct(uint64_t pa,unsigned asid) {return probe_construct(pa,asid);}
static void contract_probes(void)
{
    /* R2: a user root's ASID changed behind the index (5 -> 6). */
    reset();memset(&idx,0,sizeof(idx));m.root_index=&idx;
    create(ROOT,5,0,2);meta(ROOT)[4]=6;
    probe("stale ASID, constructor",op_construct,ROOT+PAGE,5);
    probe("stale ASID, TXM35",op_txm35,5,0);
    /* R2: a shared root's type changed behind the index. */
    reset();memset(&idx,0,sizeof(idx));m.root_index=&idx;
    create(ROOT,9,0,2);CHECK(!sptm_mac_retype(&m,ROOT,18,19,0));meta(ROOT)[2]=11;
    probe("stale shared root, TXM36",op_txm36_slot,0,0);
    /* R3: two records with one key, both indexed; one disturbed. The scan
     * visits the lower address first. */
    for(unsigned which=0;which<2;which++) {
        reset();memset(&idx,0,sizeof(idx));m.root_index=&idx;
        /* The higher address holds the key first, so hash order is not
         * address order. */
        create(ROOT+PAGE,7,0,2);create(ROOT,8,0,2);
        meta(ROOT)[4]=7;sptm_root_index_insert(&idx,ROOT,SPTM_ROOT_KEY_USER(7));
        meta(which ? ROOT+PAGE : ROOT)[0]=1;
        probe(which ? "duplicate key, higher disturbed" : "duplicate key, lower disturbed",op_txm36_slot,0,0);
    }
    /* R4: a root outside TXM's range (alloc_high lowered past it), and a
     * root record on a frame the walk never visits (below alloc_low). */
    reset();memset(&idx,0,sizeof(idx));m.root_index=&idx;
    create(ROOT,3,0,2);create(ROOT+40*PAGE,4,0,2);
    m.alloc_high=ROOT+20*PAGE;
    probe("root above alloc_high, TXM36",op_txm36_slot,1,0);
    probe("root above alloc_high, TXM35",op_txm35,4,0);
    reset();memset(&idx,0,sizeof(idx));m.root_index=&idx;
    create(ROOT,3,0,2);
    meta(BASE+PAGE)[2]=18;meta(BASE+PAGE)[4]=4;meta(BASE+PAGE)[8]=0xff;meta(BASE+PAGE)[10]=2;
    sptm_root_index_insert(&idx,BASE+PAGE,SPTM_ROOT_KEY_USER(4));
    probe("root below alloc_low, TXM35",op_txm35,4,0);
}
#endif
int main(void)
{
    for(unsigned seed=1;seed<=40;seed++)scenario(seed);
#if SNAP_ROOT_INDEX
    printf("# index: lookups=%llu scans=%llu audits=%llu notes=%llu builds=%llu live=%llu\n",
           (unsigned long long)idx.stats.lookups,(unsigned long long)idx.stats.scans,
           (unsigned long long)idx.stats.audits,(unsigned long long)idx.stats.notes,
           (unsigned long long)idx.stats.builds,(unsigned long long)idx.stats.live);
    capacity();
    audit();
    contract_probes();
#endif
    printf("PASS: %u checks, %u steps\n",checks,steps);
    return 0;
}
