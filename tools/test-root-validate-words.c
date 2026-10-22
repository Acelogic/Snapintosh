/* SPDX-License-Identifier: MIT */
/* SNAP_ROOT_VALIDATE_WORDS: SWITCH_ROOT validation with aligned 64-bit
 * descriptor loads. Build with -DSPTM_ROOT_VALIDATE_SAMPLE=0 so that EVERY
 * word-load validation is also re-walked with the original byte loads.
 * 1) The complete root-switching suite passes unchanged on the word path.
 * 2) For thousands of single-descriptor corruptions of every table level the
 *    word path returns the same result and leaves byte-identical guest RAM,
 *    host shadow memory and root state as the byte path.
 * 3) A descriptor that changes between the two walks is reported (terminal,
 *    counted) instead of being accepted by either walk alone.
 * 4) The suite again with retained level-3 verdicts (SNAP_ROOT_VALIDATE_MEMO):
 *    every memo-assisted validation agrees with the memo-free byte walk. */
#define SPTM_ROOT_SUITE root_switch_suite
#include "test-sptm-root.c"
#include "sptm-root-memo.h"
int root_switch_suite(void);
#if SPTM_ROOT_VALIDATE_SAMPLE!=0
#error "build with -DSPTM_ROOT_VALIDATE_SAMPLE=0"
#endif
static struct sptm_root_validate_stats vstats;
static struct sptm_root_memo memo;
static void memo_witness(void *ctx,uint64_t pa,uint64_t n)
{sptm_root_memo_publish(&memo,FM,BASE,BASE+SIZE,map,ctx,pa,n);}
static uint64_t flip_at,flip_pa,flip_value;
static int flipped;
static volatile uint8_t *flipping_map(void *ctx,uint64_t pa,uint64_t n)
{
    /* validations is incremented between the word walk and the byte walk. */
    if(!flipped && flip_at && vstats.validations==flip_at) {
        put(flip_pa,flip_value,8);flipped=1;
    }
    return map(ctx,pa,n);
}
static uint8_t ram_a[SIZE],host_a[sizeof host];
static struct sptm_root_state state_a;
static uint64_t random_state=UINT64_C(0xa54ff53a5f1d36f1);
static unsigned rnd(unsigned n)
{
    random_state^=random_state<<13;random_state^=random_state>>7;random_state^=random_state<<17;
    return (unsigned)(random_state%n);
}
int main(void)
{
    /* 1: the unchanged suite, first on the byte path, then on the word path
     * with every validation differentially re-walked. */
    root_backend.validate=0;
    unsigned base_failures=failures;root_switch_suite();
    root_backend.validate=&vstats;root_switch_suite();
    check(failures==base_failures,"root switching suite passes on the word path");
    check(vstats.validations>100 && vstats.sampled==vstats.validations && !vstats.mismatches,
          "every word-load validation matched the byte-load walk");

    /* 2: differential corruption sweep over root/L2/L3 (both formats). */
    unsigned compared=0,accepted=0,refused=0;
    for(unsigned round=0;round<3000;round++) {
        unsigned format=rnd(2);reset_host();
        struct sptm_memory m=reset_geometry(31,2,VA,format);uint64_t result;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,
              "fixture mapping");
        /* Corrupt one descriptor (or none) anywhere in the owned tables. */
        if(rnd(8)) {
            const uint64_t tables[]={ROOT,L2,L3,L1};
            uint64_t table=tables[rnd(format ? 4 : 3)],pa=table+8UL*rnd(2048);
            uint64_t v=get(pa,8);
            switch(rnd(6)) {
            case 0:v^=1UL<<rnd(64);break;
            case 1:v=0;break;
            case 2:v=get(table+8UL*rnd(2048),8);break;
            case 3:v=(v&~3UL)|rnd(4);break;
            case 4:v^=UINT64_C(0xff)<<(8*rnd(8));break;
            default:v=DATA|RX;break;
            }
            put(pa,v,8);
        }
        memcpy(ram_a,ram,SIZE);memcpy(host_a,host,sizeof host);
        uint64_t next_a=next_host;
        struct sptm_root_state s={0};unsigned cpu=rnd(6);
        root_backend.validate=0;current_cpu=cpu;
        enum sptm_result byte_result=sptm_mac_switch_root(&m,&s,&root_backend,cpu,ROOT,0,0);
        state_a=s;
        uint8_t ram_b[SIZE];memcpy(ram_b,ram,SIZE);
        static uint8_t host_b[sizeof host];memcpy(host_b,host,sizeof host);
        memcpy(ram,ram_a,SIZE);memcpy(host,host_a,sizeof host);next_host=next_a;
        struct sptm_root_state t={0};uint64_t sampled=vstats.sampled;
        root_backend.validate=&vstats;current_cpu=cpu;
        enum sptm_result word_result=sptm_mac_switch_root(&m,&t,&root_backend,cpu,ROOT,0,0);
        check(word_result==byte_result,"word and byte validation return the same result");
        check(!memcmp(ram,ram_b,SIZE) && !memcmp(host,host_b,sizeof host) &&
              !memcmp(&t,&state_a,sizeof t),"identical guest RAM, shadow and root state");
        check(vstats.sampled==sampled+1 && !vstats.mismatches,"differential walk ran and agreed");
        compared++;if(word_result==SPTM_OK)accepted++;else refused++;
    }
    check(accepted>200 && refused>200,"sweep exercised both acceptance and refusal");

    /* 3: a descriptor changing between the walks is terminal and counted. */
    for(unsigned format=0;format<2;format++) {
        reset_host();struct sptm_memory m=reset_geometry(31,2,VA,format);uint64_t result;
        check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,
              "fixture mapping");
        uint64_t leaf=0;
        for(unsigned i=0;i<2048 && !leaf;i++)if(get(L3+8UL*i,8))leaf=L3+8UL*i;
        check(leaf!=0,"fixture leaf located");
        uint64_t old=get(leaf,8);
        m.map=flipping_map;flip_pa=leaf;flip_value=(old&~3UL)|1;flipped=0;
        flip_at=vstats.validations+1;
        struct sptm_root_state s={0};uint64_t mismatches=vstats.mismatches;
        root_backend.validate=&vstats;current_cpu=0;
        enum sptm_result r=sptm_mac_switch_root(&m,&s,&root_backend,0,ROOT,0,0);
        check(flipped && r==SPTM_BAD_TABLE && vstats.mismatches==mismatches+1,
              "a descriptor changing between walks is reported");
        check(!installs && !s.active[0] && !s.switches,"nothing installed after a mismatch");
        put(leaf,old,8);flip_at=0;vstats.mismatches=0;
    }
    /* 4: the unchanged suite with retained level-3 verdicts (SNAP_ROOT_VALIDATE_MEMO)
     * fed by the fixture's publish callback and retype hook: every cache-hit
     * validation uses the memo and, sampled every time here, is re-walked
     * without it. No disagreement and no change in any suite result. */
    base_failures=failures;
    publish_observer=memo_witness;fixture_root_memo=&memo;
    root_backend.validate=&vstats;root_backend.memo=&memo;
    root_switch_suite();
    check(failures==base_failures,"root switching suite passes with retained verdicts");
    check(memo.stats.calls>100 && memo.stats.hits>100 && memo.stats.sampled==memo.stats.calls &&
          !memo.stats.mismatches && !vstats.mismatches,
          "every memo-assisted validation matched the memo-free reference walk");
    publish_observer=0;fixture_root_memo=0;root_backend.memo=0;
    root_backend.validate=0;
    printf("Word-load root validation: %u compared, %u accepted, %u refused; "
           "%llu validations, %llu sampled; memo %llu assisted, %llu hits, %llu misses; "
           "%u checks, %u failures\n",
           compared,accepted,refused,(unsigned long long)vstats.validations,
           (unsigned long long)vstats.sampled,(unsigned long long)memo.stats.calls,
           (unsigned long long)memo.stats.hits,(unsigned long long)memo.stats.misses,checks,failures);
    return failures ? 1 : 0;
}
