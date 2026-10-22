/* SPDX-License-Identifier: MIT */
/* SNAP_AES_BITSLICE (compat/aes-bitslice.h, docs/AES-BITSLICE-20261019.md):
 * the bitsliced cipher against FIPS-197 and aes_block, and the PAC key
 * derivation with it against the derivation without it.
 *
 * Failure inventory this covers, each as checks with the expected result:
 *   - a wrong cipher: FIPS-197 appendix C for AES-128/192/256; the S-box
 *     circuit for all 256 values in all 16 byte positions against the S-box
 *     computed here from its definition (GF(2^8) inverse, then the affine
 *     map); ShiftRows and MixColumns against byte-level transcriptions on
 *     random states; the plane packing round trip; random keys of all three
 *     sizes and random blocks against aes_block(..., 0);
 *   - a changed refusal: no key, input or output; rounds other than
 *     10/12/14; an output overlapping the key. Each must return 0 exactly
 *     when aes_block does, and leave the output untouched;
 *   - a changed derivation: compat/pauth-domain.c built with the define
 *     (linked as itself) and without it (linked with ref_ names) must derive
 *     the same keys for random seeds and user states, through
 *     pauth_domain_user_with and through pauth_domain_user_cached with the
 *     same hits and misses; where this host has the AES instructions, the
 *     hardware path agrees too;
 *   - no speedup: with --speed (built without sanitizers), a derivation
 *     with the define must take at most a tenth of the time without it.
 * tools/test-aes-bitslice.py builds this, requires weakened headers to fail
 * it and checks the sources and the monitor builds.
 *
 * cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
 *    -fno-sanitize-recover=all -Icompat -c compat/pauth-domain.c -o ref.o \
 *    -Dpauth_domain_init=ref_pauth_domain_init -Dpauth_domain_user=ref_pauth_domain_user \
 *    -Dpauth_domain_user_with=ref_pauth_domain_user_with \
 *    -Dpauth_domain_user_cached=ref_pauth_domain_user_cached \
 *    -Dpauth_root_enables=ref_pauth_root_enables
 * cc ... -DSNAP_AES_BITSLICE=1 -Icompat tools/test-aes-bitslice.c compat/pauth-domain.c \
 *    compat/aes.c ref.o -o build/test-aes-bitslice && build/test-aes-bitslice */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#include "aes-bitslice.h"
#include "pauth-domain.h"

int ref_pauth_domain_init(struct pauth_domain *,const uint8_t seed[32]);
int ref_pauth_domain_user_with(const struct pauth_domain *,const struct pauth_user_state *,
                               struct pauth_key_pair output[PAUTH_KEYS],int hardware);
int ref_pauth_domain_user_cached(const struct pauth_domain *,const struct pauth_user_state *,
                                 struct pauth_derive_cache *,struct pauth_key_pair output[PAUTH_KEYS],int hardware);

static unsigned long checks,failures;
#define CHECK(cond,...) do { checks++; if(!(cond)) { failures++; \
    if(failures<20) { printf("FAIL %s:%d: ",__FILE__,__LINE__); printf(__VA_ARGS__); printf("\n"); } } } while(0)

static uint64_t rng=0x9e3779b97f4a7c15u;
static uint64_t next(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
static void fill(void *p,size_t n) {uint8_t *b=p;for(size_t i=0;i<n;i++)b[i]=(uint8_t)next();}

/* The S-box from its definition, independent of compat/aes.c. */
static uint8_t gmul(uint8_t a,uint8_t b)
{
    uint8_t v=0;
    while(b) {if(b&1)v^=a;a=(uint8_t)((a<<1)^((a&0x80)?0x1b:0));b>>=1;}
    return v;
}
static uint8_t sbox_ref(uint8_t x)
{
    uint8_t inv=0;
    for(unsigned c=1;c<256 && x;c++)if(gmul(x,(uint8_t)c)==1) {inv=(uint8_t)c;break;}
    uint8_t s=0x63;
    for(unsigned i=0;i<8;i++) {
        unsigned bit=((inv>>i)^(inv>>((i+4)&7))^(inv>>((i+5)&7))^(inv>>((i+6)&7))^(inv>>((i+7)&7)))&1;
        s^=(uint8_t)(bit<<i);
    }
    return s;
}
static void shift_rows_ref(uint8_t s[16])
{
    uint8_t t[16];
    for(unsigned c=0;c<4;c++)for(unsigned r=0;r<4;r++)t[4*c+r]=s[4*((c+r)&3)+r];
    memcpy(s,t,16);
}
static void mix_columns_ref(uint8_t s[16])
{
    for(unsigned c=0;c<4;c++) {
        uint8_t *a=s+4*c,b[4];
        for(unsigned r=0;r<4;r++)
            b[r]=(uint8_t)(gmul(a[r],2)^gmul(a[(r+1)&3],3)^a[(r+2)&3]^a[(r+3)&3]);
        memcpy(a,b,4);
    }
}
static int hex(uint8_t *out,const char *text,size_t n)
{
    for(size_t i=0;i<n;i++) {unsigned v;if(sscanf(text+2*i,"%2x",&v)!=1)return 0;out[i]=(uint8_t)v;}
    return 1;
}

static void known_answers(void)
{
    static const struct {size_t size;const char *ct;} kat[]={
        {16,"69c4e0d86a7b0430d8cdb78070b4c55a"},
        {24,"dda97ca4864cdfe06eaf70a0ec0d7191"},
        {32,"8ea2b7ca516745bfeafc49904b496089"}};
    uint8_t key[32],pt[16],ct[16],out[16];
    for(unsigned i=0;i<32;i++)key[i]=(uint8_t)i;
    hex(pt,"00112233445566778899aabbccddeeff",16);
    for(unsigned n=0;n<3;n++) {
        struct aes_key k;hex(ct,kat[n].ct,16);
        CHECK(aes_expand(&k,key,kat[n].size),"expand %zu",kat[n].size);
        memset(out,0,16);
        CHECK(aes_encrypt_bitsliced(&k,pt,out)==1 && !memcmp(out,ct,16),"FIPS-197 C.%u bitsliced",n+1);
        memset(out,0,16);
        CHECK(aes_block(&k,pt,out,0)==1 && !memcmp(out,ct,16),"FIPS-197 C.%u aes_block",n+1);
    }
}

static void steps(void)
{
    /* The S-box for every value in every byte position. */
    for(unsigned v=0;v<256;v++) {
        uint8_t in[16],out[16];uint32_t q[8];
        for(unsigned j=0;j<16;j++)in[j]=(uint8_t)(v+j*17);
        aes_bs_pack(q,in);aes_bs_sbox(q);
        for(unsigned b=0;b<8;b++)CHECK(q[b]<=0xffff,"plane %u carries bits above 16",b);
        aes_bs_unpack(out,q);
        for(unsigned j=0;j<16;j++)
            CHECK(out[j]==sbox_ref(in[j]),"S(%02x) at %u: %02x, not %02x",in[j],j,out[j],sbox_ref(in[j]));
    }
    for(unsigned t=0;t<2000;t++) {
        uint8_t s[16],a[16],out[16];uint32_t q[8];
        fill(s,16);
        aes_bs_pack(q,s);aes_bs_unpack(out,q);
        CHECK(!memcmp(out,s,16),"pack round trip");
        memcpy(a,s,16);shift_rows_ref(a);
        aes_bs_pack(q,s);aes_bs_shift_rows(q);aes_bs_unpack(out,q);
        CHECK(!memcmp(out,a,16),"ShiftRows");
        memcpy(a,s,16);mix_columns_ref(a);
        aes_bs_pack(q,s);aes_bs_mix_columns(q);aes_bs_unpack(out,q);
        CHECK(!memcmp(out,a,16),"MixColumns");
    }
}

static void differential(unsigned blocks)
{
    static const size_t sizes[3]={16,24,32};
    for(unsigned t=0;t<blocks;t++) {
        uint8_t key[32],in[16],a[16],b[16];struct aes_key k;
        fill(key,32);fill(in,16);
        aes_expand(&k,key,sizes[t%3]);
        CHECK(aes_block(&k,in,a,0)==1 && aes_encrypt_bitsliced(&k,in,b)==1 && !memcmp(a,b,16),
              "block %u (AES-%zu) differs",t,sizes[t%3]*8);
    }
}

static void refusals(void)
{
    uint8_t key[32],in[16],a[16],b[16];
    struct {struct aes_key k;uint8_t tail[16];} box;
    fill(key,32);fill(in,16);aes_expand(&box.k,key,32);
    const unsigned rounds[]={0,9,10,11,12,13,14,15,0xffffffffu};
    for(unsigned n=0;n<sizeof(rounds)/sizeof(rounds[0]);n++) {
        struct aes_key k=box.k;k.rounds=rounds[n];
        memset(a,0xa5,16);memset(b,0xa5,16);
        int ra=aes_block(&k,in,a,0),rb=aes_encrypt_bitsliced(&k,in,b);
        CHECK(ra==rb,"rounds %u: aes_block %d, bitsliced %d",rounds[n],ra,rb);
        if(!rb) {uint8_t u[16];memset(u,0xa5,16);CHECK(!memcmp(b,u,16),"rounds %u: refused but written",rounds[n]);}
    }
    CHECK(!aes_encrypt_bitsliced(0,in,b) && !aes_encrypt_bitsliced(&box.k,0,b) &&
          !aes_encrypt_bitsliced(&box.k,in,0),"null arguments accepted");
    /* An output inside or touching the key is refused, as aes_block refuses it. */
    uint8_t *base=(uint8_t *)&box.k;
    for(size_t off=0;off+16<=sizeof(box);off+=8) {
        uint8_t saved[sizeof(box)];memcpy(saved,&box,sizeof(box));
        int rb=aes_encrypt_bitsliced(&box.k,in,base+off);
        int unchanged=!memcmp(saved,&box,sizeof(box));
        memcpy(&box,saved,sizeof(box));
        int ra=aes_block(&box.k,in,base+off,0);
        memcpy(&box,saved,sizeof(box));
        CHECK(ra==rb && (rb || unchanged),"output at key+%zu: aes_block %d, bitsliced %d",off,ra,rb);
    }
}

static int host_aes(void)
{
#if defined(__APPLE__) && defined(__aarch64__)
    int v=0;size_t n=sizeof(v);
    return !sysctlbyname("hw.optional.arm.FEAT_AES",&v,&n,0,0) && v;
#else
    return 0;
#endif
}

static void random_state(struct pauth_user_state *s)
{
    memset(s,0,sizeof(*s));
    for(unsigned k=0;k<PAUTH_KEYS;k++) {s->key[k].lo=next();s->key[k].hi=next();}
    s->extra.lo=next();s->extra.hi=next();s->apctl=0x11;
}

static void derivation(unsigned seeds,unsigned states)
{
    int hardware=host_aes();
    for(unsigned n=0;n<seeds;n++) {
        uint8_t seed[32];fill(seed,32);
        struct pauth_domain d,r;
        CHECK(pauth_domain_init(&d,seed) && ref_pauth_domain_init(&r,seed),"domain init");
        struct pauth_derive_cache cd,cr;memset(&cd,0,sizeof(cd));memset(&cr,0,sizeof(cr));
        struct pauth_user_state pool[12];
        for(unsigned i=0;i<12;i++)random_state(&pool[i]);
        for(unsigned t=0;t<states;t++) {
            struct pauth_user_state s=pool[next()%12];
            if(t%7==3)random_state(&s);
            struct pauth_key_pair a[PAUTH_KEYS],b[PAUTH_KEYS],h[PAUTH_KEYS],ca[PAUTH_KEYS],cb[PAUTH_KEYS];
            int ra=pauth_domain_user_with(&d,&s,a,0),rb=ref_pauth_domain_user_with(&r,&s,b,0);
            CHECK(ra==1 && rb==1 && !memcmp(a,b,sizeof(a)),"seed %u state %u: derived keys differ",n,t);
            if(hardware) {
                CHECK(pauth_domain_user_with(&d,&s,h,1)==1 && !memcmp(a,h,sizeof(a)),
                      "seed %u state %u: hardware path differs",n,t);
            }
            ra=pauth_domain_user_cached(&d,&s,&cd,ca,0);rb=ref_pauth_domain_user_cached(&r,&s,&cr,cb,0);
            CHECK(ra==1 && rb==1 && !memcmp(ca,cb,sizeof(ca)) && !memcmp(ca,a,sizeof(ca)),
                  "seed %u state %u: cached keys differ",n,t);
        }
        CHECK(cd.hits==cr.hits && cd.misses==cr.misses && cd.next==cr.next,
              "seed %u: cache %llu/%llu hits/misses, reference %llu/%llu",n,
              (unsigned long long)cd.hits,(unsigned long long)cd.misses,
              (unsigned long long)cr.hits,(unsigned long long)cr.misses);
        /* Refusals are the derivation's own and unchanged. */
        struct pauth_user_state bad;random_state(&bad);bad.apctl=0x10;
        struct pauth_key_pair o[PAUTH_KEYS];
        CHECK(!pauth_domain_user_with(&d,&bad,o,0) && !ref_pauth_domain_user_with(&r,&bad,o,0),"apctl refusal");
        CHECK(!pauth_domain_user_with(&d,&pool[0],o,2) && !ref_pauth_domain_user_with(&r,&pool[0],o,2),
              "hardware selector refusal");
    }
    printf("derivation: %u seeds x %u states%s\n",seeds,states,hardware ? ", hardware path compared" : "");
}

static double now(void)
{
    struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (double)t.tv_sec+(double)t.tv_nsec*1e-9;
}
static int speed(void)
{
    uint8_t seed[32];fill(seed,32);
    struct pauth_domain d,r;pauth_domain_init(&d,seed);ref_pauth_domain_init(&r,seed);
    struct pauth_user_state s;random_state(&s);
    struct pauth_key_pair o[PAUTH_KEYS];
    double best_new=1e9,best_ref=1e9;
    for(unsigned rep=0;rep<5;rep++) {
        double t0=now();
        for(unsigned i=0;i<200;i++) {s.key[0].lo++;ref_pauth_domain_user_with(&r,&s,o,0);}
        double t1=now();
        for(unsigned i=0;i<200;i++) {s.key[0].lo++;pauth_domain_user_with(&d,&s,o,0);}
        double t2=now();
        if((t1-t0)/200<best_ref)best_ref=(t1-t0)/200;
        if((t2-t1)/200<best_new)best_new=(t2-t1)/200;
    }
    printf("speed: derivation %.2f us without the define, %.2f us with it (%.1fx)\n",
           best_ref*1e6,best_new*1e6,best_ref/best_new);
    CHECK(best_new*10<=best_ref,"the bitsliced derivation is not 10x faster");
    return failures!=0;
}

int main(int argc,char **argv)
{
    if(argc>1 && !strcmp(argv[1],"--speed"))return speed();
    known_answers();
    steps();
    differential(argc>1 ? (unsigned)strtoul(argv[1],0,0) : 30000);
    refusals();
    derivation(24,400);
    if(failures) {printf("FAIL: %lu of %lu checks\n",failures,checks);return 1;}
    printf("PASS: %lu checks\n",checks);
    return 0;
}
