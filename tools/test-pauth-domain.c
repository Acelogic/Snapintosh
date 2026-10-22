/* SPDX-License-Identifier: MIT */
#include "../compat/pauth-domain.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do {assert(x);checks++;} while(0)
int main(int argc,char **argv)
{
    uint8_t seed[32];for(unsigned i=0;i<32;i++)seed[i]=(uint8_t)i;
    struct pauth_domain d={0};struct pauth_user_state s;
    struct pauth_key_pair a[5],b[5];pauth_user_init(&s);
    const struct pauth_key_pair expected[5]={
        {0xa340e85be81a413aUL,0x0d56a703fa5b3562UL},
        {0x4f876d7e22d60071UL,0x0734ec04aee2992eUL},
        {0x4c9b56c0eb5681a4UL,0xdc1190cee9f39beaUL},
        {0x4869b806682a02c3UL,0xa80b3a992c928b4aUL},
        {0x2a1908770b3821d2UL,0xaad998f1cb884ebcUL}};
    CHECK(!pauth_domain_user(&d,&s,a));CHECK(pauth_domain_init(&d,seed));
    CHECK(pauth_domain_user(&d,&s,a));CHECK(!memcmp(a,expected,sizeof(a)));
    {
        /* Derivation memo: every hit equals a direct derivation; any input
         * change (each key word, EXTRA, APCTL) misses; LRU-free eviction. */
        struct pauth_derive_cache cache;memset(&cache,0,sizeof(cache));
        struct pauth_domain none={0};
        CHECK(!pauth_domain_user_cached(&none,&s,&cache,b,0) && !cache.hits);
        CHECK(pauth_domain_user_cached(&d,&s,&cache,b,0));CHECK(!memcmp(b,expected,sizeof(b)));
        CHECK(cache.misses==1 && !cache.hits);
        CHECK(pauth_domain_user_cached(&d,&s,&cache,b,0));CHECK(!memcmp(b,expected,sizeof(b)));
        CHECK(cache.misses==1 && cache.hits==1);
        for(unsigned field=0;field<12;field++) {
            struct pauth_user_state t=s;
            if(field<10){if(field&1)t.key[field/2].hi^=1;else t.key[field/2].lo^=1;}
            else if(field==10)t.extra.lo^=1;else t.extra.hi^=1;
            struct pauth_key_pair direct[5],cached[5];uint64_t misses=cache.misses;
            CHECK(pauth_domain_user(&d,&t,direct));
            CHECK(pauth_domain_user_cached(&d,&t,&cache,cached,0));
            CHECK(cache.misses==misses+1 && !memcmp(direct,cached,sizeof(direct)));
            CHECK(pauth_domain_user_cached(&d,&t,&cache,cached,0));
            CHECK(cache.misses==misses+1 && !memcmp(direct,cached,sizeof(direct)));
        }
        struct pauth_user_state off=s;off.apctl=0;uint64_t misses=cache.misses;
        CHECK(!pauth_domain_user_cached(&d,&off,&cache,b,0) && cache.misses==misses);
        for(unsigned n=0;n<64;n++) {
            struct pauth_user_state t=s;t.key[n%5].lo+=n+100;struct pauth_key_pair direct[5],cached[5];
            CHECK(pauth_domain_user(&d,&t,direct));
            CHECK(pauth_domain_user_cached(&d,&t,&cache,cached,0));CHECK(!memcmp(direct,cached,sizeof(direct)));
        }
        misses=cache.misses;
        CHECK(pauth_domain_user_cached(&d,&s,&cache,b,0));CHECK(!memcmp(b,expected,sizeof(b)));
        CHECK(cache.misses==misses+1);
        CHECK(!pauth_domain_user_cached(&d,&s,0,b,0));
    }
#if defined(__aarch64__)
    /* FEAT_AES derivation produces the same pinned keys, for varied state. */
    CHECK(pauth_domain_user_with(&d,&s,b,1));CHECK(!memcmp(b,expected,sizeof(b)));
    for(unsigned n=0;n<256;n++) {
        struct pauth_user_state t=s;t.key[n%5].lo^=(uint64_t)n*0x9e3779b97f4a7c15UL;t.extra.hi^=n;
        struct pauth_key_pair soft[5],hard[5];
        CHECK(pauth_domain_user_with(&d,&t,soft,0) && pauth_domain_user_with(&d,&t,hard,1));
        CHECK(!memcmp(soft,hard,sizeof(soft)));
    }
    CHECK(!pauth_domain_user_with(&d,&s,b,2));
#endif
    for(unsigned key=0;key<5;key++) {
        s.key[key].lo^=1;CHECK(pauth_domain_user(&d,&s,b));
        for(unsigned k=0;k<5;k++)CHECK((memcmp(a+k,b+k,sizeof(*a))!=0)==(key==k));
        s.key[key].lo^=1;
    }
    s.extra.hi^=1;CHECK(pauth_domain_user(&d,&s,b));
    for(unsigned k=0;k<5;k++)CHECK((memcmp(a+k,b+k,sizeof(*a))!=0)==(k!=1 && k!=3));
    s.extra.hi^=1;CHECK(pauth_domain_user(&d,&s,b));CHECK(!memcmp(a,b,sizeof(a)));
    s.apctl=0;CHECK(!pauth_domain_user(&d,&s,b));CHECK(!memcmp(a,b,sizeof(a)));
    s.apctl=0x11;
    seed[0]^=1;CHECK(pauth_domain_init(&d,seed));CHECK(pauth_domain_user(&d,&s,b));
    for(unsigned k=0;k<5;k++)CHECK(memcmp(a+k,b+k,sizeof(*a)));
    const unsigned bits[]={13,27,30,31};
    for(unsigned mask=0;mask<16;mask++)for(unsigned flags=0;flags<16;flags++) {
        uint64_t old=0x30501805;
        for(unsigned i=0;i<4;i++)old|=(uint64_t)!!(mask&(1u<<i))<<bits[i];
        uint64_t got=pauth_root_enables(old,flags);
        CHECK((got&~0xc8002000UL)==(old&~0xc8002000UL));
        CHECK((got&0xc8002000UL)==((flags&2) ? (mask ? old&0xc8002000UL : 0xc8002000UL) : 0));
        if(argc==2 && !strcmp(argv[1],"--root"))
            printf("%llx %x %llx\n",(unsigned long long)old,flags,(unsigned long long)got);
    }
    aes_clear(&d,sizeof(d));
    if(argc==1)printf("pauth domain: %u checks passed; five OpenSSL reference vectors\n",checks);
    return 0;
}
