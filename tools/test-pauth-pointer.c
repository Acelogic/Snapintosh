/* SPDX-License-Identifier: MIT */
#include "../compat/pauth-pointer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks,backend_calls,backend_fail,replay;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static int sign_model(void *ctx,const struct pauth_batch_entry *e,uint64_t tbi,
                      uint64_t tbid,uint64_t *out)
{
    (void)ctx;backend_calls++;
    if(backend_fail)return 0;
    uint64_t h=e->pointer^(e->pointer>>32)^e->modifier^(e->modifier>>32)^
               ((uint64_t)e->key*0x9e37);
    *out=e->pointer|((h&255)<<47);
    if(!(tbi && (e->key==2 || !tbid)))*out|=((h>>8)&255)<<56;
    return 1;
}
static enum sptm_result call(uint64_t p,uint64_t key,uint64_t mod,unsigned auth,
    unsigned tbi,unsigned tbid,struct pauth_pointer_state *s)
{
    enum sptm_result r=pauth_pointer(p,key,mod,auth,tbi,tbid,sign_model,0,s);
    if(replay)printf("%llx %llx %llx %u %u %u %u %llx\n",
        (unsigned long long)p,(unsigned long long)key,(unsigned long long)mod,
        auth,tbi,tbid,(unsigned)r,(unsigned long long)s->result);
    return r;
}
int main(int argc,char **argv)
{
    replay=argc==2 && !strcmp(argv[1],"--replay");
    struct pauth_pointer_state s={0};
    for(unsigned key=0;key<=2;key+=2)for(unsigned tbi=0;tbi<2;tbi++)
    for(unsigned tbid=0;tbid<2;tbid++)for(unsigned tag=0;tag<256;tag++) {
        uint64_t p=0x100000000ULL+4*tag,mod=0x9837000000000000ULL+tag;
        if(tbi && (key==2 || !tbid))p|=(uint64_t)tag<<56;
        CHECK(call(p,key,mod,0,tbi,tbid,&s)==SPTM_OK);
        uint64_t signed_pointer=s.result;
        CHECK(s.native_calls==s.native_restores);
        CHECK(call(signed_pointer,key,mod,1,tbi,tbid,&s)==SPTM_OK);
        CHECK(s.result==p && s.stripped==p && s.computed==signed_pointer);
        CHECK(call(signed_pointer^(1ULL<<47),key,mod,1,tbi,tbid,&s)==SPTM_OK);
        CHECK(s.result==UINT64_MAX);
    }
    CHECK(s.signs==2048 && s.auths==4096 && s.valid==2048 && s.invalid==2048);
    CHECK(s.calls==6144 && !s.failures && s.native_calls==s.native_restores);
    /* The pinned service tests w1; upper bits do not select another key. */
    CHECK(call(0x100000000ULL,1ULL<<32,0,0,1,1,&s)==SPTM_OK);
    for(unsigned key=0;key<256;key++)if(key!=0 && key!=2) {
        unsigned before=backend_calls;
        CHECK(call(0x100000000ULL,key,0,0,1,1,&s)==SPTM_BAD_CONFIG);
        CHECK(backend_calls==before && s.result==0);
    }
    /* Original SIGN_USER_POINTER accepts raw values, including the captured
     * rpcsvchost cookie. These cases precede the implementation change. */
    const uint64_t raw_inputs[]={0xe0fc8b839d03516bULL,1ULL<<47,1ULL<<55,
                                1ULL<<56,UINT64_MAX,0x123456789abcdef0ULL};
    for(unsigned key=0;key<=2;key+=2)for(unsigned tbi=0;tbi<2;tbi++)
    for(unsigned tbid=0;tbid<2;tbid++)for(unsigned i=0;i<sizeof(raw_inputs)/sizeof(*raw_inputs);i++) {
        unsigned before=backend_calls;
        CHECK(call(raw_inputs[i],key,0xb743,0,tbi,tbid,&s)==SPTM_OK);
        CHECK(backend_calls==before+1 && s.stripped==raw_inputs[i]);
        CHECK(s.native_calls==s.native_restores && s.result==s.computed);
    }
    if(replay)return 0;
    CHECK(call(1ULL<<55,0,0,1,1,1,&s)==SPTM_BAD_ADDRESS);
    CHECK(call(0,0,0,2,1,1,&s)==SPTM_BAD_CONFIG);
    CHECK(call(0,0,0,1,2,1,&s)==SPTM_BAD_CONFIG);
    CHECK(call(0,0,0,1,1,2,&s)==SPTM_BAD_CONFIG);
    CHECK(pauth_pointer(0,0,0,0,1,1,0,0,&s)==SPTM_BAD_CONFIG);
    CHECK(pauth_pointer(0,0,0,0,1,1,sign_model,0,0)==SPTM_BAD_CONFIG);
    backend_fail=1;uint64_t restores=s.native_restores,calls=s.calls;
    CHECK(call(0x100000000ULL,0,0,1,1,1,&s)==SPTM_SHADOW_FAILED);
    CHECK(s.native_restores==restores && s.calls==calls && s.result==0);
    printf("pauth pointer: %u sanitizer checks passed\n",checks);
    return 0;
}
