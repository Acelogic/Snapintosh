/* SPDX-License-Identifier: MIT */
/* FIPS197 Appendix C and NIST SP800-38A CBC examples. */
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static size_t unhex(uint8_t *out,const char *s)
{
    size_t n=strlen(s)/2;
    for (size_t i=0;i<n;i++) { unsigned v;CHECK(sscanf(s+i*2,"%2x",&v)==1);out[i]=(uint8_t)v; }
    return n;
}
int main(void)
{
    uint8_t key[32],plain[64],expected[64],out[64],back[64],iv[16],block[16];
    struct aes_key ctx;
    const char *ecb[]={"69c4e0d86a7b0430d8cdb78070b4c55a","dda97ca4864cdfe06eaf70a0ec0d7191","8ea2b7ca516745bfeafc49904b496089"};
    unhex(plain,"00112233445566778899aabbccddeeff");
    for (unsigned i=0;i<32;i++) key[i]=(uint8_t)i;
    for (unsigned n=0;n<3;n++) {
        unhex(expected,ecb[n]);CHECK(aes_expand(&ctx,key,16+8*n));
        CHECK(aes_block(&ctx,plain,out,0));CHECK(!memcmp(out,expected,16));
        CHECK(aes_block(&ctx,out,out,1));CHECK(!memcmp(out,plain,16));
    }
    const char *keys[]={"2b7e151628aed2a6abf7158809cf4f3c","8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b","603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"};
    const char *cbc[]={"7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7","4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd","f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"};
    unhex(plain,"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    for (unsigned n=0;n<3;n++) {
        size_t size=unhex(key,keys[n]);unhex(expected,cbc[n]);CHECK(aes_expand(&ctx,key,size));
        for (unsigned j=0;j<16;j++) iv[j]=(uint8_t)j;
        for (unsigned i=0;i<64;i+=16) {
            for (unsigned j=0;j<16;j++) block[j]=plain[i+j]^iv[j];
            CHECK(aes_block(&ctx,block,out+i,0));memcpy(iv,out+i,16);
        }
        CHECK(!memcmp(out,expected,64));
        for (unsigned j=0;j<16;j++) iv[j]=(uint8_t)j;
        for (unsigned i=0;i<64;i+=16) {
            CHECK(aes_block(&ctx,expected+i,block,1));
            for (unsigned j=0;j<16;j++) back[i+j]=block[j]^iv[j];
            memcpy(iv,expected+i,16);
        }
        CHECK(!memcmp(back,plain,64));
    }
    struct aes_key before=ctx;
    for (size_t n=0;n<40;n++) if (n!=16 && n!=24 && n!=32) {
        CHECK(!aes_expand(&ctx,key,n));CHECK(!memcmp(&ctx,&before,sizeof(ctx)));
    }
    CHECK(!aes_expand(&ctx,0,16));CHECK(!aes_expand(0,key,16));
    memset(out,0xa5,sizeof(out));ctx.rounds=0;
    CHECK(!aes_block(&ctx,plain,out,0));CHECK(out[0]==0xa5);
    ctx=before;CHECK(!aes_block(&ctx,plain,out,2));CHECK(out[0]==0xa5);
    CHECK(!aes_block(&ctx,plain,ctx.round_key,0));CHECK(!memcmp(&ctx,&before,sizeof(ctx)));
    CHECK(!aes_block(&ctx,0,out,0));CHECK(!aes_block(0,plain,out,0));
    aes_clear(&ctx,sizeof(ctx));for (size_t i=0;i<sizeof(ctx);i++) CHECK(!((uint8_t *)&ctx)[i]);
    printf("AES primitive: %u checks passed (NIST block/CBC encrypt and decrypt, all key sizes)\n",checks);
}
