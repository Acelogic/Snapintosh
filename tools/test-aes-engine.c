/* SPDX-License-Identifier: MIT */
/* Command transport plus independent NIST SP800-38A CBC/ECB/CTR answers. */
#include "aes-engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++;if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1); } } while (0)
#define SRC 0x12300003ff8UL
#define DST 0x23400007ff4UL
static struct aes_engine e;
static uint8_t input[128],output[128],saved[128],key[32],plain[64],expected[64],iv[16];
static unsigned maps,pubs,fail_map;
static int inplace,alias_engine,alias_output;
static volatile uint8_t *map(void *ctx,uint64_t a,size_t n,int write)
{
    CHECK(ctx==&e && n && n<=0x4000-(a&0x3fff));maps++;
    if (maps==fail_map) return 0;
    if (alias_engine) return (volatile uint8_t *)&e;
    if (write && a>=DST && a-DST<sizeof(output) && n<=sizeof(output)-(a-DST)) {
        if (alias_output && a-DST>=12) return output;
        return (inplace ? input : output)+(a-DST);
    }
    if (!write && a>=SRC && a-SRC<sizeof(input) && n<=sizeof(input)-(a-SRC)) return input+(a-SRC);
    return 0;
}
static void publish(void *ctx,volatile uint8_t *p,size_t n)
{ CHECK(ctx==&e && p && n && !aes_engine_irq(&e));pubs++; }
static const struct aes_dma dma={&e,map,publish};
static enum aes_result wr(uint64_t off,uint64_t v)
{ return aes_engine_access(&e,&dma,off,4,1,&v); }
static uint64_t rd(uint64_t off)
{ uint64_t v=0xdeadbeef;CHECK(aes_engine_access(&e,&dma,off,4,0,&v)==AES_OK);return v; }
static void word(uint32_t v) { CHECK(wr(0x200,v)==AES_OK); }
static size_t unhex(uint8_t *out,const char *s)
{ size_t n=strlen(s)/2;for (size_t i=0;i<n;i++) {unsigned v;CHECK(sscanf(s+i*2,"%2x",&v)==1);out[i]=(uint8_t)v;}return n; }
static void words(const uint8_t *p,unsigned n)
{ for (unsigned i=0;i<n;i+=4) word((uint32_t)p[i]<<24|(uint32_t)p[i+1]<<16|(uint32_t)p[i+2]<<8|p[i+3]); }
static void reset(void)
{
    aes_engine_init(&e);maps=pubs=fail_map=0;inplace=alias_engine=alias_output=0;
    memset(input,0,sizeof(input));memset(output,0xa5,sizeof(output));
    CHECK(wr(0x1c,0x3effe)==AES_OK);CHECK(wr(0x20,64)==AES_OK);CHECK(wr(8,1)==AES_OK);
}
static void setup(unsigned size,unsigned mode,unsigned encrypt,unsigned slot,unsigned is)
{
    word(0x10000000|slot<<27|((size-16)/8)<<22|encrypt<<20|mode<<16);words(key,size);
    word(0x20000000|is<<26);words(iv,16);
    CHECK(rd(0xc)==0x3f80 && rd(0x24)==2 && !aes_engine_irq(&e));
}
static uint32_t high(uint64_t src,uint64_t dst)
{ return (uint32_t)((src>>32)<<16)|(uint32_t)(dst>>32); }
static enum aes_result transfer(uint64_t src,uint64_t dst,unsigned n,unsigned slot,unsigned is)
{
    word(0x50000000|slot<<27|is<<25|n);word(high(src,dst));word((uint32_t)src);
    return wr(0x200,(uint32_t)dst);
}
static void completion(unsigned tag)
{
    CHECK(!aes_engine_irq(&e));word(0x88000000|tag);
    CHECK(aes_engine_irq(&e));CHECK(rd(0x18)==0x20 && rd(0x30)==tag);
    CHECK(wr(0x1c,0)==AES_OK && !aes_engine_irq(&e));
    CHECK(rd(0x18)==0x20);CHECK(wr(0x1c,0x20)==AES_OK && aes_engine_irq(&e));
    CHECK(wr(0x18,0x20)==AES_OK && !aes_engine_irq(&e));
    CHECK(wr(8,2)==AES_OK && !e.running && rd(0x24)==2);
}
int main(void)
{
    const char *keys[]={"2b7e151628aed2a6abf7158809cf4f3c","8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b","603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"};
    const char *cbc[]={"7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7","4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd","f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"};
    unhex(plain,"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    for (unsigned k=0;k<3;k++) for (unsigned encrypt=0;encrypt<2;encrypt++) for (unsigned in=0;in<2;in++) {
        unsigned size=(unsigned)unhex(key,keys[k]);unhex(expected,cbc[k]);
        for (unsigned j=0;j<16;j++) iv[j]=(uint8_t)j;
        reset();inplace=(int)in;setup(size,1,encrypt,k&1,k);
        memcpy(input,encrypt ? plain : expected,64);
        /* Two commands prove IV chaining as well as discontiguous fragments. */
        CHECK(transfer(SRC,DST,32,k&1,k)==AES_OK);CHECK(transfer(SRC+32,DST+32,32,k&1,k)==AES_OK);
        CHECK(!memcmp(in ? input : output,encrypt ? expected : plain,64));
        CHECK(!memcmp(e.iv[k],expected+48,16));CHECK(e.transfers==2 && e.bytes==64 && pubs==3);
        completion(255);CHECK(e.barriers==1);
    }
    for (unsigned mode=0;mode<3;mode+=2) for (unsigned encrypt=0;encrypt<2;encrypt++) {
        unhex(key,keys[0]);
        unhex(expected,mode==0 ? "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4" : "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
        for (unsigned j=0;j<16;j++) iv[j]=(uint8_t)(0xf0+j);
        reset();setup(16,mode,encrypt,1,3);memcpy(input,encrypt ? plain : expected,64);
        CHECK(transfer(SRC,DST,64,1,3)==AES_OK);CHECK(!memcmp(output,encrypt ? expected : plain,64));completion(0);
    }
    reset();unhex(key,keys[0]);for (unsigned j=0;j<16;j++) iv[j]=(uint8_t)j;
    setup(16,1,1,0,0);memcpy(input,plain,64);unhex(expected,cbc[0]);
    CHECK(transfer(SRC,DST,64,0,0)==AES_OK);
    word(0x80000100);CHECK(!aes_engine_irq(&e) && e.barriers==1 && e.completed_tag==0);
    CHECK(!memcmp(output,expected,64));memset(output,0xa5,128);
    word(0x60000000|(DST>>32));word((uint32_t)DST);
    CHECK(!memcmp(output,expected+48,16) && e.iv_exports==1);completion(1);
    /* Every missing source/destination fragment refuses atomically, then retries. */
    for (unsigned fail=1;fail<=4;fail++) {
        reset();setup(16,1,1,0,0);memcpy(input,plain,64);memcpy(saved,output,128);fail_map=fail;
        word(0x50000040);word(high(SRC,DST));word((uint32_t)SRC);struct aes_engine before=e;
        CHECK(wr(0x200,(uint32_t)DST)==AES_DMA_REFUSED);
        CHECK(!memcmp(&e,&before,sizeof(e)) && !memcmp(output,saved,128) && !pubs && !aes_engine_irq(&e));
        fail_map=0;CHECK(wr(0x200,(uint32_t)DST)==AES_OK);CHECK(!memcmp(output,expected,64));
    }
    for (unsigned which=0;which<3;which++) {
        reset();setup(16,1,1,0,0);alias_engine=which==0;alias_output=which==1;inplace=which==2;
        memcpy(input,plain,64);memcpy(saved,input,128);
        CHECK(transfer(SRC+(which==2 ? 1 : 0),DST,64,0,0)==AES_DMA_REFUSED);
        CHECK(!pubs && !e.transfers && !aes_engine_irq(&e) && !memcmp(input,saved,128));
    }
    const uint32_t invalid[]={0,0x11000000,0x12000000,0x13000000,0x10200000,0x10040000,0x10c00000,0x10030000,0x10000001,0x30000000,0x40000000,0x70000000,0x90000000,0x88000100,0x80000101,0x64000000};
    for (unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        reset();struct aes_engine before=e;CHECK(wr(0x200,invalid[i])==AES_UNSUPPORTED);CHECK(!memcmp(&before,&e,sizeof(e)));
    }
    const uint32_t bad_lengths[]={0x50000000,0x50000001,0x50100010,0x51fffff0};
    for (unsigned i=0;i<4;i++) {reset();CHECK(wr(0x200,bad_lengths[i])==AES_BAD_VALUE);}
    reset();word(0x10910000);for (unsigned i=0;i<7;i++) word(i);CHECK(!e.keys[0].valid && e.need==8 && e.used==7);
    CHECK(wr(8,2)==AES_BAD_STATE);word(7);CHECK(e.keys[0].valid && e.keys[0].key.rounds==14);
    for (unsigned n=0;n<10;n++) {
        reset();word(0x10910000);e.need=n;struct aes_engine before=e;uint64_t v=0;
        if (n!=8) {CHECK(aes_engine_access(&e,&dma,0x200,4,1,&v)==AES_BAD_STATE);CHECK(!memcmp(&before,&e,sizeof(e)));}
    }
    reset();CHECK(wr(0x200,0x100000000UL)==AES_BAD_VALUE);CHECK(wr(8,4)==AES_UNSUPPORTED);
    for (unsigned off=0;off<0x4000;off+=4) if (off!=8 && off!=0x18 && off!=0x1c && off!=0x20 && off!=0x200)
        CHECK(wr(off,0)==AES_UNKNOWN_REGISTER);
    uint64_t v=0x55;CHECK(aes_engine_access(&e,&dma,0xc,8,0,&v)==AES_BAD_WIDTH && v==0x55);
    CHECK(wr(8,2)==AES_OK);CHECK(wr(0x200,0x88000000)==AES_BAD_STATE);
    printf("AES command engine: %u checks passed (NIST answers, 42-bit DMA, boundaries, in-place, atomic refusals, IRQ)\n",checks);
}
