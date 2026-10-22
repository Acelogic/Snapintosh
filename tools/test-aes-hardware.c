/* SPDX-License-Identifier: MIT */
/* Hardware AES encryption equals the software path bit for bit, and the
 * caller's v0/v1 (live guest state at EL2) survive every block. Host only:
 * needs an AArch64 CPU with FEAT_AES (Apple silicon or Snapdragon). */
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static uint64_t state=0x9e3779b97f4a7c15UL;
static uint8_t next(void) { state^=state<<13;state^=state>>7;state^=state<<17;return (uint8_t)state; }

static void block(int hardware,const struct aes_key *key,const uint8_t in[16],uint8_t out[16])
{
    if (hardware) CHECK(aes_encrypt_hardware(key,in,out));
    else CHECK(aes_block(key,in,out,0));
}

int main(void)
{
    /* FIPS-197 appendix C vectors through the hardware path. */
    static const uint8_t plain[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const uint8_t expected[3][16]={
        {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
        {0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91},
        {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89}};
    for (unsigned v=0;v<3;v++) {
        uint8_t bytes[32],out[16];struct aes_key key;
        for (unsigned i=0;i<32;i++) bytes[i]=(uint8_t)i;
        CHECK(aes_expand(&key,bytes,16+8*v));
        block(1,&key,plain,out);CHECK(!memcmp(out,expected[v],16));
    }
    /* Random keys and blocks: hardware == software, including in place. */
    for (unsigned n=0;n<20000;n++) {
        size_t size=16+8*(n%3);uint8_t bytes[32],in[16],soft[16],hard[16];
        for (unsigned i=0;i<32;i++) bytes[i]=next();
        for (unsigned i=0;i<16;i++) in[i]=next();
        struct aes_key key;CHECK(aes_expand(&key,bytes,size));
        block(0,&key,in,soft);block(1,&key,in,hard);CHECK(!memcmp(soft,hard,16));
        memcpy(hard,in,16);block(1,&key,hard,hard);CHECK(!memcmp(soft,hard,16));
    }
    /* Caller vector registers are preserved; decryption stays software. */
    {
        uint8_t bytes[16]={0},in[16]={1},out[16];struct aes_key key;
        CHECK(aes_expand(&key,bytes,16));
        uint64_t before[4]={0x0123456789abcdefUL,0xfedcba9876543210UL,0x1111222233334444UL,0x5555666677778888UL},after[4];
        __asm__ volatile("ld1 {v0.2d,v1.2d},[%0]"::"r"(before):"v0","v1","memory");
        int ok=aes_encrypt_hardware(&key,in,out);
        __asm__ volatile("st1 {v0.2d,v1.2d},[%0]"::"r"(after):"memory");
        CHECK(ok && !memcmp(before,after,sizeof(before)));
        uint8_t back[16];CHECK(aes_block(&key,out,back,1));CHECK(!memcmp(back,in,16));
        /* Refusals match the software validator and write nothing. */
        struct aes_key bad=key;bad.rounds=11;memset(back,0xa5,16);
        CHECK(!aes_encrypt_hardware(&bad,in,back) && back[0]==0xa5 && back[15]==0xa5);
        CHECK(!aes_encrypt_hardware(0,in,back) && !aes_encrypt_hardware(&key,0,back) && !aes_encrypt_hardware(&key,in,0));
    }
    CHECK(!aes_hardware_supported(0) && aes_hardware_supported(1UL<<4) && aes_hardware_supported(2UL<<4));
    CHECK(!aes_hardware_supported(~0UL^(15UL<<4)));
    printf("PASS: %u hardware/software AES equivalence and register-preservation checks\n",checks);
    return 0;
}
