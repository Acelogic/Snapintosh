/* SPDX-License-Identifier: MIT */
/* SNAP_AES_BITSLICE (docs/AES-BITSLICE-20261019.md): aes_block(...,0) as a
 * constant-time bitsliced cipher, for the PAC key derivation's software path
 * (compat/pauth-domain.c). aes_block computes every S-box byte as a GF(2^8)
 * inverse, about 145K operations per AES-256 block; a derive-cache miss runs
 * 15 such blocks, 325 µs at EL2 on the A16.
 *
 * Layout: bit j of plane b is bit b of state byte j (FIPS-197 order, byte
 * j = 4 * column + row), so a plane is 16 bits, one per byte, and the eight
 * planes hold one block. SubBytes is Boyar and Peralta's 113-gate circuit
 * ("A new combinational logic minimization technique with applications to
 * cryptology", 2009) over the planes. ShiftRows rotates row r's four bits of
 * each plane right by 4r; MixColumns rotates rows within each column's
 * nibble and doubles in GF(2^8) across planes. Round keys are packed into
 * planes per round from struct aes_key. Like aes.c: no tables, no branch or
 * index on key or state, and the state is cleared before returning.
 * Header-only, so builds without the define gain no code. */
#pragma once
#include <stdint.h>
#include "aes.h"

/* Bits 8k of x to bits k, and back; fixed shifts and masks. */
static inline uint64_t aes_bs_gather(uint64_t x)
{
    x&=UINT64_C(0x0101010101010101);
    x=(x|(x>>7))&UINT64_C(0x0003000300030003);
    x=(x|(x>>14))&UINT64_C(0x0000000f0000000f);
    return (x|(x>>28))&UINT64_C(0xff);
}
static inline uint64_t aes_bs_spread(uint64_t x)
{
    x&=UINT64_C(0xff);
    x=(x|(x<<28))&UINT64_C(0x0000000f0000000f);
    x=(x|(x<<14))&UINT64_C(0x0003000300030003);
    return (x|(x<<7))&UINT64_C(0x0101010101010101);
}
static inline uint64_t aes_bs_load(const uint8_t *p)
{
    uint64_t v=0;
    for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);
    return v;
}
static inline void aes_bs_pack(uint32_t q[8],const uint8_t bytes[16])
{
    uint64_t lo=aes_bs_load(bytes),hi=aes_bs_load(bytes+8);
    for(unsigned b=0;b<8;b++)q[b]=(uint32_t)(aes_bs_gather(lo>>b)|aes_bs_gather(hi>>b)<<8);
}
static inline void aes_bs_unpack(uint8_t bytes[16],const uint32_t q[8])
{
    uint64_t lo=0,hi=0;
    for(unsigned b=0;b<8;b++) {
        lo|=aes_bs_spread(q[b])<<b;
        hi|=aes_bs_spread(q[b]>>8)<<b;
    }
    for(unsigned i=0;i<8;i++) {bytes[i]=(uint8_t)(lo>>(8*i));bytes[8+i]=(uint8_t)(hi>>(8*i));}
}
static inline void aes_bs_add_key(uint32_t q[8],const uint8_t round_key[16])
{
    uint32_t k[8];aes_bs_pack(k,round_key);
    for(unsigned b=0;b<8;b++)q[b]^=k[b];
    aes_clear(k,sizeof(k));
}
/* SubBytes on all 16 bytes: x0 is the high bit (plane 7), s0 likewise. */
static inline void aes_bs_sbox(uint32_t q[8])
{
    uint32_t x0=q[7],x1=q[6],x2=q[5],x3=q[4],x4=q[3],x5=q[2],x6=q[1],x7=q[0];
    /* Top linear transformation. */
    uint32_t y14=x3^x5,y13=x0^x6,y9=x0^x3,y8=x0^x5,t0=x1^x2,y1=t0^x7,y4=y1^x3,
             y12=y13^y14,y2=y1^x0,y5=y1^x6,y3=y5^y8,t1=x4^y12,y15=t1^x5,y20=t1^x1,
             y6=y15^x7,y10=y15^t0,y11=y20^y9,y7=x7^y11,y17=y10^y11,y19=y10^y8,
             y16=t0^y11,y21=y13^y16,y18=x0^y16;
    /* Non-linear section. */
    uint32_t t2=y12&y15,t3=y3&y6,t4=t3^t2,t5=y4&x7,t6=t5^t2,t7=y13&y16,t8=y5&y1,
             t9=t8^t7,t10=y2&y7,t11=t10^t7,t12=y9&y11,t13=y14&y17,t14=t13^t12,
             t15=y8&y10,t16=t15^t12,t17=t4^t14,t18=t6^t16,t19=t9^t14,t20=t11^t16,
             t21=t17^y20,t22=t18^y19,t23=t19^y21,t24=t20^y18;
    uint32_t t25=t21^t22,t26=t21&t23,t27=t24^t26,t28=t25&t27,t29=t28^t22,
             t30=t23^t24,t31=t22^t26,t32=t31&t30,t33=t32^t24,t34=t23^t33,
             t35=t27^t33,t36=t24&t35,t37=t36^t34,t38=t27^t36,t39=t29&t38,
             t40=t25^t39;
    uint32_t t41=t40^t37,t42=t29^t33,t43=t29^t40,t44=t33^t37,t45=t42^t41,
             z0=t44&y15,z1=t37&y6,z2=t33&x7,z3=t43&y16,z4=t40&y1,z5=t29&y7,
             z6=t42&y11,z7=t45&y17,z8=t41&y10,z9=t44&y12,z10=t37&y3,z11=t33&y4,
             z12=t43&y13,z13=t40&y5,z14=t29&y2,z15=t42&y9,z16=t45&y14,z17=t41&y8;
    /* Bottom linear transformation. */
    uint32_t t46=z15^z16,t47=z10^z11,t48=z5^z13,t49=z9^z10,t50=z2^z12,t51=z2^z5,
             t52=z7^z8,t53=z0^z3,t54=z6^z7,t55=z16^z17,t56=z12^t48,t57=t50^t53,
             t58=z4^t46,t59=z3^t54,t60=t46^t57,t61=z14^t57,t62=t52^t58,t63=t49^t58,
             t64=z4^t59,t65=t61^t62,t66=z1^t63,s0=t59^t63,s6=t56^~t62,s7=t48^~t60,
             t67=t64^t65,s3=t53^t66,s4=t51^t66,s5=t47^t65,s1=t64^~s3,s2=t55^~t67;
    q[7]=s0&0xffff;q[6]=s1&0xffff;q[5]=s2&0xffff;q[4]=s3&0xffff;
    q[3]=s4&0xffff;q[2]=s5&0xffff;q[1]=s6&0xffff;q[0]=s7&0xffff;
}
static inline uint32_t aes_bs_rotr16(uint32_t w,unsigned n)
{return ((w>>n)|(w<<(16-n)))&0xffff;}
/* Row r (bits r, r+4, r+8, r+12) moves left by r columns. */
static inline void aes_bs_shift_rows(uint32_t q[8])
{
    for(unsigned b=0;b<8;b++) {
        uint32_t w=q[b];
        q[b]=(w&0x1111)|(aes_bs_rotr16(w,4)&0x2222)|(aes_bs_rotr16(w,8)&0x4444)|
             (aes_bs_rotr16(w,12)&0x8888);
    }
}
/* Row r+n of each column at row r. */
static inline uint32_t aes_bs_row1(uint32_t w) {return ((w>>1)&0x7777)|((w<<3)&0x8888);}
static inline uint32_t aes_bs_row2(uint32_t w) {return ((w>>2)&0x3333)|((w<<2)&0xcccc);}
static inline uint32_t aes_bs_row3(uint32_t w) {return ((w>>3)&0x1111)|((w<<1)&0xeeee);}
/* b_r = 2(a_r ^ a_r+1) ^ a_r+1 ^ a_r+2 ^ a_r+3; doubling mod x^8+x^4+x^3+x+1. */
static inline void aes_bs_mix_columns(uint32_t q[8])
{
    uint32_t t[8],rest[8];
    for(unsigned b=0;b<8;b++) {
        uint32_t r1=aes_bs_row1(q[b]);
        t[b]=q[b]^r1;
        rest[b]=r1^aes_bs_row2(q[b])^aes_bs_row3(q[b]);
    }
    q[0]=t[7]^rest[0];
    q[1]=t[0]^t[7]^rest[1];
    q[2]=t[1]^rest[2];
    q[3]=t[2]^t[7]^rest[3];
    q[4]=t[3]^t[7]^rest[4];
    q[5]=t[4]^rest[5];
    q[6]=t[5]^rest[6];
    q[7]=t[6]^rest[7];
    aes_clear(t,sizeof(t));aes_clear(rest,sizeof(rest));
}
/* aes_block(key,input,output,0): the same refusals (1 written, 0 refused with
 * output untouched) and the same result. */
static inline int aes_encrypt_bitsliced(const struct aes_key *key,const uint8_t input[16],uint8_t output[16])
{
    if(!key || !input || !output || (key->rounds!=10 && key->rounds!=12 && key->rounds!=14))return 0;
    uintptr_t out=(uintptr_t)output,k=(uintptr_t)key;
    if(out>UINTPTR_MAX-16 || k>UINTPTR_MAX-sizeof(*key) || (out<k+sizeof(*key) && k<out+16))return 0;
    uint32_t q[8];
    aes_bs_pack(q,input);
    aes_bs_add_key(q,key->round_key);
    for(unsigned round=1;round<=key->rounds;round++) {
        aes_bs_sbox(q);aes_bs_shift_rows(q);
        if(round<key->rounds)aes_bs_mix_columns(q);
        aes_bs_add_key(q,key->round_key+round*16);
    }
    aes_bs_unpack(output,q);
    aes_clear(q,sizeof(q));
    return 1;
}
