/* SPDX-License-Identifier: MIT */
#include "mmio.h"
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static const uint64_t syndrome=0x92000005;
static uint64_t regs[31],saved[31];
static uint32_t instruction(unsigned rt,unsigned rn,int immediate)
{
    return 0xb8400c00U|(((unsigned)immediate&511)<<12)|(rn<<5)|rt;
}
static void reject(uint32_t word,uint64_t esr,uint64_t sp)
{
    struct mmio_preload load={0x1234,12,13};
    memcpy(saved,regs,sizeof(regs));
    CHECK(!mmio_ldr32_pre_decode(word,esr,regs,sp,&load));
    CHECK(!memcmp(saved,regs,sizeof(regs)));
    CHECK(load.address==0x1234 && load.reg==12 && load.base==13);
}
int main(void)
{
    for (unsigned i=0;i<31;i++) regs[i]=0xffff000000010000UL+i*0x1000;
    struct mmio_preload load;
    CHECK(mmio_ldr32_pre_decode(0xb8414d09,syndrome,regs,0,&load));
    CHECK(load.address==regs[8]+0x14 && load.reg==9 && load.base==8);
    /* All register choices and signed immediates. Unaligned addresses and
     * constrained-unpredictable writeback overlap refuse without mutation. */
    for (unsigned rn=0;rn<32;rn++) for (unsigned rt=0;rt<32;rt++)
        for (int imm=-256;imm<256;imm++) {
            uint64_t sp=0xffff000000080000UL,original=rn==31 ? sp : regs[rn];
            uint32_t word=instruction(rt,rn,imm);
            if ((rn==rt && rn!=31) || (imm&3)) { reject(word,syndrome,sp);continue; }
            memcpy(saved,regs,sizeof(regs));
            CHECK(mmio_ldr32_pre_decode(word,syndrome,regs,sp,&load));
            CHECK(load.address==original+(uint64_t)imm && load.reg==rt && load.base==rn);
            CHECK(!memcmp(saved,regs,sizeof(regs)));
            mmio_ldr32_pre_complete(&load,0x80000118U,regs,&sp);
            for (unsigned i=0;i<31;i++)
                CHECK(regs[i]==(i==rn ? load.address : i==rt ? 0x80000118UL : saved[i]));
            CHECK(sp==(rn==31 ? load.address : 0xffff000000080000UL));
            memcpy(regs,saved,sizeof(regs));
        }
    const uint32_t bad[]={0xb8014d09,0xf8414d09,0x38414d09,0x78414d09,
        0xbc414d09,0xb8814d09,0xb8414509,0xb8414109,0xb9401509,0xd503201f};
    for (unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) reject(bad[i],syndrome,0);
    const unsigned bad_bits[]={24,10,9,8,7,6};
    for (unsigned i=0;i<sizeof(bad_bits)/sizeof(*bad_bits);i++)
        reject(0xb8414d09,syndrome|(1UL<<bad_bits[i]),0);
    reject(0xb8414d09,syndrome^(1UL<<25),0);
    reject(0xb8414d09,syndrome^(1UL<<26),0);
    reject(0xb8414d09,(syndrome&~63UL)|0x21,0);
    for (unsigned fsc=4;fsc<16;fsc++) if (fsc<8 || fsc>=12)
        CHECK(mmio_ldr32_pre_decode(0xb8414d09,(syndrome&~63UL)|fsc,regs,0,&load));
    reject(instruction(0,31,0),syndrome,4);
    regs[8]=0;reject(instruction(9,8,-4),syndrome,0);
    regs[8]=UINT64_MAX-3;reject(instruction(9,8,4),syndrome,0);
    CHECK(mmio_ldr32_pre_decode(instruction(9,8,0),syndrome,regs,0,&load));
    /* Read real model status, then commit W-result and X-base. A rejected
     * register read leaves both operands and the model untouched. */
    struct device_model model={DEVICE_I2C_EMPTY_V1,0x385018000UL,0x4000,{2,6,1110,0,0}};
    struct device_state state,before;
    CHECK(device_model_start(&model,&state,0,24000000)==DEVICE_OK);
    state.i2c.status=0x08200000;state.i2c.address=0x80000000;
    regs[8]=model.base;uint64_t sp=0,value=0;
    CHECK(mmio_ldr32_pre_decode(0xb8414d09,syndrome,regs,sp,&load));
    CHECK(device_model_access_state(&model,&state,load.address-model.base,4,0,&value)==DEVICE_OK);
    mmio_ldr32_pre_complete(&load,(uint32_t)value,regs,&sp);
    CHECK(regs[9]==0x08210118 && regs[8]==model.base+0x14);
    regs[8]=model.base;memcpy(saved,regs,sizeof(regs));before=state;
    CHECK(mmio_ldr32_pre_decode(instruction(9,8,0x40),syndrome,regs,sp,&load));
    CHECK(device_model_access_state(&model,&state,load.address-model.base,4,0,&value)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(saved,regs,sizeof(regs)) && !memcmp(&before,&state,sizeof(state)));
    printf("PASS: %u pre-indexed MMIO load and writeback checks\n",checks);
}
