/* SPDX-License-Identifier: MIT */
/* Native instruction + device integration, no physical MMIO.
 * cc -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -Icompat
 *   tools/test-mmio-pair.c compat/mmio.c compat/device.c compat/aic.c
 *   compat/watchdog.c compat/clock.c compat/dart.c -o build/test-mmio-pair
 * Run: build/test-mmio-pair (join the compiler command above onto one line).
 */
#include "mmio.h"
#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static const uint64_t syndrome=0x92000007; /* ISV=0, lower-EL translation abort */
static uint64_t regs[31], saved[31];
static struct device_state state, before;
static struct device_model model={DEVICE_MCC_PTD_COHERENT_V1,0x3003c0000UL,
                                 0x14000,{0x10000,0x1a8,0x1b8,8,0}};
static void reject(uint32_t word, uint64_t esr)
{
    struct mmio_pair pair={0x1234,{12,13}}, old=pair;
    memcpy(saved,regs,sizeof(regs));
    CHECK(!mmio_ldp64_decode(word,esr,regs,0x10000,&pair));
    CHECK(!memcmp(saved,regs,sizeof(regs)));
    CHECK(pair.address==old.address && pair.reg[0]==old.reg[0] && pair.reg[1]==old.reg[1]);
}
static void write64(uint64_t offset, uint64_t value)
{
    CHECK(device_model_access_state(&model,&state,offset,8,1,&value)==DEVICE_OK);
}
int main(void)
{
    for(unsigned i=0;i<31;i++) regs[i]=0x10000+i*0x1000;
    struct mmio_pair pair;
    /* Exact instruction at J700 readPTDMsg +0x2c. The second destination
     * overlaps the base, which is legal without writeback. */
    CHECK(mmio_ldp64_decode(0xa9402113,syndrome,regs,0,&pair));
    CHECK(pair.address==regs[8] && pair.reg[0]==19 && pair.reg[1]==8);
    uint64_t values[2]={0xabcdef,2};
    memcpy(saved,regs,sizeof(regs));
    mmio_ldp64_complete(&pair,values,regs);
    CHECK(regs[19]==values[0] && regs[8]==values[1]);
    for(unsigned i=0;i<31;i++) if(i!=8 && i!=19) CHECK(regs[i]==saved[i]);
    memcpy(regs,saved,sizeof(regs));

    /* Every signed scaled immediate, including -512 and +504. */
    for(unsigned i=0;i<128;i++) {
        CHECK(mmio_ldp64_decode(0xa9400440U | (i<<15),syndrome,regs,0,&pair));
        int displacement=(i<64 ? (int)i : (int)i-128)*8;
        CHECK(pair.address==regs[2]+(uint64_t)displacement);
        CHECK(pair.reg[0]==0 && pair.reg[1]==1);
    }
    CHECK(mmio_ldp64_decode(0xa9407fe0,syndrome,regs,0x22000,&pair)); /* x0,xzr,[sp] */
    CHECK(pair.address==0x22000 && pair.reg[0]==0 && pair.reg[1]==31);
    memcpy(saved,regs,sizeof(regs));
    mmio_ldp64_complete(&pair,values,regs);
    CHECK(regs[0]==values[0]);
    for(unsigned i=1;i<31;i++) CHECK(regs[i]==saved[i]);
    memcpy(regs,saved,sizeof(regs));
    CHECK(mmio_ldp64_decode(0xa940053f,syndrome,regs,0,&pair)); /* xzr,x1,[x9] */
    CHECK(pair.reg[0]==31 && pair.reg[1]==1);
    mmio_ldp64_complete(&pair,values,regs);
    CHECK(regs[1]==values[1]);
    memcpy(regs,saved,sizeof(regs));

    const uint32_t unsupported[]={0xa9002113,0x29402113,0xad402113,
        0xa9c02113,0xa8c02113,0xa8402113,0x69402113,0xa9404d13,0xd503201f};
    for(unsigned i=0;i<sizeof(unsupported)/sizeof(*unsupported);i++) reject(unsupported[i],syndrome);
    const unsigned bad_bits[]={24,10,9,8,7,6};
    for(unsigned i=0;i<sizeof(bad_bits)/sizeof(*bad_bits);i++) reject(0xa9402113,syndrome|(1UL<<bad_bits[i]));
    reject(0xa9402113,syndrome^(1UL<<25));
    reject(0xa9402113,syndrome^(1UL<<26));
    reject(0xa9402113,(syndrome & ~63UL)|0x21); /* alignment abort */
    CHECK(mmio_ldp64_decode(0xa9402113,(syndrome & ~63UL)|15,regs,0,&pair));
    regs[8]++; reject(0xa9402113,syndrome); regs[8]--;
    regs[8]=UINT64_MAX-7; reject(0xa9402113,syndrome); regs[8]=0x18000;

    /* The actual command/reply path, including metadata consumed exactly
     * once and no visible register/state mutation on rejected paired reads. */
    write64(0x10d88,0);
    write64(0x10d80,0x1002);
    CHECK(device_model_read_pair(&model,&state,0x1c00,values)==DEVICE_OK);
    CHECK(values[0]==2 && values[1]==2);
    CHECK(mmio_ldp64_decode(0xa9402113,syndrome,regs,0,&pair));
    mmio_ldp64_complete(&pair,values,regs);
    CHECK(regs[19]==2 && regs[8]==2);
    CHECK(device_model_read_pair(&model,&state,0x1c00,values)==DEVICE_OK);
    CHECK(values[0]==2 && values[1]==0);
    write64(0x10d88,0);
    write64(0x10d80,0x1003);
    const uint64_t bad_offsets[]={0x1c08,0x1c10,0x3ff0,0x4000,0x10d80,0x14000,UINT64_MAX};
    for(unsigned i=0;i<sizeof(bad_offsets)/sizeof(*bad_offsets);i++) {
        before=state; values[0]=0xaaaa; values[1]=0xbbbb;
        CHECK(device_model_read_pair(&model,&state,bad_offsets[i],values)!=DEVICE_OK);
        CHECK(values[0]==0xaaaa && values[1]==0xbbbb);
        CHECK(!memcmp(&before,&state,sizeof(state)));
    }
    CHECK(device_model_read_pair(&model,&state,0x1c00,values)==DEVICE_OK);
    CHECK(values[0]==3 && values[1]==2);
    printf("PASS: %u MMIO paired-read checks\n",checks);
}
