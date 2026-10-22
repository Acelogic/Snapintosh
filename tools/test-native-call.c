/* SPDX-License-Identifier: MIT */
#include "native-call.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1); } } while(0)
static unsigned checks;
int main(void)
{
    const uint64_t pc=UINT64_C(0xfffffe000c22a004);
    const uint32_t words[]={0x00201420,0xd4e00000};
    for(unsigned op=0;op<2;op++)for(unsigned sp=0;sp<2;sp++) {
        for(unsigned flags=0;flags<65536;flags++) {
            /* Exhaust all combinations of NZCV, DAIF and representative
             * upper PSTATE flags, always excluding IL and debug-step state. */
            uint64_t saved=(8+sp) | ((uint64_t)(flags&255)<<6) |
                ((uint64_t)(flags>>8)<<24),physical=0;
            uint64_t vector=sp?0x200:0;
            CHECK(native_call_return(vector,1UL<<25,saved,0x3c5,pc,words[op],&physical));
            CHECK(physical==((saved&~12UL)|4));
        }
        uint64_t saved=UINT64_C(0xa00003c8)+sp,physical=UINT64_MAX;
        uint64_t vector=sp?0x200:0;
        CHECK(!native_call_return(vector^0x200,1UL<<25,saved,0x3c5,pc,words[op],&physical));
        CHECK(physical==UINT64_MAX);
        CHECK(!native_call_return(vector,0,saved,0x3c5,pc,words[op],&physical));
        CHECK(!native_call_return(vector,(1UL<<25)|1,saved,0x3c5,pc,words[op],&physical));
        for(unsigned mode=0;mode<32;mode++)if(mode!=8+sp)
            CHECK(!native_call_return(vector,1UL<<25,(saved&~31UL)|mode,0x3c5,pc,words[op],&physical));
        for(unsigned entry=0;entry<32;entry++)if(entry!=5)
            CHECK(!native_call_return(vector,1UL<<25,saved,entry,pc,words[op],&physical));
        for(unsigned bit=20;bit<=21;bit++)
            CHECK(!native_call_return(vector,1UL<<25,saved|(1UL<<bit),0x3c5,pc,words[op],&physical));
        CHECK(!native_call_return(vector,1UL<<25,saved|(1UL<<32),0x3c5,pc,words[op],&physical));
        CHECK(!native_call_return(vector,1UL<<25,saved,0x3c5,0x1000,words[op],&physical));
        CHECK(!native_call_return(vector,1UL<<25,saved,0x3c5,pc+1,words[op],&physical));
        CHECK(!native_call_return(vector,1UL<<25,saved,0x3c5,pc,0xd503201f,&physical));
        CHECK(!native_call_return(vector,1UL<<25,saved,0x3c5,pc,words[op],0));
    }
    for(unsigned reg=0;reg<32;reg++) {
        CHECK(native_exception_writer(0xd5184000|reg));
        CHECK(native_exception_writer(0xd5184020|reg));
        CHECK(!native_exception_writer(0xd5384000|reg));
        CHECK(!native_exception_writer(0xd5384020|reg));
    }
    CHECK(sizeof(struct native_call_state)==96);
    for(unsigned ec=0;ec<64;ec++)for(unsigned private_call=0;private_call<2;private_call++)
        CHECK(native_call_snapshot_required((uint64_t)ec<<26,private_call)==
              (ec==0x30 || ec==0x32 || (ec==0x20 && !private_call)));
    for(unsigned rt=0;rt<32;rt++)for(unsigned read=0;read<2;read++) {
        uint64_t esr=(UINT64_C(0x18)<<26)|(UINT64_C(1)<<25)|(rt<<5)|read;
        CHECK(native_call_snapshot_required(esr|0x301404,0)==!read);
        CHECK(native_call_snapshot_required(esr|0x301800,0)==!read);
        CHECK(!native_call_snapshot_required(esr|0x301000,0));
        CHECK(!native_call_snapshot_required(esr|0x300000,0));
    }
    printf("PASS %u native-call return-mode, PSTATE and refusal checks\n",checks);
    return 0;
}
