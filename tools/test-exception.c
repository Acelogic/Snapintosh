/* SPDX-License-Identifier: MIT */
#include "exception.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static unsigned checks;
int main(void)
{
    const uint64_t vbar=UINT64_C(0xfffffe000b86c000);
    for(unsigned offset=0;offset<4096;offset++) {
        CHECK(exception_vector_step(UINT64_C(0x32)<<26,vbar+offset,vbar)==
              (offset<0x800 && !(offset&0x7f)));
    }
    CHECK(!exception_vector_step(UINT64_C(0x32)<<26,vbar-128,vbar));
    CHECK(!exception_vector_step(UINT64_C(0x30)<<26,vbar,vbar));
    CHECK(!exception_vector_step(UINT64_C(0x32)<<26,0,0));
    CHECK(!exception_vector_step(UINT64_C(0x32)<<26,vbar+4,vbar+4));
    for(unsigned bits=0;bits<16;bits++) {
        struct exception_step step={0};
        uint64_t original=0xa0400005UL | ((uint64_t)bits<<6);
        uint64_t spsr=original, mdscr=0x8000;
        exception_step_set(&step,0,&spsr,&mdscr);
        CHECK(spsr==original && mdscr==0x8000);
        CHECK(exception_step_fiq(&step,1) && !exception_step_fiq(&step,0));
        for(unsigned n=0;n<3;n++) {
            exception_step_set(&step,1,&spsr,&mdscr);
            CHECK(spsr==((original|(1UL<<21))&~(1UL<<9)) && mdscr==0x8001);
            CHECK(!exception_step_fiq(&step,1));
        }
        exception_step_set(&step,0,&spsr,&mdscr);
        CHECK(spsr==original && mdscr==0x8000);
        CHECK(exception_step_fiq(&step,1));
        spsr^=1UL<<9; original=spsr;
        exception_step_set(&step,0,&spsr,&mdscr);
        CHECK(spsr==original); /* stale saved_d must not leak into a new state */
        exception_step_set(&step,1,&spsr,&mdscr);
        uint64_t saved=spsr;
        CHECK(exception_step_suspend(&step,&saved));
        CHECK(saved==original && !step.active);
        uint64_t handler=0x3c5;
        exception_step_set(&step,0,&handler,&mdscr);
        CHECK(handler==0x3c5 && mdscr==0x8000);
        CHECK(!exception_step_suspend(&step,&saved) && saved==original);
    }
    const uint64_t hcr=0x488000000UL, pc=0xfffffe000c252bfcUL;
    uint64_t out;
    for(unsigned flags=0;flags<256;flags++) for(unsigned mode=8;mode<=9;mode++) {
        uint64_t spsr=((uint64_t)(flags&15)<<28) | ((uint64_t)(flags>>4)<<6) | (1UL<<22) | mode;
        out=0;
        CHECK(exception_kernel_return(0xd69f03e0,hcr,pc,spsr,&out));
        CHECK(out==((spsr&~15UL)|(mode-4)));
    }
    for(unsigned mode=0;mode<32;mode++) if(mode!=8 && mode!=9) {
        out=0xdead;
        CHECK(!exception_kernel_return(0xd69f03e0,hcr,pc,mode,&out));
        CHECK(out==0xdead);
    }
    for(unsigned i=0;i<10;i++) {
        uint64_t h=hcr,p=pc,s=0x204003c8,insn=0xd69f03e0;
        switch(i) {
        case 0: h&=~(1UL<<34);break;
        case 1: h&=~(1UL<<31);break;
        case 2: h&=~(1UL<<27);break;
        case 3: p++;break;
        case 4: p=0x1000;break;
        case 5: s|=1UL<<20;break;
        case 6: s|=1UL<<5;break;
        case 7: s|=1UL<<32;break;
        case 8: insn=0xd69f0bff;break; /* ERETAA */
        case 9: insn=0xd65f03c0;break; /* RET */
        }
        out=0xdead;
        CHECK(!exception_kernel_return(insn,h,p,s,&out));
        CHECK(out==0xdead);
    }
    CHECK(!exception_kernel_return(0xd69f03e0,hcr,pc,8,0));
    const uint64_t user_pc=0x1026f8bf0, user_sp=0x16d85fd58;
    for(unsigned flags=0;flags<256;flags++) {
        uint64_t spsr=((uint64_t)(flags&15)<<28)|((uint64_t)(flags>>4)<<6);
        CHECK(exception_user_return(0xd69f03e0,hcr,user_pc,spsr,&out));
        CHECK(out==spsr);
    }
    for(unsigned bit=0;bit<64;bit++) {
        uint64_t spsr=1UL<<bit;
        int bad=bit<6 || bit==20 || bit>=32;
        out=0xdead;
        CHECK(exception_user_return(0xd69f03e0,hcr,user_pc,spsr,&out)==!bad);
        CHECK(out==(bad ? 0xdead : spsr));
    }
    for(unsigned i=0;i<11;i++) {
        uint64_t h=hcr,p=user_pc,s=0,insn=0xd69f03e0;
        switch(i) {
        case 0:h&=~(1UL<<34);break;
        case 1:h&=~(1UL<<31);break;
        case 2:h&=~(1UL<<27);break;
        case 3:p++;break;
        case 4:p=0;break;
        case 5:p=1UL<<47;break;
        case 6:p=pc;break;
        case 7:s=4;break;
        case 8:s=8;break;
        case 9:insn=0xd69f0bff;break;
        case 10:insn=0xd65f03c0;break;
        }
        out=0xdead;
        CHECK(!exception_user_return(insn,h,p,s,&out) && out==0xdead);
    }
    CHECK(!exception_user_return(0xd69f03e0,hcr,user_pc,0,0));
    for(unsigned mode=0;mode<32;mode++) {
        CHECK(exception_monitor_origin(pc,mode)==(mode==4 || mode==5));
        CHECK(!exception_monitor_origin(user_pc,mode));
        CHECK(!exception_monitor_origin(pc+1,mode));
    }
    CHECK(exception_user_step(0x910003e0,user_pc,user_sp,0xc8000000,0,user_pc+4,user_sp,user_sp));
    /* This shipped entry intentionally accepts an 8-byte-aligned stack and
     * aligns it itself in the next instruction. */
    CHECK(user_sp%16==8);
    for(unsigned i=0;i<10;i++) {
        uint64_t insn=0x910003e0,entry=user_pc,stack=user_sp,esr=0xc8000000;
        uint64_t spsr=0,next=user_pc+4,x0=user_sp,sp=user_sp;
        switch(i) {
        case 0:insn^=1;break;
        case 1:entry++;break;
        case 2:entry=0;break;
        case 3:stack=0;break;
        case 4:esr=0x80000000;break;
        case 5:spsr=4;break;
        case 6:next=user_pc;break;
        case 7:next=pc;break;
        case 8:x0=0;break;
        case 9:sp-=16;break;
        }
        CHECK(!exception_user_step(insn,entry,stack,esr,spsr,next,x0,sp));
    }
    for(unsigned ec=0;ec<64;ec++) for(unsigned fsc=0;fsc<64;fsc++) {
        uint64_t esr=((uint64_t)ec<<26) | (1UL<<25) | fsc;
        CHECK(exception_kernel_page_fault(esr)==
              ((ec==0x21 || ec==0x25) && fsc>=4 && fsc<=15));
        for(unsigned vector=0;vector<0x800;vector+=0x80) {
            CHECK(exception_user_sync(vector,0,esr)==(vector==0x400 &&
                (ec==0x15 || ((ec==0x20 || ec==0x24) && fsc>=4 && fsc<=15))));
            CHECK(!exception_user_sync(vector,4,esr));
            CHECK(!exception_user_sync(vector,8,esr));
            CHECK(!exception_user_sync(vector,16,esr));
        }
    }
    printf("PASS: %u kernel/user return, vector and execution-witness checks\n",checks);
}
