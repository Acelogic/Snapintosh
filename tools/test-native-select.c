/* SPDX-License-Identifier: MIT */
/* compat/native-select.h, the O(1) variant selection the EL0/EL1 boundary and
 * the SPRR write handlers call: every (UPERM, PPERM, regime) state against an
 * independent model of which variant must be live, the register writes each
 * call makes (none when the variant is unchanged), and refusals. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static uint64_t ttbr0_writes[64],ttbr1_writes[64];
static unsigned ttbr0_count,ttbr1_count;
#define NATIVE_WRITE_TTBR0(v) (ttbr0_writes[ttbr0_count++&63]=(v))
#define NATIVE_WRITE_TTBR1(v) (ttbr1_writes[ttbr1_count++&63]=(v))
#include "native-select.h"

static unsigned checks,failures;
#define CHECK(x) do{checks++;if(!(x)){failures++;printf("line %d: %s\n",__LINE__,#x);}}while(0)

#define UP SPRR_UPERM_INITIAL
#define PP SPRR_PPERM_INITIAL
#define TPRO SPRR_UPERM_TPRO_WRITE
static const uint64_t T0[2][2]={{0x1000|(UINT64_C(0x104)<<48),0x2000|(UINT64_C(0x105)<<48)},
                                {0x3000|(UINT64_C(0x106)<<48),0x4000|(UINT64_C(0x107)<<48)}};
static const uint64_t T1[2]={0x5000,0x6000};

/* The model: the variant hardware must walk for this state. */
static unsigned want_w(uint64_t up,uint64_t pp,int el0){return !!((el0 ? up : pp)&TPRO);}
static unsigned want_k(uint64_t pp){return !!(pp&0x100);}

static void reset(void){ttbr0_count=ttbr1_count=0;}

static void test_uninstalled(void)
{
    struct native_cpu n;memset(&n,0,sizeof n);reset();
    CHECK(native_select(&n,1) && native_select(&n,0));
    CHECK(native_set_uperm(&n,UP|TPRO,1) && native_set_pperm(&n,PP|TPRO|0x100,0));
    /* Nothing installed, nothing written; the state is still tracked. */
    CHECK(!ttbr0_count && !ttbr1_count && n.uperm==(UP|TPRO) && n.pperm==(PP|TPRO|0x100) && !n.el0);
    CHECK(n.selects==4 && !n.flips && !n.errors);
}

static void test_install(void)
{
    for(unsigned mask=0;mask<16;mask++) {
        uint64_t up=UP|((mask&1) ? TPRO:0),pp=PP|((mask&2) ? TPRO:0)|((mask&4) ? 0x100:0);
        int el0=!!(mask&8);
        /* Over a CPU that ran another address space in the same state. */
        struct native_cpu n;memset(&n,0,sizeof n);
        CHECK(native_install(&n,T0,T1,up,pp,el0));
        uint64_t other[2][2]={{0x7000,0x7000},{0x8000,0x8000}},flips=n.flips;reset();
        unsigned w=want_w(up,pp,el0),k=want_k(pp);
        /* It names the variant for the caller's sequence and writes nothing. */
        CHECK(native_install(&n,(const uint64_t (*)[2])other,0,up,pp,el0)==other[w][k]);
        CHECK(native_install(&n,T0,T1,up,pp,el0)==T0[w][k] && !ttbr0_count && !ttbr1_count);
        CHECK(n.w==w && n.k==k && n.el0==(uint32_t)el0 && n.installed && n.flips==flips);
        CHECK(n.ttbr1[0]==T1[0] && n.ttbr1[1]==T1[1]);
        CHECK(native_install(&n,T0,0,up,pp,el0) && !n.ttbr1[0] && !n.ttbr1[1]);
    }
}

/* Every call against the model from every state: writes only on a change. */
static void test_transitions(void)
{
    for(unsigned from=0;from<16;from++)for(unsigned op=0;op<3;op++)for(unsigned arg=0;arg<8;arg++) {
        uint64_t up=UP|((from&1) ? TPRO:0),pp=PP|((from&2) ? TPRO:0)|((from&4) ? 0x100:0);
        int el0=!!(from&8);
        struct native_cpu n;memset(&n,0,sizeof n);
        CHECK(native_install(&n,T0,T1,up,pp,el0));
        unsigned w0=n.w,k0=n.k;uint64_t flips=n.flips;reset();
        int next_el0=!!(arg&4);int ok;
        if(op==0) {ok=native_select(&n,next_el0);}
        else if(op==1) {up=UP|((arg&1) ? TPRO:0);ok=native_set_uperm(&n,up,next_el0);}
        else {pp=PP|((arg&1) ? TPRO:0)|((arg&2) ? 0x100:0);ok=native_set_pperm(&n,pp,next_el0);}
        unsigned w=want_w(up,pp,next_el0),k=want_k(pp);
        CHECK(ok && n.w==w && n.k==k && n.el0==(uint32_t)next_el0 && n.uperm==up && n.pperm==pp);
        int changed=w!=w0 || k!=k0;
        CHECK(ttbr0_count==(unsigned)changed && (!changed || ttbr0_writes[0]==T0[w][k]));
        CHECK(ttbr1_count==(unsigned)(k!=k0) && (k==k0 || ttbr1_writes[0]==T1[k]));
        CHECK(n.flips==flips+(uint64_t)changed && !n.errors);
    }
}

static void test_refusal_and_uninstall(void)
{
    uint64_t t0[2][2];memcpy(t0,T0,sizeof t0);t0[1][0]=0;
    struct native_cpu n;memset(&n,0,sizeof n);reset();
    CHECK(native_install(&n,(const uint64_t (*)[2])t0,T1,UP,PP,1));
    /* The missing variant is refused (terminal for the caller) without a write. */
    reset();
    CHECK(!native_set_uperm(&n,UP|TPRO,1) && n.errors==1 && !ttbr0_count && !ttbr1_count);
    CHECK(n.w==0);
    /* An install whose reset variant is missing is refused and uninstalls. */
    CHECK(!native_install(&n,(const uint64_t (*)[2])t0,T1,UP|TPRO,PP,1) && !n.installed && n.errors==2);
    memset(&n,0,sizeof n);CHECK(native_install(&n,T0,T1,UP,PP,0));
    native_uninstall(&n);reset();
    CHECK(native_set_pperm(&n,PP|TPRO|0x100,0) && native_select(&n,1) && !ttbr0_count && !ttbr1_count);
    CHECK(!n.installed && !n.errors);
}

int main(void)
{
    test_uninstalled();test_install();test_transitions();test_refusal_and_uninstall();
    printf("%s: native variant selection, %u checks, %u failures\n",failures ? "FAIL":"PASS",checks,failures);
    return failures!=0;
}
