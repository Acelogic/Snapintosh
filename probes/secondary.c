/* SPDX-License-Identifier: MIT */
#include "secondary.h"
static uint32_t r32(uint64_t p) { return *(volatile uint32_t *)p; }
static void w32(uint64_t p,uint32_t v) { *(volatile uint32_t *)p=v; }
static void barrier(void) { __asm__ volatile("dsb sy; isb" ::: "memory"); }
int64_t secondary_psci(uint64_t fn,uint64_t a,uint64_t b,uint64_t c)
{
    register uint64_t x0 __asm__("x0")=fn, x1 __asm__("x1")=a;
    register uint64_t x2 __asm__("x2")=b, x3 __asm__("x3")=c;
    __asm__ volatile("smc #0" : "+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)
        : : "x4","x5","x6","x7","x8","x9","x10","x11","x12",
            "x13","x14","x15","x16","x17","cc","memory");
    return (int64_t)x0;
}
static int wait_clear(uint64_t p,uint32_t mask)
{
    for (unsigned n=0;n<65535;n++) if (!(r32(p)&mask)) return 1;
    return 0;
}
int secondary_gic_start(struct secondary *s)
{
    uint64_t r=s->redistributor,g=r+0x10000,mpidr;
    __asm__ volatile("mrs %0, mpidr_el1":"=r"(mpidr));
    s->observed_affinity=mpidr&UINT64_C(0xff00ffffff);
    __asm__ volatile("mov %0, sp":"=r"(s->observed_sp));
    __asm__ volatile("mrs %0, sctlr_el2":"=r"(s->observed_regime[0]));
    __asm__ volatile("mrs %0, tcr_el2":"=r"(s->observed_regime[1]));
    __asm__ volatile("mrs %0, ttbr0_el2":"=r"(s->observed_regime[2]));
    __asm__ volatile("mrs %0, mair_el2":"=r"(s->observed_regime[3]));
    for (unsigned i=0;i<4;i++) if (s->observed_regime[i]!=s->regime[i]) return 0;
    if ((s->observed_sp&15) || s->observed_sp>=s->stack || s->stack-s->observed_sp>0x10000)
        return 0;
    if (s->observed_affinity!=s->affinity || r<0x17080000 || r>=0x17500000 ||
        (r-0x17080000)%0x40000 || (r32(0x17000000)&0x80000012)!=0x12 ||
        (*(volatile uint64_t *)(r+8)>>32)!=((s->affinity&0xffffff)|((s->affinity>>32)<<24)))
        return 0;
    s->waker=r32(r+0x14); s->group=r32(g+0x80);
    s->priority=*(volatile uint8_t *)(g+0x41a);
    if (r32(g+0x100) || ((r32(g+0x200)|r32(g+0x300))&(1U<<26)) ||
        (r32(g+0xc04)&(1U<<21))) return 0;
    s->gic_saved=1;
    w32(r+0x14,(uint32_t)s->waker&~2U); barrier();
    if (!wait_clear(r+0x14,4)) return 0;
    w32(g+0x80,(uint32_t)s->group|(1U<<26));
    *(volatile uint8_t *)(g+0x41a)=0x80;
    w32(g+0x280,1U<<26); w32(g+0x100,1U<<26); barrier();
    if (!wait_clear(r,8)) return 0;
    uint64_t sre;
    __asm__ volatile("mrs %0, icc_sre_el2":"=r"(sre));
    __asm__ volatile("msr icc_sre_el2, %0; isb"::"r"(sre|1));
    __asm__ volatile("mrs %0, icc_sre_el2":"=r"(sre));
    if (!(sre&1)) return 0;
    __asm__ volatile("msr icc_pmr_el1, %0; msr icc_bpr1_el1, xzr; "
                     "msr icc_igrpen1_el1, %1; isb"::"r"(UINT64_C(0xf0)),"r"(UINT64_C(1)));
    return 1;
}
int secondary_gic_stop(struct secondary *s)
{
    __asm__ volatile("msr daifset, #15; msr cnthp_ctl_el2, xzr; isb");
    if (!s->gic_saved) return 1;
    uint64_t r=s->redistributor,g=r+0x10000;
    w32(g+0x180,1U<<26);w32(g+0x280,1U<<26);barrier();
    if (!wait_clear(r,8)) return 0;
    /* A normal timer service already EOIs its interrupt. A terminal watchdog
     * may still be pending; no unrelated interrupt is acknowledged here. */
    uint64_t pending;
    __asm__ volatile("mrs %0, icc_hppir1_el1":"=r"(pending));
    if (pending==26) {
        uint64_t id,ctl;
        __asm__ volatile("mrs %0, icc_iar1_el1; dsb sy":"=r"(id)::"memory");
        if (id<1020) {
            __asm__ volatile("mrs %0, icc_ctlr_el1":"=r"(ctl));
            __asm__ volatile("msr icc_eoir1_el1, %0; isb"::"r"(id));
            if (ctl&2) __asm__ volatile("msr icc_dir_el1, %0; isb"::"r"(id));
        }
    }
    w32(g+0x280,1U<<26);w32(g+0x80,(uint32_t)s->group);
    *(volatile uint8_t *)(g+0x41a)=(uint8_t)s->priority;
    w32(r+0x14,(uint32_t)s->waker);barrier();
    s->cleanup=(r32(g+0x100)==0 && !(r32(g+0x300)&(1U<<26)) &&
        !(r32(g+0x200)&(1U<<26)) && r32(g+0x80)==s->group &&
        *(volatile uint8_t *)(g+0x41a)==s->priority &&
        (r32(r+0x14)&2)==(s->waker&2));
    return s->cleanup==1;
}
void secondary_power_off(struct secondary *s)
{
    barrier();
    for (uint64_t p=(uint64_t)s;p<(uint64_t)(s+1);p+=64)
        __asm__ volatile("dc cvac, %0"::"r"(p):"memory");
    __asm__ volatile("dsb sy":::"memory");
    s->off_result=(uint64_t)secondary_psci(0x84000002,0,0,0);
    __atomic_store_n(&s->phase,5,__ATOMIC_RELEASE); /* CPU_OFF returned: never reusable */
    for (;;) __asm__ volatile("wfe":::"memory");
}
